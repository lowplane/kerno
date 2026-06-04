// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/optiqor/kerno/internal/preflight"
)

func newPreflightCmd() *cobra.Command {
	var (
		output    string
		outputDir string
		promAddr  string
	)

	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Validate host prerequisites for running kerno",
		Long: `Preflight runs every host prerequisite check and reports each as PASS / FAIL / WARN.

Use this before "kerno doctor" to verify the host can run kerno. Each check
includes a remediation hint when it fails.

Exit codes:
  0  All checks passed (warnings are printed to stderr but don't block)
  1  One or more checks failed`,
		Example: `  # Check if this host can run kerno
  sudo kerno preflight

  # Machine-readable for Helm hooks and CI
  kerno preflight --output json

  # Custom output directory and Prometheus port
  sudo kerno preflight --output-dir /data/kerno --prom-addr :9091`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Inherit --output from root if not set via preflight flag.
			if output == "" {
				output, _ = cmd.Root().PersistentFlags().GetString("output")
			}

			// Build CheckOptions from flags + config.
			opts := preflight.CheckOptions{}
			if outputDir != "" {
				opts.OutputDir = outputDir
			}
			if promAddr != "" {
				opts.PromAddr = promAddr
			} else if cfg != nil && cfg.Prometheus.Addr != "" {
				opts.PromAddr = cfg.Prometheus.Addr
			}

			// Run all preflight checks.
			results := preflight.RunAll(opts)

			// Render output.
			switch output {
			case "json":
				return renderPreflightJSON(cmd, results)
			default:
				return renderPreflightPretty(cmd, results)
			}
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&output, "output", "o", "", "output format: pretty, json")
	flags.StringVar(&outputDir, "output-dir", "", "output directory to check (default: /var/log/kerno)")
	flags.StringVar(&promAddr, "prom-addr", "", "Prometheus address to check (default from config)")

	return cmd
}

// preflightSummary counts the results by status.
type preflightSummary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

// preflightReport is the JSON output structure.
type preflightReport struct {
	Checks  []preflight.Result `json:"checks"`
	Summary preflightSummary   `json:"summary"`
	Ready   bool               `json:"ready"`
}

func summarize(results []preflight.Result) preflightSummary {
	var s preflightSummary
	for i := range results {
		switch results[i].Status {
		case preflight.StatusPass:
			s.Pass++
		case preflight.StatusWarn:
			s.Warn++
		case preflight.StatusFail:
			s.Fail++
		}
	}
	return s
}

func renderPreflightJSON(cmd *cobra.Command, results []preflight.Result) error {
	s := summarize(results)
	report := preflightReport{
		Checks:  results,
		Summary: s,
		Ready:   s.Fail == 0,
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}

	if s.Fail > 0 {
		return &exitError{code: 1}
	}
	return nil
}

func renderPreflightPretty(cmd *cobra.Command, results []preflight.Result) error {
	w := cmd.OutOrStdout()
	noColor := os.Getenv("NO_COLOR") != "" || !isTerminal()

	fmt.Fprintln(w, "==> Kerno preflight check")
	fmt.Fprintln(w)

	for i := range results {
		r := &results[i]
		tag := formatStatusTag(r.Status, noColor)
		fmt.Fprintf(w, "%s %s\n", tag, r.Message)
	}

	s := summarize(results)
	fmt.Fprintln(w)

	var verdict string
	if s.Fail == 0 {
		verdict = "ready to start"
	} else {
		verdict = "not ready"
	}
	fmt.Fprintf(w, "Result: %d PASS, %d WARN, %d FAIL → %s\n", s.Pass, s.Warn, s.Fail, verdict)

	// Print remediation hints for failures and warnings to stderr.
	var hints []string
	for i := range results {
		if results[i].Detail != "" && results[i].Status != preflight.StatusPass {
			hints = append(hints, fmt.Sprintf("  %s: %s", results[i].Name, results[i].Detail))
		}
	}
	if len(hints) > 0 {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Remediation hints:")
		for _, h := range hints {
			fmt.Fprintln(os.Stderr, h)
		}
	}

	if s.Fail > 0 {
		return &exitError{code: 1}
	}
	return nil
}

// formatStatusTag returns a colored [PASS], [WARN], or [FAIL] tag.
func formatStatusTag(s preflight.Status, noColor bool) string {
	label := s.String()

	if noColor {
		return "[" + label + "]"
	}

	var color string
	switch s {
	case preflight.StatusPass:
		color = "\033[32m" // green
	case preflight.StatusWarn:
		color = "\033[33m" // yellow
	case preflight.StatusFail:
		color = "\033[31m" // red
	}
	reset := "\033[0m"

	return color + "[" + label + "]" + reset
}
