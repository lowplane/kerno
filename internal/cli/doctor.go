// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/lowplane/kerno/internal/ai"
	"github.com/lowplane/kerno/internal/collector"
	"github.com/lowplane/kerno/internal/config"
	"github.com/lowplane/kerno/internal/doctor"
)

func newDoctorCmd() *cobra.Command {
	var (
		duration   time.Duration
		exitCode   bool
		continuous bool
		interval   time.Duration
		output     string
		useAI      bool
		noAI       bool
	)

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run a 30-second automated kernel diagnostic",
		Long: `Kerno Doctor collects kernel signals via eBPF for 30 seconds (configurable),
analyzes them against diagnostic rules, and prints a ranked report of findings.

This is the primary entry point for kernel troubleshooting. No configuration needed.
Add --ai to enrich findings with AI-powered analysis (requires API key).`,
		Example: `  # Run a standard 30-second diagnostic
  sudo kerno doctor

  # Quick 10-second check
  sudo kerno doctor --duration 10s

  # Machine-readable output for CI/CD
  sudo kerno doctor --output json --exit-code

  # Continuous monitoring
  sudo kerno doctor --continuous --interval 60s

  # Enable AI analysis
  sudo kerno doctor --ai`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Inherit --output from root if not set via doctor flag.
			if output == "" {
				output, _ = cmd.Root().PersistentFlags().GetString("output")
			}

			// Resolve AI enable/disable: --ai flag overrides config, --no-ai forces off.
			aiEnabled := cfg.AI.Enabled
			if useAI {
				aiEnabled = true
			}
			if noAI {
				aiEnabled = false
			}

			return runDoctor(cmd.Context(), doctorOpts{
				duration:  duration,
				exitCode:  exitCode,
				continuous: continuous,
				interval:  interval,
				output:    output,
				aiEnabled: aiEnabled,
			})
		},
	}

	flags := cmd.Flags()
	flags.DurationVarP(&duration, "duration", "d", 0, "analysis duration (default: from config, typically 30s)")
	flags.BoolVar(&exitCode, "exit-code", false, "exit 1 if critical findings exist (for CI/CD)")
	flags.BoolVar(&continuous, "continuous", false, "re-run analysis at regular intervals")
	flags.DurationVar(&interval, "interval", 60*time.Second, "interval between runs in continuous mode")
	flags.StringVarP(&output, "output", "o", "", "output format: pretty, json (overrides global --output)")
	flags.BoolVar(&useAI, "ai", false, "enable AI-powered analysis (requires API key)")
	flags.BoolVar(&noAI, "no-ai", false, "disable AI analysis even if enabled in config")

	return cmd
}

type doctorOpts struct {
	duration   time.Duration
	exitCode   bool
	continuous bool
	interval   time.Duration
	output     string
	aiEnabled  bool
}

func runDoctor(ctx context.Context, opts doctorOpts) error {
	// Use config default if no flag override.
	if opts.duration == 0 {
		if cfg != nil {
			opts.duration = cfg.Doctor.Duration
		} else {
			opts.duration = 30 * time.Second
		}
	}
	if opts.output == "" {
		opts.output = "pretty"
	}

	logger := slog.Default()

	// Resolve thresholds from config.
	thresholds := cfg.Doctor.Thresholds

	// Build optional AI analyzer.
	var analyzer doctor.Analyzer
	if opts.aiEnabled {
		var err error
		analyzer, err = buildAnalyzer(cfg, logger)
		if err != nil {
			// AI setup failure is non-fatal — warn and continue without AI.
			logger.Warn("AI analysis unavailable, continuing with rule-based diagnostics", "error", err)
		}
	}

	// Create the diagnostic engine.
	engine := doctor.NewEngine(thresholds, analyzer, logger)

	// Select renderer.
	var renderer doctor.Renderer
	switch opts.output {
	case "json":
		renderer = &doctor.JSONRenderer{Pretty: true}
	default:
		renderer = &doctor.PrettyRenderer{
			NoColor: os.Getenv("NO_COLOR") != "",
		}
	}

	// Create collector registry.
	registry := collector.NewRegistry(logger)

	// TODO(phase-2): Register live collectors here once they are implemented.
	// For now, the registry produces empty signals → "System Healthy" report.

	// Run the diagnostic loop (once, or continuous).
	for {
		if err := runDiagnosticCycle(ctx, engine, registry, renderer, opts, logger); err != nil {
			return err
		}

		if !opts.continuous {
			break
		}

		logger.Info("waiting for next cycle", "interval", opts.interval)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(opts.interval):
		}
	}

	return nil
}

// buildAnalyzer constructs the AI analyzer from configuration.
func buildAnalyzer(c *config.Config, logger *slog.Logger) (doctor.Analyzer, error) {
	aiCfg := c.AI

	// Build the LLM provider.
	provider, err := ai.NewProvider(ai.ProviderConfig{
		Name:        aiCfg.Provider,
		Model:       aiCfg.Model,
		APIKey:      aiCfg.APIKey,
		Endpoint:    aiCfg.Endpoint,
		MaxTokens:   aiCfg.MaxTokens,
		Temperature: aiCfg.Temperature,
	})
	if err != nil {
		return nil, fmt.Errorf("creating AI provider: %w", err)
	}

	// Wrap with rate limiter.
	if aiCfg.RateLimitPerMinute > 0 {
		provider = ai.NewRateLimitedProvider(provider, aiCfg.RateLimitPerMinute)
	}

	// Build the cache.
	var cache *ai.Cache
	if aiCfg.CacheTTL != "" {
		ttl, err := time.ParseDuration(aiCfg.CacheTTL)
		if err != nil {
			logger.Warn("invalid ai.cache_ttl, using 5m default", "value", aiCfg.CacheTTL, "error", err)
			ttl = 5 * time.Minute
		}
		cache = ai.NewCache(ttl)
	}

	// Resolve privacy mode.
	privacy := ai.PrivacyMode(aiCfg.PrivacyMode)
	if privacy == "" {
		privacy = ai.PrivacySummary
	}

	return ai.NewAnalyzer(ai.AnalyzerConfig{
		Provider: provider,
		Cache:    cache,
		Privacy:  privacy,
		Logger:   logger,
	}), nil
}

func runDiagnosticCycle(
	ctx context.Context,
	engine *doctor.Engine,
	registry *collector.Registry,
	renderer doctor.Renderer,
	opts doctorOpts,
	logger *slog.Logger,
) error {
	logger.Info("starting kernel diagnostic",
		"duration", opts.duration,
		"ai", opts.aiEnabled,
	)

	// Phase 1: Collect signals for the configured duration.
	collectCtx, cancel := context.WithTimeout(ctx, opts.duration)
	defer cancel()

	// Show progress to user (stderr so it doesn't pollute JSON output).
	if opts.output != "json" {
		fmt.Fprintf(os.Stderr, "Collecting kernel signals for %s...\n", opts.duration)
	}

	// Wait for collection window to complete.
	<-collectCtx.Done()

	// Check if we were canceled by the parent context (Ctrl+C) vs timeout.
	if ctx.Err() != nil {
		if opts.output != "json" {
			fmt.Fprintf(os.Stderr, "Interrupted — analyzing partial data.\n")
		}
	}

	// Phase 2: Gather combined signal snapshot from all collectors.
	signals := registry.Signals(opts.duration)

	// Phase 3: Run diagnostic engine (rules + optional AI).
	report, err := engine.Diagnose(ctx, signals)
	if err != nil {
		return fmt.Errorf("diagnosis failed: %w", err)
	}

	// Phase 4: Render the report.
	if err := renderer.Render(os.Stdout, report); err != nil {
		return fmt.Errorf("rendering report: %w", err)
	}

	// Phase 5: Exit code handling for CI/CD.
	if opts.exitCode && report.HasCritical() {
		return &exitError{code: 1}
	}

	return nil
}

// exitError is returned when --exit-code is set and critical findings exist.
type exitError struct {
	code int
}

func (e *exitError) Error() string {
	return fmt.Sprintf("critical findings detected (exit code %d)", e.code)
}

// ExitCode returns the exit code for this error.
func (e *exitError) ExitCode() int {
	return e.code
}
