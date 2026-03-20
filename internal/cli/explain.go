// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/lowplane/kerno/internal/ai"
)

const explainSystemPrompt = `You are Kerno, a Linux kernel expert. The user will paste a kernel error message, log line, or stack trace. Your job is to:

1. Explain what happened in plain English (1-2 sentences)
2. Explain WHY it happened (root cause)
3. Explain the IMPACT (what breaks because of this)
4. Provide specific FIX steps (exact commands when possible)

Be concise. Use concrete technical details. If you're not sure about the root cause, say so.
Format your response as clear sections with headers.`

func newExplainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain [error message]",
		Short: "Explain a kernel error or log message using AI",
		Long: `Kerno Explain takes a kernel error message, stack trace, or log line and
explains it in plain English with root cause analysis and fix suggestions.

No eBPF or root access required — just paste your error and get answers.
Requires an AI provider to be configured (--ai-provider or KERNO_AI_PROVIDER).`,
		Example: `  # Explain a kernel error from argument
  kerno explain "BUG: kernel NULL pointer dereference, address: 0000000000000040"

  # Explain from stdin (pipe dmesg, journalctl, etc.)
  dmesg | tail -5 | kerno explain

  # Explain a specific log line
  kerno explain "Out of memory: Killed process 1234 (postgres)"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExplain(cmd.Context(), args)
		},
	}

	return cmd
}

func runExplain(ctx context.Context, args []string) error {
	logger := slog.Default()

	// Get the error message from args or stdin.
	var errorMsg string
	if len(args) > 0 {
		errorMsg = strings.Join(args, " ")
	} else {
		// Check if stdin has data (piped input).
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			// Stdin has piped data.
			data, err := readStdin()
			if err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
			errorMsg = data
		}
	}

	if errorMsg == "" {
		return fmt.Errorf("no error message provided. Usage: kerno explain \"<error message>\" or pipe via stdin")
	}

	// Build the AI provider.
	if !cfg.AI.Enabled && cfg.AI.APIKey == "" {
		// Try to be helpful even without explicit config.
		if os.Getenv("KERNO_AI_API_KEY") == "" {
			return fmt.Errorf("AI is not configured. Set KERNO_AI_API_KEY or configure ai.enabled in config.\nSee: kerno explain --help")
		}
	}

	provider, err := ai.NewProvider(ai.ProviderConfig{
		Name:        cfg.AI.Provider,
		Model:       cfg.AI.Model,
		APIKey:      cfg.AI.APIKey,
		Endpoint:    cfg.AI.Endpoint,
		MaxTokens:   cfg.AI.MaxTokens,
		Temperature: cfg.AI.Temperature,
	})
	if err != nil {
		return fmt.Errorf("creating AI provider: %w", err)
	}

	logger.Debug("sending to AI", "provider", provider.Name(), "input_len", len(errorMsg))

	// Call the LLM.
	resp, err := provider.Complete(ctx, ai.CompletionRequest{
		SystemPrompt: explainSystemPrompt,
		UserPrompt:   errorMsg,
	})
	if err != nil {
		return fmt.Errorf("AI analysis failed: %w", err)
	}

	logger.Debug("AI response received", "tokens", resp.TokensUsed, "model", resp.Model)

	// Print the explanation.
	fmt.Println(resp.Text)

	return nil
}

func readStdin() (string, error) {
	var lines []string
	scanner := bufio.NewScanner(os.Stdin)
	// Limit to 100 lines to prevent reading huge inputs.
	for i := 0; i < 100 && scanner.Scan(); i++ {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return "", err
	}
	return strings.Join(lines, "\n"), nil
}
