// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/lowplane/kerno/internal/doctor"
)

// DefaultAnalyzer implements doctor.Analyzer by sending findings to an LLM
// provider and parsing the structured response.
type DefaultAnalyzer struct {
	provider    Provider
	cache       *Cache
	privacy     PrivacyMode
	logger      *slog.Logger
}

// AnalyzerConfig holds configuration for constructing a DefaultAnalyzer.
type AnalyzerConfig struct {
	Provider Provider
	Cache    *Cache
	Privacy  PrivacyMode
	Logger   *slog.Logger
}

// NewAnalyzer creates a DefaultAnalyzer.
func NewAnalyzer(cfg AnalyzerConfig) *DefaultAnalyzer {
	privacy := cfg.Privacy
	if privacy == "" {
		privacy = PrivacySummary
	}
	return &DefaultAnalyzer{
		provider: cfg.Provider,
		cache:    cfg.Cache,
		privacy:  privacy,
		logger:   cfg.Logger,
	}
}

// Analyze implements doctor.Analyzer. It serializes signals and findings into
// a prompt, sends it to the LLM, and parses the structured JSON response.
func (a *DefaultAnalyzer) Analyze(ctx context.Context, req doctor.AnalysisRequest) (*doctor.AnalysisResponse, error) {
	// Check cache first.
	if a.cache != nil {
		fingerprint := findingsFingerprint(req.Findings)
		if cached, ok := a.cache.Get(fingerprint); ok {
			a.logger.Debug("AI cache hit", "fingerprint", fingerprint)
			return cached, nil
		}
	}

	// Build the prompt.
	userPrompt := BuildUserPrompt(req.Signals, req.Findings, req.History, a.privacy)

	a.logger.Debug("sending to AI provider",
		"provider", a.provider.Name(),
		"privacy", a.privacy,
		"prompt_len", len(userPrompt),
	)

	// Call the LLM.
	completion, err := a.provider.Complete(ctx, CompletionRequest{
		SystemPrompt: SystemPrompt,
		UserPrompt:   userPrompt,
	})
	if err != nil {
		return nil, fmt.Errorf("AI provider %s: %w", a.provider.Name(), err)
	}

	a.logger.Info("AI analysis complete",
		"provider", a.provider.Name(),
		"model", completion.Model,
		"tokens", completion.TokensUsed,
	)

	// Parse the structured JSON response.
	response, err := parseAnalysisResponse(completion.Text)
	if err != nil {
		// If JSON parsing fails, treat the entire response as a summary.
		a.logger.Warn("AI response was not valid JSON, using as plain text summary", "error", err)
		response = &doctor.AnalysisResponse{
			Summary: completion.Text,
		}
	}
	response.TokensUsed = completion.TokensUsed

	// Cache the result.
	if a.cache != nil {
		fingerprint := findingsFingerprint(req.Findings)
		a.cache.Set(fingerprint, response)
	}

	return response, nil
}

// parseAnalysisResponse attempts to parse the LLM response as structured JSON.
func parseAnalysisResponse(text string) (*doctor.AnalysisResponse, error) {
	// Try to extract JSON from the response (LLMs sometimes wrap in markdown).
	jsonText := extractJSON(text)

	var resp doctor.AnalysisResponse
	if err := json.Unmarshal([]byte(jsonText), &resp); err != nil {
		return nil, fmt.Errorf("parsing AI response JSON: %w", err)
	}
	return &resp, nil
}

// extractJSON tries to find a JSON object in the text, handling markdown code blocks.
func extractJSON(text string) string {
	// Look for ```json ... ``` blocks.
	if start := findSubstring(text, "```json"); start >= 0 {
		content := text[start+7:]
		if end := findSubstring(content, "```"); end >= 0 {
			return content[:end]
		}
	}
	// Look for ``` ... ``` blocks.
	if start := findSubstring(text, "```"); start >= 0 {
		content := text[start+3:]
		if end := findSubstring(content, "```"); end >= 0 {
			return content[:end]
		}
	}
	// Try the raw text as-is.
	return text
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// findingsFingerprint creates a cache key from findings.
// It uses rule names and severities, not exact values, so similar
// situations share cache entries.
func findingsFingerprint(findings []doctor.Finding) string {
	if len(findings) == 0 {
		return "healthy"
	}
	parts := make([]string, len(findings))
	for i, f := range findings {
		parts[i] = fmt.Sprintf("%s:%s", f.Rule, f.Severity)
	}
	// Simple concatenation — good enough for cache key.
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "|"
		}
		result += p
	}
	return result
}
