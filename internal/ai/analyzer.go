// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/optiqor/kerno/internal/doctor"
)

// DefaultAnalyzer implements doctor.Analyzer by sending findings to an LLM
// provider and parsing the structured response.
type DefaultAnalyzer struct {
	provider    Provider
	cache       *Cache
	privacy     PrivacyMode
	logger      *slog.Logger
	maxTokens   int
	temperature float64
}

// AnalyzerConfig holds configuration for constructing a DefaultAnalyzer.
type AnalyzerConfig struct {
	Provider    Provider
	Cache       *Cache
	Privacy     PrivacyMode
	Logger      *slog.Logger
	MaxTokens   int
	Temperature float64
}

// NewAnalyzer creates a DefaultAnalyzer.
func NewAnalyzer(cfg AnalyzerConfig) *DefaultAnalyzer {
	privacy := cfg.Privacy
	if privacy == "" {
		privacy = PrivacySummary
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &DefaultAnalyzer{
		provider:    cfg.Provider,
		cache:       cfg.Cache,
		privacy:     privacy,
		logger:      logger,
		maxTokens:   cfg.MaxTokens,
		temperature: cfg.Temperature,
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
		"findings", len(req.Findings),
	)

	resp, err := a.provider.Complete(ctx, CompletionRequest{
		SystemPrompt: SystemPrompt,
		UserPrompt:   userPrompt,
		MaxTokens:    a.maxTokens,
		Temperature:  a.temperature,
	})
	if err != nil {
		return nil, fmt.Errorf("AI provider error: %w", err)
	}

	var result doctor.AnalysisResponse
	if err := json.Unmarshal([]byte(resp.Text), &result); err != nil {
		return nil, fmt.Errorf("parsing AI response: %w", err)
	}
	result.TokensUsed = resp.TokensUsed
	result.Model = resp.Model

	if a.cache != nil {
		fingerprint := findingsFingerprint(req.Findings)
		a.cache.Set(fingerprint, &result)
	}

	return &result, nil
}
	
