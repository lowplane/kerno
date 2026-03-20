// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

// Package ai implements LLM provider abstractions and the AI analysis layer
// for kerno doctor. AI is always optional — the deterministic rule engine
// works without it. AI enriches findings with natural language diagnosis,
// cross-signal correlation, and root cause analysis.
//
// No LLM SDK dependencies — all providers use net/http + encoding/json.
package ai

import (
	"context"
	"fmt"
)

// Provider abstracts an LLM backend. Implementations exist for Anthropic,
// OpenAI, and Ollama — all using raw HTTP, no SDKs.
type Provider interface {
	// Name returns the provider identifier (e.g., "anthropic", "openai", "ollama").
	Name() string

	// Complete sends a prompt to the LLM and returns the response text.
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
}

// CompletionRequest is the provider-agnostic input to an LLM.
type CompletionRequest struct {
	// SystemPrompt is the system/instruction prompt.
	SystemPrompt string

	// UserPrompt is the user message containing signal data.
	UserPrompt string

	// MaxTokens caps the response length.
	MaxTokens int

	// Temperature controls randomness (0.0–1.0).
	Temperature float64
}

// CompletionResponse is the provider-agnostic LLM output.
type CompletionResponse struct {
	// Text is the generated response content.
	Text string

	// TokensUsed is the total tokens consumed (input + output).
	TokensUsed int

	// Model is the actual model used (may differ from requested).
	Model string
}

// ProviderConfig holds the configuration needed to construct a Provider.
type ProviderConfig struct {
	// Provider name: "anthropic", "openai", "ollama".
	Name string

	// Model identifier (e.g., "claude-sonnet-4-20250514", "gpt-4o-mini").
	Model string

	// APIKey for authentication (not needed for Ollama).
	APIKey string

	// Endpoint override (e.g., "http://localhost:11434" for Ollama).
	Endpoint string

	// MaxTokens default for completions.
	MaxTokens int

	// Temperature default.
	Temperature float64
}

// NewProvider constructs the appropriate Provider from config.
func NewProvider(cfg ProviderConfig) (Provider, error) {
	switch cfg.Name {
	case "anthropic":
		return NewAnthropicProvider(cfg), nil
	case "openai":
		return NewOpenAIProvider(cfg), nil
	case "ollama":
		return NewOllamaProvider(cfg), nil
	default:
		return nil, fmt.Errorf("unknown AI provider %q: must be anthropic, openai, or ollama", cfg.Name)
	}
}
