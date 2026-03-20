// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	anthropicDefaultEndpoint = "https://api.anthropic.com"
	anthropicDefaultModel    = "claude-sonnet-4-20250514"
	anthropicAPIVersion      = "2023-06-01"
)

// AnthropicProvider implements Provider using the Anthropic Messages API.
// No SDK dependency — raw net/http + encoding/json.
type AnthropicProvider struct {
	endpoint    string
	apiKey      string
	model       string
	maxTokens   int
	temperature float64
	client      *http.Client
}

// NewAnthropicProvider creates a provider for Anthropic Claude.
func NewAnthropicProvider(cfg ProviderConfig) *AnthropicProvider {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = anthropicDefaultEndpoint
	}
	model := cfg.Model
	if model == "" {
		model = anthropicDefaultModel
	}
	maxTokens := cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 1024
	}
	temp := cfg.Temperature
	if temp == 0 {
		temp = 0.2
	}

	return &AnthropicProvider{
		endpoint:    endpoint,
		apiKey:      cfg.APIKey,
		model:       model,
		maxTokens:   maxTokens,
		temperature: temp,
		client:      &http.Client{},
	}
}

func (p *AnthropicProvider) Name() string { return "anthropic" }

func (p *AnthropicProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = p.maxTokens
	}
	temp := req.Temperature
	if temp == 0 {
		temp = p.temperature
	}

	body := anthropicRequest{
		Model:       p.model,
		MaxTokens:   maxTokens,
		Temperature: temp,
		System:      req.SystemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: req.UserPrompt},
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/v1/messages", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicAPIVersion)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic API call failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result anthropicResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	text := ""
	for _, block := range result.Content {
		if block.Type == "text" {
			text += block.Text
		}
	}

	tokensUsed := result.Usage.InputTokens + result.Usage.OutputTokens

	return &CompletionResponse{
		Text:       text,
		TokensUsed: tokensUsed,
		Model:      result.Model,
	}, nil
}

// Anthropic API types — minimal, only what we need.

type anthropicRequest struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []anthropicContentBlock `json:"content"`
	Model   string                  `json:"model"`
	Usage   anthropicUsage          `json:"usage"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}
