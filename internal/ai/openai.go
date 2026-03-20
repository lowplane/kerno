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
	openaiDefaultEndpoint = "https://api.openai.com"
	openaiDefaultModel    = "gpt-4o-mini"
)

// OpenAIProvider implements Provider using the OpenAI Chat Completions API.
// Also compatible with any OpenAI-compatible API (e.g., Azure OpenAI, vLLM).
type OpenAIProvider struct {
	endpoint    string
	apiKey      string
	model       string
	maxTokens   int
	temperature float64
	client      *http.Client
}

// NewOpenAIProvider creates a provider for OpenAI (or compatible APIs).
func NewOpenAIProvider(cfg ProviderConfig) *OpenAIProvider {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = openaiDefaultEndpoint
	}
	model := cfg.Model
	if model == "" {
		model = openaiDefaultModel
	}
	maxTokens := cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 1024
	}
	temp := cfg.Temperature
	if temp == 0 {
		temp = 0.2
	}

	return &OpenAIProvider{
		endpoint:    endpoint,
		apiKey:      cfg.APIKey,
		model:       model,
		maxTokens:   maxTokens,
		temperature: temp,
		client:      &http.Client{},
	}
}

func (p *OpenAIProvider) Name() string { return "openai" }

func (p *OpenAIProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = p.maxTokens
	}
	temp := req.Temperature
	if temp == 0 {
		temp = p.temperature
	}

	messages := []openaiMessage{
		{Role: "system", Content: req.SystemPrompt},
		{Role: "user", Content: req.UserPrompt},
	}

	body := openaiRequest{
		Model:       p.model,
		Messages:    messages,
		MaxTokens:   maxTokens,
		Temperature: temp,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai API call failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result openaiResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	text := ""
	if len(result.Choices) > 0 {
		text = result.Choices[0].Message.Content
	}

	tokensUsed := result.Usage.TotalTokens

	return &CompletionResponse{
		Text:       text,
		TokensUsed: tokensUsed,
		Model:      result.Model,
	}, nil
}

// OpenAI API types — minimal.

type openaiRequest struct {
	Model       string          `json:"model"`
	Messages    []openaiMessage `json:"messages"`
	MaxTokens   int             `json:"max_tokens"`
	Temperature float64         `json:"temperature"`
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiResponse struct {
	Choices []openaiChoice `json:"choices"`
	Model   string         `json:"model"`
	Usage   openaiUsage    `json:"usage"`
}

type openaiChoice struct {
	Message openaiMessage `json:"message"`
}

type openaiUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}
