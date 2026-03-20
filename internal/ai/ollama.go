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
	ollamaDefaultEndpoint = "http://localhost:11434"
	ollamaDefaultModel    = "llama3.1"
)

// OllamaProvider implements Provider using the local Ollama API.
// Works air-gapped — no API key needed, no data leaves the machine.
type OllamaProvider struct {
	endpoint    string
	model       string
	maxTokens   int
	temperature float64
	client      *http.Client
}

// NewOllamaProvider creates a provider for local Ollama.
func NewOllamaProvider(cfg ProviderConfig) *OllamaProvider {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = ollamaDefaultEndpoint
	}
	model := cfg.Model
	if model == "" {
		model = ollamaDefaultModel
	}
	maxTokens := cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 1024
	}
	temp := cfg.Temperature
	if temp == 0 {
		temp = 0.2
	}

	return &OllamaProvider{
		endpoint:    endpoint,
		model:       model,
		maxTokens:   maxTokens,
		temperature: temp,
		client:      &http.Client{},
	}
}

func (p *OllamaProvider) Name() string { return "ollama" }

func (p *OllamaProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	temp := req.Temperature
	if temp == 0 {
		temp = p.temperature
	}

	// Ollama uses /api/chat for chat-style completions.
	body := ollamaRequest{
		Model: p.model,
		Messages: []ollamaMessage{
			{Role: "system", Content: req.SystemPrompt},
			{Role: "user", Content: req.UserPrompt},
		},
		Stream: false, // We want the full response, not streaming.
		Options: ollamaOptions{
			Temperature: temp,
			NumPredict:  p.maxTokens,
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/api/chat", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama API call failed (is Ollama running at %s?): %w", p.endpoint, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result ollamaResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	tokensUsed := result.PromptEvalCount + result.EvalCount

	return &CompletionResponse{
		Text:       result.Message.Content,
		TokensUsed: tokensUsed,
		Model:      result.Model,
	}, nil
}

// Ollama API types.

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  ollamaOptions   `json:"options,omitempty"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaOptions struct {
	Temperature float64 `json:"temperature,omitempty"`
	NumPredict  int     `json:"num_predict,omitempty"`
}

type ollamaResponse struct {
	Model           string        `json:"model"`
	Message         ollamaMessage `json:"message"`
	PromptEvalCount int           `json:"prompt_eval_count"`
	EvalCount       int           `json:"eval_count"`
}
