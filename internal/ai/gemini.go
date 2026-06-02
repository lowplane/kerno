// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GeminiProvider implements the Provider interface for Google Gemini API.
// Uses raw HTTP + JSON — no SDK dependency.
type GeminiProvider struct {
	apiKey      string
	model       string
	endpoint    string
	maxTokens   int
	temperature float64
	client      *http.Client
}

// NewGeminiProvider creates a new Gemini provider.
func NewGeminiProvider(cfg ProviderConfig) *GeminiProvider {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://generativelanguage.googleapis.com/v1beta"
	}

	model := cfg.Model
	if model == "" {
		model = "gemini-1.5-flash" // Default to fast model
	}

	maxTokens := cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	temperature := cfg.Temperature
	if temperature == 0 {
		temperature = 0.7
	}

	return &GeminiProvider{
		apiKey:      cfg.APIKey,
		model:       model,
		endpoint:    endpoint,
		maxTokens:   maxTokens,
		temperature: temperature,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Name returns "gemini".
func (p *GeminiProvider) Name() string {
	return "gemini"
}

// Complete sends a completion request to the Gemini API.
func (p *GeminiProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	if p.apiKey == "" {
		return nil, fmt.Errorf("gemini: API key not configured (set KERNO_AI_API_KEY)")
	}

	// Build the request payload.
	payload := geminiRequest{
		Contents: []geminiContent{
			{
				Parts: []geminiPart{
					{Text: req.SystemPrompt + "\n\n" + req.UserPrompt},
				},
			},
		},
		GenerationConfig: geminiGenerationConfig{
			Temperature:     p.temperature,
			MaxOutputTokens: p.maxTokens,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("gemini: marshaling request: %w", err)
	}

	// Build the URL with API key.
	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s",
		p.endpoint, p.model, p.apiKey)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gemini: creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Send the request.
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gemini: reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gemini: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse the response.
	var geminiResp geminiResponse
	if err := json.Unmarshal(respBody, &geminiResp); err != nil {
		return nil, fmt.Errorf("gemini: parsing response: %w", err)
	}

	// Extract text from candidates.
	if len(geminiResp.Candidates) == 0 {
		return nil, fmt.Errorf("gemini: no candidates in response")
	}

	candidate := geminiResp.Candidates[0]
	if len(candidate.Content.Parts) == 0 {
		return nil, fmt.Errorf("gemini: no parts in candidate content")
	}

	text := candidate.Content.Parts[0].Text

	// Extract token usage.
	tokensUsed := 0
	if geminiResp.UsageMetadata != nil {
		tokensUsed = geminiResp.UsageMetadata.PromptTokenCount +
			geminiResp.UsageMetadata.CandidatesTokenCount
	}

	return &CompletionResponse{
		Text:       text,
		TokensUsed: tokensUsed,
		Model:      p.model,
	}, nil
}

// ─── Gemini API Types ───────────────────────────────────────────────────────

type geminiRequest struct {
	Contents         []geminiContent         `json:"contents"`
	GenerationConfig geminiGenerationConfig  `json:"generationConfig"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	Temperature     float64 `json:"temperature"`
	MaxOutputTokens int     `json:"maxOutputTokens"`
}

type geminiResponse struct {
	Candidates    []geminiCandidate    `json:"candidates"`
	UsageMetadata *geminiUsageMetadata `json:"usageMetadata,omitempty"`
}

type geminiCandidate struct {
	Content geminiContent `json:"content"`
}

type geminiUsageMetadata struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}
