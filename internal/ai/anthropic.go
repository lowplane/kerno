// Package ai — Anthropic provider integration.
//
// Change from the original: replace the inline &http.Client{} with the shared
// client returned by NewHTTPClient so that proxy and CA settings apply.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/optiqor/kerno/internal/config"
)

const (
	anthropicAPIURL     = "https://api.anthropic.com/v1/messages"
	anthropicAPIVersion = "2023-06-01"
	anthropicModel      = "claude-opus-4-5"
)

// AnthropicClient sends AI requests to the Anthropic Messages API.
type AnthropicClient struct {
	apiKey string
	model  string
	http   *http.Client // shared enterprise-aware client
}

// NewAnthropicClient constructs a ready-to-use AnthropicClient.
// The *http.Client is built once via NewHTTPClient so proxy + CA settings
// from config are automatically honoured.
func NewAnthropicClient(cfg *config.Config) (*AnthropicClient, error) {
	httpClient, err := NewHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("anthropic: %w", err)
	}

	model := cfg.AI.Model
	if model == "" {
		model = anthropicModel
	}

	apiKey := cfg.AI.APIKey
	if apiKey == "" {
		// Fallback handled at call-site or via env var wrapper in the caller.
		return nil, fmt.Errorf("anthropic: api_key is required (set config.ai.api_key or KERNO_AI_API_KEY)")
	}

	return &AnthropicClient{
		apiKey: apiKey,
		model:  model,
		http:   httpClient,
	}, nil
}

// ---------------------------------------------------------------------------
// Request / response types (minimal – only what Kerno uses)
// ---------------------------------------------------------------------------

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Complete sends a single-turn completion request and returns the assistant text.
func (c *AnthropicClient) Complete(ctx context.Context, prompt string) (string, error) {
	reqBody := anthropicRequest{
		Model:     c.model,
		MaxTokens: 2048,
		Messages:  []anthropicMessage{{Role: "user", Content: prompt}},
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("anthropic: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicAPIURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("anthropic: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", anthropicAPIVersion)

	// Use the shared enterprise-aware client (proxy + CA already configured).
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic: HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("anthropic: read response: %w", err)
	}

	var apiResp anthropicResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("anthropic: decode response (status %d): %w", resp.StatusCode, err)
	}

	if apiResp.Error != nil {
		return "", fmt.Errorf("anthropic API error %s: %s", apiResp.Error.Type, apiResp.Error.Message)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	if len(apiResp.Content) == 0 {
		return "", fmt.Errorf("anthropic: empty content in response")
	}

	return apiResp.Content[0].Text, nil
}
