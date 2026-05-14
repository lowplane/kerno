// Package ai — OpenAI provider integration.
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
	openAIAPIURL = "https://api.openai.com/v1/chat/completions"
	openAIModel  = "gpt-4o"
)

// OpenAIClient sends AI requests to the OpenAI Chat Completions API.
type OpenAIClient struct {
	apiKey string
	model  string
	http   *http.Client // shared enterprise-aware client
}

// NewOpenAIClient constructs a ready-to-use OpenAIClient.
func NewOpenAIClient(cfg *config.Config) (*OpenAIClient, error) {
	httpClient, err := NewHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("openai: %w", err)
	}

	model := cfg.AI.Model
	if model == "" {
		model = openAIModel
	}

	apiKey := cfg.AI.APIKey
	if apiKey == "" {
		return nil, fmt.Errorf("openai: api_key is required (set config.ai.api_key or KERNO_AI_API_KEY)")
	}

	return &OpenAIClient{
		apiKey: apiKey,
		model:  model,
		http:   httpClient,
	}, nil
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// Complete sends a single-turn chat completion and returns the assistant text.
func (c *OpenAIClient) Complete(ctx context.Context, prompt string) (string, error) {
	reqBody := openAIRequest{
		Model:    c.model,
		Messages: []openAIMessage{{Role: "user", Content: prompt}},
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("openai: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openAIAPIURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("openai: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	// Use the shared enterprise-aware client.
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai: HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("openai: read response: %w", err)
	}

	var apiResp openAIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("openai: decode response (status %d): %w", resp.StatusCode, err)
	}

	if apiResp.Error != nil {
		return "", fmt.Errorf("openai API error %s: %s", apiResp.Error.Type, apiResp.Error.Message)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	if len(apiResp.Choices) == 0 {
		return "", fmt.Errorf("openai: empty choices in response")
	}

	return apiResp.Choices[0].Message.Content, nil
}
