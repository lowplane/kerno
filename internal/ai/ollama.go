// Package ai — Ollama provider integration (air-gapped / on-prem LLM).
//
// Change from the original: replace the inline &http.Client{} with the shared
// client returned by NewHTTPClient so that proxy and CA settings apply.
// Ollama is typically accessed over HTTP on localhost, but enterprise
// deployments may run it behind a TLS-terminating reverse proxy – so the
// same CA-cert logic applies.
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
	ollamaDefaultHost  = "http://localhost:11434"
	ollamaAPIPath      = "/api/chat"
	ollamaDefaultModel = "llama3"
)

// OllamaClient sends AI requests to a local or remote Ollama instance.
type OllamaClient struct {
	baseURL string
	model   string
	http    *http.Client // shared enterprise-aware client
}

// NewOllamaClient constructs a ready-to-use OllamaClient.
func NewOllamaClient(cfg *config.Config) (*OllamaClient, error) {
	httpClient, err := NewHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("ollama: %w", err)
	}

	model := cfg.AI.Model
	if model == "" {
		model = ollamaDefaultModel
	}

	// Ollama host can be configured via OLLAMA_HOST env or the generic proxy
	// field.  For now we default to localhost; a future PR can add a
	// config.ai.ollama_host field.
	baseURL := ollamaDefaultHost

	return &OllamaClient{
		baseURL: baseURL,
		model:   model,
		http:    httpClient,
	}, nil
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

type ollamaRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaResponse struct {
	Message ollamaMessage `json:"message"`
	Error   string        `json:"error,omitempty"`
}

// Complete sends a single-turn chat request and returns the assistant text.
func (c *OllamaClient) Complete(ctx context.Context, prompt string) (string, error) {
	reqBody := ollamaRequest{
		Model:    c.model,
		Messages: []ollamaMessage{{Role: "user", Content: prompt}},
		Stream:   false,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("ollama: marshal request: %w", err)
	}

	url := c.baseURL + ollamaAPIPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("ollama: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Use the shared enterprise-aware client.
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama: HTTP request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("ollama: read response: %w", err)
	}

	var apiResp ollamaResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", fmt.Errorf("ollama: decode response (status %d): %w", resp.StatusCode, err)
	}

	if apiResp.Error != "" {
		return "", fmt.Errorf("ollama API error: %s", apiResp.Error)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	return apiResp.Message.Content, nil
}
