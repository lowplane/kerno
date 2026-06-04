// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGeminiProvider_Complete(t *testing.T) {
	tests := []struct {
		name           string
		response       geminiResponse
		wantText       string
		wantTokens     int
		wantModel      string
		wantStatusCode int
		wantError      bool
	}{
		{
			name: "successful completion",
			response: geminiResponse{
				Candidates: []geminiCandidate{
					{
						Content: geminiContent{
							Parts: []geminiPart{
								{Text: "This is a test response from Gemini."},
							},
						},
					},
				},
				UsageMetadata: &geminiUsageMetadata{
					PromptTokenCount:     10,
					CandidatesTokenCount: 8,
					TotalTokenCount:      18,
				},
			},
			wantText:       "This is a test response from Gemini.",
			wantTokens:     18,
			wantModel:      "gemini-1.5-flash",
			wantStatusCode: http.StatusOK,
			wantError:      false,
		},
		{
			name: "no usage metadata",
			response: geminiResponse{
				Candidates: []geminiCandidate{
					{
						Content: geminiContent{
							Parts: []geminiPart{
								{Text: "Response without metadata"},
							},
						},
					},
				},
			},
			wantText:       "Response without metadata",
			wantTokens:     0,
			wantModel:      "gemini-1.5-flash",
			wantStatusCode: http.StatusOK,
			wantError:      false,
		},
		{
			name:           "API error",
			response:       geminiResponse{},
			wantStatusCode: http.StatusUnauthorized,
			wantError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method and headers
				if r.Method != "POST" {
					t.Errorf("Expected POST request, got %s", r.Method)
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("Expected Content-Type: application/json, got %s", r.Header.Get("Content-Type"))
				}

				// Send response
				w.WriteHeader(tt.wantStatusCode)
				if tt.wantStatusCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.response)
				} else {
					w.Write([]byte(`{"error": {"message": "API error"}}`))
				}
			}))
			defer server.Close()

			// Create provider with test server endpoint
			provider := NewGeminiProvider(ProviderConfig{
				Name:        "gemini",
				Model:       "gemini-1.5-flash",
				APIKey:      "test-key",
				Endpoint:    server.URL,
				MaxTokens:   1000,
				Temperature: 0.7,
			})

			// Create completion request
			req := CompletionRequest{
				SystemPrompt: "You are a helpful assistant.",
				UserPrompt:   "Hello, world!",
				MaxTokens:    1000,
				Temperature:  0.7,
			}

			// Call Complete
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := provider.Complete(ctx, req)

			// Check error expectation
			if tt.wantError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify response
			if resp.Text != tt.wantText {
				t.Errorf("Text = %q, want %q", resp.Text, tt.wantText)
			}
			if resp.TokensUsed != tt.wantTokens {
				t.Errorf("TokensUsed = %d, want %d", resp.TokensUsed, tt.wantTokens)
			}
			if resp.Model != tt.wantModel {
				t.Errorf("Model = %q, want %q", resp.Model, tt.wantModel)
			}
		})
	}
}

func TestGeminiProvider_Name(t *testing.T) {
	provider := NewGeminiProvider(ProviderConfig{})
	if got := provider.Name(); got != "gemini" {
		t.Errorf("Name() = %q, want %q", got, "gemini")
	}
}

func TestGeminiProvider_NoAPIKey(t *testing.T) {
	provider := NewGeminiProvider(ProviderConfig{
		Name:     "gemini",
		Model:    "gemini-1.5-flash",
		Endpoint: "https://example.com",
	})

	req := CompletionRequest{
		SystemPrompt: "test",
		UserPrompt:   "test",
	}

	ctx := context.Background()
	_, err := provider.Complete(ctx, req)

	if err == nil {
		t.Fatal("Expected error for missing API key, got nil")
	}

	if err.Error() != "gemini: API key not configured (set KERNO_AI_API_KEY)" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestGeminiProvider_Defaults(t *testing.T) {
	provider := NewGeminiProvider(ProviderConfig{
		APIKey: "test-key",
	})

	if provider.model != "gemini-1.5-flash" {
		t.Errorf("Default model = %q, want %q", provider.model, "gemini-1.5-flash")
	}
	if provider.endpoint != "https://generativelanguage.googleapis.com/v1beta" {
		t.Errorf("Default endpoint = %q, want %q", provider.endpoint, "https://generativelanguage.googleapis.com/v1beta")
	}
	if provider.maxTokens != 4096 {
		t.Errorf("Default maxTokens = %d, want %d", provider.maxTokens, 4096)
	}
	if provider.temperature != 0.7 {
		t.Errorf("Default temperature = %f, want %f", provider.temperature, 0.7)
	}
}
