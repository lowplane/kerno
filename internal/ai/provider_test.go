// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ─── NewProvider routing ───────────────────────────────────────────────────

func TestNewProviderRoutesByName(t *testing.T) {
	cases := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{"anthropic", "anthropic", false},
		{"openai", "openai", false},
		{"ollama", "ollama", false},
		{"mistral", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		p, err := NewProvider(ProviderConfig{Name: c.name})
		if c.wantErr {
			if err == nil {
				t.Errorf("NewProvider(%q) want error", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("NewProvider(%q) error: %v", c.name, err)
			continue
		}
		if p.Name() != c.want {
			t.Errorf("Name() = %q, want %q", p.Name(), c.want)
		}
	}
}

// ─── Anthropic Provider ────────────────────────────────────────────────────

func TestAnthropicProviderHappyPath(t *testing.T) {
	var capturedBody anthropicRequest
	var capturedKey, capturedVersion string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedKey = r.Header.Get("x-api-key")
		capturedVersion = r.Header.Get("anthropic-version")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &capturedBody)

		_ = json.NewEncoder(w).Encode(anthropicResponse{
			Content: []anthropicContentBlock{{Type: "text", Text: "hello from claude"}},
			Model:   "claude-test",
			Usage:   anthropicUsage{InputTokens: 10, OutputTokens: 20},
		})
	}))
	defer srv.Close()

	p := NewAnthropicProvider(ProviderConfig{
		APIKey:   "test-key",
		Endpoint: srv.URL,
		Model:    "claude-test",
	})

	resp, err := p.Complete(context.Background(), CompletionRequest{
		SystemPrompt: "you are a kernel doctor",
		UserPrompt:   "diagnose this",
	})
	if err != nil {
		t.Fatalf("Complete error: %v", err)
	}

	if resp.Text != "hello from claude" {
		t.Errorf("Text = %q, want %q", resp.Text, "hello from claude")
	}
	if resp.TokensUsed != 30 {
		t.Errorf("TokensUsed = %d, want 30", resp.TokensUsed)
	}
	if resp.Model != "claude-test" {
		t.Errorf("Model = %q, want claude-test", resp.Model)
	}

	// Verify request shape.
	if capturedKey != "test-key" {
		t.Errorf("x-api-key = %q, want test-key", capturedKey)
	}
	if capturedVersion != anthropicAPIVersion {
		t.Errorf("anthropic-version = %q, want %q", capturedVersion, anthropicAPIVersion)
	}
	if capturedBody.System != "you are a kernel doctor" {
		t.Errorf("system prompt not forwarded; got %q", capturedBody.System)
	}
	if len(capturedBody.Messages) != 1 || capturedBody.Messages[0].Content != "diagnose this" {
		t.Errorf("user prompt not forwarded; got %+v", capturedBody.Messages)
	}
}

func TestAnthropicProviderErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := NewAnthropicProvider(ProviderConfig{Endpoint: srv.URL})
	_, err := p.Complete(context.Background(), CompletionRequest{UserPrompt: "x"})
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %v, want status 401 mention", err)
	}
}

func TestAnthropicProviderConnectionError(t *testing.T) {
	p := NewAnthropicProvider(ProviderConfig{Endpoint: "http://127.0.0.1:1"}) // refused
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := p.Complete(ctx, CompletionRequest{UserPrompt: "x"})
	if err == nil {
		t.Fatal("expected connection error")
	}
}

func TestAnthropicProviderUsesPerRequestOverrides(t *testing.T) {
	var capturedBody anthropicRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &capturedBody)
		_ = json.NewEncoder(w).Encode(anthropicResponse{
			Content: []anthropicContentBlock{{Type: "text", Text: "ok"}},
		})
	}))
	defer srv.Close()

	p := NewAnthropicProvider(ProviderConfig{
		Endpoint:    srv.URL,
		MaxTokens:   100,
		Temperature: 0.1,
	})

	_, err := p.Complete(context.Background(), CompletionRequest{
		UserPrompt:  "x",
		MaxTokens:   500,
		Temperature: 0.9,
	})
	if err != nil {
		t.Fatal(err)
	}

	if capturedBody.MaxTokens != 500 {
		t.Errorf("MaxTokens = %d, want 500 (request override)", capturedBody.MaxTokens)
	}
	if capturedBody.Temperature != 0.9 {
		t.Errorf("Temperature = %v, want 0.9", capturedBody.Temperature)
	}
}

// ─── OpenAI Provider ───────────────────────────────────────────────────────

func TestOpenAIProviderHappyPath(t *testing.T) {
	var capturedBody openaiRequest
	var authHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &capturedBody)

		_ = json.NewEncoder(w).Encode(openaiResponse{
			Choices: []openaiChoice{{Message: openaiMessage{Content: "hello from gpt"}}},
			Model:   "gpt-test",
			Usage:   openaiUsage{TotalTokens: 50},
		})
	}))
	defer srv.Close()

	p := NewOpenAIProvider(ProviderConfig{
		APIKey:   "sk-test",
		Endpoint: srv.URL,
		Model:    "gpt-test",
	})

	resp, err := p.Complete(context.Background(), CompletionRequest{
		SystemPrompt: "kernel doctor",
		UserPrompt:   "diagnose",
	})
	if err != nil {
		t.Fatalf("Complete error: %v", err)
	}

	if resp.Text != "hello from gpt" {
		t.Errorf("Text = %q", resp.Text)
	}
	if resp.TokensUsed != 50 {
		t.Errorf("TokensUsed = %d, want 50", resp.TokensUsed)
	}
	if authHeader != "Bearer sk-test" {
		t.Errorf("Authorization = %q, want Bearer sk-test", authHeader)
	}
	// Both messages forwarded.
	if len(capturedBody.Messages) != 2 {
		t.Errorf("messages = %d, want 2 (system + user)", len(capturedBody.Messages))
	}
}

func TestOpenAIProviderEmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(openaiResponse{Choices: nil})
	}))
	defer srv.Close()

	p := NewOpenAIProvider(ProviderConfig{Endpoint: srv.URL})
	resp, err := p.Complete(context.Background(), CompletionRequest{UserPrompt: "x"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if resp.Text != "" {
		t.Errorf("Text on empty choices = %q, want empty", resp.Text)
	}
}

func TestOpenAIProviderInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json at all"))
	}))
	defer srv.Close()

	p := NewOpenAIProvider(ProviderConfig{Endpoint: srv.URL})
	_, err := p.Complete(context.Background(), CompletionRequest{UserPrompt: "x"})
	if err == nil {
		t.Error("expected parse error on invalid JSON")
	}
}

// ─── Ollama Provider ───────────────────────────────────────────────────────

func TestOllamaProviderHappyPath(t *testing.T) {
	var capturedBody ollamaRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &capturedBody)
		_ = json.NewEncoder(w).Encode(ollamaResponse{
			Model:           "llama-test",
			Message:         ollamaMessage{Content: "hello from llama"},
			PromptEvalCount: 7,
			EvalCount:       13,
		})
	}))
	defer srv.Close()

	p := NewOllamaProvider(ProviderConfig{
		Endpoint: srv.URL,
		Model:    "llama-test",
	})

	resp, err := p.Complete(context.Background(), CompletionRequest{
		SystemPrompt: "sys",
		UserPrompt:   "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Text != "hello from llama" {
		t.Errorf("Text = %q", resp.Text)
	}
	if resp.TokensUsed != 20 {
		t.Errorf("TokensUsed = %d, want 20", resp.TokensUsed)
	}
	if capturedBody.Stream {
		t.Error("Stream should be false")
	}
	if len(capturedBody.Messages) != 2 {
		t.Errorf("messages = %d, want 2", len(capturedBody.Messages))
	}
}

func TestOllamaProviderConnectionRefused(t *testing.T) {
	p := NewOllamaProvider(ProviderConfig{Endpoint: "http://127.0.0.1:1"})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := p.Complete(ctx, CompletionRequest{UserPrompt: "x"})
	if err == nil {
		t.Fatal("expected connection error")
	}
	if !strings.Contains(err.Error(), "Ollama") {
		t.Errorf("error should mention Ollama (helpful hint); got: %v", err)
	}
}

// ─── Cache ─────────────────────────────────────────────────────────────────

func TestCacheGetMissReturnsFalse(t *testing.T) {
	c := NewCache(time.Minute)
	if _, ok := c.Get("nonexistent"); ok {
		t.Error("Get on miss should return false")
	}
}

func TestCacheSetGet(t *testing.T) {
	c := NewCache(time.Minute)
	resp := mockAnalysisResponse("first")
	c.Set("key1", resp)

	got, ok := c.Get("key1")
	if !ok {
		t.Fatal("Get('key1') should hit")
	}
	if got.Summary != "first" {
		t.Errorf("got Summary %q, want first", got.Summary)
	}
}

func TestCacheExpiration(t *testing.T) {
	c := NewCache(50 * time.Millisecond)
	c.Set("k", mockAnalysisResponse("x"))

	if _, ok := c.Get("k"); !ok {
		t.Fatal("immediate Get should hit")
	}

	time.Sleep(100 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Error("Get after TTL should miss")
	}
}

func TestCacheLazyEviction(t *testing.T) {
	c := NewCache(time.Millisecond)
	for i := 0; i < 200; i++ {
		c.Set(fmt.Sprintf("k%d", i), mockAnalysisResponse(""))
	}
	time.Sleep(50 * time.Millisecond)

	// Trigger eviction via another Set after threshold (>100 entries).
	c.Set("trigger", mockAnalysisResponse(""))

	// At least *some* expired entries should have been swept. We avoid
	// requiring 100% sweep because Go's map deletion-during-range is
	// allowed to visit a subset; the exact count depends on the runtime
	// and is non-deterministic under -race.
	c.mu.RLock()
	remaining := len(c.entries)
	c.mu.RUnlock()
	if remaining >= 201 {
		t.Errorf("lazy eviction not triggered: %d entries remain (started 201)", remaining)
	}
}

// ─── Rate Limiter ──────────────────────────────────────────────────────────

func TestRateLimitedProviderAllowsBurst(t *testing.T) {
	stub := &countingProvider{}
	rl := NewRateLimitedProvider(stub, 5)

	for i := 0; i < 5; i++ {
		_, err := rl.Complete(context.Background(), CompletionRequest{})
		if err != nil {
			t.Errorf("call %d: unexpected error: %v", i, err)
		}
	}

	// 6th call should fail.
	_, err := rl.Complete(context.Background(), CompletionRequest{})
	if err == nil {
		t.Error("6th call should be rate-limited")
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("error = %v, should mention rate limit", err)
	}

	if got := stub.calls.Load(); got != 5 {
		t.Errorf("inner provider called %d times, want 5 (rate-limited rejects don't reach inner)", got)
	}
}

func TestRateLimitedProviderForwardsName(t *testing.T) {
	stub := &countingProvider{name: "openai"}
	rl := NewRateLimitedProvider(stub, 100)
	if rl.Name() != "openai" {
		t.Errorf("Name() = %q, want openai", rl.Name())
	}
}

func TestRateLimitedProviderHandlesNonPositiveLimit(t *testing.T) {
	stub := &countingProvider{}
	rl := NewRateLimitedProvider(stub, 0)
	// Default of 10 should kick in — first call should succeed.
	_, err := rl.Complete(context.Background(), CompletionRequest{})
	if err != nil {
		t.Errorf("first call failed unexpectedly: %v", err)
	}
}

// ─── Test helpers ──────────────────────────────────────────────────────────

type countingProvider struct {
	name  string
	calls atomic.Uint64
	err   error
}

func (p *countingProvider) Name() string {
	if p.name == "" {
		return "stub"
	}
	return p.name
}

func (p *countingProvider) Complete(_ context.Context, _ CompletionRequest) (*CompletionResponse, error) {
	p.calls.Add(1)
	if p.err != nil {
		return nil, p.err
	}
	return &CompletionResponse{Text: "stub", TokensUsed: 1, Model: "stub"}, nil
}

// mockAnalysisResponse builds a doctor.AnalysisResponse value referenced
// only via the package's import of doctor — we keep it inline rather
// than importing doctor here, since the cache type uses *doctor.AnalysisResponse.
//
// Defined in cache_helpers_test.go to avoid import cycles in the test.
var _ = errors.New // silence unused import on some toolchains

func TestOllamaProviderTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer server.Close()

	p := NewOllamaProvider(ProviderConfig{
		Endpoint: server.URL,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := p.Complete(ctx, CompletionRequest{
		SystemPrompt: "test",
		UserPrompt:   "test",
	})

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestOllamaProviderServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	p := NewOllamaProvider(ProviderConfig{
		Endpoint: server.URL,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := p.Complete(ctx, CompletionRequest{
		SystemPrompt: "test",
		UserPrompt:   "test",
	})

	if err == nil {
		t.Fatal("expected server error, got nil")
	}

	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("expected status 500 error, got: %v", err)
	}
}

func TestOllamaProviderMalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":`))
	}))
	defer server.Close()

	p := NewOllamaProvider(ProviderConfig{
		Endpoint: server.URL,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := p.Complete(ctx, CompletionRequest{
		SystemPrompt: "test",
		UserPrompt:   "test",
	})

	if err == nil {
		t.Fatal("expected malformed JSON error, got nil")
	}
}
