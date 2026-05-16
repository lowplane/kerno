package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/optiqor/kerno/internal/doctor"
	"github.com/optiqor/kerno/internal/metrics"
)

// Sink represents a destination for doctor findings.
type Sink interface {
	// Name returns the identifier of the sink (e.g., "slack", "pagerduty").
	Name() string
	// Send delivers the findings to the destination. It may be called concurrently.
	Send(ctx context.Context, findings []doctor.Finding) error
}

// BuildSinks parses sink URLs and returns a list of configured Sinks.
// It resolves environment variable references (e.g., slack://$KERNO_SLACK_WEBHOOK_URL).
func BuildSinks(urls []string, logger *slog.Logger) ([]Sink, error) {
	var sinks []Sink
	for _, rawURL := range urls {
		u := expandEnvInURL(rawURL)

		switch {
		case strings.HasPrefix(u, "slack://"):
			webhookURL := strings.TrimPrefix(u, "slack://")
			if webhookURL == "" {
				return nil, errors.New("slack sink requires a webhook URL")
			}
			// Re-add https if they stripped it in the slack:// prefix, assuming https:// for hooks.
			if !strings.HasPrefix(webhookURL, "http") {
				webhookURL = "https://" + webhookURL
			}
			sinks = append(sinks, NewSlackSink(webhookURL, logger))

		case strings.HasPrefix(u, "pagerduty://"):
			routingKey := strings.TrimPrefix(u, "pagerduty://")
			if routingKey == "" {
				return nil, errors.New("pagerduty sink requires a routing key")
			}
			sinks = append(sinks, NewPagerDutySink(routingKey, logger))

		case strings.HasPrefix(u, "discord://"):
			webhookURL := strings.TrimPrefix(u, "discord://")
			if webhookURL == "" {
				return nil, errors.New("discord sink requires a webhook URL")
			}
			if !strings.HasPrefix(webhookURL, "http") {
				webhookURL = "https://" + webhookURL
			}
			sinks = append(sinks, NewDiscordSink(webhookURL, logger))

		default:
			return nil, fmt.Errorf("unsupported sink type: %s", rawURL)
		}
	}
	return sinks, nil
}

// expandEnvInURL allows users to pass "slack://$KERNO_SLACK_WEBHOOK_URL"
// to avoid putting secrets in shell history.
func expandEnvInURL(u string) string {
	return os.Expand(u, func(key string) string {
		return os.Getenv(key)
	})
}

// sendWithRetry executes an HTTP request with exponential backoff.
// Max 3 attempts.
func sendWithRetry(ctx context.Context, client *http.Client, req *http.Request, sinkName string) error {
	const maxRetries = 3
	baseDelay := 1 * time.Second

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		// We must clone the request body for retries
		var bodyCopy []byte
		if req.Body != nil {
			var err error
			bodyCopy, err = readAllAndClose(req.Body)
			if err != nil {
				return fmt.Errorf("reading request body: %w", err)
			}
			req.Body = ioNopCloser(bytes.NewReader(bodyCopy))
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
				// Client error (not rate limit) - don't retry.
				metrics.SinksFailedTotal.WithLabelValues(sinkName).Inc()
				return lastErr
			}
		}

		if attempt < maxRetries-1 {
			select {
			case <-time.After(baseDelay * time.Duration(1<<attempt)):
			case <-ctx.Done():
				return ctx.Err()
			}
			// Restore body for the next attempt
			if bodyCopy != nil {
				req.Body = ioNopCloser(bytes.NewReader(bodyCopy))
			}
		}
	}

	metrics.SinksFailedTotal.WithLabelValues(sinkName).Inc()
	return fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr)
}

// Helper to read and close body
func readAllAndClose(rc interface{ Read(p []byte) (n int, err error); Close() error }) ([]byte, error) {
	defer rc.Close()
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(rc)
	return buf.Bytes(), err
}

// Helper to create a ReadCloser
type nopCloser struct {
	*bytes.Reader
}

func (nopCloser) Close() error { return nil }

func ioNopCloser(r *bytes.Reader) interface{ Read(p []byte) (n int, err error); Close() error } {
	return nopCloser{r}
}
