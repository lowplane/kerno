package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/optiqor/kerno/internal/doctor"
)

// SlackSink implements Sink for Slack Incoming Webhooks using Block Kit.
type SlackSink struct {
	url    string
	logger *slog.Logger
	client *http.Client
}

// NewSlackSink creates a new SlackSink.
func NewSlackSink(url string, logger *slog.Logger) *SlackSink {
	return &SlackSink{
		url:    url,
		logger: logger,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (s *SlackSink) Name() string { return "slack" }

func (s *SlackSink) Send(ctx context.Context, findings []doctor.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	payload := s.buildPayload(findings)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if err := sendWithRetry(ctx, s.client, req, s.Name()); err != nil {
		return fmt.Errorf("slack sink failed: %w", err)
	}

	s.logger.Debug("sent findings to slack", "count", len(findings))
	return nil
}

func (s *SlackSink) buildPayload(findings []doctor.Finding) map[string]interface{} {
	attachments := make([]map[string]interface{}, 0, len(findings))

	for _, f := range findings {
		color := "#f2c744" // yellow for WARNING
		if f.Severity == doctor.SeverityCritical {
			color = "#e01e5a" // red for CRITICAL
		}

		blocks := []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]interface{}{
					"type": "plain_text",
					"text": fmt.Sprintf("[%s] %s", f.Severity.String(), f.Title),
				},
			},
			{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Cause:*\n%s\n\n*Impact:*\n%s", f.Cause, f.Impact),
				},
			},
		}

		if f.Process != "" {
			blocks = append(blocks, map[string]interface{}{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Process:* `%s` | *Signal:* `%s`", f.Process, f.Signal),
				},
			})
		}

		if f.Evidence != "" {
			blocks = append(blocks, map[string]interface{}{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Evidence:*\n```%s```", f.Evidence),
				},
			})
		}

		if len(f.Fix) > 0 {
			var fixText string
			for _, fix := range f.Fix {
				fixText += fmt.Sprintf("• %s\n", fix)
			}
			blocks = append(blocks, map[string]interface{}{
				"type": "section",
				"text": map[string]interface{}{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Fix:*\n%s", fixText),
				},
			})
		}

		attachments = append(attachments, map[string]interface{}{
			"color":  color,
			"blocks": blocks,
		})
	}

	return map[string]interface{}{
		"text":        "Kerno Diagnostic Findings",
		"attachments": attachments,
	}
}
