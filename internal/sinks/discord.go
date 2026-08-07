package sinks

import (
	"context"
	"log/slog"
	"strings"

	"github.com/optiqor/kerno/internal/doctor"
)

// DiscordSink implements Sink for Discord using its built-in Slack compatibility.
type DiscordSink struct {
	slack *SlackSink
}

// NewDiscordSink creates a new DiscordSink.
func NewDiscordSink(url string, logger *slog.Logger) *DiscordSink {
	// Discord natively supports Slack payloads if you append /slack to the webhook URL.
	if !strings.HasSuffix(url, "/slack") {
		url = strings.TrimRight(url, "/") + "/slack"
	}

	return &DiscordSink{
		slack: NewSlackSink(url, logger),
	}
}

func (s *DiscordSink) Name() string { return "discord" }

func (s *DiscordSink) Send(ctx context.Context, findings []doctor.Finding) error {
	// Delegate to the Slack sink implementation since the endpoint accepts Slack payloads.
	return s.slack.Send(ctx, findings)
}
