package sinks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/optiqor/kerno/internal/doctor"
)

// PagerDutySink implements Sink for PagerDuty Events API v2.
type PagerDutySink struct {
	routingKey string
	logger     *slog.Logger
	client     *http.Client

	mu     sync.Mutex
	active map[string]struct{}
}

// NewPagerDutySink creates a new PagerDutySink.
func NewPagerDutySink(routingKey string, logger *slog.Logger) *PagerDutySink {
	return &PagerDutySink{
		routingKey: routingKey,
		logger:     logger,
		client:     &http.Client{Timeout: 10 * time.Second},
		active:     make(map[string]struct{}),
	}
}

func (s *PagerDutySink) Name() string { return "pagerduty" }

// Send delivers findings to PagerDuty. It triggers incidents for active findings
// and resolves incidents for findings that have cleared since the last cycle.
func (s *PagerDutySink) Send(ctx context.Context, findings []doctor.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	current := make(map[string]doctor.Finding)
	for _, f := range findings {
		key := fingerprint(f)
		current[key] = f
	}

	var errs []error

	// Trigger or update currently active findings.
	for key, f := range current {
		if err := s.sendEvent(ctx, "trigger", key, f); err != nil {
			errs = append(errs, fmt.Errorf("triggering %s: %w", key, err))
		} else {
			s.active[key] = struct{}{}
		}
	}

	// Resolve findings that are no longer present.
	for key := range s.active {
		if _, exists := current[key]; !exists {
			// Create a dummy finding just to hold the key for resolution.
			// The Events API v2 only strictly needs the routing_key and dedup_key for a resolve.
			dummy := doctor.Finding{Rule: "cleared"} 
			if err := s.sendEvent(ctx, "resolve", key, dummy); err != nil {
				errs = append(errs, fmt.Errorf("resolving %s: %w", key, err))
			} else {
				delete(s.active, key)
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("pagerduty sink encountered %d errors, first: %w", len(errs), errs[0])
	}
	return nil
}

func (s *PagerDutySink) sendEvent(ctx context.Context, action, dedupKey string, f doctor.Finding) error {
	payload := map[string]interface{}{
		"routing_key":  s.routingKey,
		"event_action": action,
		"dedup_key":    dedupKey,
	}

	if action == "trigger" {
		severity := "warning"
		if f.Severity == doctor.SeverityCritical {
			severity = "critical"
		} else if f.Severity == doctor.SeverityInfo {
			severity = "info"
		}

		payload["payload"] = map[string]interface{}{
			"summary":  fmt.Sprintf("[%s] %s", f.Severity.String(), f.Title),
			"source":   "kerno",
			"severity": severity,
			"custom_details": map[string]string{
				"rule":     f.Rule,
				"process":  f.Process,
				"signal":   f.Signal,
				"cause":    f.Cause,
				"evidence": f.Evidence,
			},
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling pagerduty payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://events.pagerduty.com/v2/enqueue", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating pagerduty request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if err := sendWithRetry(ctx, s.client, req, s.Name()); err != nil {
		return err
	}

	s.logger.Debug("sent pagerduty event", "action", action, "dedup_key", dedupKey)
	return nil
}
