// Copyright 2026 Lowplane contributors
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"strings"
	"time"

	"github.com/lowplane/kerno/internal/collector"
	"github.com/lowplane/kerno/internal/doctor"
)

// PrivacyMode controls what data is sent to the LLM.
type PrivacyMode string

const (
	// PrivacyFull sends all data including hostnames, IPs, PIDs.
	PrivacyFull PrivacyMode = "full"

	// PrivacyRedacted strips hostnames, IPs, and PIDs but keeps metrics.
	PrivacyRedacted PrivacyMode = "redacted"

	// PrivacySummary sends only aggregated numbers — no identifying info.
	PrivacySummary PrivacyMode = "summary"
)

// SystemPrompt is the kernel diagnostics expert prompt for the LLM.
const SystemPrompt = `You are Kerno, a kernel diagnostics expert for Linux. You analyze eBPF-collected kernel signals and explain issues in plain English a junior SRE can understand.

Your response MUST be valid JSON with this exact structure:
{
  "summary": "Plain-English diagnosis paragraph (2-4 sentences)",
  "correlations": [{"signals": ["signal1", "signal2"], "description": "...", "confidence": 0.85}],
  "rootCauses": [{"description": "...", "severity": "CRITICAL|WARNING|INFO", "fix": "specific command or action", "confidence": 0.9}],
  "anomalies": [{"signal": "...", "metric": "...", "currentVal": "...", "baselineVal": "...", "description": "..."}]
}

Rules:
- Explain the "why" not just the "what"
- Suggest specific, actionable fixes (exact commands when possible)
- Correlate signals when multiple subsystems show problems
- Use concrete numbers from the data provided
- If not confident in a root cause, say so and lower the confidence score
- Never hallucinate metrics — only reference data provided
- Keep the summary concise (under 200 words)
- Return ONLY valid JSON, no markdown or extra text`

// BuildUserPrompt serializes signals and findings into a token-efficient prompt.
func BuildUserPrompt(signals *collector.Signals, findings []doctor.Finding, history []*collector.Signals, privacy PrivacyMode) string {
	var b strings.Builder

	// Host info.
	if privacy == PrivacyFull {
		if signals.Host.Hostname != "" {
			fmt.Fprintf(&b, "HOST: %s", signals.Host.Hostname)
		}
		if signals.Host.KernelVer != "" {
			fmt.Fprintf(&b, ", kernel %s", signals.Host.KernelVer)
		}
		if signals.Host.Arch != "" {
			fmt.Fprintf(&b, ", %s", signals.Host.Arch)
		}
		b.WriteString("\n")
	} else if privacy == PrivacyRedacted {
		if signals.Host.KernelVer != "" {
			fmt.Fprintf(&b, "HOST: [redacted], kernel %s", signals.Host.KernelVer)
		}
		b.WriteString("\n")
	}

	// Time window.
	fmt.Fprintf(&b, "WINDOW: %s ending %s\n\n", signals.Duration, signals.Timestamp.Format(time.RFC3339))

	// Findings (ranked).
	if len(findings) > 0 {
		b.WriteString("FINDINGS (ranked):\n")
		for _, f := range findings {
			process := ""
			if f.Process != "" && privacy == PrivacyFull {
				process = fmt.Sprintf(" — process: %s", f.Process)
			}
			fmt.Fprintf(&b, "[%-8s] %s: %s%s\n", f.Severity, f.Signal, f.Title, process)
			if f.Evidence != "" {
				fmt.Fprintf(&b, "           evidence: %s\n", f.Evidence)
			}
		}
		b.WriteString("\n")
	}

	// Raw metrics (token-efficient compact format).
	b.WriteString("RAW METRICS:\n")
	writeSignalMetrics(&b, signals, privacy)

	// History (if available, for trend detection).
	if len(history) > 0 {
		b.WriteString("\nHISTORY (previous snapshots, oldest first):\n")
		for i, h := range history {
			fmt.Fprintf(&b, "  snapshot %d (%s ago):\n", i+1, time.Since(h.Timestamp).Truncate(time.Second))
			writeSignalMetricsSummary(&b, h)
		}
	}

	return b.String()
}

func writeSignalMetrics(b *strings.Builder, s *collector.Signals, privacy PrivacyMode) {
	if s.Syscall != nil {
		fmt.Fprintf(b, "syscall: total=%d", s.Syscall.TotalCount)
		if len(s.Syscall.Entries) > 0 {
			b.WriteString(", top_slow=[")
			for i, e := range s.Syscall.Entries {
				if i > 4 {
					break // Top 5 only.
				}
				if i > 0 {
					b.WriteString(", ")
				}
				name := e.Name
				if privacy != PrivacyFull {
					name = e.Name // syscall names are not sensitive
				}
				fmt.Fprintf(b, "%s:%s", name, e.Latency.P99)
			}
			b.WriteString("]")
		}
		b.WriteString("\n")
	}

	if s.TCP != nil {
		fmt.Fprintf(b, "tcp: active=%d, retransmits=%d, retransmit_rate=%.1f%%, rtt_p99=%s\n",
			s.TCP.ActiveConnections, s.TCP.TotalRetransmits, s.TCP.RetransmitRate, s.TCP.RTT.P99)
	}

	if s.DiskIO != nil {
		fmt.Fprintf(b, "diskio: reads=%d, writes=%d, syncs=%d, sync_p99=%s, write_p99=%s\n",
			s.DiskIO.TotalReads, s.DiskIO.TotalWrites, s.DiskIO.TotalSyncs,
			s.DiskIO.SyncLatency.P99, s.DiskIO.WriteLatency.P99)
	}

	if s.Sched != nil {
		fmt.Fprintf(b, "sched: total=%d, runq_p99=%s, runq_p50=%s\n",
			s.Sched.TotalCount, s.Sched.RunqDelay.P99, s.Sched.RunqDelay.P50)
	}

	if s.FD != nil {
		fmt.Fprintf(b, "fd: opens=%d, closes=%d, growth=%.1f/s, net_delta=%d\n",
			s.FD.TotalOpens, s.FD.TotalCloses, s.FD.GrowthRate, s.FD.NetDelta)
	}

	if s.OOM != nil {
		fmt.Fprintf(b, "oom: events=%d\n", s.OOM.Count)
		if privacy == PrivacyFull {
			for _, e := range s.OOM.Events {
				fmt.Fprintf(b, "  victim: %s (pid %d, rss=%d pages, oom_score=%d)\n",
					e.Comm, e.PID, e.RSSPages, e.OOMScore)
			}
		}
	}
}

func writeSignalMetricsSummary(b *strings.Builder, s *collector.Signals) {
	if s.Syscall != nil {
		fmt.Fprintf(b, "    syscall: total=%d", s.Syscall.TotalCount)
		if len(s.Syscall.Entries) > 0 {
			fmt.Fprintf(b, ", top_p99=%s", s.Syscall.Entries[0].Latency.P99)
		}
		b.WriteString("\n")
	}
	if s.TCP != nil {
		fmt.Fprintf(b, "    tcp: retransmit_rate=%.1f%%, rtt_p99=%s\n", s.TCP.RetransmitRate, s.TCP.RTT.P99)
	}
	if s.DiskIO != nil {
		fmt.Fprintf(b, "    diskio: sync_p99=%s\n", s.DiskIO.SyncLatency.P99)
	}
	if s.Sched != nil {
		fmt.Fprintf(b, "    sched: runq_p99=%s\n", s.Sched.RunqDelay.P99)
	}
}
