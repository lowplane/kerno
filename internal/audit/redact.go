// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// RedactSummary counts how many items of each category were stripped.
type RedactSummary struct {
	PIDs  int `json:"pid"`
	IPs   int `json:"ip"`
	Paths int `json:"path"`
}

// Total returns the sum of all redacted item counts.
func (r RedactSummary) Total() int {
	return r.PIDs + r.IPs + r.Paths
}

var (
	// rePID matches "pid=1234" and "PID: 99" — colon or equals, optional
	// whitespace, then digits. The \s+ form was too broad: "pid count 99"
	// would match. We want only the canonical key=value / key: value forms.
	rePID = regexp.MustCompile(`(?i)\bpid[=:]\s*\d+\b`)

	// reIP matches bare IPv4 addresses (no port). Word-boundary anchors
	// prevent partial matches inside longer numbers.
	reIP = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`)

	// rePath matches absolute paths under the sensitive top-level dirs
	// listed in the schema. At least one character must follow the
	// top-level dir so bare "/etc" is not matched (nothing to redact).
	rePath = regexp.MustCompile(`(?i)(/(?:etc|home|root|var|tmp|proc|sys|run|opt|usr)/[^\s"',;\])}]+)`)
)

// Redact strips PIDs, IPv4 addresses, and filesystem paths from s.
// Returns the sanitised string and a summary of what was removed.
// Idempotent: running twice on the same input produces the same result
// because the replacement tokens ("pid=<redacted>", "<ip-redacted>",
// "/<dir>/<redacted>") do not match any of the three regexes.
func Redact(s string) (string, RedactSummary) {
	var sum RedactSummary

	// Order matters: PIDs first, then IPs, then paths.
	// Each replacement token is designed not to trigger subsequent passes.

	pidMatches := rePID.FindAllString(s, -1)
	sum.PIDs = len(pidMatches)
	if sum.PIDs > 0 {
		s = rePID.ReplaceAllString(s, "pid=<redacted>")
	}

	ipMatches := reIP.FindAllString(s, -1)
	sum.IPs = len(ipMatches)
	if sum.IPs > 0 {
		s = reIP.ReplaceAllString(s, "<ip-redacted>")
	}

	pathMatches := rePath.FindAllString(s, -1)
	sum.Paths = len(pathMatches)
	if sum.Paths > 0 {
		s = rePath.ReplaceAllStringFunc(s, func(match string) string {
			// match looks like "/etc/kerno/config.yaml"
			// SplitN with n=3 gives ["", "etc", "kerno/config.yaml"]
			parts := strings.SplitN(match, "/", 3)
			if len(parts) >= 2 && parts[1] != "" {
				return "/" + parts[1] + "/<redacted>"
			}
			return "<path-redacted>"
		})
	}

	return s, sum
}

// RedactPath reduces a full absolute path to its top-level directory only,
// keeping enough context for a compliance reviewer to identify which
// subsystem owns the file without exposing the exact location.
//
//	"/etc/kerno/config.yaml"     → "/etc/<redacted>"
//	"/var/log/kerno-audit.jsonl" → "/var/<redacted>"
//	"relative/path"              → "<path-redacted>"
//	"/"                          → "<path-redacted>"
func RedactPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		return "<path-redacted>"
	}
	parts := strings.SplitN(p, "/", 3)
	// parts[0] is always "" (empty string before the leading slash).
	// parts[1] is the top-level directory name.
	if len(parts) < 2 || parts[1] == "" {
		return "<path-redacted>"
	}
	return "/" + parts[1] + "/<redacted>"
}

// RedactRemoteAddr redacts an HTTP r.RemoteAddr value so no client IP
// ever reaches the audit log.
//
// Handled formats:
//   - "host:port"   → "<ip-redacted>"   (TCP/IPv4, e.g. "10.0.0.1:54321")
//   - "[::1]:port"  → "<ip-redacted>"   (TCP/IPv6)
//   - anything else → "<path-redacted>" (unix socket or unrecognised)
//
// net.SplitHostPort handles the IPv6 bracket stripping, so we do not need
// to special-case it.
func RedactRemoteAddr(addr string) string {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Not a valid host:port pair — treat as a unix-domain socket path.
		return "<path-redacted>"
	}
	return "<ip-redacted>"
}

// HashPayload returns a 16-character lowercase hex fingerprint of payload
// using FNV-1a (64-bit). Non-cryptographic — used only as a stable trace
// identifier to link audit records to payload deliveries without exposing
// the payload content itself.
func HashPayload(payload string) string {
	const (
		offset64 uint64 = 14695981039346656037
		prime64  uint64 = 1099511628211
	)
	h := offset64
	for i := 0; i < len(payload); i++ {
		h ^= uint64(payload[i])
		h *= prime64
	}
	return fmt.Sprintf("%016x", h)
}
