// Copyright 2026 Optiqor contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

// sensitivePaths is the curated default set used by `kerno audit files
// --sensitive`. Picked for highest signal-per-noise on a typical Linux
// host: credentials, secret material, sudo policy, kernel modules.
var sensitivePaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/etc/ssh/sshd_config",
	"/etc/ssl",
	"/etc/pki",
	"/root/.ssh",
	"/root/.bash_history",
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit security-sensitive kernel events",
		Long: `Watch for accesses to security-sensitive paths in real time.

Uses inotify (no eBPF needed) so it works without root for paths the
caller can read. For pod-scoped or kernel-only events, prefer
'kerno trace' or 'kerno watch'.`,
	}
	cmd.AddCommand(newAuditFilesCmd())
	return cmd
}

func newAuditFilesCmd() *cobra.Command {
	var (
		watchPaths []string
		sensitive  bool
		duration   time.Duration
		output     string
	)

	cmd := &cobra.Command{
		Use:   "files",
		Short: "Watch file accesses on a list of paths",
		Long: `Audit file open/modify/access events on the given paths.

By default, --sensitive watches a curated set of credential and
configuration paths (/etc/passwd, /etc/shadow, /etc/sudoers, /etc/ssl,
~/.ssh, etc.). Use --watch to specify your own.

This command uses inotify, not eBPF — it sees only what the kernel
exposes via the standard file-event API. Pod-scoped or container-aware
auditing requires the file_audit eBPF program (Phase 1.2.7).`,
		Example: `  # Watch the curated sensitive set
  sudo kerno audit files --sensitive

  # Watch a specific list
  sudo kerno audit files --watch /etc/passwd,/etc/ssl,/var/log/auth.log

  # JSON output for SIEM ingestion
  sudo kerno audit files --sensitive --output json

  # Stop after 30 seconds
  sudo kerno audit files --sensitive --duration 30s`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output == "" {
				output = resolveOutput(cmd)
			}

			paths := watchPaths
			if sensitive {
				paths = append(paths, sensitivePaths...)
			}
			paths = uniqueExisting(paths)
			if len(paths) == 0 {
				return errors.New("no paths to watch — use --sensitive or --watch <paths>")
			}

			return runAuditFiles(cmd.Context(), auditFilesOpts{
				paths:    paths,
				duration: duration,
				output:   output,
			})
		},
	}

	flags := cmd.Flags()
	flags.StringSliceVar(&watchPaths, "watch", nil, "comma-separated list of paths to watch")
	flags.BoolVar(&sensitive, "sensitive", false, "auto-watch the curated sensitive-path set")
	flags.DurationVar(&duration, "duration", 0, "stop after this duration (0 = run until interrupted)")
	flags.StringVarP(&output, "output", "o", "", "output format: pretty (terminal), json (SIEM)")

	return cmd
}

type auditFilesOpts struct {
	paths    []string
	duration time.Duration
	output   string
}

// auditEvent is the structured form of an inotify hit. Field names
// match what's emitted in JSON mode for SIEM consumption.
type auditEvent struct {
	Time   string `json:"time"`
	Path   string `json:"path"`
	Op     string `json:"op"`
	Mask   uint32 `json:"mask"`
	Cookie uint32 `json:"cookie,omitempty"`
}

// uniqueExisting filters paths down to those that exist on disk and
// removes duplicates. Non-existent paths are silently dropped — the
// curated sensitive set varies by distro.
func uniqueExisting(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func runAuditFiles(ctx context.Context, opts auditFilesOpts) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("inotify_init: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	// Track watch descriptor → path so events can be attributed.
	wdToPath := map[int32]string{}
	const mask = unix.IN_ACCESS | unix.IN_MODIFY | unix.IN_OPEN | unix.IN_ATTRIB |
		unix.IN_CLOSE_WRITE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE

	for _, p := range opts.paths {
		wd, err := unix.InotifyAddWatch(fd, p, mask)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: cannot watch %s: %v\n", p, err)
			continue
		}
		// inotify watch descriptors are returned as ints but always fit
		// in int32 in practice — the kernel API uses __s32.
		wdToPath[int32(wd)] = p //nolint:gosec // bounded by kernel-side __s32 wd
	}

	if len(wdToPath) == 0 {
		return errors.New("could not register any watches — check permissions")
	}

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if opts.duration > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.duration)
		defer cancel()
	}

	if opts.output != "json" {
		fmt.Fprintf(os.Stderr, "kerno: watching %d paths (Ctrl+C to stop)\n", len(wdToPath))
		for _, p := range opts.paths {
			fmt.Fprintf(os.Stderr, "  · %s\n", p)
		}
		fmt.Fprintln(os.Stderr)
	}

	encoder := json.NewEncoder(os.Stdout)

	// inotify reads can block; do them on a goroutine and select on ctx.
	events := make(chan auditEvent, 64)
	go readInotify(ctx, fd, wdToPath, events)

	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-events:
			if opts.output == "json" {
				_ = encoder.Encode(e)
			} else {
				fmt.Printf("[%s] %-7s %s\n", e.Time, e.Op, e.Path)
			}
		}
	}
}

// readInotify pumps inotify events on fd into the events channel until
// ctx is canceled. Closes fd when done so the read returns EBADF.
func readInotify(ctx context.Context, fd int, wdToPath map[int32]string, events chan<- auditEvent) {
	go func() {
		<-ctx.Done()
		// Closing the fd forces the blocking Read to return.
		_ = unix.Close(fd)
	}()

	buf := make([]byte, 4096)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			return
		}
		if n <= 0 {
			return
		}
		decodeInotifyBatch(buf[:n], wdToPath, events)
	}
}

// decodeInotifyBatch walks a batch of struct inotify_event blobs and
// pushes a typed auditEvent into ch for each.
func decodeInotifyBatch(buf []byte, wdToPath map[int32]string, ch chan<- auditEvent) {
	for offset := 0; offset+unix.SizeofInotifyEvent <= len(buf); {
		raw := (*unix.InotifyEvent)(unsafePointer(&buf[offset]))
		nameLen := int(raw.Len)
		if offset+unix.SizeofInotifyEvent+nameLen > len(buf) {
			return
		}

		path := wdToPath[raw.Wd]
		if nameLen > 0 {
			// raw.Name is variable-length; use the bytes that follow.
			nameStart := offset + unix.SizeofInotifyEvent
			nameBytes := buf[nameStart : nameStart+nameLen]
			// Strip trailing NULs.
			if i := indexOfZero(nameBytes); i >= 0 {
				nameBytes = nameBytes[:i]
			}
			if len(nameBytes) > 0 {
				path = filepath.Join(path, string(nameBytes))
			}
		}

		ch <- auditEvent{
			Time:   time.Now().Format(time.RFC3339Nano),
			Path:   path,
			Op:     opName(raw.Mask),
			Mask:   raw.Mask,
			Cookie: raw.Cookie,
		}
		offset += unix.SizeofInotifyEvent + nameLen
	}
}

func indexOfZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// opName maps the inotify event mask to a single human-readable verb.
// We pick the highest-signal flag — modifying a sudoers file is more
// interesting than the open that preceded it.
func opName(mask uint32) string {
	switch {
	case mask&unix.IN_DELETE != 0:
		return "DELETE"
	case mask&unix.IN_MOVED_FROM != 0, mask&unix.IN_MOVED_TO != 0:
		return "MOVE"
	case mask&unix.IN_MODIFY != 0:
		return "MODIFY"
	case mask&unix.IN_CLOSE_WRITE != 0:
		return "WRITE"
	case mask&unix.IN_ATTRIB != 0:
		return "CHATTR"
	case mask&unix.IN_OPEN != 0:
		return "OPEN"
	case mask&unix.IN_ACCESS != 0:
		return "ACCESS"
	default:
		return fmt.Sprintf("UNKNOWN(0x%x)", mask)
	}
}
