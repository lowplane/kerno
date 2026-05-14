# Copyright 2026 Optiqor contributors
# SPDX-License-Identifier: Apache-2.0
#
# vhs tape — records the kerno doctor MVP demo for the README hero GIF.
#
# IMPORTANT: vhs records a non-interactive shell that cannot type a sudo
# password. The Makefile grants bin/kerno the BPF caps via setcap so
# this tape never types `sudo`.
#
# The doctor output is the MVP — we widen the canvas so the KERNO logo
# and box-drawn report aren't cropped, and dwell on the final report
# for ~25 s so a viewer can actually read the findings.
#
# Run with:    make demo
# Output:      demo.gif

Output demo.gif

# ── visual config ──
# Width  1300 fits the 80-col box-drawn finding plus padding.
# Height 1400 fits the full ~50-line report (KERNO logo + header +
# triage + finding panels + recommended order + summary) in a single
# screen, so the KERNO banner stays visible at the top after the
# doctor finishes painting. Without this the report scrolls past the
# top frame and the viewer never sees the brand.
Set Shell      "bash"
Set FontSize   14
Set Width      1300
Set Height     1400
Set Theme      "Dracula"
Set TypingSpeed 40ms
Set Padding    24

# ── silent setup ──
# Hide PATH/config/prompt setup so the recording shows only the clean
# `kerno doctor` marketing surface.
Hide
Type "export PS1='$ '"
Enter
Type "export PATH=$(pwd)/bin:$PATH"
Enter
Type "export KERNO_CONFIG=$(pwd)/scripts/verify-config.yaml"
Enter
Type "clear"
Enter
Show

# ── intro ──
Type "# Kerno doctor — kernel-level incident diagnosis in one command"
Sleep 1500ms
Enter
Sleep 600ms

Type "# Step 1: induce a synthetic disk-fsync bottleneck"
Sleep 800ms
Enter
Type "kerno chaos --induce disk-sat --duration 25s --intensity high --yes &"
Enter
# Let chaos warm up the kernel signals.
Sleep 3s

Hide
Type "clear"
Enter
Show

# ── doctor run — the MVP hero shot ──
Type "# Step 2: ask the kernel what's wrong"
Sleep 800ms
Enter
Type "kerno doctor --duration 10s"
Enter

# Doctor runs for ~10 s + a couple seconds to render. After it paints,
# dwell for ~22 s so the viewer can read the KERNO banner, the findings
# panel, evidence, and the recommended action order. This is the part
# we want every viewer to actually read.
Sleep 35s

# ── outro ──
Type "# Root cause identified. Same flow runs in CI: 'make verify'."
Sleep 5s
