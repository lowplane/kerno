#!/usr/bin/env bash
# Copyright 2026 Optiqor contributors
# SPDX-License-Identifier: Apache-2.0
#
# Pre-commit hook: ensure the commit message has a Signed-off-by line.
# Invoked by .pre-commit-config.yaml (commit-msg stage).

set -euo pipefail

msg_file="${1:-}"
if [[ -z "$msg_file" || ! -f "$msg_file" ]]; then
    # Fallback: check the last commit (used when invoked outside pre-commit).
    if git log -1 --pretty=%B | grep -q "^Signed-off-by:"; then
        exit 0
    fi
else
    if grep -q "^Signed-off-by:" "$msg_file"; then
        exit 0
    fi
fi

echo "ERROR: commit message is missing a Signed-off-by line." >&2
echo "Use 'git commit -s' (or '--signoff') to add it automatically." >&2
echo "See: https://github.com/optiqor/kerno/blob/main/CONTRIBUTING.md#dco" >&2
exit 1
