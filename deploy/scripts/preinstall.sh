#!/bin/bash
set -e

# Create group and user before file extraction so ownership is applied correctly
if ! getent group kerno > /dev/null 2>&1; then
  groupadd -r kerno
fi
if ! id -u kerno > /dev/null 2>&1; then
  useradd -r -s /usr/sbin/nologin -d /nonexistent -c "Kerno daemon" -g kerno kerno
fi