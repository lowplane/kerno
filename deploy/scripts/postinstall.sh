#!/bin/bash

set -e
# Create a locked-down system user if it doesn't already exist
if ! id -u kerno &>/dev/null; then
  useradd -r -s /usr/sbin/nologin -d /nonexistent -c "Kerno daemon" kerno
fi
# Ensure the config dir is owned by kerno
mkdir -p /etc/kerno
chown kerno:kerno /etc/kerno
chmod 750 /etc/kerno
systemctl daemon-reload