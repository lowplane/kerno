#!/bin/bash
set -e

systemctl daemon-reload 2>/dev/null || true

# On an upgrade, restart only if the unit is already running so the new binary
# takes effect (preremove leaves it running across upgrades). try-restart is a
# no-op on a fresh install where the unit was never started.
systemctl try-restart kerno 2>/dev/null || true
