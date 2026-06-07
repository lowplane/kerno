#!/bin/bash
set -e

# Stop and disable only on a real removal, not during a package upgrade.
# dpkg passes "remove"/"upgrade" as $1; rpm passes 0 (uninstall) / 1 (upgrade).
if [ "$1" = "remove" ] || [ "$1" = "0" ]; then
    systemctl stop kerno || true
    systemctl disable kerno || true
fi
