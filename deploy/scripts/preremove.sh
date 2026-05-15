#!/bin/bash

set -e
systemctl stop kerno  || true
systemctl disable kerno || true