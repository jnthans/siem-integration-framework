#!/usr/bin/env bash
# {VENDOR_DISPLAY} — Wazuh wodle runtime wrapper.
#
# This is the command target in ossec.conf. It sets environment variables
# and execs the Python entry point — replacing the shell process entirely.
#
# CUSTOMIZE: Replace {VENDOR} placeholders and set your config values.

set -euo pipefail

# ── Runtime configuration ──
# API endpoint
export {VENDOR_UPPER}_BASE_URL="https://api.vendor.com"

# Paths (defaults are relative to this script's directory)
# export {VENDOR_UPPER}_STATE_FILE="/var/ossec/wodles/{VENDOR_LOWER}/state.json"
# export {VENDOR_UPPER}_SECRETS_FILE="/var/ossec/wodles/{VENDOR_LOWER}/.secrets"

# Polling behavior
# export {VENDOR_UPPER}_SOURCE="all"
# export {VENDOR_UPPER}_LOOKBACK_HOURS="1"

# Debug (0=off, 1=info, 2=verbose, 3=trace — stderr only)
export {VENDOR_UPPER}_DEBUG="0"

# ── Vendor-specific settings ──
# Add any vendor-specific environment variables here
# export {VENDOR_UPPER}_PAGE_LIMIT="100"
# export {VENDOR_UPPER}_MODE="balanced"

# ── Execute ──
# Replace shell with Python — no lingering parent process.
# "$@" forwards any CLI arguments from ossec.conf or manual testing.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/{VENDOR_LOWER}.py" "$@"
