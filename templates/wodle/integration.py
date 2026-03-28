#!/usr/bin/env python3
"""
{VENDOR_DISPLAY} — Wazuh integration entry point.

Orchestrates API polling, state management, and event emission.
Replace {VENDOR}, {VENDOR_DISPLAY}, {NAMESPACE}, and module references
with your vendor-specific values.
"""

import argparse
import os
import sys

# Local imports — update these to match your module names
from {VENDOR}_utils import (
    log, emit, emit_error, load_state, save_state,
    load_secrets_file, get_secret, DEBUG_LEVEL,
    INTEGRATION_NAME
)
from {VENDOR}_{MODULE_A} import fetch_{MODULE_A}
# from {VENDOR}_{MODULE_B} import fetch_{MODULE_B}  # uncomment if needed


def parse_args():
    """Parse CLI arguments. CLI flags override environment variables."""
    parser = argparse.ArgumentParser(description="{VENDOR_DISPLAY} Wazuh integration")
    parser.add_argument(
        "--source",
        choices=["{MODULE_A}", "all"],  # add module names as needed
        default=None,
        help="Which event streams to poll (default: all)"
    )
    parser.add_argument(
        "-a", "--all",
        action="store_true",
        dest="all_mode",
        help="Test/backfill: ignore state, do not update state"
    )
    parser.add_argument(
        "-l", "--lookback",
        type=int,
        default=None,
        help="Hours to look back (first run or --all mode)"
    )
    parser.add_argument(
        "-d", "--debug",
        type=int,
        choices=[0, 1, 2, 3],
        default=None,
        help="Debug verbosity: 0=off, 1=info, 2=verbose, 3=trace"
    )
    return parser.parse_args()


def load_config(args):
    """Merge environment variables with CLI overrides."""
    import {VENDOR}_utils as utils

    # Debug level — CLI overrides env var
    utils.DEBUG_LEVEL = (
        args.debug if args.debug is not None
        else int(os.environ.get("{VENDOR_UPPER}_DEBUG", "0"))
    )

    config = {
        "source": args.source or os.environ.get("{VENDOR_UPPER}_SOURCE", "all"),
        "all_mode": args.all_mode,
        "lookback_hours": (
            args.lookback if args.lookback is not None
            else int(os.environ.get("{VENDOR_UPPER}_LOOKBACK_HOURS", "1"))
        ),
        "state_file": os.environ.get(
            "{VENDOR_UPPER}_STATE_FILE",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "state.json")
        ),
        "secrets_file": os.environ.get(
            "{VENDOR_UPPER}_SECRETS_FILE",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secrets")
        ),
        "base_url": os.environ.get("{VENDOR_UPPER}_BASE_URL", "https://api.vendor.com"),
        # Add vendor-specific config here
    }
    return config


def should_run(module_name, config):
    """Check if a module should run based on --source flag."""
    return config["source"] in ("all", module_name)


def main():
    args = parse_args()
    config = load_config(args)

    log(1, "Starting (source={}, lookback={}h, all_mode={})",
        config["source"], config["lookback_hours"], config["all_mode"])

    # Load credentials
    secrets = load_secrets_file(config["secrets_file"])
    credentials = {
        # Build your credential dict here using get_secret()
        # "api_key": get_secret("{VENDOR_LOWER}_api_key", "{VENDOR_UPPER}_API_KEY", secrets),
    }

    # Load persisted state
    state = load_state(config["state_file"])
    log(2, "Loaded state: {}", state)

    # ── Module A ──
    if should_run("{MODULE_A}", config):
        try:
            cursor_key = "{MODULE_A}_cursor"
            new_cursor = fetch_{MODULE_A}(
                credentials=credentials,
                cursor=state.get(cursor_key),
                config=config
            )
            state[cursor_key] = new_cursor
        except Exception as e:
            emit_error("{MODULE_A}", str(e))
            log(1, "{MODULE_A} failed: {}", e)

    # ── Module B (uncomment if needed) ──
    # if should_run("{MODULE_B}", config):
    #     try:
    #         cursor_key = "{MODULE_B}_cursor"
    #         new_cursor = fetch_{MODULE_B}(
    #             credentials=credentials,
    #             cursor=state.get(cursor_key),
    #             config=config
    #         )
    #         state[cursor_key] = new_cursor
    #     except Exception as e:
    #         emit_error("{MODULE_B}", str(e))
    #         log(1, "{MODULE_B} failed: {}", e)

    # Save state (skip in --all mode)
    if not config["all_mode"]:
        save_state(config["state_file"], state)
        log(2, "Saved state: {}", state)
    else:
        log(1, "All mode — state not saved")

    log(1, "Complete")


if __name__ == "__main__":
    main()
