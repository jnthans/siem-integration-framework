#!/usr/bin/env python3
"""
{VENDOR_DISPLAY} — {MODULE_A} domain module.

Handles API requests, pagination, and event transformation for the
{MODULE_A} endpoint(s). Replace all {PLACEHOLDERS} with vendor-specific values.
"""

from datetime import datetime, timezone

from {VENDOR}_utils import (
    log, emit, emit_error, http_get, http_post, http_with_retry,
    INTEGRATION_NAME, NAMESPACE
)


def fetch_{MODULE_A}(credentials, cursor, config):
    """Fetch events from the {MODULE_A} API surface.

    Args:
        credentials: dict with API credentials (keys depend on auth method)
        cursor: opaque cursor/timestamp from previous run (None on first run)
        config: dict with base_url, lookback_hours, all_mode, etc.

    Returns:
        Updated cursor value to persist for next run.
    """
    base_url = config["base_url"]
    headers = _build_headers(credentials)

    # ── Determine start position ──
    if cursor and not config["all_mode"]:
        # Normal run — resume from last position
        log(1, "{MODULE_A}: resuming from cursor")
        start_param = cursor
    else:
        # First run or --all mode — use lookback
        lookback_hours = config["lookback_hours"]
        start_time = datetime.now(timezone.utc).replace(
            microsecond=0
        ) - __import__("datetime").timedelta(hours=lookback_hours)
        start_param = start_time.isoformat()
        log(1, "{MODULE_A}: starting from {} (lookback {}h)", start_param, lookback_hours)

    # ── Pagination loop ──
    page = 0
    total_events = 0
    has_more = True
    current_cursor = cursor

    while has_more:
        page += 1

        # ── Build request ──
        # CUSTOMIZE: Replace with your vendor's API request format
        # Example for cursor-based pagination (POST):
        request_body = {
            "cursor": start_param if page == 1 else current_cursor,
            "limit": config.get("page_limit", 100),
        }

        # Example for time-window pagination (GET):
        # url = "{}/api/v2/events?since={}&limit={}".format(
        #     base_url, start_param if page == 1 else current_cursor,
        #     config.get("page_limit", 100)
        # )

        # ── Execute request ──
        url = "{}/api/v2/events".format(base_url)  # CUSTOMIZE: your endpoint
        response = http_with_retry(
            lambda: http_post(url, headers, request_body)
        )

        # ── Extract events from response ──
        # CUSTOMIZE: match your vendor's response structure
        events = response.get("items", [])
        new_cursor = response.get("cursor", current_cursor)
        has_more = response.get("has_more", False)

        log(1, "{MODULE_A}: page {} — {} events", page, len(events))

        # ── Transform and emit each event ──
        for raw_event in events:
            event = _transform(raw_event)
            emit(event)
            total_events += 1

        current_cursor = new_cursor

        # Use start_param only for the first page
        if page == 1:
            start_param = None

    log(1, "{MODULE_A}: complete — {} events across {} pages", total_events, page)
    return current_cursor


def _build_headers(credentials):
    """Construct HTTP headers for this API surface.

    CUSTOMIZE: Replace with your vendor's auth mechanism.
    """
    # Bearer token example:
    return {
        "Authorization": "Bearer {}".format(credentials.get("api_key", "")),
        "Accept": "application/json",
    }

    # Basic auth example:
    # from {VENDOR}_utils import basic_auth_headers
    # headers = basic_auth_headers(credentials["principal"], credentials["secret"])
    # headers["Accept"] = "application/json"
    # return headers


def _transform(raw_event):
    """Transform a raw vendor event into the namespaced emission format.

    CUSTOMIZE: Map vendor fields. Preserve nested objects — do not flatten.
    """
    # Determine event type from vendor data
    # CUSTOMIZE: replace with your vendor's event type field
    event_type = raw_event.get("type", "unknown")

    return {
        "integration": INTEGRATION_NAME,
        NAMESPACE: {
            "event_type": event_type,
            # Include all vendor fields under the namespace
            # Option A: spread all fields (if no conflicts)
            **{k: v for k, v in raw_event.items()},
            # Option B: selectively map fields (if renaming needed)
            # "actor": raw_event.get("actor_details"),
            # "target": raw_event.get("target_resource"),
            # "timestamp": raw_event.get("created_at"),
        }
    }
