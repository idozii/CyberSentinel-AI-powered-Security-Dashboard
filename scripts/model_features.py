"""Explicit ML feature allowlists for CyberSentinel.

Do not feed audit metadata, scenario labels, raw paths, source IPs, run IDs,
User-Agent strings or other simulation identifiers directly to a model.
"""
from __future__ import annotations

# Step 3: backwards compatible single-request allowlist.
MODEL_INPUT_COLUMNS = (
    "http_method", "query_present", "status_code", "request_bytes",
    "response_bytes", "duration_ms",
)

EXCLUDED_FROM_MODEL = frozenset({
    "scenario_label", "label_source", "simulation_run_id",
    "request_id", "source_ip", "forwarded_for", "user_agent",
    "referer", "raw", "path", "host", "container_id", "service",
    "schema_version", "captured_at",
})


def select_model_features(row: dict[str, str]) -> dict[str, str]:
    missing = [column for column in MODEL_INPUT_COLUMNS if column not in row]
    if missing:
        raise ValueError(f"Missing model feature columns: {missing}")
    return {column: row[column] for column in MODEL_INPUT_COLUMNS}


# Step 4: numeric window-level features. Never add scenario/run/user agent.
WINDOW_MODEL_INPUT_COLUMNS = (
    "request_count", "request_rate_per_second", "get_ratio", "post_ratio",
    "login_attempt_count", "failed_login_count", "unique_path_count",
    "http_401_ratio", "http_404_ratio", "http_4xx_ratio", "query_ratio",
    "mean_duration_ms", "mean_request_bytes", "mean_response_bytes",
)


def select_window_model_features(row: dict[str, str]) -> dict[str, float]:
    """Read only approved numeric input features from a window-feature row."""
    missing = [column for column in WINDOW_MODEL_INPUT_COLUMNS if column not in row]
    if missing:
        raise ValueError(f"Missing window ML features: {missing}")
    from math import isfinite

    output: dict[str, float] = {}
    for name in WINDOW_MODEL_INPUT_COLUMNS:
        number = float(row[name])
        if not isfinite(number):
            raise ValueError(f"Non-finite window ML feature: {name}")
        output[name] = number
    return output
