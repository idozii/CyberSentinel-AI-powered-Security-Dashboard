"""Conservative feature-selection contract for upcoming Step 4.

The labeled CSV preserves telemetry for audit, but ML inputs MUST be selected
by explicit allowlist rather than feeding all CSV columns into a model.
These single-request features are not yet suitable for behavioral detection;
window-based aggregation comes next.
"""
from __future__ import annotations

MODEL_INPUT_COLUMNS = (
    "http_method", "query_present", "status_code", "request_bytes",
    "response_bytes", "duration_ms",
)

# Metadata, identifiers, and lab-specific information never become features.
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
