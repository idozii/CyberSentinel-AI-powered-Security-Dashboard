"""The same minimal-field validation contract as the legacy local agent API."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class TelemetryEvent(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    event_id: str = Field(min_length=16, max_length=64, pattern=r'^[A-Za-z0-9_-]+$')
    occurred_at: int
    source_ref: str = Field(min_length=32, max_length=32, pattern=r'^[a-f0-9]{32}$')
    method: str
    path_group: str
    status_code: int = Field(ge=100, le=599)
    duration_ms: float = Field(ge=0, le=120000, allow_inf_nan=False)
    request_bytes: int = Field(ge=0, le=100000000)
    response_bytes: int = Field(ge=0, le=100000000)
