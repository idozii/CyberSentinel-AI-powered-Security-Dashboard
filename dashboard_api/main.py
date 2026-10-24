"""FastAPI backend for offline lab experiment artifacts only (localhost default).

Launch: uvicorn dashboard_api.main:app --host 127.0.0.1 --port 8001
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from dashboard_api.store import ArtifactError, ArtifactStore

DEFAULT_ROOT = Path(__file__).resolve().parents[1] / "simulations/runtime/processed"
SCENARIOS = ("simulated_benign", "simulated_brute_force", "simulated_path_scan", "simulated_mixed_attack")


def create_app(runs_root: Path | None = None) -> FastAPI:
    root = runs_root or Path(os.environ.get("CYBERSENTINEL_RUNS_ROOT", DEFAULT_ROOT))
    store = ArtifactStore(root)
    api = FastAPI(
        title="CyberSentinel Local Experiment API", version="0.1.0",
        description="Read-only API for simulated lab results. NOT a real-time threat detector.",
    )

    @api.exception_handler(FileNotFoundError)
    async def missing_artifact(_request, _exc):
        return JSONResponse(status_code=404, content={"detail": "Experiment or artifact not found"})

    @api.exception_handler(ArtifactError)
    async def invalid_artifact(_request, exc):
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @api.get("/api/health")
    def health():
        return {"status": "ok", "mode": "offline-local-simulation", "read_only": True}

    @api.get("/api/runs")
    def runs():
        return {"runs": store.list_runs()}

    @api.get("/api/runs/{run_id}/summary")
    def summary(run_id: str):
        return store.summary(run_id)

    @api.get("/api/runs/{run_id}/windows")
    def windows(run_id: str, limit: int = Query(500, ge=1, le=1000),
                scenario: str | None = Query(None)):
        if scenario is not None and scenario not in SCENARIOS:
            raise HTTPException(422, detail="Unrecognized scenario")
        return store.windows(run_id, limit=limit, scenario=scenario)

    @api.get("/api/runs/{run_id}/metrics")
    def metrics(run_id: str):
        return store.metrics(run_id)

    @api.get("/api/runs/{run_id}/predictions")
    def predictions(run_id: str, limit: int = Query(500, ge=1, le=1000),
                    partition: str | None = Query(None)):
        if partition not in (None, "validation", "test"):
            raise HTTPException(422, detail="Partition must be validation or test")
        return store.predictions(run_id, limit=limit, partition=partition)

    @api.get("/api/runs/{run_id}/robustness")
    def robustness(run_id: str):
        return store.robustness(run_id)

    return api


app = create_app()
