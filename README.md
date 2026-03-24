# Cyber Sentinel - AI-powered-Security-Dashboard

## Goals

Build an AI-assisted security monitoring stack that can observe a containerized webapp, persist traffic telemetry for later training, and evolve into anomaly detection and dashboarding.

## What Is Implemented

This repository now includes a first working data-collection pipeline for a single Docker host:

- `scripts/collector.py`: tails structured proxy access logs, normalizes each request into a canonical `TrafficEvent`, and writes rotated JSONL files
- `scripts/etl.py`: validates raw JSONL, flattens events, and exports training-friendly CSV or normalized JSONL
- `scripts/train_model.py`: provides a baseline dataset profiler for quick inspection before model work
- `simulations/docker-compose.yml`: example stack with `nginx`, a sample `webapp`, and mounted output directories
- `simulations/nginx/default.conf`: sample reverse proxy config that emits parseable security telemetry
- `tests/`: unit tests for parsing, rotation, and ETL

## Canonical Event Schema

Each JSONL record includes:

- `schema_version`
- `captured_at`
- `service`
- `container_id`
- `source_ip`
- `http_method`
- `host`
- `path`
- `query_present`
- `status_code`
- `request_bytes`
- `response_bytes`
- `duration_ms`
- `user_agent`
- `referer`
- `forwarded_for`
- `request_id`
- `raw`

## Quick Start

Start the sample stack:

```powershell
docker compose -f simulations/docker-compose.yml up --build
```

Run the collector against the mounted NGINX log file:

```powershell
python scripts/collector.py `
  --input simulations/runtime/logs/access.log `
  --output-dir simulations/runtime/raw `
  --target-service webapp `
  --follow
```

Generate safe attack-like traffic against the sample proxy:

```powershell
python scripts/attack_replay.py `
  --base-url http://127.0.0.1:8080 `
  --scenario mixed `
  --attempts 15 `
  --concurrency 5
```

Convert collected JSONL into flat training rows:

```powershell
python scripts/etl.py `
  --input-dir simulations/runtime/raw `
  --output simulations/runtime/processed/events.csv `
  --format csv
```

Inspect the resulting dataset:

```powershell
python scripts/train_model.py --input simulations/runtime/processed/events.csv
```

Run tests:

```powershell
python -m unittest discover -s tests
```

## Tech Stack

- Collector and ETL: Python standard library
- Proxy: NGINX
- Container runtime: Docker / Docker Compose
- Future model targets: Isolation Forest / Autoencoder
- Future platform targets: FastAPI backend, React frontend, PostgreSQL, Elasticsearch

## Datasets

- UNSW-NB15: [UNSW-NB15 Dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- NSL-KDD: [Kaggle NSL-KDD Dataset](https://www.kaggle.com/datasets/primus11/nsl-kdd-dataset-filtered-version-of-kdd)
- Honeypot logs: [Kaggle Honeypot-attack-logs](https://www.kaggle.com/datasets/lougarou/honeypot-attack-logs?utm_source=chatgpt.com)

## Contributors

- [idozii](https://github.com/idozii) - Data Scientist
- [Vincent](https://github.com/nguyentr4n14) - Software Dev
- [Dcornel](https://github.com/cornel05) - ML Engineer
- [DarealDanh](https://github.com/darealDanh) - Hacker
