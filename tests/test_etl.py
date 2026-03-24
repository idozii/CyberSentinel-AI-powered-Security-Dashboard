import csv
import json
import shutil
import unittest
import uuid
from pathlib import Path

from scripts.etl import iter_events, summarize_events, write_csv


class EtlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_root = Path(__file__).resolve().parent / ".tmp"
        self.temp_root.mkdir(exist_ok=True)

    def test_iter_events_and_write_csv(self) -> None:
        sample_event = {
            "schema_version": "traffic_event.v1",
            "captured_at": "2026-03-24T05:00:00+00:00",
            "service": "webapp",
            "container_id": "abc123",
            "source_ip": "198.51.100.9",
            "http_method": "GET",
            "host": "example.local",
            "path": "/",
            "query_present": False,
            "status_code": 200,
            "request_bytes": 321,
            "response_bytes": 654,
            "duration_ms": 17.2,
            "user_agent": "unittest",
            "referer": "",
            "forwarded_for": "",
            "request_id": "req-1",
        }
        temp_dir = self.temp_root / f"etl-{uuid.uuid4().hex}"
        temp_dir.mkdir(parents=True, exist_ok=False)
        try:
            input_dir = temp_dir / "raw"
            output_path = temp_dir / "processed" / "events.csv"
            input_dir.mkdir(parents=True, exist_ok=True)
            (input_dir / "sample.jsonl").write_text(json.dumps(sample_event) + "\n", encoding="utf-8")

            events = list(iter_events(input_dir))
            summary = summarize_events(events)
            count = write_csv(events, output_path)

            self.assertEqual(count, 1)
            self.assertEqual(summary["events"], 1)
            self.assertEqual(summary["services"], ["webapp"])

            with output_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["path"], "/")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
