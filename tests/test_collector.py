import json
import shutil
import unittest
import uuid
from pathlib import Path

from scripts.collector import CollectorConfig, JsonlRotator, parse_log_line, process_stream


SAMPLE_LOG = json.dumps(
    {
        "time_iso8601": "2026-03-24T05:00:00+00:00",
        "service": "webapp",
        "container_id": "abc123",
        "remote_addr": "10.0.0.9",
        "xff": "198.51.100.9, 10.0.0.9",
        "request_method": "POST",
        "host": "example.local",
        "uri": "/login",
        "args": "next=/admin",
        "status": "401",
        "request_length": "512",
        "bytes_sent": "1024",
        "request_time": "0.125",
        "http_user_agent": "unittest",
        "http_referer": "https://example.local/",
        "request_id": "req-1",
    }
)


class CollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_root = Path(__file__).resolve().parent / ".tmp"
        self.temp_root.mkdir(exist_ok=True)

    def test_parse_log_line_maps_expected_fields(self) -> None:
        event = parse_log_line(SAMPLE_LOG, target_service="webapp", schema_version="traffic_event.v1")

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.service, "webapp")
        self.assertEqual(event.source_ip, "198.51.100.9")
        self.assertEqual(event.status_code, 401)
        self.assertTrue(event.query_present)
        self.assertEqual(event.duration_ms, 125.0)

    def test_parse_log_line_filters_non_target_service(self) -> None:
        event = parse_log_line(SAMPLE_LOG, target_service="payments", schema_version="traffic_event.v1")
        self.assertIsNone(event)

    def test_process_stream_rotates_output_files(self) -> None:
        temp_dir = self.temp_root / f"collector-{uuid.uuid4().hex}"
        temp_dir.mkdir(parents=True, exist_ok=False)
        try:
            config = CollectorConfig(
                input_path=None,
                output_dir=temp_dir,
                target_service="webapp",
                schema_version="traffic_event.v1",
                rotate_bytes=200,
                follow=False,
                poll_interval=0.01,
            )
            writer = JsonlRotator(config.output_dir, config.target_service, config.rotate_bytes)
            try:
                count = process_stream([SAMPLE_LOG, SAMPLE_LOG, SAMPLE_LOG], config, writer)
            finally:
                writer.close()

            output_files = sorted(temp_dir.glob("*.jsonl"))
            self.assertEqual(count, 3)
            self.assertGreaterEqual(len(output_files), 2)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
