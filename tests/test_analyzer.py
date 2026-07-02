import unittest

from signaltrail.analyzer import analyze_events, classify_domain, format_bytes


class AnalyzerTests(unittest.TestCase):
    def test_classify_domain_marks_common_analytics(self) -> None:
        self.assertIn("tracker_or_analytics", classify_domain("app-measurement.com"))
        self.assertIn("telemetry", classify_domain("api.example.com", "/v1/metrics"))
        self.assertIn("possible_location", classify_domain("api.example.com", "/nearby?lat=12"))
        self.assertIn("possible_audio", classify_domain("api.example.com", "/speech/transcribe"))

    def test_analyze_events_flags_plaintext_and_tracker(self) -> None:
        report = analyze_events(
            [
                {
                    "started_at": 1,
                    "scheme": "http",
                    "method": "GET",
                    "host": "example.com",
                    "path": "/profile",
                    "bytes_client_to_server": 100,
                    "bytes_server_to_client": 200,
                },
                {
                    "started_at": 1,
                    "scheme": "https",
                    "method": "CONNECT",
                    "host": "app-measurement.com",
                    "path": "",
                    "bytes_client_to_server": 100,
                    "bytes_server_to_client": 200,
                },
            ]
        )

        titles = {finding["title"] for finding in report["findings"]}
        self.assertIn("Plaintext HTTP request", titles)
        self.assertIn("Tracker or analytics-looking domain", titles)

    def test_analyze_events_flags_possible_sensor_related_traffic(self) -> None:
        report = analyze_events(
            [
                {
                    "started_at": 1,
                    "scheme": "https",
                    "method": "CONNECT",
                    "host": "api.example.com",
                    "path": "/v1/location/update",
                    "bytes_client_to_server": 100,
                    "bytes_server_to_client": 200,
                }
            ]
        )

        self.assertTrue(
            any(finding["title"] == "Possible sensor-related network traffic" for finding in report["findings"])
        )
        audit = report["privacy_audit"]
        self.assertEqual(audit["summary"]["sensor_signal_count"], 1)
        self.assertTrue(any(signal["category"] == "sensor_location" for signal in audit["signals"]))

    def test_plaintext_sensor_signal_is_high_risk(self) -> None:
        report = analyze_events(
            [
                {
                    "started_at": 1,
                    "scheme": "http",
                    "method": "POST",
                    "host": "api.example.com",
                    "path": "/v1/speech/transcribe",
                    "bytes_client_to_server": 200,
                    "bytes_server_to_client": 100,
                }
            ]
        )

        signal = next(item for item in report["privacy_audit"]["signals"] if item["category"] == "sensor_audio")
        self.assertEqual(signal["risk"], "high")
        self.assertEqual(signal["confidence"], "medium")

    def test_format_bytes(self) -> None:
        self.assertEqual(format_bytes(42), "42 B")
        self.assertEqual(format_bytes(2048), "2.0 KB")


if __name__ == "__main__":
    unittest.main()
