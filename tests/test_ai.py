import unittest

from signaltrail.ai import build_ai_prompt, extract_response_text, offline_analysis


class AiTests(unittest.TestCase):
    def test_build_ai_prompt_contains_privacy_audit(self) -> None:
        prompt = build_ai_prompt({"event_count": 1, "privacy_audit": {"summary": {"risk_score": 20}}})
        self.assertIn("privacy_audit", prompt)
        self.assertIn("risk_score", prompt)

    def test_extract_response_text_supports_direct_output_text(self) -> None:
        self.assertEqual(extract_response_text({"output_text": "hello"}), "hello")

    def test_extract_response_text_supports_output_content(self) -> None:
        text = extract_response_text({"output": [{"content": [{"text": "hello"}, {"text": "world"}]}]})
        self.assertEqual(text, "hello\nworld")

    def test_offline_analysis_mentions_sensor_signals(self) -> None:
        report = {
            "event_count": 2,
            "top_domains": [{"domain": "api.example.com"}],
            "privacy_audit": {
                "summary": {"risk_label": "medium", "risk_score": 40, "sensor_signal_count": 1},
                "signals": [
                    {
                        "risk": "medium",
                        "title": "Possible location usage",
                        "evidence": "api.example.com/v1/location matched possible_location",
                    }
                ],
            },
        }
        analysis = offline_analysis(report)
        self.assertIn("possible sensor-related", analysis["summary"])


if __name__ == "__main__":
    unittest.main()
