import tempfile
import unittest
from pathlib import Path

from src.log_analyzer import analyze_log


class TestLogAnalyzer(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = Path(self.temp_dir.name) / "auth.log"

        self.log_path.write_text(
            "Failed password for user1 from 192.0.2.10 port 50001 ssh2\n"
            "Failed password for user1 from 192.0.2.10 port 50002 ssh2\n"
            "Failed password for user1 from 192.0.2.10 port 50003 ssh2\n"
            "Accepted password for user1 from 192.0.2.10 port 50004 ssh2\n"
            "Accepted password for user2 from 192.0.2.30 port 50005 ssh2\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_counts_authentication_events(self):
        report = analyze_log(self.log_path)

        self.assertEqual(report["total_failed"], 3)
        self.assertEqual(report["total_successful"], 2)
        self.assertEqual(report["unique_failed_sources"], 1)

    def test_detects_repeated_failed_logins(self):
        report = analyze_log(self.log_path)

        alerts = [
            alert for alert in report["alerts"]
            if alert["type"] == "Repeated failed logins"
        ]

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "192.0.2.10")
        self.assertEqual(alerts[0]["count"], 3)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

    def test_detects_failures_followed_by_success(self):
        report = analyze_log(self.log_path)

        alerts = [
            alert for alert in report["alerts"]
            if alert["type"]
            == "Failed attempts followed by successful login"
        ]

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_higher_threshold_suppresses_alerts(self):
        report = analyze_log(self.log_path, threshold=4)

        self.assertEqual(report["alerts"], [])

    def test_successful_logins_alone_do_not_trigger_alerts(self):
        self.log_path.write_text(
            "Accepted password for user2 from 192.0.2.30 port 50005 ssh2\n",
            encoding="utf-8",
        )

        report = analyze_log(self.log_path)

        self.assertEqual(report["total_successful"], 1)
        self.assertEqual(report["total_failed"], 0)
        self.assertEqual(report["alerts"], [])

    def test_missing_log_file_raises_error(self):
        missing_path = Path(self.temp_dir.name) / "missing.log"

        with self.assertRaises(FileNotFoundError):
            analyze_log(missing_path)

    def test_invalid_threshold_raises_error(self):
        with self.assertRaises(ValueError):
            analyze_log(self.log_path, threshold=0)


if __name__ == "__main__":
    unittest.main()
