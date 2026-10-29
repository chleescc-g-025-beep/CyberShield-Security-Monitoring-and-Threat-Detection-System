import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.report_generator import (
    generate_markdown_report,
    read_scan_evidence,
)


class TestReportGenerator(unittest.TestCase):

    def test_reads_port_findings(self):
        with TemporaryDirectory() as temp_dir:
            scan_file = Path(temp_dir) / "scan.txt"
            scan_file.write_text(
                "631/tcp open ipp CUPS 2.4\n"
                "34573/tcp closed unknown\n",
                encoding="utf-8",
            )

            findings = read_scan_evidence(scan_file)

            self.assertEqual(len(findings), 2)
            self.assertIn("631/tcp open ipp CUPS 2.4", findings[0])
            self.assertIn("34573/tcp closed unknown", findings[1])

    def test_missing_scan_file_is_reported(self):
        findings = read_scan_evidence(
            "file_that_does_not_exist.txt"
        )

        self.assertTrue(
            any("unavailable" in item for item in findings)
        )

    def test_empty_scan_file_has_no_findings_message(self):
        with TemporaryDirectory() as temp_dir:
            scan_file = Path(temp_dir) / "empty.txt"
            scan_file.write_text("", encoding="utf-8")

            findings = read_scan_evidence(scan_file)

            self.assertEqual(
                findings,
                ["No port findings could be extracted."],
            )

    def test_report_contains_security_alerts(self):
        log_report = {
            "log_file": "sample_logs/auth.log",
            "threshold": 3,
            "total_failed": 4,
            "total_successful": 2,
            "unique_failed_sources": 2,
            "alerts": [
                {
                    "type": "Repeated failed logins",
                    "severity": "MEDIUM",
                    "source_ip": "192.0.2.10",
                    "count": 3,
                    "message": "Three failed login attempts detected.",
                }
            ],
        }

        report = generate_markdown_report(
            log_report, []
        )

        self.assertIn("# CyberShield Security Assessment Report", report)
        self.assertIn("Repeated failed logins", report)
        self.assertIn("192.0.2.10", report)
        self.assertIn("Recommended Actions", report)
        self.assertIn("Limitations", report)

    def test_report_handles_no_alerts(self):
        log_report = {
            "log_file": "sample_logs/auth.log",
            "threshold": 3,
            "total_failed": 0,
            "total_successful": 2,
            "unique_failed_sources": 0,
            "alerts": [],
        }

        report = generate_markdown_report(
            log_report, []
        )

        self.assertIn(
            "No configured detection rules were triggered.",
            report,
        )


if __name__ == "__main__":
    unittest.main()
