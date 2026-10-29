
#!/usr/bin/env python3

import argparse
from datetime import datetime
from pathlib import Path

from src.log_analyzer import analyze_log


def read_scan_evidence(scan_path):
    """Extract port findings from a saved Nmap text report."""
    path = Path(scan_path)

    if not path.is_file():
        return [f"Scan evidence unavailable: {path}"]

    findings = []

    for line in path.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        parts = line.split()

        if (
            len(parts) >= 3
            and "/" in parts[0]
            and parts[1] in {"open", "closed", "filtered"}
        ):
            findings.append(line.strip())

    return findings or ["No port findings could be extracted."]


def generate_markdown_report(log_report, scan_paths):
    """Combine network scan evidence and log-analysis results."""
    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    lines = [
        "# CyberShield Security Assessment Report",
        "",
        f"**Generated:** {timestamp}",
        "**Assessment type:** Local network audit and log analysis",
        "**Purpose:** Educational defensive security assessment",
        "",
        "## 1. Executive Summary",
        "",
        (
            "This report combines saved Nmap scan observations "
            "with authentication log analysis. Findings require "
            "appropriate investigation and do not automatically "
            "establish that a vulnerability or attack occurred."
        ),
        "",
        "## 2. Network Scan Findings",
        "",
    ]

    for scan_path in scan_paths:
        lines.extend([f"### Evidence: `{scan_path}`", ""])

        findings = read_scan_evidence(scan_path)

        lines.extend(f"- `{finding}`" for finding in findings)
        lines.append("")

    lines.extend([
        "## 3. Authentication Log Analysis",
        "",
        f"- Log file: `{log_report['log_file']}`",
        f"- Detection threshold: {log_report['threshold']}",
	f"- Correlation window: {log_report.get('window_minutes', 10)} minutes",
        f"- Failed authentication events: {log_report['total_failed']}",
        (
            "- Successful authentication events: "
            f"{log_report['total_successful']}"
        ),
        (
            "- Unique sources associated with failed logins: "
            f"{log_report['unique_failed_sources']}"
        ),
        "",
        "## 4. Security Alerts",
        "",
    ])

    if not log_report["alerts"]:
        lines.extend([
            "No configured detection rules were triggered.",
            "",
        ])
    else:
        for number, alert in enumerate(
            log_report["alerts"], start=1
        ):
            lines.extend([
                f"### Alert {number}: {alert['type']}",
                "",
                f"- **Severity:** {alert['severity']}",
                f"- **Source IP:** `{alert['source_ip']}`",
                f"- **Evidence count:** {alert['count']}",
                f"- **Details:** {alert['message']}",
                "",
            ])

    lines.extend([
        "## 5. Recommended Actions",
        "",
        "1. Investigate repeated authentication failures.",
        (
            "2. Review account activity when repeated failures "
            "are associated with a successful login."
        ),
        (
            "3. Verify unexpected network services and identify "
            "the processes listening on their ports."
        ),
        (
            "4. Keep the operating system and installed services "
            "updated using trusted security repositories."
        ),
        (
            "5. Repeat the audit after any changes and compare "
            "the new evidence with previous results."
        ),
        "",
        "## 6. Limitations",
        "",
        "- The log analyser uses simple pattern-matching rules.",
        "- Detection depends on parseable timestamps and simple pattern-matching rules.",
        "- Scan results describe the system at the time of each scan.",
        "- Synthetic log entries are not evidence of real incidents.",
        "- Severity labels are preliminary project-defined indicators.",
        "",
        "## 7. Conclusion",
        "",
        (
            "CyberShield demonstrates basic network service inspection, "
            "authentication log analysis, rule-based alerting, and "
            "automated security reporting. Further validation is needed "
            "before using the tool for operational security monitoring."
        ),
        "",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a CyberShield Markdown security report."
    )

    parser.add_argument(
        "--log",
        default="sample_logs/auth.log",
        help="Authentication log file to analyse",
    )
    parser.add_argument(
        "--scan",
        nargs="*",
        default=[
            "evidence/initial-scan.txt",
            "evidence/follow-up-scan.txt",
        ],
        help="Saved Nmap evidence files",
    )
    parser.add_argument(
        "--output",
        default="reports/security-report.md",
        help="Path for the generated Markdown report",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Failed-login alert threshold",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=10,
        help="Time window for correlating failed and successful logins",
    )

    args = parser.parse_args()

    try:
        log_report = analyze_log(
	    args.log,
	    threshold=args.threshold,
	    window_minutes=args.window_minutes,
	)
        markdown = generate_markdown_report(
            log_report, args.scan
        )

        output_path = Path(args.output)
        output_path.parent.mkdir(
            parents=True, exist_ok=True
        )
        output_path.write_text(
            markdown, encoding="utf-8"
        )

        print("CyberShield report generated successfully.")
        print(f"Output file: {output_path}")
        print(
            f"Alerts recorded: {len(log_report['alerts'])}"
        )

    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
