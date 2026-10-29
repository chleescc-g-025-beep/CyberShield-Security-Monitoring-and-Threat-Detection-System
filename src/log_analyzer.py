#!/usr/bin/env python3

"""
CyberShield Security Log Analyzer

Analyses authentication logs for repeated failed login attempts.
Uses synthetic or authorised log data for defensive monitoring.
"""

import argparse
import re
from collections import Counter
from pathlib import Path


FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

SUCCESSFUL_LOGIN_PATTERN = re.compile(
    r"Accepted password for \S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def analyze_log(log_path, threshold=3):
    """Analyse a log file and return a structured security report."""

    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    path = Path(log_path)

    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    failed_attempts = Counter()
    successful_attempts = Counter()
    total_failed = 0
    total_successful = 0

    with path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            failed_match = FAILED_LOGIN_PATTERN.search(line)
            successful_match = SUCCESSFUL_LOGIN_PATTERN.search(line)

            if failed_match:
                ip = failed_match.group("ip")
                failed_attempts[ip] += 1
                total_failed += 1

            elif successful_match:
                ip = successful_match.group("ip")
                successful_attempts[ip] += 1
                total_successful += 1

    alerts = []

    for ip, count in sorted(failed_attempts.items()):
        if count >= threshold:
            alerts.append({
                "type": "Repeated failed logins",
                "source_ip": ip,
                "count": count,
                "severity": "MEDIUM",
                "message": (
                    f"{count} failed login attempts were recorded "
                    f"from {ip}."
                ),
            })

    for ip in sorted(failed_attempts.keys() & successful_attempts.keys()):
        if failed_attempts[ip] >= threshold:
            alerts.append({
                "type": "Failed attempts followed by successful login",
                "source_ip": ip,
                "count": failed_attempts[ip],
                "severity": "HIGH",
                "message": (
                    f"The logs contain repeated failed attempts and "
                    f"a successful login from {ip}. Investigate the "
                    f"event sequence and account activity."
                ),
            })

    return {
        "log_file": str(path),
        "threshold": threshold,
        "total_failed": total_failed,
        "total_successful": total_successful,
        "unique_failed_sources": len(failed_attempts),
        "alerts": alerts,
    }


def print_report(report):
    """Print a readable security report."""

    print("\n" + "=" * 55)
    print("CYBERSHIELD - SECURITY LOG ANALYSIS REPORT")
    print("=" * 55)

    print(f"Log file: {report['log_file']}")
    print(f"Detection threshold: {report['threshold']} failed attempts")
    print(f"Failed login events: {report['total_failed']}")
    print(f"Successful login events: {report['total_successful']}")
    print(f"Unique failed-login sources: {report['unique_failed_sources']}")

    print("\nSECURITY ALERTS")
    print("-" * 55)

    if not report["alerts"]:
        print("No configured detection rules were triggered.")
    else:
        for number, alert in enumerate(report["alerts"], start=1):
            print(f"\nAlert {number}: {alert['type']}")
            print(f"Severity: {alert['severity']}")
            print(f"Source IP: {alert['source_ip']}")
            print(f"Evidence count: {alert['count']}")
            print(f"Details: {alert['message']}")

    print("\nNote: Alerts require investigation and do not prove an attack.")
    print("=" * 55)


def main():
    parser = argparse.ArgumentParser(
        description="CyberShield authentication log analyser"
    )

    parser.add_argument(
        "log_file",
        help="Path to the authentication log to analyse",
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Failed login threshold for an alert (default: 3)",
    )

    args = parser.parse_args()

    try:
        report = analyze_log(args.log_file, args.threshold)
        print_report(report)
    except (FileNotFoundError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
