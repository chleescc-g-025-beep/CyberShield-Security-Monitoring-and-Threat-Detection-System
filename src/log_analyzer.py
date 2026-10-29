#!/usr/bin/env python3

"""
CyberShield Security Log Analyzer

Analyses authentication logs for repeated failed logins and
successful logins following repeated failures within a time window.
Uses synthetic or authorised log data for defensive monitoring.
"""

import argparse
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path


FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

SUCCESSFUL_LOGIN_PATTERN = re.compile(
    r"Accepted password for \S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

TIMESTAMP_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+"
    r"\d{2}:\d{2}:\d{2})"
)


def parse_timestamp(line):
    """Parse a traditional syslog timestamp, using the current year."""
    match = TIMESTAMP_PATTERN.search(line)

    if not match:
        return None

    timestamp_text = match.group("timestamp")
    timestamp_text = " ".join(timestamp_text.split())

    try:
        return datetime.strptime(
            f"{datetime.now().year} {timestamp_text}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None


def analyze_log(log_path, threshold=3, window_minutes=10):
    """Analyse authentication events and return a security report."""

    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    if window_minutes < 1:
        raise ValueError("Window must be at least 1 minute.")

    path = Path(log_path)

    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    failed_attempts = Counter()
    successful_attempts = Counter()
    events = []

    total_failed = 0
    total_successful = 0

    with path.open(
        "r", encoding="utf-8", errors="replace"
    ) as log_file:
        for line in log_file:
            timestamp = parse_timestamp(line)

            failed_match = FAILED_LOGIN_PATTERN.search(line)
            successful_match = SUCCESSFUL_LOGIN_PATTERN.search(line)

            if failed_match:
                ip = failed_match.group("ip")
                failed_attempts[ip] += 1
                total_failed += 1

                if timestamp is not None:
                    events.append({
                        "timestamp": timestamp,
                        "source_ip": ip,
                        "event": "failed",
                    })

            elif successful_match:
                ip = successful_match.group("ip")
                successful_attempts[ip] += 1
                total_successful += 1

                if timestamp is not None:
                    events.append({
                        "timestamp": timestamp,
                        "source_ip": ip,
                        "event": "success",
                    })

    alerts = []

    # Rule 1: repeated failed logins.
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

    # Rule 2: a successful login after enough failures within
    # the configured time window.
    events.sort(key=lambda event: event["timestamp"])

    failed_events_by_ip = defaultdict(list)
    correlated_alerts = {}

    window = timedelta(minutes=window_minutes)

    for event in events:
        ip = event["source_ip"]
        timestamp = event["timestamp"]

        if event["event"] == "failed":
            failed_events_by_ip[ip].append(timestamp)
            continue

        # Keep only failures that occurred before this success
        # and within the configured time window.
        recent_failures = [
            failure_time
            for failure_time in failed_events_by_ip[ip]
            if timestamp - window <= failure_time < timestamp
        ]

        failed_events_by_ip[ip] = recent_failures

        if len(recent_failures) >= threshold and ip not in correlated_alerts:
            correlated_alerts[ip] = {
                "type": "Failed attempts followed by successful login",
                "source_ip": ip,
                "count": len(recent_failures),
                "severity": "HIGH",
                "message": (
                    f"A successful login from {ip} occurred after "
                    f"{len(recent_failures)} failed login attempts "
                    f"within {window_minutes} minutes. "
                    "Investigate the account activity."
                ),
            }

    alerts.extend(
        correlated_alerts[ip] for ip in sorted(correlated_alerts)
    )

    return {
        "log_file": str(path),
        "threshold": threshold,
        "window_minutes": window_minutes,
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
    print(f"Correlation window: {report['window_minutes']} minutes")
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

    parser.add_argument(
        "--window-minutes",
        type=int,
        default=10,
        help="Time window for correlating failed and successful logins",
    )

    args = parser.parse_args()

    try:
        report = analyze_log(
            args.log_file,
            threshold=args.threshold,
            window_minutes=args.window_minutes,
        )
        print_report(report)
    except (FileNotFoundError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main() 
