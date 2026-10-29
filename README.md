# CyberShield — Security Monitoring and Threat Detection

## Overview

CyberShield is an educational cybersecurity project that combines local network auditing, authentication log analysis, rule-based alerting, and automated security reporting.

The project demonstrates foundational defensive security skills using Python, Nmap, and automated unit testing.

## Features

- **Network auditing:** Reads saved Nmap scan reports and identifies recorded open, closed, and filtered ports.
- **Authentication log analysis:** Counts failed and successful authentication events by source IP address.
- **Security alerting:** Detects repeated failed logins and identifies sources associated with repeated failures and successful logins.
- **Automated reporting:** Generates a Markdown report containing scan findings, authentication statistics, security alerts, recommendations, and limitations.
- **Automated testing:** Uses Python's `unittest` framework to validate the log analyser and report generator.

## Project Structure

```text
network-security-audit/
├── .gitignore
├── README.md
├── project-report.md
├── evidence/
│   ├── initial-scan.txt
│   └── follow-up-scan.txt
├── reports/
│   └── security-report.md
├── sample_logs/
│   └── auth.log
├── src/
│   ├── log_analyzer.py
│   └── report_generator.py
└── tests/
    ├── test_log_analyzer.py
    └── test_report_generator.py
```

## Requirements

- Python 3
- Nmap for conducting network scans
- A terminal such as Bash
- Git

The log analyser and report generator use Python's standard library.

## Running the Project

Run all commands from the project root directory.

### 1. Analyse the sample authentication log

```bash
python3 src/log_analyzer.py sample_logs/auth.log
```

Set a different failed-login threshold:

```bash
python3 src/log_analyzer.py sample_logs/auth.log --threshold 4
```

### 2. Generate the security assessment report

```bash
python3 -m src.report_generator
```

The report is written to:

```text
reports/security-report.md
```

The default configuration analyses `sample_logs/auth.log` and reads the saved scan evidence in `evidence/`.

### 3. Run the automated tests

```bash
python3 -m unittest discover -s tests -v
```

The current test suite contains 12 tests covering authentication event counting, alert detection, threshold handling, error handling, scan evidence extraction, and report generation.

## Example Findings

The saved network scan evidence records the following observations:

- Port 631/tcp was reported open and associated with CUPS.
- Port 34573/tcp was open in the initial scan and closed in the follow-up scan.

These observations describe the scan results only. They do not establish why the port state changed or whether a vulnerability existed.

The synthetic authentication log contains failed and successful login events from documentation-only IP addresses. The configured rules generate alerts when their thresholds are met.

## Security Recommendations

1. Investigate repeated authentication failures.
2. Review account activity when repeated failures are associated with successful logins.
3. Verify unexpected listening services and identify their owning processes.
4. Apply appropriate security updates.
5. Repeat authorised scans after changes and compare the evidence.

## Limitations

- The sample authentication events are synthetic and do not represent real incidents.
- Detection relies on simple pattern-matching rules.
- Failed and successful login events are grouped by source IP; chronological sequence and time-window correlation are not implemented.
- Scan findings reflect the system at the time of each scan.
- Alert severity is preliminary and does not replace professional investigation.

## Ethical Use

Only scan systems and networks that you own or have explicit permission to assess.

This project is intended for education and defensive security practice. It is not a replacement for a production security monitoring platform.

Learning Outcomes

This project demonstrates practical experience with:

Network reconnaissance and service identification.

Log parsing and event counting in Python.

Rule-based detection and alerting.

Unit testing with unittest.

Automated Markdown report generation.

Git version control and security evidence documentation
