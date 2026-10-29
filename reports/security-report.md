# CyberShield Security Assessment Report

**Generated:** 2026-10-29T13:47:30+02:00
**Assessment type:** Local network audit and log analysis
**Purpose:** Educational defensive security assessment

## 1. Executive Summary

This report combines saved Nmap scan observations with authentication log analysis. Findings require appropriate investigation and do not automatically establish that a vulnerability or attack occurred.

## 2. Network Scan Findings

### Evidence: `evidence/initial-scan.txt`

- `631/tcp   open  ipp         CUPS 2.4`
- `34573/tcp open  ssl/unknown`

### Evidence: `evidence/follow-up-scan.txt`

- `631/tcp   open   ipp     CUPS 2.4`
- `34573/tcp closed unknown`

## 3. Authentication Log Analysis

- Log file: `sample_logs/auth.log`
- Detection threshold: 3
- Correlation window: 10 minutes
- Failed authentication events: 4
- Successful authentication events: 2
- Unique sources associated with failed logins: 2

## 4. Security Alerts

### Alert 1: Repeated failed logins

- **Severity:** MEDIUM
- **Source IP:** `192.0.2.10`
- **Evidence count:** 3
- **Details:** 3 failed login attempts were recorded from 192.0.2.10.

### Alert 2: Failed attempts followed by successful login

- **Severity:** HIGH
- **Source IP:** `192.0.2.10`
- **Evidence count:** 3
- **Details:** A successful login from 192.0.2.10 occurred after 3 failed login attempts within 10 minutes. Investigate the account activity.

## 5. Recommended Actions

1. Investigate repeated authentication failures.
2. Review account activity when repeated failures are associated with a successful login.
3. Verify unexpected network services and identify the processes listening on their ports.
4. Keep the operating system and installed services updated using trusted security repositories.
5. Repeat the audit after any changes and compare the new evidence with previous results.

## 6. Limitations

- The log analyser uses simple pattern-matching rules.
- Detection depends on parseable timestamps and simple pattern-matching rules.
- Scan results describe the system at the time of each scan.
- Synthetic log entries are not evidence of real incidents.
- Severity labels are preliminary project-defined indicators.

## 7. Conclusion

CyberShield demonstrates basic network service inspection, authentication log analysis, rule-based alerting, and automated security reporting. Further validation is needed before using the tool for operational security monitoring.
