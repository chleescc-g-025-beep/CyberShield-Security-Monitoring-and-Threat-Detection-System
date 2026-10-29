# Basic Network Security Audit and Vulnerability Assessment

## 1. Project Overview

This project demonstrates the use of Nmap and Linux system administration tools to perform a basic network security audit on an Ubuntu computer.

The purpose of the project is to identify exposed network services, inspect service configurations, investigate software versions, and recommend measures to improve system security.

This is a beginner-level cybersecurity project designed to demonstrate practical skills in network reconnaissance, security assessment, evidence collection, and technical reporting.

## 2. Objectives

The objectives of this project are to:

Use Nmap to scan a local computer for open TCP ports.

Identify network services and their versions.

Investigate the network interfaces on which a service listens.

Inspect the configuration of printing services.

Check installed software versions against available package versions.

Investigate potential security risks using evidence and official security advisories.

Document findings and recommend appropriate security improvements.

## 3. Scope and Authorisation

The initial assessment targets 127.0.0.1, the loopback address
of the computer running the scan.

The assessment is limited to the local computer and does not
authorise scanning other systems or networks.

## 4. Tools Used

Ubuntu Linux 24.04 LTS        Operating system being assessed
Nmap 7.94SVN                  Network scanning and service identification
ss                            Inspection of listening network sockets
systemctl                     Checking service status
dpkg-query                    Checking installed package versions
apt                           Inspecting available software package versions
Bash terminal                 Executing commands and managing project files
Markdown                      Documenting the project and findings

## 5. Methodology

The assessment follows these steps:

Verify that Nmap is installed.

Scan the local computer using Nmap.

Identify open TCP ports and associated services.

Inspect the listening addresses of identified services.

Review relevant service configuration settings.

Check installed software package versions.

Compare package versions with available repository versions.

Investigate potential security issues using official security advisories.

Document the findings and recommend security improvements.


## 6. Findings

Findings will be documented after examining the actual scan results.

## 7. Recommendations

Security recommendations will be based on the services identified
and any risks supported by the collected evidence.

## 8. Conclusion

Ths project demonstrates the use of Nmap and Linux administration tools to investigate a local network service.

The initial scan identified CUPS on TCP port 631. Follow-up inspection showed that the observed listeners were bound to loopback addresses, and the installed CUPS package versions matched the versions available from the configured repositories.

The project illustrates the importance of combining network scan results with configuration checks and package-version verification before determining whether a security issue exists.

The assessment will be strengthened by completing the remaining package checks, reviewing applicable security advisories, and finalising the supporting evidence.

## 6. Findings and Analysis

### Finding NSA-001: CUPS Service Detected

Observation:
An Nmap service-detection scan of 127.0.0.1
identified TCP port 631 as open and associated it with
Internet Printing Protocol (IPP) and CUPS 2.4.

Evidence:
evidence/initial-scan.txt

Analysis:
The service was investigated to determine its listening
addresses and installed package version.

### Finding NSA-002: CUPS Listening Addresses

Observation:
The observed TCP listeners used 127.0.0.1:631 and [::1]:631.

Assessment: This is a positive security indicator because the observed listeners are restricted to loopback interfaces.

Recommendation: Preserve the restricted configuration unless broader access is required and appropriately secured.

Status: Initial configuration check completed.

### Finding NSA-003: Installed Package Version

Observation:
The installed CUPS packages were version 2.4.7-1.2ubuntu7.14, matching the candidate versions reported by the package manager.

Assessment: The installed version should be evaluated against the security advisories applicable to Ubuntu 24.04 LTS.

Recommendation: Continue applying security updates and verify package status against official Ubuntu security information.

Status: Initial version check completed; advisory review required.

## 7. Recommendations

1. Keep Ubuntu and CUPS security updates current.
2. Keep printing services disabled if they are not needed.
3. Restrict network access to printing services according
   to actual operational requirements.
4. Review the service configuration after relevant changes.
5. Base vulnerability assessments on the operating system,
   package revision, and applicable security advisories.

## 8. Conclusion

This project demonstrates the use of Nmap and Linux administration tools to investigate a local network service.

The initial scan identified CUPS on TCP port 631. Follow-up inspection showed that the observed listeners were bound to loopback addresses, and the installed CUPS package versions matched the versions available from the configured repositories.

The project illustrates the importance of combining network scan results with configuration checks and package-version verification before determining whether a security issue exists.

The assessment will be strengthened by completing the remaining package checks, reviewing applicable security advisories, and finalising the supporting evidence.