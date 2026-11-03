# Autonomous Container Image Vulnerability & SBOM Scanner 🐳🛡️

[![CI/CD Pipeline](https://github.com/GarciaVillenaLuis/container-image-vuln-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/GarciaVillenaLuis/container-image-vuln-scanner/actions/workflows/ci.yml)
[![SBOM Standard](https://img.shields.io/badge/SBOM-CycloneDX%20%7C%20SPDX-0078D4?style=flat-square&logo=linuxfoundation&logoColor=white)](https://cyclonedx.org/)
[![NIST Compliance](https://img.shields.io/badge/Security-NIST%20SP%20800--190-orange?style=flat-square)](https://csrc.nist.gov/publications/detail/sp/800-190/final)
[![Docker Hardening](https://img.shields.io/badge/Container-CIS%20Docker%20v1.6-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Vulnerability Feed](https://img.shields.io/badge/Feed-CVSS%20v3.1%20%2B%20EPSS-red?style=flat-square)](https://nvd.nist.gov/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square)](LICENSE)

Autonomous command-line scanner and policy gate analyzing **Container Images**, **Software Bill of Materials (SBOMs)** in **CycloneDX / SPDX formats**, and **Dockerfiles** for known CVEs, CVSS v3.1 base metrics, and container security misconfigurations.

Developed and maintained by **Luis García Villena** (*Security Transformation Analyst @ Accenture | CCSP® & CCGP ISMS Forum*).

---

## 🌟 Key Capabilities

- **Multi-Format SBOM Ingestion**: Seamlessly ingests industry-standard CycloneDX (v1.4/v1.5) and SPDX (v2.2/v2.3) JSON manifests produced by modern build toolchains (Syft, Trivy, Docker Scout, Grype).
- **Vulnerability Correlation & CVSS Gating**: Evaluates open-source packages and base OS libraries against high-risk zero-days and known exploited vulnerabilities (e.g., XZ-Utils backdoor `CVE-2024-3094`, HTTP/2 Rapid Reset `CVE-2023-44487`, Spring4Shell `CVE-2022-22965`).
- **Dockerfile Static Security Linter**:
  - Flags dangerous `USER root` declarations or omitted non-root users (`DOCKER-02`, `DOCKER-05`).
  - Warns against untagged `:latest` base images (`DOCKER-01`).
  - Identifies untrusted curl-to-shell executions (`curl | bash` - `DOCKER-03`).
  - Blocks unwanted SSH daemon exposures on port 22 (`DOCKER-04`).
- **DevSecOps Shift-Left Integration**: Designed for zero-dependency execution in air-gapped CI/CD runners with configurable exit-code gating (`--fail-on HIGH` / `CRITICAL`).
- **Registry Telemetry Posture**: Live container posture metrics and scan records stored in [`reports/container_security_matrix.json`](./reports/container_security_matrix.json).

---

## 🚀 Quick Start & CLI Usage

### Requirements
- Python 3.9+ (Standard library only — zero pip dependencies required)

### Syntax & Available Options

```bash
python container_vuln_scanner.py [OPTIONS]
```

| Parameter | Type | Description |
| :--- | :---: | :--- |
| `--sbom, -s PATH` | `string` | Path to CycloneDX or SPDX JSON SBOM file |
| `--dockerfile, -d PATH` | `string` | Path to Dockerfile to audit and lint |
| `--fail-on LEVEL` | `choice` | Gating severity threshold: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` (default: `HIGH`) |
| `--format FMT` | `choice` | Output format: `table` (default) or `json` |
| `--stats` | `flag` | Display live enterprise container registry security telemetry |

---

## 💻 Practical Usage Scenarios

### 1. Scan a CycloneDX SBOM against Vulnerability Thresholds
```bash
python container_vuln_scanner.py --sbom samples/cyclonedx_sbom.json
```
**Sample Output:**
```text
------------------------------------------------------------------------------------------------
CVE              | PACKAGE            | SEVERITY   | CVSS   | FIXED VERSION    | EXPLOITED 
------------------------------------------------------------------------------------------------
CVE-2024-3094    | xz-utils           | CRITICAL   | 10.0   | 5.6.1-r1         | YES       
CVE-2023-38545   | curl               | CRITICAL   | 9.8    | 8.4.0            | NO        
------------------------------------------------------------------------------------------------
Gating Policy Threshold: HIGH -> Decision: [FAILED]
Summary: 2 Critical, 0 High, 0 Medium
```

### 2. Lint a Dockerfile for Security Misconfigurations
```bash
python container_vuln_scanner.py --dockerfile samples/sample_dockerfile
```
**Sample Output:**
```text
Dockerfile Audit Result: [REVIEW_REQUIRED] (5 finding(s))
  - [MEDIUM] [L2] DOCKER-01: Base image uses ':latest' or untagged version (node:latest)
    Remediation: Pin base image to specific digest (SHA256) or immutable semantic version.
  - [CRITICAL] [L7] DOCKER-03: Piping untrusted remote script directly to shell (curl | bash)
    Remediation: Download package artifacts, verify SHA256 checksums, and execute statically.
  - [HIGH] [L16] DOCKER-04: SSH Port 22 exposed in container image
    Remediation: Remove SSH daemon from container; use kubectl exec or SSM instead.
  - [HIGH] [GLOBAL] DOCKER-05: Missing USER instruction (Container defaults to running as root)
    Remediation: Add 'USER nonroot:nonroot' before entrypoint.
```

---

## 🧪 Automated Testing

Execute the test suite locally:
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
