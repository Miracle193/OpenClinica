# Shift-Left AppSec Pipeline for OpenClinica

## Project Overview

This project demonstrates the implementation of a **Shift-Left Application Security (AppSec) pipeline** for OpenClinica, a healthcare and clinical trial data management platform.

The goal of this project was to integrate automated security testing directly into the development lifecycle using static analysis, dependency scanning, and secrets detection within a CI/CD pipeline.

The pipeline automatically scans the codebase during pull requests and code pushes to identify:

* Vulnerable dependencies
* Insecure coding practices
* Hardcoded secrets and credentials

This project focuses on improving security earlier in the Software Development Lifecycle (SDLC) by implementing automated DevSecOps workflows.

---

# Architecture

```text

                ┌── Semgrep
Checkout ───────┼── Dependency Check
                └── Gitleaks
                        ↓
                 Upload Reports & Findings
                        ↓
               Pipeline Pass / Fail Decision
```

---

# 🔧 Technologies & Tools Used

| Category                                   | Tool                     |
| ------------------------------------------ | ------------------------ |
| CI/CD                                      | GitHub Actions           |
| Static Application Security Testing (SAST) | Semgrep                  |
| Software Composition Analysis (SCA)        | OWASP Dependency-Check   |
| Secrets Detection                          | Gitleaks                 |
| Development Environment                    | Visual Studio Code + WSL |
| Operating System                           | Ubuntu (WSL)             |

---

# 🔐 Security Scanning Implemented

## 1. Static Application Security Testing (SAST)

Implemented automated source code scanning using Semgrep to identify:

* Injection vulnerabilities
* Insecure coding patterns
* Hardcoded credentials
* Misconfigurations

### Example Commands

```bash
semgrep scan --config=auto .
semgrep scan --config=auto --json > semgrep-report.json
```

---

## 2. Dependency Vulnerability Scanning (SCA)

Used OWASP Dependency-Check to identify vulnerable third-party libraries and known CVEs affecting the application.

### Example Command

```bash
dependency-check.sh --scan . --format HTML
```

---

## 3. Secrets Scanning

Implemented secrets detection using Gitleaks to detect:

* API keys
* Tokens
* Hardcoded passwords
* Exposed credentials

### Example Command

```bash
gitleaks detect --source . --report-format json --report-path gitleaks-report.json
```

---

# ⚙️ CI/CD Pipeline

The security pipeline was integrated into GitHub Actions and configured to run automatically on:

* Pull Requests
* Push Events

## Pipeline Features

* Automated security scanning
* Report generation
* Artifact uploads
* Pipeline failure on high-severity findings
* Centralized security reporting

---

# Project Structure

```text
OpenClinica/
│
├── .github/
│   └── workflows/
│       └── security.yml
│
├── reports/
│   ├── semgrep-report.json
│   ├── dependency-check-report.html
│   ├── gitleaks-report.json
│   └── findings-summary.md
│
├── screenshots/
│   ├── github-actions-pipeline.png
│   ├── semgrep-findings.png
│   └── dependency-check-report.png
│
└── README.md
```

---

# Findings Summary

The security pipeline identified several categories of findings, including:

* Vulnerable third-party dependencies with known CVEs
* Potential insecure coding patterns
* Misconfigurations and security anti-patterns
* Exposed or hardcoded secrets

Findings were prioritized based on:

* Severity
* Confidence
* Potential impact
* Exploitability

---

# Screenshots

## GitHub Actions Pipeline


---

# Future Improvements

Planned enhancements for the project include:

* Integrating OWASP ZAP for Dynamic Application Security Testing (DAST)
* Adding authenticated scanning
* Implementing automated PR comments for findings
* Creating custom Semgrep rules
* Integrating Slack or email alerts
* Security dashboard visualization

---

# ⚠️ Disclaimer

This project was created strictly for educational and defensive security purposes in a controlled environment using publicly available source code.
