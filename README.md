# OWASP Top 10 (2025) Vulnerability Scanner v2.0

Python scanner for **authorized** training targets (local demo app, **DVWA in Docker**, or similar). Organized around the **OWASP Top 10 — 2025** with professional PDF and HTML reports including exploitation proof screenshots.

## What's New in v2.0

- **Updated to OWASP Top 10 (2025)**
- **Professional HTML report** with dark theme, interactive navigation
- **Screenshot capture** for exploitation proof documentation
- **Enhanced PDF report** with risk score banner, improved structure
- **Both PDF and HTML output** options

## Important

- Use only on systems you **own** or are **explicitly allowed** to test.
- Payloads are **non-destructive** (no DROP, DELETE, or mass writes).
- Requests use conservative throttling and 10s timeout.

## Setup

```powershell
cd ca_ecommerce_scanner
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Quick Start

### 1) Local Flask Demo

**Terminal A** - Start demo target:
```powershell
python demo_target.py
```

**Terminal B** - Run scanner with both report formats:
```powershell
python main.py --demo --output demo_report.pdf --html-output demo_report.html --screenshots --verbose
```

### 2) DVWA in Docker

```powershell
python main.py --url http://127.0.0.1:3000 --profile dvwa --dvwa-login admin:password --output dvwa_report.pdf --html-output dvwa_report.html --screenshots --verbose --ignore-robots
```

## CLI Options

| Flag | Description |
|------|-------------|
| `--url` | Target base URL |
| `--output` | PDF report path (default: security_report.pdf) |
| `--html-output` | HTML report path (default: security_report.html) |
| `--profile ecommerce` | Generic shop-style paths (default) |
| `--profile dvwa` | DVWA / PHP lab paths |
| `--modules sqli,auth,...` | Run specific modules only |
| `--screenshots` | Capture exploitation proof screenshots |
| `--screenshots-dir` | Screenshots directory (default: screenshots/) |
| `--html-only` | Generate HTML report only |
| `--pdf-only` | Generate PDF report only |
| `--verbose` | Show detailed progress |
| `--ignore-robots` | Ignore robots.txt (use only with authorization) |
| `--demo` | Target local demo at http://127.0.0.1:5000 |

## OWASP Top 10 (2025) Coverage

| Module | OWASP Category |
|--------|---------------|
| `sqli`, `xss` | A03:2025 - Injection |
| `auth` | A07:2025 - Identification and Authentication Failures |
| `access` | A01:2025 - Broken Access Control |
| `crypto` | A02:2025 - Cryptographic Failures |
| `misconfig`, `headers` | A05:2025 - Security Misconfiguration |
| `components` | A06:2025 - Vulnerable and Outdated Components |
| `design` | A04:2025 - Insecure Design |
| `integrity` | A08:2025 - Software and Data Integrity Failures |
| `logging` | A09:2025 - Security Logging and Monitoring Failures |
| `ssrf` | A10:2025 - Server-Side Request Forgery |

## Report Contents

### PDF Report
- Cover page with risk score banner
- Table of contents
- Executive summary with severity breakdown
- Methodology & scope
- Risk overview (pie + bar charts)
- OWASP Top 10 coverage matrix
- Detailed findings with evidence, payloads, and remediation
- Remediation roadmap
- Appendix with references

### HTML Report
- Professional dark theme design
- Sticky navigation menu
- Risk score display
- Interactive severity stats
- OWASP coverage table
- Detailed findings with:
  - Payload evidence
  - Server response snippets
  - Exploitation proof screenshots (iframe embedded)
  - Step-by-step remediation
  - Secure code examples
- Remediation roadmap
- Appendix

## Screenshot Capture

When `--screenshots` is enabled, the scanner captures:
- HTML proof documents with request/response details
- Payloads used and server responses
- Timestamps and attack context

Screenshots are saved to the specified directory and linked in both reports.

## Example Output

```
[*] Starting scan against http://127.0.0.1:5000
[*] Screenshot capture enabled -> screenshots/
[+] sqli: completed (3 findings)
[+] xss: completed (1 findings)
[+] auth: completed (2 findings)
[*] OWASP Top 10 (2025) — findings by category: A01=1, A03=4, A07=2

Scan completed. Total findings: 7
Screenshots captured: 7
[*] PDF report generated: security_report.pdf
[*] HTML report generated: security_report.html
```

## SQL Injection Detection

The scanner uses multiple non-destructive probe styles:
- Classic OR-based injection
- SQL comment injection (#, --)
- Inline comment spacing
- UNION-based probes
- Case manipulation
- Whitespace normalization

## Disclaimer

This tool is for **authorized security testing only**. Unauthorized scanning is illegal and unethical. Always obtain proper authorization before testing any system.