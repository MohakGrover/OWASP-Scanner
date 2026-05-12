"""
OWASP Top 10 — 2025 canonical labels and scanner ↔ category mapping.

Used for report coverage matrix and consistent finding metadata.
"""

from __future__ import annotations

# Fallback (should not appear on published findings).
A00_UNCLASSIFIED = "A00:2025 - (Scanner meta)"

# Full strings stored on each finding (`owasp_category`).
A01_BROKEN_ACCESS_CONTROL = "A01:2025 - Broken Access Control"
A02_CRYPTOGRAPHIC_FAILURES = "A02:2025 - Cryptographic Failures"
A03_INJECTION = "A03:2025 - Injection"
A04_INSECURE_DESIGN = "A04:2025 - Insecure Design"
A05_SECURITY_MISCONFIGURATION = "A05:2025 - Security Misconfiguration"
A06_VULNERABLE_COMPONENTS = "A06:2025 - Vulnerable and Outdated Components"
A07_IDENTIFICATION_AUTH_FAILURES = "A07:2025 - Identification and Authentication Failures"
A08_SOFTWARE_DATA_INTEGRITY = "A08:2025 - Software and Data Integrity Failures"
A09_LOGGING_MONITORING = "A09:2025 - Security Logging and Monitoring Failures"
A10_SSRF = "A10:2025 - Server-Side Request Forgery (SSRF)"

OWASP_2025_ROWS: list[dict[str, str]] = [
    {"code": "A01", "id": "A01:2025", "name": "Broken Access Control"},
    {"code": "A02", "id": "A02:2025", "name": "Cryptographic Failures"},
    {"code": "A03", "id": "A03:2025", "name": "Injection"},
    {"code": "A04", "id": "A04:2025", "name": "Insecure Design"},
    {"code": "A05", "id": "A05:2025", "name": "Security Misconfiguration"},
    {"code": "A06", "id": "A06:2025", "name": "Vulnerable and Outdated Components"},
    {"code": "A07", "id": "A07:2025", "name": "Identification and Authentication Failures"},
    {"code": "A08", "id": "A08:2025", "name": "Software and Data Integrity Failures"},
    {"code": "A09", "id": "A09:2025", "name": "Security Logging and Monitoring Failures"},
    {"code": "A10", "id": "A10:2025", "name": "Server-Side Request Forgery"},
]

# Alias for backward compatibility
OWASP_2021_ROWS = OWASP_2025_ROWS

# Which CLI `--modules` keys exercise which Top 10 code (A01..A10).
SCANNER_TO_OWASP_CODES: dict[str, list[str]] = {
    "access": ["A01"],
    "crypto": ["A02"],
    "sqli": ["A03"],
    "xss": ["A03"],
    "design": ["A04"],
    "misconfig": ["A05"],
    "headers": ["A05"],
    "components": ["A06"],
    "auth": ["A07"],
    "integrity": ["A08"],
    "logging": ["A09"],
    "ssrf": ["A10"],
}


def finding_count_for_code(findings: list[dict], code: str) -> int:
    prefix = f"{code}:2025"
    return sum(1 for f in findings if str(f.get("owasp_category", "")).startswith(prefix))


def modules_exercising_code(selected_modules: list[str], code: str) -> list[str]:
    return sorted(m for m in selected_modules if code in SCANNER_TO_OWASP_CODES.get(m, []))


def was_category_tested(selected_modules: list[str], code: str) -> bool:
    return bool(modules_exercising_code(selected_modules, code))