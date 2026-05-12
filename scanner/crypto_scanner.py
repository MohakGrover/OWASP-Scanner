"""Cryptographic failures and transport checks."""

from __future__ import annotations

from urllib.parse import urlparse

from .base_scanner import BaseScanner
from utils.owasp_top10 import A02_CRYPTOGRAPHIC_FAILURES
from utils.payloads import SENSITIVE_URL_PATTERNS
from utils.profiles import get_login_paths


class CryptoScanner(BaseScanner):
    scanner_name = "crypto"
    owasp_category = A02_CRYPTOGRAPHIC_FAILURES

    def run(self) -> list[dict]:
        findings = []
        base = self.context.base_url.rstrip("/")
        pages = list(dict.fromkeys(get_login_paths(self.context.profile) + ["/checkout", "/cart"]))

        if not self.is_https:
            findings.append(
                self.finding(
                    vuln_id="VULN-A02-001",
                    title="Insecure Transport for Sensitive Pages",
                    severity="HIGH",
                    cvss_score=8.2,
                    endpoint="/",
                    method="GET",
                    parameter="scheme",
                    payload_used=urlparse(base).scheme,
                    evidence="Base URL uses HTTP.",
                    description="Sensitive actions should always use encrypted transport.",
                    impact="Exposure of credentials and session tokens.",
                    remediation="Redirect HTTP to HTTPS and enable HSTS.",
                    references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
                    cwe_id="CWE-319",
                )
            )

        for path in pages:
            full = base + path
            if any(marker in full.lower() for marker in SENSITIVE_URL_PATTERNS):
                findings.append(
                    self.finding(
                        vuln_id="VULN-A02-002",
                        title="Sensitive Data in URL Pattern",
                        severity="MEDIUM",
                        cvss_score=6.0,
                        endpoint=path,
                        method="GET",
                        parameter="query string",
                        payload_used="URL inspection",
                        evidence=f"Sensitive marker discovered in URL: {full}",
                        description="Sensitive values in URLs may leak via logs and referers.",
                        impact="Potential disclosure of private information.",
                        remediation="Move sensitive fields to POST body and avoid logging them.",
                        references=["https://cwe.mitre.org/data/definitions/598.html"],
                        cwe_id="CWE-598",
                    )
                )
        return findings
