"""Security headers scanner."""

from __future__ import annotations

from .base_scanner import BaseScanner
from utils.owasp_top10 import A05_SECURITY_MISCONFIGURATION


class HeadersScanner(BaseScanner):
    scanner_name = "headers"
    owasp_category = A05_SECURITY_MISCONFIGURATION

    REQUIRED_HEADERS = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
    ]

    def run(self) -> list[dict]:
        findings = []
        try:
            resp = self.client.request("GET", self.context.base_url, cookies=self.context.cookies)
            for header in self.REQUIRED_HEADERS:
                if header not in resp.headers:
                    findings.append(
                        self.finding(
                            vuln_id=f"VULN-A05-HDR-{header[:3].upper()}",
                            title=f"A05 Misconfiguration — Missing security header: {header}",
                            severity="MEDIUM",
                            cvss_score=5.0,
                            endpoint="/",
                            method="GET",
                            parameter="HTTP response header",
                            payload_used="header audit",
                            evidence=f"Header {header} not present in response.",
                            description="A recommended browser-side protection header is missing.",
                            impact="Reduced resilience against common browser exploitation vectors.",
                            remediation=f"Set {header} with environment-appropriate policy.",
                            references=["https://owasp.org/www-project-secure-headers/"],
                            cwe_id="CWE-693",
                        )
                    )
        except Exception:
            pass
        return findings
