"""Outdated components indicator checks."""

from __future__ import annotations

from .base_scanner import BaseScanner
from utils.owasp_top10 import A06_VULNERABLE_COMPONENTS


class ComponentsScanner(BaseScanner):
    scanner_name = "components"
    owasp_category = A06_VULNERABLE_COMPONENTS

    def run(self) -> list[dict]:
        findings = []
        try:
            resp = self.client.request("GET", self.context.base_url, cookies=self.context.cookies)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            for hk in ("server", "x-powered-by"):
                if hk in headers and any(x in headers[hk].lower() for x in ["php/5", "apache/2.2", "nginx/1.10"]):
                    findings.append(
                        self.finding(
                            vuln_id="VULN-A06-001",
                            title="Potentially Outdated Server Component",
                            severity="HIGH",
                            cvss_score=7.8,
                            endpoint="/",
                            method="GET",
                            parameter=hk,
                            payload_used=headers[hk],
                            evidence=f"Version-looking server header: {hk}={headers[hk]}",
                            description="Exposed old component version indicator.",
                            impact="Known vulnerabilities may be exploitable.",
                            remediation="Patch server/runtime and minimize version disclosure.",
                            references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
                            cwe_id="CWE-1104",
                        )
                    )
        except Exception:
            pass
        return findings
