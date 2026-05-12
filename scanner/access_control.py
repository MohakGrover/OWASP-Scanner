"""Broken access control checks."""

from __future__ import annotations

from .base_scanner import BaseScanner
from utils.owasp_top10 import A01_BROKEN_ACCESS_CONTROL
from utils.payloads import TRAVERSAL_PAYLOADS
from utils.profiles import get_restricted_paths


class AccessControlScanner(BaseScanner):
    scanner_name = "access"
    owasp_category = A01_BROKEN_ACCESS_CONTROL

    def run(self) -> list[dict]:
        findings: list[dict] = []
        for path in get_restricted_paths(self.context.profile):
            try:
                resp = self.client.request("GET", self.context.base_url.rstrip("/") + path, cookies=self.context.cookies)
                if resp.status_code == 200 and len(resp.text or "") > 50:
                    uid = abs(hash(path)) % 9000 + 100
                    findings.append(
                        self.finding(
                            vuln_id=f"VULN-A01-{uid:04d}",
                            title="Sensitive Endpoint Accessible Without Strong Auth",
                            severity="HIGH",
                            cvss_score=8.1,
                            endpoint=path,
                            method="GET",
                            parameter="-",
                            payload_used="unauthenticated GET",
                            evidence=f"HTTP 200 with substantive body ({len(resp.text or '')} bytes) on {path}",
                            description="A potentially privileged or dangerous module responded while unauthenticated.",
                            impact="Unauthorized access to administrative or dangerous functionality.",
                            remediation="Enforce authentication and server-side authorization on every sensitive route.",
                            references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                            cwe_id="CWE-284",
                            remediation_steps=[
                                "Deny-by-default for admin modules; require role checks server-side.",
                                "Remove setup/install endpoints from production builds.",
                            ],
                        )
                    )
            except Exception:
                pass

        for payload in TRAVERSAL_PAYLOADS:
            path = f"/download?file={payload}"
            try:
                resp = self.client.request("GET", self.context.base_url.rstrip("/") + path, cookies=self.context.cookies)
                if "root:" in (resp.text or "") or "[extensions]" in (resp.text or "").lower():
                    findings.append(
                        self.finding(
                            vuln_id="VULN-A01-LFI",
                            title="Directory Traversal / LFI Indicator",
                            severity="HIGH",
                            cvss_score=8.6,
                            endpoint="/download",
                            method="GET",
                            parameter="file",
                            payload_used=payload,
                            evidence="Response includes file content signatures.",
                            description="Path traversal input may access system files.",
                            impact="Sensitive server file disclosure.",
                            remediation="Use strict allowlists and canonical path checks.",
                            references=["https://cwe.mitre.org/data/definitions/22.html"],
                            cwe_id="CWE-22",
                        )
                    )
            except Exception:
                pass
        return findings
