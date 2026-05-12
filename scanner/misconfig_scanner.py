"""Security misconfiguration checks."""

from __future__ import annotations

from .base_scanner import BaseScanner
from utils.owasp_top10 import A05_SECURITY_MISCONFIGURATION
from utils.profiles import get_misconfig_probes


class MisconfigScanner(BaseScanner):
    scanner_name = "misconfig"
    owasp_category = A05_SECURITY_MISCONFIGURATION

    def run(self) -> list[dict]:
        findings: list[dict] = []
        for path in get_misconfig_probes(self.context.profile):
            try:
                resp = self.client.request("GET", self.context.base_url.rstrip("/") + path, cookies=self.context.cookies)
                if resp.status_code == 200 and len(resp.text or "") > 20:
                    uid = abs(hash(path)) % 9000 + 100
                    findings.append(
                        self.finding(
                            vuln_id=f"VULN-A05-{uid:04d}",
                            title="Sensitive or Debug Artifact Exposed",
                            severity="HIGH",
                            cvss_score=8.0,
                            endpoint=path,
                            method="GET",
                            parameter="-",
                            payload_used="direct GET",
                            evidence=f"HTTP 200 with body length {len(resp.text or '')} on {path}",
                            description="Configuration, docs, or debug endpoints may be world-readable.",
                            impact="Secrets, stack traces, or topology details may leak.",
                            remediation="Remove public access; relocate secrets; disable directory listing.",
                            references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                            cwe_id="CWE-16",
                            remediation_steps=[
                                "Block /setup.php and similar installers in production.",
                                "Store credentials outside the web root with strict permissions.",
                            ],
                        )
                    )
            except Exception:
                pass

        listing_paths = ["/uploads/", "/images/", "/static/", "/hackable/uploads/"]
        for path in listing_paths:
            try:
                resp = self.client.request("GET", self.context.base_url.rstrip("/") + path, cookies=self.context.cookies)
                body = (resp.text or "").lower()
                if "index of /" in body or "<title>directory listing" in body:
                    findings.append(
                        self.finding(
                            vuln_id="VULN-A05-DIR",
                            title="Directory Listing Enabled",
                            severity="MEDIUM",
                            cvss_score=5.8,
                            endpoint=path,
                            method="GET",
                            parameter="-",
                            payload_used="directory browse",
                            evidence=f"Directory listing signature found on {path}",
                            description="Directory indexing can expose file structures and assets.",
                            impact="Information disclosure aiding further attacks.",
                            remediation="Disable auto-indexing on web server.",
                            references=["https://cwe.mitre.org/data/definitions/548.html"],
                            cwe_id="CWE-548",
                        )
                    )
            except Exception:
                pass
        return findings
