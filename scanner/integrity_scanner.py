"""Software and data integrity failure checks."""

from __future__ import annotations

from bs4 import BeautifulSoup

from .base_scanner import BaseScanner
from utils.owasp_top10 import A08_SOFTWARE_DATA_INTEGRITY


class IntegrityScanner(BaseScanner):
    scanner_name = "integrity"
    owasp_category = A08_SOFTWARE_DATA_INTEGRITY

    def run(self) -> list[dict]:
        findings = []
        try:
            resp = self.client.request("GET", self.context.base_url, cookies=self.context.cookies)
            soup = BeautifulSoup(resp.text or "", "lxml")
            scripts = soup.find_all("script", src=True)
            for script in scripts:
                src = script.get("src", "")
                if src.startswith("http") and any(cdn in src for cdn in ("cdn", "jsdelivr", "unpkg")):
                    if not script.get("integrity"):
                        findings.append(
                            self.finding(
                                vuln_id="VULN-A08-001",
                                title="External Script Missing SRI",
                                severity="MEDIUM",
                                cvss_score=6.2,
                                endpoint="/",
                                method="GET",
                                parameter="script[src]",
                                payload_used=src,
                                evidence=f"CDN script has no integrity hash: {src}",
                                description="Third-party script integrity is not pinned.",
                                impact="Supply chain tampering risk.",
                                remediation="Add Subresource Integrity hashes and crossorigin policy.",
                                references=["https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"],
                                cwe_id="CWE-353",
                            )
                        )
                        break
        except Exception:
            pass
        return findings
