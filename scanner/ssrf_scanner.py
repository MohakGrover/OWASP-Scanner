"""SSRF-style indicator checks (URL parameters that trigger backend fetch errors)."""

from __future__ import annotations

from urllib.parse import urlencode

from .base_scanner import BaseScanner
from utils.owasp_top10 import A10_SSRF
from utils.payloads import SSRF_SAFE_PAYLOADS
from utils.profiles import get_ssrf_targets


class SsrfScanner(BaseScanner):
    scanner_name = "ssrf"
    owasp_category = A10_SSRF

    def run(self) -> list[dict]:
        findings: list[dict] = []
        targets = get_ssrf_targets(self.context.profile)
        hit_keys: set[str] = set()

        for endpoint, param in targets:
            for payload in SSRF_SAFE_PAYLOADS:
                try:
                    url = f"{self.context.base_url.rstrip('/')}{endpoint}?{urlencode({param: payload})}"
                    self.log(f"[*] SSRF probe {endpoint} {param}=…")
                    resp = self.client.request("GET", url, cookies=self.context.cookies)
                    body = (resp.text or "").lower()
                    if any(
                        s in body
                        for s in (
                            "connection refused",
                            "timed out",
                            "could not resolve",
                            "failed to open stream",
                            "unable to connect",
                            "curl error",
                            "127.0.0.1",
                            "localhost",
                        )
                    ):
                        key = f"{endpoint}|{param}"
                        if key in hit_keys:
                            break
                        hit_keys.add(key)
                        findings.append(
                            self.finding(
                                vuln_id=f"VULN-A10-{abs(hash(key)) % 9000 + 100:04d}",
                                title="Possible Server-Side URL Fetch (SSRF-style)",
                                severity="HIGH",
                                cvss_score=8.3,
                                endpoint=endpoint,
                                method="GET",
                                parameter=param,
                                payload_used=payload,
                                evidence="Backend error or echo suggests server-side fetch of a user-supplied URL.",
                                description="The application may retrieve attacker-controlled URLs from the server network.",
                                impact="Access to internal services, metadata endpoints, or port scanning from server context.",
                                remediation="Strict allowlist destinations; block private IP ranges; disable redirects.",
                                references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
                                cwe_id="CWE-918",
                                remediation_steps=[
                                    "Parse and validate URL scheme/host against an allowlist.",
                                    "Block link-local and RFC1918 ranges at the egress layer.",
                                ],
                            )
                        )
                        break
                except Exception:
                    pass
        return findings
