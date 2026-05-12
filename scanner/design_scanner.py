"""Insecure design checks (anti-automation indicators)."""

from __future__ import annotations

from utils.helpers import extract_forms
from utils.owasp_top10 import A04_INSECURE_DESIGN
from utils.profiles import PROFILE_DVWA, get_login_paths
from .base_scanner import BaseScanner


class DesignScanner(BaseScanner):
    scanner_name = "design"
    owasp_category = A04_INSECURE_DESIGN

    def run(self) -> list[dict]:
        findings = []
        paths = list(dict.fromkeys(get_login_paths(self.context.profile) + ["/register", "/checkout"]))
        if self.context.profile == PROFILE_DVWA:
            paths += ["/register.php", "/vulnerabilities/csrf/"]
        for path in paths:
            try:
                resp = self.client.request("GET", self.context.base_url.rstrip("/") + path, cookies=self.context.cookies)
                body = (resp.text or "").lower()
                forms = extract_forms(resp.text or "")
                if forms and "captcha" not in body and "recaptcha" not in body:
                    findings.append(
                        self.finding(
                            vuln_id=f"VULN-A04-{abs(hash(path)) % 9000 + 100:04d}",
                            title="No CAPTCHA or Bot Challenge Detected",
                            severity="MEDIUM",
                            cvss_score=5.4,
                            endpoint=path,
                            method="GET",
                            parameter="-",
                            payload_used="form analysis",
                            evidence=f"Form found with no CAPTCHA markers on {path}",
                            description="High-risk workflows are missing anti-automation controls.",
                            impact="Automated abuse and credential stuffing risk increases.",
                            remediation="Introduce CAPTCHA/risk-based challenge and lockout logic.",
                            references=["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
                            cwe_id="CWE-799",
                        )
                    )
            except Exception:
                pass
        return findings
