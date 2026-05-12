"""Logging and monitoring weakness checks."""

from __future__ import annotations

from .base_scanner import BaseScanner
from utils.owasp_top10 import A09_LOGGING_MONITORING
from utils.profiles import PROFILE_DVWA, get_login_paths


class LoggingScanner(BaseScanner):
    scanner_name = "logging"
    owasp_category = A09_LOGGING_MONITORING

    def run(self) -> list[dict]:
        findings: list[dict] = []
        paths = get_login_paths(self.context.profile)
        if not paths:
            return findings
        url = self.context.base_url.rstrip("/") + paths[0]
        profile = self.context.profile
        try:
            responses: list[tuple[int, int]] = []
            for _ in range(4):
                form = {"username": "x", "password": "y"}
                if profile == PROFILE_DVWA:
                    form["Login"] = "Login"
                resp = self.client.request("POST", url, data=form, cookies=self.context.cookies, allow_redirects=True)
                responses.append((resp.status_code, len(resp.text or "")))
            if len(set(responses)) == 1:
                findings.append(
                    self.finding(
                        vuln_id="VULN-A09-001",
                        title="No Observable Response Change on Repeated Failed Logins",
                        severity="MEDIUM",
                        cvss_score=5.9,
                        endpoint=paths[0],
                        method="POST",
                        parameter="username/password",
                        payload_used="repeated invalid credentials",
                        evidence=f"Uniform responses across attempts: {responses}",
                        description="Application may lack effective security event response signals.",
                        impact="Brute force attacks remain less detectable and stoppable.",
                        remediation="Implement event monitoring, lockout, and alerting policies.",
                        references=["https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"],
                        cwe_id="CWE-778",
                        remediation_steps=[
                            "Log failed auth with IP, user-agent, and correlation id.",
                            "Alert on velocity thresholds for failed logins.",
                        ],
                    )
                )
        except Exception:
            pass
        return findings
