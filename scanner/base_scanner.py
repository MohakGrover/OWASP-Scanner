"""Shared base scanner functionality."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from utils.helpers import utc_now_iso
from utils.http_client import HttpClient
from utils.owasp_top10 import A00_UNCLASSIFIED


from utils.screenshot_capture import ScreenshotCapture


@dataclass
class ScanContext:
    base_url: str
    verbose: bool = False
    cookies: dict[str, str] = field(default_factory=dict)
    ignore_robots: bool = False
    """ecommerce = generic shop paths; dvwa = DVWA/php paths (Docker lab)."""
    profile: str = "ecommerce"
    screenshot_capture: ScreenshotCapture | None = None


class BaseScanner:
    scanner_name = "base"
    owasp_category = A00_UNCLASSIFIED

    def __init__(self, context: ScanContext, client: HttpClient):
        self.context = context
        self.client = client

    def log(self, message: str) -> None:
        if self.context.verbose:
            print(message)

    def finding(
        self,
        *,
        vuln_id: str,
        title: str,
        severity: str,
        cvss_score: float,
        endpoint: str,
        method: str,
        parameter: str,
        payload_used: str,
        evidence: str,
        description: str,
        impact: str,
        remediation: str,
        references: list[str],
        cwe_id: str,
        remediation_steps: list[str] | None = None,
        code_example: str | None = None,
        approaches_tried: list[str] | None = None,
        response_snippet: str | None = None,
        related_cwe_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        row: dict[str, Any] = {
            "id": vuln_id,
            "owasp_category": self.owasp_category,
            "title": title,
            "severity": severity,
            "cvss_score": cvss_score,
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "payload_used": payload_used,
            "evidence": evidence,
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "references": references,
            "cwe_id": cwe_id,
            "detected_at": utc_now_iso(),
        }
        if remediation_steps:
            row["remediation_steps"] = remediation_steps
        if code_example:
            row["code_example"] = code_example
        if approaches_tried:
            row["approaches_tried"] = approaches_tried
        if response_snippet:
            row["response_snippet"] = response_snippet
        if related_cwe_ids:
            row["related_cwe_ids"] = related_cwe_ids

        # Capture exploitation proof screenshot if enabled
        if self.context.screenshot_capture:
            full_url = f"{self.context.base_url.rstrip('/')}{endpoint}"
            if parameter:
                full_url = f"{full_url}?{parameter}={payload_used}" if payload_used else full_url

            screenshot = self.context.screenshot_capture.capture_request_response(
                finding_id=vuln_id,
                url=full_url,
                method=method,
                payload=payload_used,
                response_text=response_snippet,
                attack_type=self.owasp_category,
                description=f"{title}: {description[:200]}",
            )
            row["screenshot_path"] = screenshot.image_path

        return row

    def run(self) -> list[dict[str, Any]]:
        return []

    @property
    def is_https(self) -> bool:
        return urlparse(self.context.base_url).scheme.lower() == "https"
