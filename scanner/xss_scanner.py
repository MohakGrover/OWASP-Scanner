"""Reflected XSS (injection) indicators — safe string reflection only."""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import quote, urlencode, urlparse, urlunparse

from .base_scanner import BaseScanner
from utils.owasp_top10 import A03_INJECTION
from utils.profiles import get_xss_targets


class XssScanner(BaseScanner):
    scanner_name = "xss"
    owasp_category = A03_INJECTION

    def _variants(self) -> list[tuple[str, str]]:
        marker = "OWASPReflectedMarker9z7y"
        return [
            ("plain_marker", marker),
            ("url_encoded_marker", quote(marker, safe="")),
            ("attr_context_break", marker + '">'),
            ("html_context_break", "<b>" + marker + "</b>"),
        ]

    def _request(self, path: str, method: str, param: str, payload: str):
        base = self.context.base_url.rstrip("/")
        full = base + path
        if method.upper() == "GET":
            parsed = urlparse(full)
            query = urlencode({param: payload})
            url = urlunparse(parsed._replace(query=query))
            return self.client.request("GET", url, cookies=self.context.cookies)
        return self.client.request(
            "POST",
            full,
            data={param: payload},
            cookies=self.context.cookies,
            allow_redirects=True,
        )

    def run(self) -> list[dict]:
        findings: list[dict] = []
        hits: dict[tuple[str, str, str], list[tuple[str, str]]] = defaultdict(list)
        core = "OWASPReflectedMarker9z7y"

        for path, method, param in get_xss_targets(self.context.profile):
            for label, payload in self._variants():
                self.log(f"[*] XSS reflection [{label}] {method} {path}?{param}=…")
                try:
                    resp = self._request(path, method, param, payload)
                    body = resp.text or ""
                    if core in body or payload in body:
                        self.log(f"[+] XSS reflection: {path} ({label})")
                        hits[(path, method, param)].append((label, payload[:80]))
                except Exception as exc:
                    self.log(f"[!] XSS probe failed {path}: {exc}")

        for idx, ((path, method, param), rows) in enumerate(hits.items(), start=1):
            labels = [r[0] for r in rows]
            findings.append(
                self.finding(
                    vuln_id=f"VULN-A03-XSS-{idx:03d}",
                    title="Reflected Input (Potential XSS / HTML Injection)",
                    severity="HIGH",
                    cvss_score=7.2,
                    endpoint=path,
                    method=method,
                    parameter=param,
                    payload_used=rows[0][1],
                    evidence=(
                        f"Probe string reappeared in HTTP response without apparent encoding. "
                        f"Approaches: {', '.join(labels)}."
                    ),
                    description="User-controlled input may be reflected into HTML, enabling script or markup injection.",
                    impact="Session theft, defacement, or phishing via executed scripts in victim browsers.",
                    remediation="Context-aware encoding (HTML/JS/URL), CSP, and template auto-escaping.",
                    references=[
                        "https://owasp.org/Top10/A03_2021-Injection/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ],
                    cwe_id="CWE-79",
                    remediation_steps=[
                        "Encode output per sink (HTML body, attribute, JS, URL).",
                        "Adopt a strict Content-Security-Policy as defense-in-depth.",
                        "Use framework default auto-escaping for all dynamic content.",
                    ],
                    approaches_tried=labels,
                )
            )
        return findings
