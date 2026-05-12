"""SQL injection indicator checks using multiple safe bypass-style probes (lab use)."""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlencode, urlparse, urlunparse

from .base_scanner import BaseScanner
from utils.owasp_top10 import A03_INJECTION
from utils.payloads import SQL_ERROR_PATTERNS, SQLI_APPROACHES
from utils.profiles import get_sqli_targets


class SqliScanner(BaseScanner):
    scanner_name = "sqli"
    owasp_category = A03_INJECTION

    def _match_error(self, text: str) -> str | None:
        lower = (text or "").lower()
        return next((p for p in SQL_ERROR_PATTERNS if p in lower), None)

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
        hits: dict[tuple[str, str], list[tuple[str, str, str]]] = defaultdict(list)
        targets = get_sqli_targets(self.context.profile)

        for path, method, param in targets:
            for label, payload in SQLI_APPROACHES:
                self.log(f"[*] SQLi [{label}] {method} {path}?{param}=…")
                try:
                    resp = self._request(path, method, param, payload)
                    matched = self._match_error(resp.text or "")
                    if matched:
                        self.log(f"[+] FOUND: {path} — {label} — marker={matched}")
                        hits[(path, param)].append((label, payload, matched))
                except Exception as exc:
                    self.log(f"[!] SQLi probe failed {path} {label}: {exc}")

        for idx, ((path, param), rows) in enumerate(hits.items(), start=1):
            labels = [r[0] for r in rows]
            markers = sorted({r[2] for r in rows})
            payloads_preview = "; ".join(f"{r[0]}:{r[1][:40]}" for r in rows[:5])
            if len(rows) > 5:
                payloads_preview += f"; …(+{len(rows) - 5} more)"
            last_resp = None
            try:
                last_resp = self._request(path, method, param, rows[-1][1])
            except Exception:
                pass
            snippet = ""
            if last_resp and last_resp.text:
                snippet = (last_resp.text.replace("\r", "")[:280] + "…") if len(last_resp.text) > 280 else last_resp.text

            findings.append(
                self.finding(
                    vuln_id=f"VULN-A03-{idx:03d}",
                            title="A03 Injection — SQL Error / Syntax Disclosure (Indicators)",
                    severity="CRITICAL",
                    cvss_score=9.0,
                    endpoint=path,
                    method=method,
                    parameter=param,
                    payload_used=rows[0][1][:120] + ("…" if len(rows[0][1]) > 120 else ""),
                    evidence=(
                        f"Matched DB/SQL error signatures: {', '.join(markers)}. "
                        f"Successful probe approaches ({len(rows)}): {', '.join(labels)}. "
                        f"Sample payload map: {payloads_preview}"
                    ),
                    description=(
                        "The application returned SQL-layer error material when fed "
                        "multiple non-destructive injection-style probes (OR/UNION/comment evasion)."
                    ),
                    impact="Attackers can refine injections using error feedback; risk of data access or modification.",
                    remediation="Use parameterized queries/prepared statements; centralize input validation; generic errors.",
                    references=[
                        "https://owasp.org/Top10/A03_2021-Injection/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/89.html",
                    ],
                    cwe_id="CWE-89",
                    remediation_steps=[
                        "Replace dynamic SQL concatenation with bound parameters for every query.",
                        "Return generic errors to users; log detailed errors server-side only.",
                        "Add positive validation for identifiers (allowlists) where parameters cannot be bound.",
                        "Deploy a WAF only as a secondary control, not a substitute for secure code.",
                    ],
                    code_example=(
                        "# Example (Python): cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
                    ),
                    approaches_tried=labels,
                    response_snippet=snippet,
                )
            )
        return findings
