"""Deep crawling and endpoint discovery module."""

from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .base_scanner import BaseScanner
from utils.owasp_top10 import A01_BROKEN_ACCESS_CONTROL
from utils.http_client import HttpClient
from dataclasses import dataclass, field
from typing import Set


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered endpoint."""
    url: str
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    form_fields: dict[str, str] = field(default_factory=dict)
    is_auth_required: bool = False
    content_type: str = ""


class CrawlerScanner(BaseScanner):
    """Deep crawler for comprehensive endpoint discovery."""
    scanner_name = "crawler"
    owasp_category = A01_BROKEN_ACCESS_CONTROL

    def __init__(self, context, client: HttpClient):
        super().__init__(context, client)
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: list[DiscoveredEndpoint] = []
        self.base_domain = urlparse(self.context.base_url).netloc

    def run(self) -> list[dict]:
        """Run deep crawling to discover all endpoints."""
        findings: list[dict] = []

        self.log("[*] Starting deep crawling...")

        # Initial queue with target URL
        to_visit = deque([self.context.base_url])
        max_depth = 3
        max_urls = 200

        while to_visit and len(self.visited_urls) < max_urls:
            url = to_visit.popleft()

            if url in self.visited_urls:
                continue

            self.visited_urls.add(url)
            self.log(f"[*] Crawling: {url}")

            try:
                resp = self.client.request("GET", url, cookies=self.context.cookies, allow_redirects=True)

                if resp.status_code != 200:
                    continue

                # Extract endpoints from response
                endpoints = self._extract_endpoints(url, resp.text, resp.headers.get("Content-Type", ""))
                self.discovered_endpoints.extend(endpoints)

                # Queue new URLs for crawling
                new_urls = self._extract_links(resp.text, url)
                for new_url in new_urls:
                    if new_url not in self.visited_urls and len(self.visited_urls) < max_urls:
                        # Check depth (simple heuristic)
                        if new_url.count('/') - self.context.base_url.count('/') <= max_depth:
                            to_visit.append(new_url)

            except Exception as e:
                self.log(f"[!] Crawl error {url}: {e}")
                continue

        self.log(f"[+] Crawling complete: {len(self.discovered_endpoints)} endpoints discovered")

        # Store discovered endpoints in context for other scanners to use
        self.context.discovered_endpoints = self.discovered_endpoints
        self.context.crawl_results = {
            "total_urls": len(self.visited_urls),
            "total_endpoints": len(self.discovered_endpoints),
            "unique_parameters": self._extract_unique_parameters()
        }

        return findings

    def _extract_endpoints(self, url: str, html: str, content_type: str) -> list[DiscoveredEndpoint]:
        """Extract endpoints from HTML response."""
        endpoints = []

        if "text/html" not in content_type:
            return endpoints

        soup = BeautifulSoup(html, "lxml")

        # Extract from <a> tags
        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(url, href)
            if self._is_internal_url(full_url):
                endpoints.append(DiscoveredEndpoint(url=full_url, method="GET"))

        # Extract from forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            form_url = urljoin(url, action)
            method = form.get("method", "get").upper()

            # Extract form fields
            form_fields = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    form_fields[name] = inp.get("type", "text")

            endpoints.append(DiscoveredEndpoint(
                url=form_url,
                method=method,
                form_fields=form_fields
            ))

        # Extract from JavaScript (basic)
        scripts = soup.find_all("script")
        js_urls = self._extract_js_urls(html)
        for js_url in js_urls:
            full_url = urljoin(url, js_url)
            if self._is_internal_url(full_url):
                endpoints.append(DiscoveredEndpoint(url=full_url, method="GET"))

        return endpoints

    def _extract_js_urls(self, html: str) -> list[str]:
        """Extract URLs from JavaScript code."""
        js_urls = []

        # Match fetch(), axios, $.ajax, fetch('/api/...')
        patterns = [
            r"fetch\s*\(\s*['\"]([^'\"]+)['\"]",
            r"axios\.[a-z]+\s*\(\s*['\"]([^'\"]+)['\"]",
            r"\.get\s*\(\s*['\"]([^'\"]+)['\"]",
            r"\.post\s*\(\s*['\"]([^'\"]+)['\"]",
            r"window\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"href\s*:\s*['\"]([^'\"]+)['\"]",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            js_urls.extend(matches)

        return js_urls

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract all links from HTML."""
        links = []
        soup = BeautifulSoup(html, "lxml")

        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(base_url, href)
            if self._is_internal_url(full_url):
                links.append(full_url)

        return links

    def _is_internal_url(self, url: str) -> bool:
        """Check if URL is internal to the target domain."""
        try:
            parsed = urlparse(url)
            # Allow same domain or relative paths
            if parsed.netloc and parsed.netloc != self.base_domain:
                # Allow same-domain paths
                if not parsed.netloc.startswith("www." + self.base_domain) and parsed.netloc != self.base_domain:
                    return False
            return True
        except Exception:
            return False

    def _extract_unique_parameters(self) -> list[str]:
        """Extract all unique parameters from discovered endpoints."""
        params = set()
        for ep in self.discovered_endpoints:
            params.update(ep.parameters)
            params.update(ep.form_fields.keys())
        return sorted(params)


class ContextAwareScanner(BaseScanner):
    """Context-aware scanner that understands application state and workflows."""
    scanner_name = "context"
    owasp_category = A01_BROKEN_ACCESS_CONTROL

    def run(self) -> list[dict]:
        """Run context-aware tests."""
        findings: list[dict] = []

        self.log("[*] Running context-aware tests...")

        # Check if crawler has run and has endpoints
        if not hasattr(self.context, 'discovered_endpoints'):
            self.log("[!] No crawl data available, skipping context-aware tests")
            return findings

        # Test stateful workflows
        findings.extend(self._test_stateful_workflows())

        # Test parameter pollution
        findings.extend(self._test_parameter_pollution())

        # Test HTTP verb tampering
        findings.extend(self._test_verb_tampering())

        return findings

    def _test_stateful_workflows(self) -> list[dict]:
        """Test for state-based access control issues."""
        findings = []

        # Try to access authenticated endpoints with different states
        endpoints = getattr(self.context, 'discovered_endpoints', [])

        auth_indicators = ["dashboard", "profile", "account", "settings", "admin", "user"]
        public_indicators = ["login", "register", "forgot", "public", "index"]

        for ep in endpoints:
            # Skip if already looks public
            if any(ind in ep.url.lower() for ind in public_indicators):
                continue

            # Check if looks like authenticated endpoint
            if any(ind in ep.url.lower() for ind in auth_indicators):
                # Try without auth
                try:
                    resp = self.client.request("GET", ep.url, cookies={})
                    if resp.status_code == 200:
                        text = (resp.text or "").lower()
                        if "login" not in text and "signin" not in text:
                            findings.append(
                                self.finding(
                                    vuln_id="VULN-A01-CTX-001",
                                    title="Authenticated Endpoint Accessible Without Session",
                                    severity="HIGH",
                                    cvss_score=7.5,
                                    endpoint=ep.url,
                                    method="GET",
                                    parameter="-",
                                    payload_used="no session cookies",
                                    evidence=f"HTTP 200 - authenticated page returned without session",
                                    description="Endpoint that typically requires authentication is accessible without a session.",
                                    impact="Unauthorized access to user-specific functionality.",
                                    remediation="Implement proper session-based authentication checks.",
                                    references=["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                                    cwe_id="CWE-285",
                                    related_cwe_ids=["CWE-862", "CWE-284"],
                                )
                            )
                except Exception:
                    pass

        return findings

    def _test_parameter_pollution(self) -> list[dict]:
        """Test for HTTP Parameter Pollution (HPP)."""
        findings = []

        endpoints = getattr(self.context, 'discovered_endpoints', [])

        for ep in endpoints[:10]:  # Limit to first 10
            if not ep.parameters and not ep.form_fields:
                continue

            params = list(ep.parameters) if ep.parameters else list(ep.form_fields.keys())
            if not params:
                continue

            param = params[0]
            test_value = "test1"
            polluted_value = f"{test_value}&{param}=test2"

            try:
                url = ep.url
                if "?" in url:
                    url += f"&{param}={test_value}"
                else:
                    url += f"?{param}={test_value}"

                resp = self.client.request(ep.method, url, cookies=self.context.cookies)

                # Check if application handles multiple parameters differently
                if resp.status_code == 200:
                    text = resp.text or ""
                    if "test1" in text and "test2" in text:
                        findings.append(
                            self.finding(
                                vuln_id="VULN-A01-CTX-002",
                                title="Potential HTTP Parameter Pollution",
                                severity="MEDIUM",
                                cvss_score=6.0,
                                endpoint=ep.url,
                                method=ep.method,
                                parameter=param,
                                payload_used=polluted_value,
                                evidence="Application appears to process multiple values for same parameter",
                                description="Application may be vulnerable to parameter pollution attacks.",
                                impact="May lead to bypassing validation or WAF, or unexpected behavior.",
                                remediation="Validate and sanitize all parameters consistently.",
                                references=["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                                cwe_id="CWE-235",
                            )
                        )
            except Exception:
                pass

        return findings

    def _test_verb_tampering(self) -> list[dict]:
        """Test for HTTP method tampering."""
        findings = []

        endpoints = getattr(self.context, 'discovered_endpoints', [])

        for ep in endpoints[:5]:
            if ep.method != "GET":
                continue

            # Try GET as POST
            try:
                resp = self.client.request("POST", ep.url, cookies=self.context.cookies, data={"test": "value"})

                if resp.status_code in [200, 405]:
                    findings.append(
                        self.finding(
                            vuln_id="VULN-A01-CTX-003",
                            title="HTTP Verb Tampering Possible",
                            severity="MEDIUM",
                            cvss_score=5.5,
                            endpoint=ep.url,
                            method="POST (on GET endpoint)",
                            parameter="-",
                            payload_used="verb tampering",
                            evidence=f"Endpoint responds to alternate HTTP method",
                            description="Application accepts HTTP methods different from expected.",
                            impact="May bypass security controls that rely on specific HTTP methods.",
                            remediation="Explicitly define and validate allowed HTTP methods.",
                            references=["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                            cwe_id="CWE-16",
                        )
                    )
            except Exception:
                pass

        return findings