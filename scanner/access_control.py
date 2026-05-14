"""Broken access control checks - A01:2025 OWASP Top 10.

CWE References:
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
- CWE-23: Relative Path Traversal
- CWE-36: Absolute Path Traversal
- CWE-59: Improper Link Resolution Before File Access (Link Following)
- CWE-61: UNIX Symbolic Link (Symlink) Following
- CWE-65: Windows Hard Link
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CWE-201: Exposure of Sensitive Information Through Sent Data
- CWE-219: Storage of File with Sensitive Data Under Web Root
- CWE-276: Incorrect Default Permissions
- CWE-281: Improper Preservation of Permissions
- CWE-282: Improper Ownership Management
- CWE-283: Unverified Ownership
- CWE-284: Improper Access Control
- CWE-285: Improper Authorization
- CWE-352: Cross-Site Request Forgery (CSRF)
- CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- CWE-377: Insecure Temporary File
- CWE-379: Creation of Temporary File in Directory with Insecure Permissions
- CWE-402: Transmission of Private Resources into a New Sphere (Resource Leak)
- CWE-424: Improper Protection of Alternate Path
- CWE-425: Direct Request (Forced Browsing)
- CWE-441: Unintended Proxy or Intermediary (Confused Deputy)
- CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory
- CWE-540: Inclusion of Sensitive Information in Source Code
- CWE-548: Exposure of Information Through Directory Listing
- CWE-552: Files or Directories Accessible to External Parties
- CWE-566: Authorization Bypass Through User-Controlled SQL Primary Key
- CWE-601: URL Redirection to Untrusted Site (Open Redirect)
- CWE-615: Inclusion of Sensitive Information in Source Code Comments
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-668: Exposure of Resource to Wrong Sphere
- CWE-732: Incorrect Permission Assignment for Critical Resource
- CWE-749: Exposed Dangerous Method or Function
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-922: Insecure Storage of Sensitive Information
- CWE-1275: Sensitive Cookie with Improper SameSite Attribute
"""

from __future__ import annotations

import base64
import json
import re

from .base_scanner import BaseScanner
from utils.owasp_top10 import A01_BROKEN_ACCESS_CONTROL
from utils.payloads import TRAVERSAL_PAYLOADS
from utils.profiles import get_restricted_paths


class AccessControlScanner(BaseScanner):
    scanner_name = "access"
    owasp_category = A01_BROKEN_ACCESS_CONTROL

    def run(self) -> list[dict]:
        findings: list[dict] = []

        # 1. Check for sensitive endpoints accessible without authentication
        findings.extend(self._check_unauthenticated_access())

        # 2. Check for directory traversal / LFI
        findings.extend(self._check_directory_traversal())

        # 3. Check for Insecure Direct Object References (IDOR)
        findings.extend(self._check_idor())

        # 4. Check for CORS misconfiguration
        findings.extend(self._check_cors_misconfiguration())

        # 5. Check for force browsing to authenticated pages
        findings.extend(self._check_force_browsing())

        # 6. Check for missing API access controls (POST/PUT/DELETE)
        findings.extend(self._check_api_access_controls())

        # 7. Check for privilege escalation via parameter manipulation
        findings.extend(self._check_privilege_escalation())

        # 8. Check for JWT vulnerabilities
        findings.extend(self._check_jwt_vulnerabilities())

        # 9. Check for insecure session handling
        findings.extend(self._check_session_security())

        # 10. Check for open redirect vulnerabilities
        findings.extend(self._check_open_redirect())

        # 11. Check for directory listing exposure
        findings.extend(self._check_directory_listing())

        return findings

    def _check_unauthenticated_access(self) -> list[dict]:
        """Check if sensitive endpoints are accessible without authentication."""
        findings: list[dict] = []
        for path in get_restricted_paths(self.context.profile):
            try:
                resp = self.client.request("GET", self.context.base_url.rstrip("/") + path, cookies=self.context.cookies)
                if resp.status_code == 200 and len(resp.text or "") > 50:
                    uid = abs(hash(path)) % 9000 + 100
                    findings.append(
                        self.finding(
                            vuln_id=f"VULN-A01-{uid:04d}",
                            title="Sensitive Endpoint Accessible Without Strong Auth",
                            severity="HIGH",
                            cvss_score=8.1,
                            endpoint=path,
                            method="GET",
                            parameter="-",
                            payload_used="unauthenticated GET",
                            evidence=f"HTTP 200 with substantive body ({len(resp.text or '')} bytes) on {path}",
                            description="A potentially privileged or dangerous module responded while unauthenticated. Violation of least privilege - access should be denied by default.",
                            impact="Unauthorized access to administrative or dangerous functionality. Users can act outside their intended permissions.",
                            remediation="Deny by default. Implement access control mechanisms server-side and enforce authentication on every sensitive route.",
                            references=["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                            cwe_id="CWE-284",
                            remediation_steps=[
                                "Deny-by-default for admin modules; require role checks server-side.",
                                "Remove setup/install endpoints from production builds.",
                                "Implement least privilege - only grant access for specific capabilities/roles.",
                            ],
                            related_cwe_ids=["CWE-862", "CWE-863", "CWE-732", "CWE-276"],
                        )
                    )
            except Exception:
                pass
        return findings

    def _check_directory_traversal(self) -> list[dict]:
        """Check for directory traversal / LFI vulnerabilities."""
        findings: list[dict] = []
        for payload in TRAVERSAL_PAYLOADS:
            path = f"/download?file={payload}"
            try:
                resp = self.client.request("GET", self.context.base_url.rstrip("/") + path, cookies=self.context.cookies)
                if "root:" in (resp.text or "") or "[extensions]" in (resp.text or "").lower():
                    findings.append(
                        self.finding(
                            vuln_id="VULN-A01-LFI",
                            title="Directory Traversal / LFI Indicator",
                            severity="HIGH",
                            cvss_score=8.6,
                            endpoint="/download",
                            method="GET",
                            parameter="file",
                            payload_used=payload,
                            evidence="Response includes file content signatures.",
                            description="Path traversal input may allow access to system files outside the intended directory.",
                            impact="Sensitive server file disclosure - attackers can read configuration files, credentials, or source code.",
                            remediation="Use strict allowlists, canonical path checks, and validate input before file operations.",
                            references=[
                                "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
                                "https://cwe.mitre.org/data/definitions/22.html",
                            ],
                            cwe_id="CWE-22",
                            related_cwe_ids=["CWE-23", "CWE-36", "CWE-59", "CWE-61", "CWE-65", "CWE-424", "CWE-219", "CWE-538"],
                        )
                    )
            except Exception:
                pass
        return findings

    def _check_idor(self) -> list[dict]:
        """Check for Insecure Direct Object References (IDOR)."""
        findings: list[dict] = []

        # IDOR test patterns - modify object identifiers to access other users' data
        idor_paths = [
            ("/user/profile", "GET", "user_id", ["1", "2", "123", "admin"]),
            ("/account", "GET", "id", ["1", "2", "0"]),
            ("/orders", "GET", "order_id", ["1", "2", "100"]),
            ("/api/user", "GET", "id", ["1", "2"]),
            ("/api/orders", "GET", "orderId", ["1", "2"]),
            ("/profile", "GET", "uid", ["1", "2", "admin"]),
            ("/dashboard", "GET", "user", ["1", "2", "admin"]),
            ("/my-account", "GET", "account_id", ["1", "2"]),
        ]

        for path, method, param, test_values in idor_paths:
            for test_value in test_values:
                try:
                    url = f"{self.context.base_url.rstrip('/')}{path}?{param}={test_value}"
                    resp = self.client.request(method, url, cookies=self.context.cookies)

                    # Check if we got access to another user's data
                    if resp.status_code == 200:
                        text_lower = (resp.text or "").lower()
                        idor_indicators = [
                            "email", "password", "address", "phone", "credit card",
                            "order history", "account details", "profile", "settings"
                        ]

                        if any(indicator in text_lower for indicator in idor_indicators):
                            findings.append(
                                self.finding(
                                    vuln_id="VULN-A01-IDOR",
                                    title="Insecure Direct Object Reference (IDOR)",
                                    severity="HIGH",
                                    cvss_score=7.5,
                                    endpoint=path,
                                    method=method,
                                    parameter=param,
                                    payload_used=f"{param}={test_value}",
                                    evidence=f"HTTP 200 - able to access data by modifying {param} to {test_value}",
                                    description="The application allows users to access other users' accounts by providing their unique identifier (IDOR). Users can view or edit someone else's account by modifying object references.",
                                    impact="Unauthorized information disclosure - users can view or modify other users' sensitive data including orders, profiles, and personal information.",
                                    remediation="Implement proper access control checks that enforce record ownership. Verify the current user has permission before accessing any object.",
                                    references=[
                                        "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
                                        "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                                    ],
                                    cwe_id="CWE-639",
                                    remediation_steps=[
                                        "Implement object-level authorization checks.",
                                        "Use indirect references (mapping internal IDs to external).",
                                        "Verify ownership before allowing access to any resource.",
                                    ],
                                    related_cwe_ids=["CWE-566", "CWE-441", "CWE-283", "CWE-200", "CWE-359"],
                                )
                            )
                            break
                except Exception:
                    pass
        return findings

    def _check_cors_misconfiguration(self) -> list[dict]:
        """Check for CORS misconfiguration allowing unauthorized origins."""
        findings: list[dict] = []

        # Test endpoints that might expose API data
        api_paths = ["/api/", "/api/user", "/api/users", "/api/data", "/api/info"]

        # Malicious origins to test
        malicious_origins = [
            "http://evil.com",
            "http://attacker.com",
            "https://malicious-site.com",
            "null",  # null origin
        ]

        for path in api_paths:
            url = self.context.base_url.rstrip("/") + path
            for origin in malicious_origins:
                try:
                    resp = self.client.request(
                        "GET",
                        url,
                        cookies=self.context.cookies,
                        headers={"Origin": origin}
                    )

                    # Check if the malicious origin is reflected in the response
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                    # If wildcard or malicious origin is allowed
                    if acao == "*" or (origin in acao and acac == "true"):
                        findings.append(
                            self.finding(
                                vuln_id="VULN-A01-CORS",
                                title="CORS Misconfiguration Allows Untrusted Origins",
                                severity="MEDIUM",
                                cvss_score=6.5,
                                endpoint=path,
                                method="GET",
                                parameter="Origin header",
                                payload_used=origin,
                                evidence=f"Access-Control-Allow-Origin: {acao}, Allow-Credentials: {acac}",
                                description="CORS policy permits API access from untrusted or unauthorized origins. This allows malicious websites to make API requests on behalf of the user.",
                                impact="Attackers from untrusted origins can access sensitive API data with user's credentials. Cross-origin attacks can lead to data theft.",
                                remediation="Restrict CORS to specific trusted origins. Do not use wildcard (*) with credentials. Minimize CORS usage.",
                                references=[
                                    "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
                                    "https://portswigger.net/web-security/cors",
                                ],
                                cwe_id="CWE-346",
                                remediation_steps=[
                                    "Explicitly list allowed origins instead of using wildcards.",
                                    "Avoid using Access-Control-Allow-Credentials with wildcard origins.",
                                    "Implement CORS only where needed, minimize usage.",
                                ],
                                related_cwe_ids=["CWE-200", "CWE-497"],
                            )
                        )
                        break
                except Exception:
                    pass
        return findings

    def _check_force_browsing(self) -> list[dict]:
        """Check for force browsing - accessing authenticated pages without auth."""
        findings: list[dict] = []

        # Paths that typically require authentication
        protected_paths = [
            "/admin",
            "/admin/dashboard",
            "/admin/users",
            "/admin/settings",
            "/user/dashboard",
            "/user/settings",
            "/profile",
            "/account",
            "/orders",
            "/payment",
            "/billing",
            "/settings",
            "/dashboard",
            "/manage",
            "/control-panel",
        ]

        # Test without any cookies (unauthenticated)
        for path in protected_paths:
            try:
                url = self.context.base_url.rstrip("/") + path
                # Try without any session
                resp = self.client.request("GET", url, cookies={})

                # If we get a 200 with actual content (not a redirect to login)
                if resp.status_code == 200 and len(resp.text or "") > 100:
                    # Check if it's actually the protected page, not a login form
                    text_lower = (resp.text or "").lower()
                    if "login" not in text_lower and "sign in" not in text_lower:
                        findings.append(
                            self.finding(
                                vuln_id="VULN-A01-FORCE",
                                title="Force Browsing to Authenticated Pages",
                                severity="HIGH",
                                cvss_score=7.5,
                                endpoint=path,
                                method="GET",
                                parameter="-",
                                payload_used="no authentication",
                                evidence=f"HTTP 200 - protected page accessible without authentication",
                                description="The application allows unauthenticated users to access pages that should require authentication. This is force browsing - guessing URLs to access privileged pages.",
                                impact="Unauthorized access to privileged functionality. Standard users can access admin pages or authenticated areas.",
                                remediation="Implement server-side authentication checks on all protected routes. Deny by default.",
                                references=[
                                    "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
                                ],
                                cwe_id="CWE-285",
                                remediation_steps=[
                                    "Implement server-side authentication on every protected route.",
                                    "Deny access by default unless explicitly authorized.",
                                    "Use middleware or decorators to enforce auth checks.",
                                ],
                                related_cwe_ids=["CWE-425", "CWE-862", "CWE-863", "CWE-552"],
                            )
                        )
                        break
            except Exception:
                pass
        return findings

    def _check_api_access_controls(self) -> list[dict]:
        """Check for missing access controls on API endpoints (POST, PUT, DELETE)."""
        findings: list[dict] = []

        # API endpoints to test for missing authorization
        api_endpoints = [
            ("/api/users", "POST", {"username": "test", "email": "test@test.com"}),
            ("/api/user", "POST", {"name": "test"}),
            ("/api/products", "POST", {"name": "product"}),
            ("/api/orders", "POST", {"item": "test"}),
            ("/api/data", "POST", {"data": "test"}),
            ("/api/users/1", "PUT", {"name": "updated"}),
            ("/api/user/1", "PUT", {"email": "hacked@test.com"}),
            ("/api/products/1", "PUT", {"price": "0"}),
            ("/api/orders/1", "PUT", {"status": "shipped"}),
            ("/api/users/1", "DELETE", None),
            ("/api/user/1", "DELETE", None),
            ("/api/products/1", "DELETE", None),
            ("/api/orders/1", "DELETE", None),
        ]

        for path, method, data in api_endpoints:
            try:
                url = self.context.base_url.rstrip("/") + path

                # Try without authentication
                if method == "POST":
                    resp = self.client.request("POST", url, json=data, cookies={})
                elif method == "PUT":
                    resp = self.client.request("PUT", url, json=data or {}, cookies={})
                else:  # DELETE
                    resp = self.client.request("DELETE", url, cookies={})

                # If we get a successful response (2xx) without authentication
                if 200 <= resp.status_code < 300:
                    findings.append(
                        self.finding(
                            vuln_id="VULN-A01-API",
                            title="Missing Access Control on API Endpoint",
                            severity="HIGH",
                            cvss_score=8.1,
                            endpoint=path,
                            method=method,
                            parameter="-",
                            payload_used="no authentication",
                            evidence=f"HTTP {resp.status_code} - {method} request succeeded without authentication",
                            description="The API endpoint allows unauthenticated or unauthorized users to perform sensitive operations (POST/PUT/DELETE). Missing access control on API methods.",
                            impact="Unauthorized data modification or deletion. Attackers can create, modify, or delete any records.",
                            remediation="Implement authentication and authorization checks on all API endpoints. Enforce server-side access controls.",
                            references=[
                                "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
                            ],
                            cwe_id="CWE-306",
                            remediation_steps=[
                                "Require authentication for all API endpoints.",
                                "Implement role-based access control (RBAC).",
                                "Verify user permissions before any write operations.",
                            ],
                            related_cwe_ids=["CWE-862", "CWE-863", "CWE-284", "CWE-402", "CWE-668"],
                        )
                    )
            except Exception:
                pass
        return findings

    def _check_privilege_escalation(self) -> list[dict]:
        """Check for privilege escalation via parameter manipulation."""
        findings: list[dict] = []

        # Common parameter names used for privilege manipulation
        privilege_params = [
            ("role", "admin"),
            ("role", "administrator"),
            ("is_admin", "1"),
            ("is_admin", "true"),
            ("admin", "1"),
            ("admin", "true"),
            ("privilege", "admin"),
            ("access_level", "admin"),
            ("user_type", "admin"),
            ("auth_level", "admin"),
            ("is_root", "1"),
            ("is_superuser", "1"),
        ]

        # Paths that might be vulnerable to privilege escalation
        paths_to_test = [
            "/user/profile",
            "/profile",
            "/account",
            "/settings",
            "/api/user",
            "/api/profile",
            "/dashboard",
            "/admin",
        ]

        for path in paths_to_test:
            for param, value in privilege_params:
                try:
                    url = f"{self.context.base_url.rstrip('/')}{path}?{param}={value}"
                    resp = self.client.request("GET", url, cookies=self.context.cookies)

                    # Check if granting admin privileges worked
                    if resp.status_code == 200:
                        text_lower = (resp.text or "").lower()
                        admin_indicators = ["admin", "dashboard", "settings", "users", "manage"]

                        if any(indicator in text_lower for indicator in admin_indicators):
                            findings.append(
                                self.finding(
                                    vuln_id="VULN-A01-PRIV",
                                    title="Privilege Escalation via Parameter Manipulation",
                                    severity="CRITICAL",
                                    cvss_score=9.1,
                                    endpoint=path,
                                    method="GET",
                                    parameter=param,
                                    payload_used=f"{param}={value}",
                                    evidence=f"Access granted to elevated privileges via parameter manipulation",
                                    description="The application allows users to gain privileges beyond those expected. By manipulating parameters (role, admin, is_admin), a standard user can escalate to admin privileges.",
                                    impact="Full compromise of the application. Attackers can gain administrative access and perform any action.",
                                    remediation="Implement server-side role verification. Never trust client-provided role/privilege parameters.",
                                    references=[
                                        "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
                                    ],
                                    cwe_id="CWE-269",
                                    remediation_steps=[
                                        "Retrieve user roles from server-side session, not from request parameters.",
                                        "Implement proper authorization checks before granting privileges.",
                                        "Use declarative access controls rather than conditional logic.",
                                    ],
                                    related_cwe_ids=["CWE-284", "CWE-285", "CWE-732", "CWE-749"],
                                )
                            )
                            break
                except Exception:
                    pass
        return findings

    def _check_jwt_vulnerabilities(self) -> list[dict]:
        """Check for JWT token vulnerabilities."""
        findings: list[dict] = []

        # Check cookies for JWT tokens
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')

        # Look for JWT in cookies
        for cookie_name, cookie_value in self.context.cookies.items():
            if jwt_pattern.match(cookie_value):
                # Test JWT vulnerabilities
                findings.extend(self._test_jwt_vulnerabilities(cookie_name, cookie_value))

        # Also check response headers/set-cookie
        try:
            resp = self.client.request("GET", self.context.base_url.rstrip("/") + "/")
            set_cookie = resp.headers.get("Set-Cookie", "")
            if "jwt" in set_cookie.lower() or "token" in set_cookie.lower():
                # Try to decode from Set-Cookie
                match = jwt_pattern.search(set_cookie)
                if match:
                    findings.extend(self._test_jwt_vulnerabilities("Set-Cookie", match.group(0)))
        except Exception:
            pass

        return findings

    def _test_jwt_vulnerabilities(self, token_name: str, token: str) -> list[dict]:
        """Test specific JWT vulnerabilities."""
        findings: list[dict] = []

        try:
            parts = token.split('.')
            if len(parts) != 3:
                return findings

            # Check 1: JWT with 'none' algorithm
            try:
                import base64
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                if header.get("alg", "").lower() == "none":
                    findings.append(
                        self.finding(
                            vuln_id="VULN-A01-JWT-NONE",
                            title="JWT 'none' Algorithm Allowed",
                            severity="HIGH",
                            cvss_score=8.2,
                            endpoint="/",
                            method="GET",
                            parameter=token_name,
                            payload_used="alg:none",
                            evidence=f"JWT token uses 'none' algorithm - signature verification disabled",
                            description="The JWT token accepts the 'none' algorithm, meaning tokens are not cryptographically signed. Attackers can forge tokens.",
                            impact="Complete authentication bypass. Attackers can impersonate any user by creating unsigned tokens.",
                            remediation="Reject tokens with 'none' algorithm. Explicitly specify and verify the expected algorithm.",
                            references=[
                                "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
                                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                            ],
                            cwe_id="CWE-347",
                            related_cwe_ids=["CWE-613", "CWE-287"],
                        )
                    )
            except Exception:
                pass

            # Check 2: JWT without expiration (exp claim)
            try:
                import base64
                import json as json
                payload = base64.urlsafe_b64decode(parts[1] + '==')
                if b'"exp"' not in payload:
                    findings.append(
                        self.finding(
                            vuln_id="VULN-A01-JWT-EXP",
                            title="JWT Token Missing Expiration",
                            severity="MEDIUM",
                            cvss_score=6.5,
                            endpoint="/",
                            method="GET",
                            parameter=token_name,
                            payload_used="no exp claim",
                            evidence="JWT token has no 'exp' expiration claim",
                            description="JWT token does not have an expiration time. Tokens remain valid indefinitely.",
                            impact="Stolen tokens remain valid forever. No way to revoke compromised tokens.",
                            remediation="Always set expiration (exp) claim on JWTs. Use short-lived tokens with refresh tokens.",
                            references=[
                                "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
                            ],
                            cwe_id="CWE-613",
                            related_cwe_ids=["CWE-922", "CWE-377", "CWE-379"],
                        )
                    )
            except Exception:
                pass

        except Exception:
            pass

        return findings

    def _check_session_security(self) -> list[dict]:
        """Check for insecure session handling."""
        findings: list[dict] = []

        # Check if session cookies lack security flags
        try:
            resp = self.client.request("GET", self.context.base_url.rstrip("/") + "/")
            set_cookie = resp.headers.get("Set-Cookie", "")

            if set_cookie:
                missing_flags = []
                cookie_lower = set_cookie.lower()

                if "httponly" not in cookie_lower:
                    missing_flags.append("HttpOnly")
                if "secure" not in cookie_lower and self.is_https:
                    missing_flags.append("Secure")
                if "samesite" not in cookie_lower:
                    missing_flags.append("SameSite")

                if missing_flags:
                    findings.append(
                        self.finding(
                            vuln_id="VULN-A01-SESSION",
                            title="Insecure Session Cookie Configuration",
                            severity="MEDIUM",
                            cvss_score=6.5,
                            endpoint="/",
                            method="GET",
                            parameter="Set-Cookie",
                            payload_used=f"Missing: {', '.join(missing_flags)}",
                            evidence=f"Session cookie missing security flags: {', '.join(missing_flags)}",
                            description="Session cookies are not properly secured with HttpOnly, Secure, and SameSite flags.",
                            impact="Session cookies can be stolen via XSS (if HttpOnly missing), transmitted over HTTP (if Secure missing), or used in cross-site requests (if SameSite missing).",
                            remediation="Set HttpOnly, Secure, and SameSite attributes on session cookies. Invalidate sessions on server after logout.",
                            references=[
                                "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
                            ],
                            cwe_id="CWE-614",
                            remediation_steps=[
                                "Set HttpOnly flag to prevent XSS-based cookie theft.",
                                "Set Secure flag to ensure cookies only sent over HTTPS.",
                                "Set SameSite attribute to prevent CSRF.",
                                "Implement server-side session invalidation on logout.",
                            ],
                            related_cwe_ids=["CWE-1275", "CWE-352", "CWE-281", "CWE-276"],
                        )
                    )
        except Exception:
            pass

        return findings

    def _check_open_redirect(self) -> list[dict]:
        """Check for open redirect vulnerabilities (CWE-601)."""
        findings: list[dict] = []

        # Common redirect parameters
        redirect_params = [
            "url", "next", "redirect", "return", "return_url",
            "dest", "destination", "continue", "callback", "redir",
            "origin", "redirect_url", "redirect_uri", "target"
        ]

        # Test values that indicate open redirect
        redirect_test_values = [
            "http://evil.com",
            "https://attacker.com",
            "//attacker.com",
        ]

        paths_to_test = [
            "/login", "/signin", "/account", "/redirect", "/go",
            "/auth", "/oauth", "/callback", "/verify", "/validate"
        ]

        for path in paths_to_test[:5]:
            for param in redirect_params[:5]:
                for test_value in redirect_test_values:
                    try:
                        url = f"{self.context.base_url.rstrip('/')}{path}?{param}={test_value}"
                        resp = self.client.request("GET", url, allow_redirects=False, cookies=self.context.cookies)

                        # Check if we get a redirect to an external/untrusted site
                        if resp.status_code in [301, 302, 303, 307, 308]:
                            location = resp.headers.get("Location", "")
                            if location.startswith("http") and ("evil.com" in location or "attacker.com" in location):
                                findings.append(
                                    self.finding(
                                        vuln_id="VULN-A01-REDIRECT",
                                        title="URL Redirection to Untrusted Site (Open Redirect)",
                                        severity="MEDIUM",
                                        cvss_score=6.5,
                                        endpoint=path,
                                        method="GET",
                                        parameter=param,
                                        payload_used=test_value,
                                        evidence=f"Redirect to: {location}",
                                        description="The application redirects users to external or untrusted URLs based on user input. Attackers can craft malicious URLs tophish users or bypass security controls.",
                                        impact="Users may be redirected to malicious sites leading to phishing attacks or credential theft. Attackers can exploit trust in the legitimate site.",
                                        remediation="Validate and sanitize all redirect destinations. Use an allowlist of permitted URLs. Avoid user-controlled redirect parameters.",
                                        references=[
                                            "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
                                        ],
                                        cwe_id="CWE-601",
                                        related_cwe_ids=["CWE-200", "CWE-441", "CWE-668"],
                                    )
                                )
                                break
                    except Exception:
                        pass
        return findings

    def _check_directory_listing(self) -> list[dict]:
        """Check for directory listing exposure (CWE-548)."""
        findings: list[dict] = []

        # Common directories that might have listing enabled
        directory_paths = [
            "/images", "/assets", "/uploads", "/files", "/docs",
            "/static", "/media", "/public", "/content", "/data",
            "/backup", "/backups", "/logs", "/temp", "/tmp",
            "/api/docs", "/swagger", "/admin/uploads", "/uploads/images",
        ]

        for path in directory_paths:
            try:
                url = self.context.base_url.rstrip("/") + path
                resp = self.client.request("GET", url, cookies=self.context.cookies)

                if resp.status_code == 200:
                    text_lower = (resp.text or "").lower()

                    # Check for directory listing indicators
                    listing_indicators = [
                        "index of", "directory listing", "parent directory",
                        "last modified", "name", "size",
                        "[ to parent", "directory of",
                    ]

                    if any(indicator in text_lower for indicator in listing_indicators):
                        findings.append(
                            self.finding(
                                vuln_id="VULN-A01-DIRLIST",
                                title="Directory Listing Enabled (Information Exposure)",
                                severity="MEDIUM",
                                cvss_score=5.3,
                                endpoint=path,
                                method="GET",
                                parameter="-",
                                payload_used="no payload",
                                evidence=f"HTTP 200 - Directory listing detected with file index",
                                description="The application exposes a directory listing, revealing files and folders that should not be publicly accessible.",
                                impact="Exposure of sensitive files, backup files, configuration files, source code, or internal documentation. Attackers gather information for further attacks.",
                                remediation="Disable directory listing on web servers. Ensure proper file access controls. Remove backup files and sensitive data from web roots.",
                                references=[
                                    "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
                                ],
                                cwe_id="CWE-548",
                                related_cwe_ids=["CWE-552", "CWE-219", "CWE-538", "CWE-497"],
                            )
                        )
                        break
            except Exception:
                pass
        return findings