"""Identification and authentication weakness checks."""

from __future__ import annotations

import time

from .base_scanner import BaseScanner
from utils.owasp_top10 import A07_IDENTIFICATION_AUTH_FAILURES
from utils.payloads import DEFAULT_CREDENTIALS
from utils.profiles import PROFILE_DVWA, get_login_paths


def _login_failed(text: str) -> bool:
    t = (text or "").lower()
    needles = (
        "invalid",
        "incorrect",
        "login failed",
        "wrong password",
        "authentication failed",
        "try again",
        "bad credentials",
    )
    return any(n in t for n in needles)


def _login_success(resp, profile: str) -> bool:
    if _login_failed(resp.text or ""):
        return False
    loc = (resp.headers.get("Location") or "").lower()
    if resp.status_code == 302 and loc and "login" not in loc:
        return True
    body = (resp.text or "").lower()
    if "logout" in body and "password" not in body[:800]:
        return True
    if profile == PROFILE_DVWA and resp.status_code == 302 and "index.php" in loc:
        return True
    return False


def _extract_login_form(html: str) -> dict | None:
    """Extract hidden fields from login form for accurate testing."""
    import re
    form_data = {}
    # Find all input fields
    inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
    for inp in inputs:
        form_data[inp] = ""
    return form_data if form_data else None


class AuthScanner(BaseScanner):
    scanner_name = "auth"
    owasp_category = A07_IDENTIFICATION_AUTH_FAILURES

    def _test_login_bypass(self, login_url: str, profile: str) -> list[dict]:
        """Test for SQL injection login bypass vulnerabilities."""
        findings = []

        # Common SQL injection payloads for login bypass
        bypass_payloads = [
            ("admin' OR '1'='1", "classic_or_bypass"),
            ("admin' OR '1'='1' --", "classic_or_comment"),
            ("admin' OR '1'='1' #", "classic_or_hash"),
            ('admin" OR "1"="1', "double_quote_bypass"),
            ("' OR '1'='1' /*", "inline_comment_bypass"),
            ("admin' OR 1=1--", "boolean_bypass"),
            ("' OR '1'='1' OR '", "stacked_or"),
        ]

        for payload, approach in bypass_payloads:
            try:
                self.log(f"[*] Auth bypass SQLi [{approach}] POST {login_url}")
                form = {"username": payload, "password": "anything"}
                if profile == PROFILE_DVWA:
                    form["Login"] = "Login"

                resp = self.client.request(
                    "POST",
                    login_url,
                    data=form,
                    cookies=self.context.cookies,
                    allow_redirects=True,
                )

                # Check if login succeeded (bypass worked)
                if _login_success(resp, profile):
                    findings.append(
                        self.finding(
                            vuln_id="VULN-A07-004",
                            title="SQL Injection Login Bypass",
                            severity="CRITICAL",
                            cvss_score=9.8,
                            endpoint=login_url.replace(self.context.base_url.rstrip("/"), ""),
                            method="POST",
                            parameter="username",
                            payload_used=payload,
                            evidence=f"Login bypass succeeded with payload: {payload}",
                            description="The login form is vulnerable to SQL injection. An attacker can bypass authentication using SQL injection payloads.",
                            impact="Complete authentication bypass leading to unauthorized access to any account.",
                            remediation="Use parameterized queries for login form. Never concatenate user input into SQL queries.",
                            references=[
                                "https://owasp.org/Top10/A03_2021-Injection/",
                                "https://cwe.mitre.org/data/definitions/89.html",
                            ],
                            cwe_id="CWE-89",
                            remediation_steps=[
                                "Replace dynamic SQL with prepared statements.",
                                "Implement input validation and sanitization.",
                                "Use ORM or parameterized database queries.",
                            ],
                        )
                    )
                    break
            except Exception as exc:
                self.log(f"[!] Auth bypass probe failed: {exc}")

        return findings

    def _test_username_enumeration(self, login_url: str, profile: str) -> list[dict]:
        """Test for username/email enumeration vulnerability."""
        findings = []

        try:
            # First, get a valid response with wrong creds
            form_wrong = {"username": "nonexistent_user_12345", "password": "wrongpassword"}
            form_valid = {"username": "admin", "password": "wrongpassword"}
            if profile == PROFILE_DVWA:
                form_wrong["Login"] = "Login"
                form_valid["Login"] = "Login"

            resp_wrong = self.client.request(
                "POST",
                login_url,
                data=form_wrong,
                cookies=self.context.cookies,
                allow_redirects=True,
            )
            resp_valid = self.client.request(
                "POST",
                login_url,
                data=form_valid,
                cookies=self.context.cookies,
                allow_redirects=True,
            )

            # Compare responses for differences that reveal username validity
            wrong_text = (resp_wrong.text or "").lower()
            valid_text = (resp_valid.text or "").lower()

            # Check for username enumeration indicators
            enum_indicators = [
                ("username", "invalid username" in wrong_text and "invalid" not in valid_text),
                ("email", "email not found" in wrong_text),
                ("account", "account not found" in wrong_text or "account does not exist" in wrong_text),
                ("user", "user not found" in wrong_text),
            ]

            # Check for timing differences (simple test)
            start = time.time()
            self.client.request("POST", login_url, data=form_wrong, cookies=self.context.cookies, allow_redirects=True)
            wrong_time = time.time() - start

            start = time.time()
            self.client.request("POST", login_url, data=form_valid, cookies=self.context.cookies, allow_redirects=True)
            valid_time = time.time() - start

            timing_diff = abs(wrong_time - valid_time)

            # If responses differ significantly or timing differs
            if (wrong_text != valid_text and
                (len(resp_wrong.text or "") != len(resp_valid.text or "") or
                 wrong_text.count("invalid") > valid_text.count("invalid"))):
                findings.append(
                    self.finding(
                        vuln_id="VULN-A07-005",
                        title="User Enumeration via Login Response",
                        severity="MEDIUM",
                        cvss_score=5.3,
                        endpoint=login_url.replace(self.context.base_url.rstrip("/"), ""),
                        method="POST",
                        parameter="username",
                        payload_used="nonexistent_user_12345 vs admin",
                        evidence=f"Different responses: nonexistent returned '{resp_wrong.text[:100]}', admin returned '{resp_valid.text[:100]}'",
                        description="The login form reveals whether a username/email exists based on error messages or response differences.",
                        impact="Attackers can enumerate valid usernames to target attacks.",
                        remediation="Use generic error messages like 'Invalid username or password' for both cases.",
                        references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
                        cwe_id="CWE-204",
                        remediation_steps=[
                            "Return same error message for invalid username and wrong password.",
                            "Implement rate limiting on login attempts.",
                            "Add account lockout after multiple failures.",
                        ],
                    )
                )
        except Exception as exc:
            self.log(f"[!] Username enumeration check failed: {exc}")

        return findings

    def run(self) -> list[dict]:
        findings: list[dict] = []
        profile = self.context.profile
        creds = list(DEFAULT_CREDENTIALS)
        if profile == PROFILE_DVWA:
            creds.insert(0, ("admin", "password"))

        if not self.is_https:
            findings.append(
                self.finding(
                    vuln_id="VULN-A07-001",
                    title="Login over non-HTTPS",
                    severity="CRITICAL",
                    cvss_score=9.1,
                    endpoint="/login",
                    method="GET",
                    parameter="scheme",
                    payload_used="http://",
                    evidence="Base URL is not HTTPS.",
                    description="Credentials may be exposed in transit.",
                    impact="Account compromise via traffic interception.",
                    remediation="Enforce HTTPS and HSTS for all authentication pages.",
                    references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
                    cwe_id="CWE-319",
                    remediation_steps=[
                        "Terminate TLS on a trusted edge and redirect all HTTP to HTTPS.",
                        "Enable HSTS with preload for production domains.",
                    ],
                )
            )

        login_paths = get_login_paths(profile)
        for login_path in login_paths:
            login_url = self.context.base_url.rstrip("/") + login_path

            # Test SQL injection login bypass
            sqli_bypass_findings = self._test_login_bypass(login_url, profile)
            findings.extend(sqli_bypass_findings)

            # Test username enumeration
            enum_findings = self._test_username_enumeration(login_url, profile)
            findings.extend(enum_findings)

            # Test default credentials
            for username, password in creds:
                try:
                    self.log(f"[*] Auth default-cred probe POST {login_path} user={username}")
                    form = {"username": username, "password": password}
                    if profile == PROFILE_DVWA:
                        form["Login"] = "Login"
                    resp = self.client.request(
                        "POST",
                        login_url,
                        data=form,
                        cookies=self.context.cookies,
                        allow_redirects=True,
                    )
                    if _login_success(resp, profile):
                        findings.append(
                            self.finding(
                                vuln_id="VULN-A07-002",
                                title="Weak or Default Credentials Accepted",
                                severity="CRITICAL",
                                cvss_score=9.8,
                                endpoint=login_path,
                                method="POST",
                                parameter="username/password",
                                payload_used=f"{username} / {password}",
                                evidence=(
                                    f"HTTP {resp.status_code}; Location={resp.headers.get('Location', '')!r}; "
                                    f"logout/session indicator in body."
                                ),
                                description="A common default credential pair may still authenticate.",
                                impact="Full account takeover, often with administrative rights.",
                                remediation="Remove default accounts, enforce MFA, and strong password policy.",
                                references=["https://cwe.mitre.org/data/definitions/521.html"],
                                cwe_id="CWE-521",
                                remediation_steps=[
                                    "Force password change on first login for any bootstrap account.",
                                    "Disable vendor defaults; rotate any leaked credentials immediately.",
                                    "Add MFA for privileged roles.",
                                ],
                            )
                        )
                        break
                except Exception as exc:
                    self.log(f"[!] Auth probe failed {login_path}: {exc}")

        if login_paths:
            login_url = self.context.base_url.rstrip("/") + login_paths[0]
            try:
                probe_count = 6
                statuses: list[int] = []
                last_text = ""
                for _ in range(probe_count):
                    form = {"username": "nouser", "password": "badpass"}
                    if profile == PROFILE_DVWA:
                        form["Login"] = "Login"
                    resp = self.client.request(
                        "POST",
                        login_url,
                        data=form,
                        cookies=self.context.cookies,
                        allow_redirects=True,
                    )
                    statuses.append(resp.status_code)
                    last_text = resp.text or ""
                if len(set(statuses)) == 1:
                    findings.append(
                        self.finding(
                            vuln_id="VULN-A07-003",
                            title="Possible Missing Rate Limiting on Login",
                            severity="HIGH",
                            cvss_score=7.5,
                            endpoint=login_paths[0],
                            method="POST",
                            parameter="username/password",
                            payload_used="rapid invalid login attempts",
                            evidence=(
                                f"{probe_count} sequential attempts returned uniform HTTP {statuses[0]}; "
                                f"last body snippet: {last_text[:200]!r}"
                            ),
                            description="No obvious backoff, CAPTCHA, or lockout signal observed.",
                            impact="Credential stuffing and brute force attacks are easier.",
                            remediation="Add per-IP and per-account throttling, lockout, and risk-based MFA.",
                            references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
                            cwe_id="CWE-307",
                            remediation_steps=[
                                "Implement exponential backoff after N failures.",
                                "Add CAPTCHA or proof-of-work only after risk signals.",
                            ],
                        )
                    )
            except Exception as exc:
                self.log(f"[!] Rate limiting check failed: {exc}")

        return findings
