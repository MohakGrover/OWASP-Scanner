"""Scan profiles: path sets for generic e-commerce vs DVWA (PHP) labs."""

from __future__ import annotations

PROFILE_ECOMMERCE = "ecommerce"
PROFILE_DVWA = "dvwa"


def get_sqli_targets(profile: str) -> list[tuple[str, str, str]]:
    """Return list of (path, HTTP method, primary parameter name)."""
    sqli_targets = [
        ("/vulnerabilities/sqli/", "GET", "id"),
        ("/vulnerabilities/sqli_blind/", "GET", "id"),
        ("/vulnerabilities/sqli_cookie/", "GET", "id"),
    ]
    if profile == PROFILE_DVWA:
        # Login form SQL injection testing
        sqli_targets.extend([
            ("/login.php", "POST", "username"),
            ("/login.php", "POST", "password"),
        ])
    else:
        sqli_targets.extend([
            ("/login", "POST", "username"),
            ("/login", "POST", "email"),
            ("/signin", "POST", "username"),
        ])
    return sqli_targets
    return [
        ("/search", "GET", "q"),
        ("/products", "GET", "q"),
        ("/products", "GET", "id"),
        ("/login", "GET", "q"),
        ("/api/products", "GET", "id"),
        ("/cart", "GET", "sku"),
    ]


def get_login_paths(profile: str) -> list[str]:
    if profile == PROFILE_DVWA:
        return ["/login.php", "/index.php"]
    return ["/login", "/signin", "/account/login"]


def get_restricted_paths(profile: str) -> list[str]:
    if profile == PROFILE_DVWA:
        return [
            "/vulnerabilities/csrf/",
            "/vulnerabilities/upload/",
            "/vulnerabilities/exec/",
            "/setup.php",
            "/phpinfo.php",
        ]
    return ["/admin", "/dashboard", "/user/profile", "/api/admin"]


def get_misconfig_probes(profile: str) -> list[str]:
    base = ["/phpinfo.php", "/.env", "/config.php", "/wp-config.php", "/.git/config", "/server-status"]
    if profile == PROFILE_DVWA:
        base += ["/instructions.php", "/README.md", "/config/config.inc.php"]
    return list(dict.fromkeys(base))


def get_xss_targets(profile: str) -> list[tuple[str, str, str]]:
    """Reflected XSS probes: (path, method, param)."""
    if profile == PROFILE_DVWA:
        return [
            ("/vulnerabilities/xss_r/", "GET", "name"),
            ("/vulnerabilities/xss_r/", "GET", "term"),
        ]
    return [
        ("/search", "GET", "q"),
        ("/products", "GET", "q"),
        ("/comment", "GET", "msg"),
        ("/api/search", "GET", "query"),
    ]


def get_ssrf_targets(profile: str) -> list[tuple[str, str]]:
    """(path, default query param name)."""
    rows = [
        ("/import", "url"),
        ("/webhook-test", "url"),
        ("/fetch", "url"),
        ("/redirect", "redirect"),
        ("/proxy", "target"),
    ]
    if profile == PROFILE_DVWA:
        rows += [
            ("/vulnerabilities/ssrf/", "url"),
            ("/vulnerabilities/fi/", "page"),
        ]
    return rows
