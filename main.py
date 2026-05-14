"""OWASP Top 10 (2025) vulnerability scanner with professional reporting."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib import robotparser
from urllib.parse import urlparse

import requests

from report.html_generator import HTMLReportGenerator
from report.pdf_generator import build_pdf_report
from scanner import (
    AccessControlScanner,
    AuthScanner,
    ComponentsScanner,
    CryptoScanner,
    DesignScanner,
    IntegrityScanner,
    LoggingScanner,
    MisconfigScanner,
    ScanContext,
    SqliScanner,
    SsrfScanner,
    XssScanner,
)
from scanner.headers_scanner import HeadersScanner
from utils.http_client import HttpClient
from utils.owasp_top10 import OWASP_2025_ROWS, finding_count_for_code
from utils.payloads import SQLI_APPROACHES
from utils.profiles import PROFILE_DVWA, PROFILE_ECOMMERCE
from utils.screenshot_capture import ScreenshotCapture

DISCLAIMER = "OWASP Top 10 (2025) oriented scanner — for authorized security testing / lab use only."


def _dvwa_acquire_session(base_url: str, client: HttpClient, user_pass: str, verbose: bool = False) -> dict[str, str]:
    """POST to DVWA login.php and return cookie dict."""
    if ":" not in user_pass:
        raise SystemExit("--dvwa-login must be user:password")
    username, _, password = user_pass.partition(":")
    login_url = base_url.rstrip("/") + "/login.php"
    resp = client.request(
        "POST",
        login_url,
        data={"username": username.strip(), "password": password.strip(), "Login": "Login"},
        allow_redirects=True,
    )
    jar = requests.utils.dict_from_cookiejar(resp.cookies)
    if not jar:
        jar = requests.utils.dict_from_cookiejar(client.session.cookies)
    if verbose:
        print(f"[*] DVWA login POST {login_url} -> HTTP {resp.status_code}; cookies: {list(jar.keys())}")
    if not jar:
        print(
            "[!] DVWA auto-login returned no cookies (wrong app on port, or custom auth). "
            "Use --cookie \"PHPSESSID=...; security=low\" from your browser."
        )
    return jar


def parse_cookie(cookie_str: str) -> dict[str, str]:
    if not cookie_str:
        return {}
    result = {}
    for part in cookie_str.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def is_allowed_by_robots(base_url: str, user_agent: str = "*") -> bool:
    rp = robotparser.RobotFileParser()
    robots_url = base_url.rstrip("/") + "/robots.txt"
    try:
        rp.set_url(robots_url)
        rp.read()
        return rp.can_fetch(user_agent, base_url)
    except Exception:
        return True


def run_module(module_name: str, scanner_cls, context: ScanContext, client: HttpClient) -> list[dict]:
    scanner = scanner_cls(context=context, client=client)
    return scanner.run()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OWASP Top 10 (2025) vulnerability scanner — modular checks (non-destructive payloads)"
    )
    parser.add_argument("--url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--output", default="security_report.pdf", help="Output PDF report path")
    parser.add_argument("--html-output", default="security_report.html", help="Output HTML report path")
    parser.add_argument("--modules", default="all", help="Comma-separated modules or all")
    parser.add_argument("--cookie", default="", help='Cookie string, e.g. "PHPSESSID=abc; security=low"')
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--ignore-robots", action="store_true")
    parser.add_argument("--demo", action="store_true", help="Use local demo target http://127.0.0.1:5000")
    parser.add_argument(
        "--profile",
        choices=(PROFILE_ECOMMERCE, PROFILE_DVWA),
        default=PROFILE_ECOMMERCE,
        help=f"Path set: {PROFILE_ECOMMERCE} (generic) or {PROFILE_DVWA} (DVWA / PHP lab)",
    )
    parser.add_argument(
        "--dvwa-login",
        metavar="USER:PASS",
        default="",
        help="DVWA only: log in first (e.g. admin:password) so SQLi and labs return real responses",
    )
    parser.add_argument("--screenshots", action="store_true", help="Capture exploitation proof screenshots")
    parser.add_argument("--screenshots-dir", default="screenshots", help="Directory for screenshots")
    parser.add_argument("--html-only", action="store_true", help="Generate HTML report only")
    parser.add_argument("--pdf-only", action="store_true", help="Generate PDF report only")
    args = parser.parse_args()

    print(f"\n{'=' * 68}\n{DISCLAIMER}\n{'=' * 68}\n")

    target_url = "http://127.0.0.1:5000" if args.demo else args.url
    if not target_url:
        raise SystemExit("Provide --url or use --demo")

    if urlparse(target_url).scheme not in ("http", "https"):
        raise SystemExit("Target URL must start with http:// or https://")

    if not args.ignore_robots and not is_allowed_by_robots(target_url):
        raise SystemExit("Blocked by robots.txt. Use --ignore-robots only with explicit authorization.")

    profile = PROFILE_ECOMMERCE if args.demo else args.profile

    cookies = parse_cookie(args.cookie)
    client = HttpClient()
    if args.dvwa_login.strip():
        if profile != PROFILE_DVWA:
            raise SystemExit("--dvwa-login is only valid with --profile dvwa")
        _dvwa_acquire_session(target_url, client, args.dvwa_login.strip(), verbose=args.verbose)
        session_jar = requests.utils.dict_from_cookiejar(client.session.cookies)
        cookies = {**session_jar, **cookies}

    # Initialize screenshot capture if enabled
    screenshot_capture = None
    if args.screenshots:
        screenshot_capture = ScreenshotCapture(output_dir=args.screenshots_dir)
        print(f"[*] Screenshot capture enabled -> {args.screenshots_dir}/")

    context = ScanContext(
        base_url=target_url,
        verbose=args.verbose,
        cookies=cookies,
        ignore_robots=args.ignore_robots,
        profile=profile,
        screenshot_capture=screenshot_capture,
    )

    scanner_map = {
        "sqli": SqliScanner,
        "xss": XssScanner,
        "auth": AuthScanner,
        "access": AccessControlScanner,
        "crypto": CryptoScanner,
        "misconfig": MisconfigScanner,
        "components": ComponentsScanner,
        "design": DesignScanner,
        "integrity": IntegrityScanner,
        "logging": LoggingScanner,
        "ssrf": SsrfScanner,
        "headers": HeadersScanner,
    }
    selected = list(scanner_map.keys()) if args.modules == "all" else [m.strip() for m in args.modules.split(",") if m.strip()]
    selected = [m for m in selected if m in scanner_map]
    if not selected:
        raise SystemExit("No valid modules selected.")

    findings: list[dict] = []
    for name in selected:
        try:
            result = run_module(name, scanner_map[name], context, client)
            findings.extend(result)
            print(f"[+] {name}: completed ({len(result)} findings)")
        except Exception as exc:
            print(f"[!] {name}: module error, continuing ({exc})")

    findings.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)

    # Generate screenshot index if screenshots were captured
    if screenshot_capture and screenshot_capture.screenshots:
        index_path = screenshot_capture.generate_index_html()
        print(f"[*] Screenshot index: {index_path}")

    # Generate reports based on flags
    generate_pdf = not args.html_only
    generate_html = not args.pdf_only

    metadata = {
        "modules": selected,
        "mode": "demo" if args.demo else "standard",
        "profile": profile,
        "sqli_approach_count": len(SQLI_APPROACHES),
        "sqli_approach_names": [a[0] for a in SQLI_APPROACHES],
        "report_title": "OWASP Top 10 (2025) Vulnerability Assessment Report",
        "screenshots_dir": args.screenshots_dir,
    }

    if generate_pdf:
        build_pdf_report(
            output_path=args.output,
            target_url=target_url,
            findings=findings,
            metadata=metadata,
        )
        print(f"[*] PDF report generated: {args.output}")

    if generate_html:
        html_gen = HTMLReportGenerator()
        html_path = html_gen.generate_report(
            output_path=args.html_output,
            target_url=target_url,
            findings=findings,
            metadata=metadata,
            screenshots_dir=args.screenshots_dir,
        )
        print(f"[*] HTML report generated: {html_path}")

    # Print OWASP summary
    nonzero = [f"{r['code']}={finding_count_for_code(findings, r['code'])}" for r in OWASP_2025_ROWS if finding_count_for_code(findings, r["code"])]
    if nonzero:
        print("[*] OWASP Top 10 (2025) — findings by category: " + ", ".join(nonzero))

    print(f"\nScan completed. Total findings: {len(findings)}")
    if screenshot_capture:
        print(f"Screenshots captured: {len(screenshot_capture.screenshots)}")


if __name__ == "__main__":
    main()