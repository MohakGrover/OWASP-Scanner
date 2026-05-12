"""Utility helpers for URL and HTML handling."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_url(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def extract_same_origin_links(base_url: str, html: str) -> list[str]:
    soup = BeautifulSoup(html or "", "lxml")
    base_host = urlparse(base_url).netloc
    links: set[str] = set()
    for a in soup.select("a[href]"):
        href = (a.get("href") or "").strip()
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.netloc == base_host:
            links.add(absolute)
    return sorted(links)


def extract_forms(html: str) -> list[dict]:
    soup = BeautifulSoup(html or "", "lxml")
    results: list[dict] = []
    for form in soup.find_all("form"):
        inputs: list[str] = []
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if name:
                inputs.append(name)
        results.append(
            {
                "action": form.get("action", ""),
                "method": (form.get("method", "get") or "get").lower(),
                "fields": inputs,
            }
        )
    return results
