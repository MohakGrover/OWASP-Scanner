"""HTTP client with retry, delay, and timeout defaults."""

from __future__ import annotations

import time
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class HttpConfig:
    timeout: int = 10
    delay_seconds: float = 0.6
    verify_tls: bool = True


class HttpClient:
    def __init__(self, config: HttpConfig | None = None):
        self.config = config or HttpConfig()
        self.session = requests.Session()
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            status=2,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST", "HEAD", "OPTIONS"]),
            backoff_factor=0.2,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        time.sleep(self.config.delay_seconds)
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("verify", self.config.verify_tls)
        return self.session.request(method=method.upper(), url=url, **kwargs)
