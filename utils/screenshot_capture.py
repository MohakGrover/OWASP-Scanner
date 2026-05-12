"""Screenshot capture module for exploitation proof documentation."""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

SCREENSHOT_DIR = "screenshots"


@dataclass
class Screenshot:
    """Represents a captured screenshot with metadata."""
    finding_id: str
    timestamp: str
    url: str
    method: str
    payload: Optional[str] = None
    response_snippet: Optional[str] = None
    image_data: Optional[str] = None  # Base64 encoded
    image_path: Optional[str] = None
    description: str = ""
    attack_type: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "timestamp": self.timestamp,
            "url": self.url,
            "method": self.method,
            "payload": self.payload,
            "response_snippet": self.response_snippet,
            "image_path": self.image_path,
            "description": self.description,
            "attack_type": self.attack_type,
        }


class ScreenshotCapture:
    """Captures exploitation proof screenshots."""

    def __init__(self, output_dir: str = SCREENSHOT_DIR):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.screenshots: list[Screenshot] = []
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def capture_request_response(
        self,
        finding_id: str,
        url: str,
        method: str,
        payload: Optional[str] = None,
        response_text: Optional[str] = None,
        attack_type: str = "",
        description: str = "",
    ) -> Screenshot:
        """Capture a request/response as proof of exploitation."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        screenshot = Screenshot(
            finding_id=finding_id,
            timestamp=timestamp,
            url=url,
            method=method,
            payload=payload,
            response_snippet=response_text[:500] if response_text else None,
            attack_type=attack_type,
            description=description,
        )

        # Create HTML proof document
        html_path = self._create_html_proof(screenshot)

        screenshot.image_path = str(html_path)
        self.screenshots.append(screenshot)

        return screenshot

    def capture_browser_screenshot(
        self,
        finding_id: str,
        url: str,
        attack_type: str = "",
        description: str = "",
    ) -> Optional[Screenshot]:
        """Capture browser screenshot using playwright if available."""
        try:
            from playwright.sync_api import sync_playwright

            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            filename = f"{finding_id}_{timestamp}.png"
            filepath = self.output_dir / filename

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=30000)
                page.screenshot(path=str(filepath), full_page=True)
                browser.close()

            screenshot = Screenshot(
                finding_id=finding_id,
                timestamp=timestamp,
                url=url,
                method="GET",
                image_path=str(filepath),
                attack_type=attack_type,
                description=description,
            )
            self.screenshots.append(screenshot)
            return screenshot

        except ImportError:
            # Playwright not available, fall back to HTML proof
            return self.capture_request_response(
                finding_id=finding_id,
                url=url,
                method="GET",
                attack_type=attack_type,
                description=f"{description} (Browser capture unavailable)",
            )
        except Exception as e:
            return self.capture_request_response(
                finding_id=finding_id,
                url=url,
                method="GET",
                attack_type=attack_type,
                description=f"{description} - Browser error: {str(e)}",
            )

    def _create_html_proof(self, screenshot: Screenshot) -> Path:
        """Create an HTML proof document with request/response details."""
        filename = f"proof_{screenshot.finding_id}_{screenshot.timestamp}.html"
        filepath = self.output_dir / filename

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Exploitation Proof - {screenshot.finding_id}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            padding: 30px;
            min-height: 100vh;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(90deg, #e94560, #0f3460);
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 25px;
        }}
        .header h1 {{
            color: white;
            font-size: 24px;
            margin-bottom: 8px;
        }}
        .header .badge {{
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            color: #ffcc00;
        }}
        .card {{
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .card h2 {{
            color: #e94560;
            font-size: 16px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }}
        .info-item {{
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-radius: 8px;
        }}
        .info-item label {{
            display: block;
            color: #888;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 5px;
        }}
        .info-item span {{
            color: #4fc3f7;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            word-break: break-all;
        }}
        .payload-box {{
            background: #1e1e1e;
            border: 1px solid #e94560;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
        }}
        .payload-box h3 {{
            color: #e94560;
            font-size: 14px;
            margin-bottom: 10px;
        }}
        .payload-content {{
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: #98ff98;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 300px;
            overflow-y: auto;
            padding: 10px;
            background: #0d0d0d;
            border-radius: 5px;
        }}
        .response-box {{
            background: #1e1e1e;
            border: 1px solid #4fc3f7;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
        }}
        .response-box h3 {{
            color: #4fc3f7;
            font-size: 14px;
            margin-bottom: 10px;
        }}
        .response-content {{
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #ffcc00;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 400px;
            overflow-y: auto;
            padding: 10px;
            background: #0d0d0d;
            border-radius: 5px;
        }}
        .timestamp {{
            text-align: right;
            color: #666;
            font-size: 11px;
            margin-top: 20px;
        }}
        .warning-banner {{
            background: linear-gradient(90deg, #ff6b6b, #ee5a24);
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            text-align: center;
            margin-bottom: 20px;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="warning-banner">
            ⚠️ AUTHORIZED SECURITY TESTING EVIDENCE ONLY ⚠️
        </div>

        <div class="header">
            <h1>🛡️ Exploitation Proof Document</h1>
            <span class="badge">{screenshot.attack_type or 'Vulnerability Finding'}</span>
        </div>

        <div class="card">
            <h2>📋 Finding Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <label>Finding ID</label>
                    <span>{screenshot.finding_id}</span>
                </div>
                <div class="info-item">
                    <label>Attack Type</label>
                    <span>{screenshot.attack_type}</span>
                </div>
                <div class="info-item">
                    <label>Timestamp (UTC)</label>
                    <span>{screenshot.timestamp}</span>
                </div>
                <div class="info-item">
                    <label>HTTP Method</label>
                    <span>{screenshot.method}</span>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>🎯 Target URL</h2>
            <div class="info-item">
                <label>Request URL</label>
                <span>{screenshot.url}</span>
            </div>
        </div>

        <div class="card">
            <h2>💉 Injected Payload</h2>
            <div class="payload-box">
                <h3>Malicious Input</h3>
                <div class="payload-content">{screenshot.payload or 'N/A'}</div>
            </div>
        </div>

        <div class="card">
            <h2>📄 Server Response</h2>
            <div class="response-box">
                <h3>Response Snippet (First 500 chars)</h3>
                <div class="response-content">{screenshot.response_snippet or 'N/A'}</div>
            </div>
        </div>

        <div class="card">
            <h2>📝 Description</h2>
            <p style="color: #ccc; line-height: 1.6;">{screenshot.description or 'Vulnerability detected during automated security scan.'}</p>
        </div>

        <div class="timestamp">
            Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} |
            OWASP Scanner v2.0 |
            For Authorized Testing Only
        </div>
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filepath

    def get_screenshots_for_finding(self, finding_id: str) -> list[Screenshot]:
        """Get all screenshots for a specific finding."""
        return [s for s in self.screenshots if s.finding_id == finding_id]

    def get_all_screenshots(self) -> list[Screenshot]:
        """Get all captured screenshots."""
        return self.screenshots

    def generate_index_html(self) -> Path:
        """Generate an index HTML with all screenshots."""
        filename = f"screenshots_index_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / filename

        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Exploitation Proofs - Index</title>
    <style>
        body {
            font-family: 'Segoe UI', sans-serif;
            background: #1a1a2e;
            color: #e0e0e0;
            padding: 30px;
        }
        h1 { color: #e94560; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 10px;
            padding: 20px;
        }
        .card h3 { color: #4fc3f7; margin-bottom: 10px; }
        .card a { color: #e94560; text-decoration: none; }
        .card a:hover { text-decoration: underline; }
        .meta { font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <h1>🛡️ Exploitation Proofs Index</h1>
    <p>Total screenshots: """ + str(len(self.screenshots)) + """</p>
    <div class="grid">
"""

        for shot in self.screenshots:
            html_content += f"""
        <div class="card">
            <h3>{shot.finding_id}</h3>
            <p class="meta">
                <strong>Type:</strong> {shot.attack_type}<br>
                <strong>Method:</strong> {shot.method}<br>
                <strong>Time:</strong> {shot.timestamp}
            </p>
            <p class="meta"><strong>URL:</strong> {shot.url[:60]}...</p>
            <a href="{shot.image_path}">View Proof →</a>
        </div>
"""

        html_content += """
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filepath