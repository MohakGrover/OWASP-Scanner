"""Professional HTML report generator with embedded screenshots and proof documentation."""

from __future__ import annotations

import base64
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

WEASYPRINT_AVAILABLE = False
_WeasyHTML = None


def _check_weasyprint():
    """Lazy check for WeasyPrint availability."""
    global WEASYPRINT_AVAILABLE, _WeasyHTML
    if WEASYPRINT_AVAILABLE and _WeasyHTML is not None:
        return True
    try:
        from weasyprint import HTML as WeasyHTML
        _WeasyHTML = WeasyHTML
        WEASYPRINT_AVAILABLE = True
        return True
    except Exception:
        return False


class HTMLReportGenerator:
    """Generates professional HTML vulnerability assessment reports."""

    def __init__(self, output_dir: str = "report/html"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        output_path: str,
        target_url: str,
        findings: list[dict],
        metadata: dict,
        screenshots_dir: str = "screenshots",
    ) -> str:
        """Generate comprehensive HTML report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        counts = Counter(f.get("severity", "INFO") for f in findings)
        risk_score = self._calculate_risk_score(findings)

        html_content = self._build_html(
            target_url=target_url,
            timestamp=timestamp,
            findings=findings,
            metadata=metadata,
            counts=counts,
            risk_score=risk_score,
            screenshots_dir=screenshots_dir,
        )

        output_file = self.output_dir / output_path if not Path(output_path).is_absolute() else Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        return str(output_file)

    def _calculate_risk_score(self, findings: list[dict]) -> int:
        """Calculate overall risk score (0-100)."""
        weights = {"CRITICAL": 20, "HIGH": 12, "MEDIUM": 7, "LOW": 3, "INFO": 1}
        score = sum(weights.get(f.get("severity", "INFO"), 0) for f in findings)
        return max(0, min(100, score))

    def _get_severity_color(self, severity: str) -> str:
        colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#2563eb",
            "INFO": "#1f2937",
        }
        return colors.get(severity, "#6b7280")

    def _get_risk_label(self, score: int) -> tuple[str, str]:
        if score >= 70:
            return "CRITICAL", "#dc2626"
        elif score >= 50:
            return "HIGH", "#ea580c"
        elif score >= 30:
            return "MEDIUM", "#ca8a04"
        elif score >= 15:
            return "LOW", "#2563eb"
        return "MINIMAL", "#16a34a"

    def _build_html(
        self,
        target_url: str,
        timestamp: str,
        findings: list[dict],
        metadata: dict,
        counts: Counter,
        risk_score: int,
        screenshots_dir: str,
    ) -> str:
        modules = metadata.get("modules", [])
        sqli_count = metadata.get("sqli_approach_count", 0)
        sqli_approaches = metadata.get("sqli_approach_names", [])

        risk_label, risk_color = self._get_risk_label(risk_score)

        sorted_findings = sorted(findings, key=lambda x: float(x.get("cvss_score", 0) or 0), reverse=True)
        findings_html = self._build_findings_section(sorted_findings, screenshots_dir)
        owasp_table = self._build_owasp_coverage_table(findings, modules)

        sqli_list = ''.join(f'<li style="padding: 5px 0;"><i class="fas fa-check" style="color: #16a34a; margin-right: 10px;"></i>{approach}</li>' for approach in sqli_approaches)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {target_url}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{
            --primary: #1a2744;
            --secondary: #2d4a6f;
            --accent: #e94560;
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #1f2937;
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: 'Segoe UI', 'Inter', -apple-system, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}

        .cover {{
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            border-radius: 20px;
            padding: 60px 40px;
            margin-bottom: 30px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}

        .cover::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
            opacity: 0.5;
        }}

        .cover h1 {{ font-size: 42px; font-weight: 800; color: white; margin-bottom: 10px; position: relative; }}
        .cover .subtitle {{ font-size: 18px; color: rgba(255,255,255,0.8); margin-bottom: 30px; position: relative; }}

        .risk-score {{
            display: inline-flex; align-items: center; gap: 15px;
            background: {risk_color}; padding: 15px 30px; border-radius: 50px; margin: 30px 0;
        }}
        .risk-score .score {{ font-size: 48px; font-weight: 800; color: white; }}
        .risk-score .label {{ font-size: 14px; text-transform: uppercase; letter-spacing: 2px; color: rgba(255,255,255,0.9); }}

        .meta-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px; max-width: 900px; margin: 30px auto 0; position: relative;
        }}
        .meta-item {{
            background: rgba(255,255,255,0.1); backdrop-filter: blur(10px);
            padding: 20px; border-radius: 12px; text-align: left;
        }}
        .meta-item label {{ display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: rgba(255,255,255,0.6); margin-bottom: 5px; }}
        .meta-item span {{ font-size: 16px; font-weight: 600; color: white; }}

        .nav {{
            background: var(--bg-card); border-radius: 15px; padding: 15px 25px;
            margin-bottom: 30px; display: flex; gap: 10px; overflow-x: auto;
            position: sticky; top: 10px; z-index: 100; box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        .nav a {{
            color: var(--text-muted); text-decoration: none; padding: 10px 20px;
            border-radius: 8px; font-weight: 500; white-space: nowrap; transition: all 0.3s ease;
        }}
        .nav a:hover, .nav a.active {{ background: var(--accent); color: white; }}

        .card {{
            background: var(--bg-card); border-radius: 15px; padding: 30px;
            margin-bottom: 25px; border: 1px solid rgba(255,255,255,0.05);
        }}
        .card-header {{
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 25px; padding-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        .card-header h2 {{ font-size: 24px; color: white; display: flex; align-items: center; gap: 12px; }}
        .card-header h2 i {{ color: var(--accent); }}

        .severity-stats {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px; margin-bottom: 30px;
        }}
        .stat-card {{
            background: var(--bg-card); border-radius: 12px; padding: 25px;
            text-align: center; border: 2px solid transparent; transition: all 0.3s ease;
        }}
        .stat-card:hover {{ transform: translateY(-5px); border-color: var(--accent); }}
        .stat-card .count {{ font-size: 42px; font-weight: 800; }}
        .stat-card .label {{ font-size: 13px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-top: 5px; }}

        .finding-card {{
            background: var(--bg-card); border-radius: 15px; margin-bottom: 25px;
            overflow: hidden; border-left: 4px solid var(--accent);
        }}
        .finding-header {{
            padding: 25px; display: flex; justify-content: space-between;
            align-items: flex-start; border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        .finding-title h3 {{ font-size: 20px; color: white; margin-bottom: 8px; }}
        .finding-title .id {{ font-size: 12px; color: var(--text-muted); font-family: monospace; }}
        .severity-badge {{
            padding: 8px 20px; border-radius: 25px; font-weight: 700;
            font-size: 13px; text-transform: uppercase; letter-spacing: 1px;
        }}
        .finding-body {{ padding: 25px; }}
        .finding-meta {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px; margin-bottom: 20px; padding: 20px; background: rgba(0,0,0,0.3); border-radius: 10px;
        }}
        .finding-meta .item {{ display: flex; flex-direction: column; gap: 5px; }}
        .finding-meta .item label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); }}
        .finding-meta .item span {{ font-family: monospace; font-size: 13px; color: #4fc3f7; }}

        .finding-section {{ margin-bottom: 20px; }}
        .finding-section h4 {{
            font-size: 14px; text-transform: uppercase; letter-spacing: 1px;
            color: var(--accent); margin-bottom: 10px; display: flex; align-items: center; gap: 8px;
        }}
        .finding-section p, .finding-section li {{ font-size: 14px; color: var(--text); line-height: 1.7; }}

        .code-block {{
            background: #0d1117; border: 1px solid rgba(255,255,255,0.1); border-radius: 8px;
            padding: 20px; font-family: 'Fira Code', 'Courier New', monospace;
            font-size: 12px; color: #98ff98; overflow-x: auto; white-space: pre-wrap;
            word-break: break-all; max-height: 200px; overflow-y: auto;
        }}

        .proof-screenshot {{
            background: var(--bg-card); border: 2px solid var(--accent);
            border-radius: 12px; padding: 20px; margin: 20px 0;
        }}
        .proof-screenshot h4 {{ color: var(--accent); margin-bottom: 15px; display: flex; align-items: center; gap: 8px; }}
        .proof-screenshot iframe {{ width: 100%; height: 400px; border: none; border-radius: 8px; }}

        .steps-list {{ list-style: none; }}
        .steps-list li {{ padding: 10px 15px; margin-bottom: 8px; background: rgba(0,0,0,0.2); border-radius: 8px; display: flex; gap: 10px; }}
        .steps-list li::before {{
            content: attr(data-step); background: var(--accent); color: white;
            width: 25px; height: 25px; border-radius: 50%; display: flex;
            align-items: center; justify-content: center; font-size: 12px; font-weight: bold; flex-shrink: 0;
        }}

        .roadmap-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }}
        .roadmap-card {{ background: linear-gradient(135deg, var(--bg-card), rgba(0,0,0,0.3)); border-radius: 15px; padding: 25px; text-align: center; }}
        .roadmap-card .timeline {{ font-size: 24px; font-weight: 800; color: var(--accent); margin-bottom: 10px; }}
        .roadmap-card .focus {{ font-size: 16px; font-weight: 600; color: white; margin-bottom: 15px; }}
        .roadmap-card .actions {{ font-size: 13px; color: var(--text-muted); line-height: 1.6; }}

        .footer {{ text-align: center; padding: 40px; color: var(--text-muted); font-size: 12px; border-top: 1px solid rgba(255,255,255,0.05); margin-top: 40px; }}

        @media (max-width: 768px) {{
            .roadmap-grid {{ grid-template-columns: 1fr; }}
            .cover {{ padding: 40px 20px; }}
            .cover h1 {{ font-size: 28px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Cover -->
        <div class="cover">
            <h1>Security Assessment Report</h1>
            <p class="subtitle">OWASP Top 10 (2025) Vulnerability Assessment</p>
            <div class="risk-score">
                <span class="score">{risk_score}</span>
                <span class="label">Risk Score<br>/100</span>
            </div>
            <p style="color: {risk_color}; font-size: 18px; font-weight: 600; position: relative;">
                Overall Risk Level: {risk_label}
            </p>
            <div class="meta-grid">
                <div class="meta-item">
                    <label>Target URL</label>
                    <span>{target_url}</span>
                </div>
                <div class="meta-item">
                    <label>Scan Date</label>
                    <span>{timestamp}</span>
                </div>
                <div class="meta-item">
                    <label>Profile</label>
                    <span>{metadata.get('profile', 'ecommerce').upper()}</span>
                </div>
                <div class="meta-item">
                    <label>Total Findings</label>
                    <span>{len(findings)}</span>
                </div>
            </div>
        </div>

        <!-- Navigation -->
        <nav class="nav">
            <a href="#executive-summary">Executive Summary</a>
            <a href="#methodology">Methodology</a>
            <a href="#risk-overview">Risk Overview</a>
            <a href="#owasp-coverage">OWASP Coverage</a>
            <a href="#findings">Detailed Findings</a>
            <a href="#remediation">Remediation</a>
            <a href="#appendix">Appendix</a>
        </nav>

        <!-- Executive Summary -->
        <section id="executive-summary" class="card">
            <div class="card-header">
                <h2><i class="fas fa-chart-pie"></i> Executive Summary</h2>
            </div>
            <div class="severity-stats">
                <div class="stat-card" style="border-color: {self._get_severity_color('CRITICAL')};">
                    <div class="count" style="color: {self._get_severity_color('CRITICAL')};">{counts.get('CRITICAL', 0)}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="stat-card" style="border-color: {self._get_severity_color('HIGH')};">
                    <div class="count" style="color: {self._get_severity_color('HIGH')};">{counts.get('HIGH', 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="stat-card" style="border-color: {self._get_severity_color('MEDIUM')};">
                    <div class="count" style="color: {self._get_severity_color('MEDIUM')};">{counts.get('MEDIUM', 0)}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="stat-card" style="border-color: {self._get_severity_color('LOW')};">
                    <div class="count" style="color: {self._get_severity_color('LOW')};">{counts.get('LOW', 0)}</div>
                    <div class="label">Low</div>
                </div>
                <div class="stat-card" style="border-color: {self._get_severity_color('INFO')};">
                    <div class="count" style="color: {self._get_severity_color('INFO')};">{counts.get('INFO', 0)}</div>
                    <div class="label">Info</div>
                </div>
            </div>
            <div style="padding: 20px; background: rgba(0,0,0,0.3); border-radius: 10px; margin-top: 20px;">
                <p style="font-size: 15px; line-height: 1.8;">
                    This report presents findings from an <strong>OWASP Top 10 (2025)</strong> oriented security scan
                    conducted on <strong>{target_url}</strong>. A total of <strong>{len(findings)} vulnerabilities</strong> were
                    identified. The overall risk posture is <strong style="color: {risk_color};">{risk_label}</strong>
                    with a score of <strong>{risk_score}/100</strong>.
                </p>
            </div>
        </section>

        <!-- Methodology -->
        <section id="methodology" class="card">
            <div class="card-header">
                <h2><i class="fas fa-clipboard-list"></i> Methodology & Scope</h2>
            </div>
            <div class="finding-meta">
                <div class="item"><label>Profile</label><span>{metadata.get('profile', 'ecommerce').upper()}</span></div>
                <div class="item"><label>Mode</label><span>{metadata.get('mode', 'standard').upper()}</span></div>
                <div class="item"><label>Modules Run</label><span>{', '.join(modules)}</span></div>
                <div class="item"><label>SQLi Approaches</label><span>{sqli_count} techniques</span></div>
            </div>
            <div class="finding-section">
                <h4><i class="fas fa-bug"></i> SQL Injection Probe Techniques</h4>
                <ul style="list-style: none;">{sqli_list}</ul>
            </div>
            <div style="background: linear-gradient(135deg, #7c3aed, #db2777); padding: 15px 20px; border-radius: 10px; margin-top: 20px;">
                <p style="font-size: 13px; color: white;">
                    <i class="fas fa-shield-alt"></i>
                    <strong>Disclaimer:</strong> Non-destructive payloads only. No data modification or system compromise attempts.
                    For authorized security testing only.
                </p>
            </div>
        </section>

        <!-- OWASP Coverage -->
        <section id="owasp-coverage" class="card">
            <div class="card-header">
                <h2><i class="fas fa-shield-alt"></i> OWASP Top 10 (2025) Coverage</h2>
            </div>
            {owasp_table}
        </section>

        <!-- Detailed Findings -->
        <section id="findings">
            <div class="card">
                <div class="card-header">
                    <h2><i class="fas fa-search"></i> Detailed Findings</h2>
                    <span style="color: var(--text-muted);">{len(findings)} Total</span>
                </div>
            </div>
            {findings_html}
        </section>

        <!-- Remediation -->
        <section id="remediation" class="card">
            <div class="card-header">
                <h2><i class="fas fa-tools"></i> Remediation Roadmap</h2>
            </div>
            <div class="roadmap-grid">
                <div class="roadmap-card" style="border: 2px solid var(--critical);">
                    <div class="timeline">0-2 Days</div>
                    <div class="focus" style="color: var(--critical);">CRITICAL Issues</div>
                    <div class="actions">Stop error disclosure<br>Patch authentication<br>Emergency config toggles<br>Isolate affected endpoints</div>
                </div>
                <div class="roadmap-card" style="border: 2px solid var(--high);">
                    <div class="timeline">1 Week</div>
                    <div class="focus" style="color: var(--high);">HIGH Priority</div>
                    <div class="actions">Access control review<br>Header hardening<br>SSRF egress controls<br>Session audit</div>
                </div>
                <div class="roadmap-card" style="border: 2px solid var(--medium);">
                    <div class="timeline">30 Days</div>
                    <div class="focus" style="color: var(--medium);">MEDIUM/LOW</div>
                    <div class="actions">Monitoring setup<br>SRI implementation<br>Dependency upgrades<br>QA regression tests</div>
                </div>
            </div>
        </section>

        <!-- Appendix -->
        <section id="appendix" class="card">
            <div class="card-header">
                <h2><i class="fas fa-attach-file"></i> Appendix</h2>
            </div>
            <div class="finding-section">
                <h4><i class="fas fa-cog"></i> Scan Configuration</h4>
                <div class="code-block">Mode: {metadata.get('mode', 'standard')} | Profile: {metadata.get('profile', 'ecommerce')}</div>
            </div>
            <div class="finding-section">
                <h4><i class="fas fa-exclamation-circle"></i> False Positive Disclaimer</h4>
                <p>Automated findings may include false positives. Each finding should be validated in application context
                before remediation planning.</p>
            </div>
            <div class="finding-section">
                <h4><i class="fas fa-file-code"></i> References</h4>
                <ul style="list-style: none;">
                    <li><i class="fas fa-link" style="color: var(--accent); margin-right: 10px;"></i>OWASP Top 10 (2025) - https://owasp.org/Top10/</li>
                    <li><i class="fas fa-link" style="color: var(--accent); margin-right: 10px;"></i>CWE/CVE Databases</li>
                    <li><i class="fas fa-link" style="color: var(--accent); margin-right: 10px;"></i>CVSS 3.1 Scoring Guide</li>
                </ul>
            </div>
        </section>

        <!-- Footer -->
        <div class="footer">
            <p>
                <strong>Generated by OWASP Top 10 (2025) Scanner v2.0</strong><br>
                Report Date: {timestamp} | Classification: CONFIDENTIAL<br>
                For authorized security testing only.
            </p>
        </div>
    </div>
</body>
</html>"""

    def _build_findings_section(self, findings: list[dict], screenshots_dir: str) -> str:
        """Build the detailed findings HTML section."""
        if not findings:
            return '''
            <div class="card" style="text-align: center; padding: 60px;">
                <i class="fas fa-check-circle" style="font-size: 60px; color: #16a34a;"></i>
                <h3 style="color: white; margin-top: 20px;">No Vulnerabilities Found</h3>
                <p style="color: var(--text-muted); margin-top: 10px;">All automated checks passed successfully.</p>
            </div>
            '''

        findings_html = []
        for idx, finding in enumerate(findings, 1):
            sev = finding.get("severity", "INFO")
            sev_color = self._get_severity_color(sev)
            screenshot_path = self._find_screenshot(finding.get("id", ""), screenshots_dir)

            payload_section = f'''
                <div class="finding-section">
                    <h4><i class="fas fa-bug"></i> Injected Payload</h4>
                    <div class="code-block">{finding.get('payload', 'N/A')}</div>
                </div>
            ''' if finding.get("payload") else ""

            response_section = f'''
                <div class="finding-section">
                    <h4><i class="fas fa-server"></i> Server Response</h4>
                    <div class="code-block" style="color: #ffcc00;">{str(finding.get('response_snippet', 'N/A'))[:500]}</div>
                </div>
            ''' if finding.get("response_snippet") else ""

            proof_section = f'''
                <div class="proof-screenshot">
                    <h4><i class="fas fa-camera"></i> Exploitation Proof (Screenshot)</h4>
                    <iframe src="{screenshot_path}" title="Proof of exploitation"></iframe>
                    <p style="font-size: 12px; color: var(--text-muted); margin-top: 10px;">
                        <i class="fas fa-file-code"></i> {screenshot_path}
                    </p>
                </div>
            ''' if screenshot_path and Path(screenshot_path).exists() else ""

            steps_html = ""
            if finding.get("remediation_steps"):
                steps = finding["remediation_steps"]
                steps_html = f'''
                <div class="finding-section">
                    <h4><i class="fas fa-list-ol"></i> Remediation Steps</h4>
                    <ol class="steps-list">
                        {''.join(f'<li data-step="{i+1}">{step}</li>' for i, step in enumerate(steps))}
                    </ol>
                </div>
                '''

            code_section = f'''
                <div class="finding-section">
                    <h4><i class="fas fa-code"></i> Secure Code Example</h4>
                    <div class="code-block">{finding.get('code_example', 'N/A')}</div>
                </div>
            ''' if finding.get("code_example") else ""

            refs_html = ''.join(f'<li><i class="fas fa-link" style="color: #4fc3f7; margin-right: 8px;"></i>{ref}</li>' for ref in (finding.get('references') or []))

            finding_html = f'''
            <div class="finding-card" id="finding-{finding.get('id', idx)}">
                <div class="finding-header">
                    <div class="finding-title">
                        <div class="id">{finding.get('id', f'FIND-{idx:04d}')}</div>
                        <h3>{finding.get('title', 'Untitled Finding')}</h3>
                    </div>
                    <div class="severity-badge" style="background: {sev_color}; color: white;">{sev}</div>
                </div>
                <div class="finding-body">
                    <div class="finding-meta">
                        <div class="item"><label>OWASP Category</label><span>{finding.get('owasp_category', 'Unknown')}</span></div>
                        <div class="item"><label>CWE ID</label><span>{finding.get('cwe_id', 'N/A')}</span></div>
                        <div class="item"><label>CVSS Score</label><span>{finding.get('cvss_score', 'N/A')}</span></div>
                        <div class="item"><label>Method</label><span>{finding.get('method', 'GET')} → {finding.get('endpoint', 'N/A')}</span></div>
                        <div class="item"><label>Parameter</label><span>{finding.get('parameter', 'N/A')}</span></div>
                    </div>
                    <div class="finding-section">
                        <h4><i class="fas fa-info-circle"></i> Description</h4>
                        <p>{finding.get('description', 'No description available.')}</p>
                    </div>
                    {payload_section}
                    {response_section}
                    {proof_section}
                    <div class="finding-section">
                        <h4><i class="fas fa-exclamation-triangle"></i> Impact</h4>
                        <p>{finding.get('impact', 'Impact assessment pending.')}</p>
                    </div>
                    {steps_html}
                    <div class="finding-section">
                        <h4><i class="fas fa-lightbulb"></i> Remediation Summary</h4>
                        <p>{finding.get('remediation', 'Remediation guidance pending.')}</p>
                    </div>
                    {code_section}
                    <div class="finding-section">
                        <h4><i class="fas fa-book"></i> References</h4>
                        <ul style="list-style: none;">{refs_html}</ul>
                    </div>
                </div>
            </div>
            '''
            findings_html.append(finding_html)

        return ''.join(findings_html)

    def _build_owasp_coverage_table(self, findings: list[dict], modules: list[str]) -> str:
        """Build the OWASP coverage table."""
        from utils.owasp_top10 import OWASP_2025_ROWS, finding_count_for_code, modules_exercising_code, was_category_tested

        rows = ['<table class="data-table"><thead><tr><th>Rank</th><th>Category</th><th>Tested</th><th>Modules</th><th>Findings</th></tr></thead><tbody>']

        for row in OWASP_2025_ROWS:
            code = row["code"]
            tested = "Yes" if was_category_tested(modules, code) else "No"
            mods = ", ".join(modules_exercising_code(modules, code)) or "—"
            n = finding_count_for_code(findings, code)
            tested_color = "#16a34a" if was_category_tested(modules, code) else "#dc2626"

            rows.append(f'''<tr><td><strong>{row["id"]}</strong></td><td>{row["name"]}</td>
                <td style="color: {tested_color}; font-weight: 600;">{tested}</td>
                <td style="font-size: 12px; color: var(--text-muted);">{mods}</td>
                <td><strong style="color: {'#dc2626' if n > 0 else 'var(--text-muted)'};">{n}</strong></td></tr>''')

        rows.append('</tbody></table>')
        return ''.join(rows)

    def _find_screenshot(self, finding_id: str, screenshots_dir: str) -> Optional[str]:
        """Find screenshot for a finding."""
        screenshots_path = Path(screenshots_dir)
        if not screenshots_path.exists():
            return None

        for ext in ['.html', '.png', '.jpg']:
            matches = list(screenshots_path.glob(f"proof_{finding_id}*{ext}"))
            if matches:
                return str(matches[0])
            matches = list(screenshots_path.glob(f"*{finding_id}*{ext}"))
            if matches:
                return str(matches[0])
        return None

    def generate_pdf_from_html(self, html_path: str, pdf_output: str) -> Optional[str]:
        """Convert HTML to PDF using WeasyPrint."""
        if not _check_weasyprint():
            print("[!] PDF conversion unavailable: WeasyPrint/GTK3 not installed")
            return None

        try:
            output_path = Path(pdf_output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            _WeasyHTML(html_path).write_pdf(str(output_path))
            return str(output_path)
        except Exception as e:
            print(f"PDF generation failed: {e}")
            return None


def build_html_report(*_args, **_kwargs) -> str:
    """Legacy function for compatibility."""
    gen = HTMLReportGenerator()
    return gen.generate_report(
        output_path=kwargs.get('output_path', 'report.html'),
        target_url=kwargs.get('target_url', ''),
        findings=kwargs.get('findings', []),
        metadata=kwargs.get('metadata', {}),
        screenshots_dir=kwargs.get('screenshots_dir', 'screenshots'),
    )