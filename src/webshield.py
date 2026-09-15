from __future__ import annotations

import argparse
import html
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS helps enforce HTTPS.",
    "Content-Security-Policy": "CSP reduces script injection risk.",
    "X-Content-Type-Options": "nosniff reduces MIME confusion.",
    "X-Frame-Options": "Helps prevent clickjacking.",
    "Referrer-Policy": "Limits referrer information leakage.",
    "Permissions-Policy": "Restricts sensitive browser features.",
}

@dataclass
class Finding:
    check: str
    status: str
    severity: str
    details: str
    recommendation: str


def validate_target(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be a valid http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not allowed")
    return parsed.geturl()


def scan(url: str, timeout: float = 10.0) -> dict[str, Any]:
    target = validate_target(url)
    started = datetime.now(timezone.utc).isoformat()
    response = requests.get(
        target,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "WebShield-Scanner/1.0 (authorized defensive audit)"},
    )
    headers = {k: v for k, v in response.headers.items()}
    findings: list[Finding] = []
    final_url = response.url

    if urlparse(target).scheme != "https":
        findings.append(Finding("HTTPS", "fail", "high", "Target starts over HTTP.", "Serve the site over HTTPS and redirect HTTP to HTTPS."))
    else:
        findings.append(Finding("HTTPS", "pass", "info", "Target uses HTTPS.", "Keep certificates valid and renew them before expiry."))

    lower_headers = {k.lower(): v for k, v in headers.items()}
    for name, explanation in SECURITY_HEADERS.items():
        value = lower_headers.get(name.lower())
        if value:
            findings.append(Finding(name, "pass", "info", f"Header present: {value[:240]}", explanation))
        else:
            sev = "medium" if name in {"Content-Security-Policy", "Strict-Transport-Security"} else "low"
            findings.append(Finding(name, "fail", sev, "Header not found in the response.", explanation))

    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        cookie_lower = set_cookie.lower()
        for flag, severity, recommendation in [
            ("secure", "medium", "Mark session cookies Secure so browsers send them only over HTTPS."),
            ("httponly", "medium", "Mark session cookies HttpOnly to reduce script access."),
            ("samesite", "low", "Set SameSite=Lax or Strict where compatible."),
        ]:
            present = re.search(rf"(?:^|;|,)\s*{flag}(?:=|;|,|$)", cookie_lower) is not None
            findings.append(Finding(f"Cookie {flag}", "pass" if present else "warn", severity, "Flag detected." if present else "Flag not detected in Set-Cookie.", recommendation))
    else:
        findings.append(Finding("Session cookies", "info", "info", "No Set-Cookie header observed on this response.", "Review authenticated endpoints separately if applicable."))

    return {
        "tool": "WebShield Scanner",
        "version": "1.0.0",
        "scan_started_utc": started,
        "target": target,
        "final_url": final_url,
        "status_code": response.status_code,
        "server": headers.get("Server", "not disclosed"),
        "findings": [asdict(f) for f in findings],
        "scope_note": "Passive single-request review only. No exploitation, brute force, crawling, or destructive tests performed.",
    }


def write_html(report: dict[str, Any], path: Path) -> None:
    rows = []
    for finding in report["findings"]:
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(finding[k]))}</td>" for k in ("check", "status", "severity", "details", "recommendation")) + "</tr>")
    document = f"""<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>WebShield Report</title>
<style>body{{font-family:system-ui;max-width:1100px;margin:2rem auto;color:#14213d}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #d8dee9;padding:.6rem;text-align:left}}th{{background:#14213d;color:#fff}}.note{{background:#eef6ff;padding:1rem;border-radius:8px}}</style>
<h1>WebShield Scanner Report</h1><p><b>Target:</b> {html.escape(report['target'])}<br><b>Final URL:</b> {html.escape(report['final_url'])}<br><b>Status:</b> {report['status_code']}</p><p class=\"note\">{html.escape(report['scope_note'])}</p>
<table><thead><tr><th>Check</th><th>Status</th><th>Severity</th><th>Details</th><th>Recommendation</th></tr></thead><tbody>{''.join(rows)}</tbody></table></html>"""
    path.write_text(document, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive defensive HTTP security header scanner")
    parser.add_argument("url", help="Authorized http(s) URL")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--json", dest="json_path", default="report.json")
    parser.add_argument("--html", dest="html_path", default="report.html")
    args = parser.parse_args()
    report = scan(args.url, args.timeout)
    Path(args.json_path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_html(report, Path(args.html_path))
    print(json.dumps({"target": report["target"], "status_code": report["status_code"], "findings": len(report["findings"]), "json": args.json_path, "html": args.html_path}, ensure_ascii=False))

if __name__ == "__main__":
    main()

# Product safety: this module performs one passive request to a user-supplied target.
# Use it only on systems you own or are explicitly authorized to assess.
