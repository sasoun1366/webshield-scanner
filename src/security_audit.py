"""WebShield Security Audit: read-only local and authorized remote host checks.

This module intentionally uses an allowlist of diagnostic commands. It does not
exploit services, brute-force credentials, change configuration, or download
payloads. Use only on systems you own or are explicitly authorized to assess.
"""
from __future__ import annotations

import argparse
import html
import json
import platform
import shlex
import shutil
import socket
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


@dataclass
class Finding:
    check: str
    status: str
    severity: str
    details: str
    recommendation: str


@dataclass
class CommandResult:
    output: str = ""
    error: str = ""
    returncode: int = 0


class AuditError(RuntimeError):
    pass


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_local(command: list[str], timeout: int = 15) -> CommandResult:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return CommandResult(proc.stdout.strip(), proc.stderr.strip(), proc.returncode)
    except FileNotFoundError:
        return CommandResult(error=f"Command not found: {command[0]}", returncode=127)
    except subprocess.TimeoutExpired:
        return CommandResult(error="Command timed out", returncode=124)
    except OSError as exc:
        return CommandResult(error=str(exc), returncode=1)


def _run_powershell(script: str, timeout: int = 20) -> CommandResult:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return CommandResult(error="PowerShell was not found", returncode=127)
    return _run_local([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], timeout)


def _first_line(result: CommandResult) -> str:
    return (result.output or result.error or "unavailable").splitlines()[0][:500]


def _finding(check: str, status: str, severity: str, details: str, recommendation: str) -> Finding:
    return Finding(check, status, severity, details[:1000], recommendation)


def audit_linux(run: Callable[[list[str], int], CommandResult] = _run_local) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    evidence: dict[str, Any] = {}

    release = run(["sh", "-c", "cat /etc/os-release 2>/dev/null | sed -n 's/^PRETTY_NAME=//p' | head -1"], 10)
    evidence["os"] = _first_line(release).strip('"')
    kernel = run(["uname", "-sr"], 10)
    evidence["kernel"] = _first_line(kernel)

    updates = run(["sh", "-c", "if command -v apt-get >/dev/null; then apt-get -s upgrade 2>/dev/null | sed -n 's/^The following packages will be upgraded: //p'; elif command -v dnf >/dev/null; then dnf -q check-update 2>/dev/null | head -20; elif command -v yum >/dev/null; then yum -q check-update 2>/dev/null | head -20; else echo 'package manager unavailable'; fi"], 20)
    evidence["pending_updates"] = updates.output[:2000]
    if updates.returncode in (0, 100) and updates.output.strip() and "package manager unavailable" not in updates.output:
        findings.append(_finding("Security updates", "warn", "medium", "The package manager reports pending updates.", "Review and apply updates through the distribution's normal change process."))
    else:
        findings.append(_finding("Security updates", "pass", "info", "No pending updates were reported by the available package-manager check, or the check was inconclusive.", "Keep automatic or scheduled security updates enabled."))

    firewall = run(["sh", "-c", "if command -v ufw >/dev/null; then ufw status 2>/dev/null; elif command -v firewall-cmd >/dev/null; then firewall-cmd --state 2>/dev/null; elif command -v nft >/dev/null; then nft list ruleset 2>/dev/null | head -40; elif command -v iptables >/dev/null; then iptables -S 2>/dev/null | head -40; else echo 'firewall tool unavailable'; fi"], 15)
    evidence["firewall"] = firewall.output[:4000]
    fw = firewall.output.lower()
    if "inactive" in fw or "not running" in fw or ("firewall tool unavailable" not in fw and not firewall.output.strip()):
        findings.append(_finding("Host firewall", "fail", "high", "A local firewall appears inactive.", "Enable and review a host firewall such as ufw, firewalld, or nftables."))
    elif "unavailable" in fw:
        findings.append(_finding("Host firewall", "warn", "medium", "No supported firewall command was found; status could not be confirmed.", "Confirm firewall policy with the system administrator."))
    else:
        findings.append(_finding("Host firewall", "pass", "info", "A firewall command returned an active or configured ruleset.", "Review rules periodically and restrict inbound services."))

    ssh = run(["sh", "-c", "if command -v systemctl >/dev/null; then systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || true; else echo unavailable; fi"], 10)
    evidence["ssh_service"] = _first_line(ssh)
    if ssh.output.strip() == "active":
        findings.append(_finding("SSH exposure", "warn", "medium", "The SSH service is active.", "Restrict SSH to trusted networks, disable password login where practical, and use key-based authentication with MFA or a bastion."))
    else:
        findings.append(_finding("SSH exposure", "pass", "info", "SSH was not reported as active by the service check.", "If SSH is required, harden and restrict it rather than exposing it broadly."))

    root_login = run(["sh", "-c", "if [ -r /etc/ssh/sshd_config ]; then awk 'tolower($1)==\"permitrootlogin\" {print $2}' /etc/ssh/sshd_config | tail -1; else echo unavailable; fi"], 10)
    evidence["permit_root_login"] = _first_line(root_login)
    if root_login.output.lower() in {"yes", "without-password", "prohibit-password"}:
        findings.append(_finding("SSH root login", "fail", "high", f"PermitRootLogin is set to {root_login.output}.", "Disable direct root SSH login and use a named administrator account with least privilege."))
    else:
        findings.append(_finding("SSH root login", "pass", "info", "Direct root SSH login was not enabled by the inspected setting.", "Keep root SSH login disabled."))
    return findings, evidence


def audit_windows(run_ps: Callable[[str, int], CommandResult] = _run_powershell) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    evidence: dict[str, Any] = {}
    info = run_ps("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | ConvertTo-Json -Compress", 15)
    evidence["os"] = _first_line(info)

    firewall = run_ps("Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress", 20)
    evidence["firewall"] = firewall.output[:4000]
    if firewall.returncode != 0:
        findings.append(_finding("Windows Firewall", "warn", "medium", "Windows Firewall profile status could not be read.", "Run the audit with an account allowed to read firewall policy."))
    else:
        try:
            profiles = json.loads(firewall.output)
            if isinstance(profiles, dict): profiles = [profiles]
            disabled = [p.get("Name", "unknown") for p in profiles if not p.get("Enabled")]
            if disabled:
                findings.append(_finding("Windows Firewall", "fail", "high", f"Disabled profiles: {', '.join(disabled)}.", "Enable firewall profiles and review inbound rules."))
            else:
                findings.append(_finding("Windows Firewall", "pass", "info", "All reported firewall profiles are enabled.", "Keep inbound rules restrictive and review exceptions."))
        except (json.JSONDecodeError, TypeError):
            findings.append(_finding("Windows Firewall", "warn", "medium", "Firewall output was not parseable.", "Review firewall status in Windows Security or PowerShell."))

    hotfix = run_ps("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID,InstalledOn | ConvertTo-Json -Compress", 20)
    evidence["recent_hotfixes"] = hotfix.output[:2500]
    findings.append(_finding("Windows updates", "info", "info", "Recent installed hotfix information was collected; this is not a complete patch-compliance determination.", "Use Windows Update/management tooling to confirm all security updates are approved and installed."))

    rdp = run_ps(r"Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue | Select-Object fDenyTSConnections | ConvertTo-Json -Compress", 15)
    evidence["rdp"] = _first_line(rdp)
    if '"fDenyTSConnections":0' in rdp.output.replace(" ", ""):
        findings.append(_finding("Remote Desktop", "warn", "medium", "Remote Desktop appears enabled.", "Restrict RDP to a VPN or management subnet, require Network Level Authentication, and use MFA."))
    else:
        findings.append(_finding("Remote Desktop", "pass", "info", "Remote Desktop was not reported as enabled by the inspected setting.", "Keep RDP disabled unless it is required and restricted."))
    return findings, evidence


def audit_local() -> dict[str, Any]:
    system = platform.system().lower()
    if system == "linux":
        findings, evidence = audit_linux()
    elif system == "windows":
        findings, evidence = audit_windows()
    else:
        raise AuditError(f"Unsupported local operating system: {platform.system()}")
    return build_report("local", system, findings, evidence)


def _ssh_runner(host: str, user: str, port: int = 22, identity: str | None = None) -> Callable[[list[str], int], CommandResult]:
    if not host or not user: raise AuditError("SSH host and user are required")
    def run(command: list[str], timeout: int = 15) -> CommandResult:
        # The audit passes only fixed shell snippets constructed in this module.
        remote = " ".join(shlex.quote(x) for x in command)
        args = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-p", str(port)]
        if identity: args += ["-i", identity]
        args += [f"{user}@{host}", "--", remote]
        return _run_local(args, timeout)
    return run


def audit_remote_linux(host: str, user: str, port: int = 22, identity: str | None = None) -> dict[str, Any]:
    findings, evidence = audit_linux(_ssh_runner(host, user, port, identity))
    report = build_report("remote-ssh", "linux", findings, evidence)
    report["connection"] = {"transport": "ssh", "host": host, "user": user, "port": port}
    return report


def audit_remote_windows(host: str, user: str, password: str, port: int = 5986, use_ssl: bool = True) -> dict[str, Any]:
    try:
        import winrm  # type: ignore
    except ImportError as exc:
        raise AuditError("Remote Windows auditing requires optional dependency pywinrm") from exc
    scheme = "https" if use_ssl else "http"
    endpoint = f"{scheme}://{host}:{port}/wsman"
    session = winrm.Session(endpoint, auth=(user, password), transport="ntlm", server_cert_validation="validate" if use_ssl else "ignore")
    def run_ps(script: str, timeout: int = 20) -> CommandResult:
        try:
            result = session.run_ps(script)
            return CommandResult(result.std_out.decode(errors="replace").strip(), result.std_err.decode(errors="replace").strip(), result.status_code)
        except Exception as exc:  # connection libraries expose several exception types
            return CommandResult(error=str(exc), returncode=1)
    findings, evidence = audit_windows(run_ps)
    report = build_report("remote-winrm", "windows", findings, evidence)
    report["connection"] = {"transport": "winrm", "host": host, "user": user, "port": port, "ssl": use_ssl}
    return report


def build_report(scope: str, operating_system: str, findings: list[Finding], evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool": "WebShield Security Audit",
        "version": "1.0.0",
        "scan_started_utc": now_utc(),
        "scope": scope,
        "operating_system": operating_system,
        "findings": [asdict(x) for x in findings],
        "evidence": evidence,
        "safety_note": "Read-only defensive checks only. No exploitation, brute force, crawling, payload execution, or configuration changes were performed.",
    }


def write_html(report: dict[str, Any], path: Path) -> None:
    rows = []
    for f in report["findings"]:
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(f.get(k, '')))}</td>" for k in ("check", "status", "severity", "details", "recommendation")) + "</tr>")
    title = html.escape(report["tool"])
    body = f"""<!doctype html><html lang='en'><meta charset='utf-8'><title>{title}</title>
<style>body{{font-family:system-ui;max-width:1200px;margin:2rem auto;color:#14213d}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #d8dee9;padding:.6rem;text-align:left;vertical-align:top}}th{{background:#14213d;color:white}}.note{{background:#eef6ff;padding:1rem;border-radius:8px}}pre{{white-space:pre-wrap;background:#f6f8fa;padding:1rem}}</style>
<h1>{title}</h1><p><b>Scope:</b> {html.escape(str(report['scope']))} &nbsp; <b>OS:</b> {html.escape(str(report['operating_system']))}</p>
<p class='note'>{html.escape(report['safety_note'])}</p><table><thead><tr><th>Check</th><th>Status</th><th>Severity</th><th>Details</th><th>Recommendation</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<h2>Evidence</h2><pre>{html.escape(json.dumps(report.get('evidence', {}), ensure_ascii=False, indent=2))}</pre></html>"""
    path.write_text(body, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Authorized, read-only WebShield host security audit")
    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("local", help="Audit this Windows or Linux host")
    ssh = sub.add_parser("ssh", help="Audit an authorized Linux host over SSH")
    ssh.add_argument("host"); ssh.add_argument("--user", required=True); ssh.add_argument("--port", type=int, default=22); ssh.add_argument("--identity")
    win = sub.add_parser("winrm", help="Audit an authorized Windows host over WinRM")
    win.add_argument("host"); win.add_argument("--user", required=True); win.add_argument("--password", required=True); win.add_argument("--port", type=int, default=5986); win.add_argument("--no-ssl", action="store_true")
    for command in (sub.choices.values()):
        command.add_argument("--json", default="security-audit.json")
        command.add_argument("--html", default="security-audit.html")
    args = parser.parse_args()
    if args.mode == "local": report = audit_local()
    elif args.mode == "ssh": report = audit_remote_linux(args.host, args.user, args.port, args.identity)
    else: report = audit_remote_windows(args.host, args.user, args.password, args.port, not args.no_ssl)
    Path(args.json).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_html(report, Path(args.html))
    print(json.dumps({"scope": report["scope"], "os": report["operating_system"], "findings": len(report["findings"]), "json": args.json, "html": args.html}, ensure_ascii=False))


if __name__ == "__main__":
    main()
