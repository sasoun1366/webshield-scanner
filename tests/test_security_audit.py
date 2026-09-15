from src.security_audit import CommandResult, audit_linux, audit_windows


def linux_runner(command, timeout=15):
    text = " ".join(command)
    if "os-release" in text:
        return CommandResult('"Ubuntu 24.04 LTS"')
    if "uname" in text:
        return CommandResult("Linux 6.8")
    if "apt-get" in text:
        return CommandResult("")
    if "firewall" in text or "nft" in text or "iptables" in text:
        return CommandResult("Status: active")
    if "systemctl" in text:
        return CommandResult("inactive")
    if "sshd_config" in text:
        return CommandResult("no")
    return CommandResult("")


def test_linux_audit_is_read_only_and_reports_checks():
    findings, evidence = audit_linux(linux_runner)
    assert evidence["os"] == "Ubuntu 24.04 LTS"
    assert any(f.check == "Host firewall" and f.status == "pass" for f in findings)
    assert any(f.check == "SSH root login" for f in findings)


def windows_runner(script, timeout=20):
    if "Win32_OperatingSystem" in script:
        return CommandResult('{"Caption":"Microsoft Windows 11","Version":"10.0","BuildNumber":"22631"}')
    if "Get-NetFirewallProfile" in script:
        return CommandResult('[{"Name":"Domain","Enabled":true},{"Name":"Private","Enabled":true},{"Name":"Public","Enabled":true}]')
    if "Get-HotFix" in script:
        return CommandResult('{"HotFixID":"KB0000001"}')
    if "fDenyTSConnections" in script:
        return CommandResult('{"fDenyTSConnections":1}')
    return CommandResult("")


def test_windows_audit_reports_firewall():
    findings, evidence = audit_windows(windows_runner)
    assert "Windows 11" in evidence["os"]
    assert any(f.check == "Windows Firewall" and f.status == "pass" for f in findings)
    assert any(f.check == "Remote Desktop" and f.status == "pass" for f in findings)
