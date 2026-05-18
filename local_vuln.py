#!/usr/bin/env python3
"""
Local vulnerability detection without CVE lookups.
Hard-coded rules: Telnet, cleartext FTP, SMB exposure,
anonymous FTP, unauthenticated HTTP admin paths, SSL cert issues.
Stdlib only.
"""

import ftplib
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ── Rule catalogue ─────────────────────────────────────────────────────────────

_PORT_RULES = [
    {
        "port": 23, "protocol": "Telnet",
        "severity": "CRITICAL", "cvss": 9.8,
        "title": "Telnet cleartext protocol exposed",
        "desc":  "Port 23 open: Telnet transmits credentials and data in plaintext.",
    },
    {
        "port": 21, "protocol": "FTP",
        "severity": "HIGH", "cvss": 7.5,
        "title": "FTP cleartext protocol exposed",
        "desc":  "Port 21 open: FTP transmits credentials in plaintext. Use SFTP or FTPS.",
    },
    {
        "port": 445, "protocol": "SMB",
        "severity": "HIGH", "cvss": 7.5,
        "title": "SMB port exposed",
        "desc":  "Port 445 open: SMB exposure can lead to lateral movement (EternalBlue, etc.).",
    },
    {
        "port": 3389, "protocol": "RDP",
        "severity": "HIGH", "cvss": 7.5,
        "title": "RDP exposed to network",
        "desc":  "Port 3389 open: RDP brute-force and BlueKeep-style vulnerabilities apply.",
    },
    {
        "port": 5900, "protocol": "VNC",
        "severity": "HIGH", "cvss": 7.2,
        "title": "VNC exposed to network",
        "desc":  "Port 5900 open: VNC is often poorly authenticated or unencrypted.",
    },
    {
        "port": 135, "protocol": "MSRPC",
        "severity": "MEDIUM", "cvss": 5.3,
        "title": "MS-RPC endpoint mapper exposed",
        "desc":  "Port 135 open: Windows RPC endpoint mapper should not be internet-facing.",
    },
    {
        "port": 139, "protocol": "NetBIOS",
        "severity": "MEDIUM", "cvss": 5.3,
        "title": "NetBIOS session service exposed",
        "desc":  "Port 139 open: Legacy NetBIOS/SMB service; disable if unused.",
    },
    {
        "port": 80, "protocol": "HTTP",
        "severity": "LOW", "cvss": 3.1,
        "title": "Unencrypted HTTP service",
        "desc":  "Port 80 open: Consider redirecting to HTTPS.",
    },
]

_HTTP_PATHS = [
    "/admin", "/admin/", "/manager/html", "/manager/",
    "/phpmyadmin", "/phpmyadmin/", "/wp-admin/", "/setup",
    "/console", "/.env", "/config", "/api/v1/admin",
]

_SSL_TIMEOUT  = 5.0
_HTTP_TIMEOUT = 4.0

# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_finding(title: str, desc: str, severity: str, cvss: float,
                  port: int = 0, extra: str = "") -> dict:
    return {
        "title":    title,
        "desc":     (desc + "  " + extra).strip(),
        "severity": severity,
        "cvss":     cvss,
        "port":     port,
        "source":   "local",
    }

# ── Checks ─────────────────────────────────────────────────────────────────────

def _check_port_rules(port_results: dict) -> list[dict]:
    findings = []
    open_ports = {p for p, r in port_results.items() if r.get("state") == "open"}
    for rule in _PORT_RULES:
        if rule["port"] in open_ports:
            findings.append(_make_finding(
                rule["title"], rule["desc"],
                rule["severity"], rule["cvss"],
                port=rule["port"],
            ))
    return findings


def _check_smb_v1(port_results: dict) -> list[dict]:
    findings = []
    r = port_results.get(445, {})
    if r.get("state") == "open" and "SMBv1" in r.get("version", ""):
        findings.append(_make_finding(
            "SMBv1 detected",
            "SMBv1 is vulnerable to EternalBlue (MS17-010). Disable immediately.",
            severity="CRITICAL", cvss=9.8, port=445,
        ))
    return findings


def _check_anon_ftp(ip: str, timeout: float) -> list[dict]:
    findings = []
    try:
        ftp = ftplib.FTP(timeout=timeout)
        ftp.connect(ip, 21, timeout=timeout)
        ftp.login()          # anonymous / anonymous@
        ftp.quit()
        findings.append(_make_finding(
            "Anonymous FTP login allowed",
            "FTP server accepts anonymous credentials. Files may be readable or writable.",
            severity="HIGH", cvss=7.5, port=21,
        ))
    except ftplib.error_perm:
        pass   # login refused → not anonymous
    except Exception:
        pass   # connection error, timeout, etc.
    return findings


def _check_http_paths(ip: str, port: int, timeout: float) -> list[dict]:
    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    for path in _HTTP_PATHS:
        url = f"{scheme}://{ip}:{port}{path}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "netmap/1.0"})
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception:
            continue

        if code in (200, 201, 204):
            findings.append(_make_finding(
                f"Unauthenticated access: {path}",
                f"HTTP {code} returned for {path} on port {port} without authentication.",
                severity="HIGH", cvss=7.2, port=port,
                extra=f"URL: {url}",
            ))
        elif code in (401, 403):
            pass   # auth required / forbidden — expected
    return findings


def _check_ssl_cert(ip: str, port: int, timeout: float) -> list[dict]:
    findings = []
    ctx_strict = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx_strict.wrap_socket(raw, server_hostname=ip):
                pass   # valid cert — no finding
    except ssl.SSLCertVerificationError as e:
        msg = str(e).lower()
        if "expired" in msg or "certificate has expired" in msg:
            findings.append(_make_finding(
                "Expired SSL/TLS certificate",
                f"TLS certificate on port {port} is expired.",
                severity="HIGH", cvss=7.4, port=port,
            ))
        elif "self-signed" in msg or "self signed" in msg or "unable to get local issuer" in msg:
            findings.append(_make_finding(
                "Self-signed SSL/TLS certificate",
                f"TLS certificate on port {port} is self-signed (untrusted CA).",
                severity="MEDIUM", cvss=5.9, port=port,
            ))
        else:
            findings.append(_make_finding(
                "Invalid SSL/TLS certificate",
                f"TLS certificate on port {port} failed validation: {str(e)[:80]}",
                severity="MEDIUM", cvss=5.9, port=port,
            ))
    except (ConnectionRefusedError, socket.timeout, OSError):
        pass
    except ssl.SSLError:
        findings.append(_make_finding(
            "SSL/TLS handshake error",
            f"TLS handshake failed on port {port}. Possible protocol mismatch.",
            severity="LOW", cvss=3.7, port=port,
        ))
    return findings

# ── Public API ─────────────────────────────────────────────────────────────────

def audit(ip: str, port_results: dict, timeout: float = 3.0) -> list[dict]:
    """
    Run all local vulnerability checks against a discovered host.
    Returns list of finding dicts: {title, desc, severity, cvss, port, source}.
    """
    findings = []

    # Static port rules
    findings += _check_port_rules(port_results)
    findings += _check_smb_v1(port_results)

    open_ports = {p for p, r in port_results.items() if r.get("state") == "open"}

    # Anonymous FTP
    if 21 in open_ports:
        findings += _check_anon_ftp(ip, timeout)

    # HTTP admin paths
    for port in (80, 443, 8080, 8443):
        if port in open_ports:
            findings += _check_http_paths(ip, port, timeout)

    # SSL certificate checks
    for port in (443, 8443, 993, 995, 465, 587):
        if port in open_ports:
            findings += _check_ssl_cert(ip, port, timeout)

    # Deduplicate by title+port
    seen: set[tuple] = set()
    deduped = []
    for f in findings:
        key = (f["title"], f["port"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    deduped.sort(key=lambda f: -f["cvss"])
    return deduped


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 local_vuln.py <ip>")
        sys.exit(1)
    ip = sys.argv[1]
    ports_open = {21, 22, 80, 443, 445, 23}
    fake_results = {p: {"state": "open", "version": ""} for p in ports_open}
    results = audit(ip, fake_results)
    print(f"\n{len(results)} finding(s) for {ip}\n")
    for f in results:
        print(f"  [{f['severity']:8}] CVSS={f['cvss']}  {f['title']}")
        print(f"             {f['desc'][:80]}")
