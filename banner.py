#!/usr/bin/env python3
"""
Banner grabbing via connexion TCP réelle — stdlib uniquement.
Pour chaque port ouvert : connexion, lecture des premiers octets,
identification du service et de sa version.
"""

import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ports qui parlent TLS d'emblée
_SSL_PORTS = {443, 8443, 465, 993, 995}

# Probe HTTP envoyé si le serveur ne parle pas en premier
_HTTP_PROBE = b"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: netmap/1.0\r\nAccept: */*\r\n\r\n"

# ── Identification ─────────────────────────────────────────────────────────────

def _clean(raw: bytes, maxlen: int = 120) -> str:
    """Transforme des octets bruts en texte affichable."""
    s = raw.decode("latin-1")
    return "".join(c if c.isprintable() else " " for c in s)[:maxlen].strip()


def _identify(raw: bytes, port: int) -> tuple[str, str, str]:
    """
    Retourne (service, version, banner_affichable) depuis les premiers octets reçus.
    Couvre : SSH, FTP, SMTP, POP3, IMAP, HTTP/S, Telnet, SMB, VNC, Redis, MySQL.
    """
    if not raw:
        return "unknown", "", ""

    banner_text = _clean(raw)

    # SSH — "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    if raw.startswith(b"SSH-"):
        line   = raw.split(b"\n")[0].decode(errors="replace").strip()
        parts  = line.split("-", 2)
        version = parts[2] if len(parts) >= 3 else line
        return "SSH", version[:60], banner_text

    # FTP / SMTP — "220 vsftpd 3.0.3"
    if raw[:4] in (b"220 ", b"220-"):
        line = raw.split(b"\n")[0].decode(errors="replace").strip()
        svc  = "SMTP" if port in {25, 465, 587} else "FTP"
        return svc, line[4:64].strip(), banner_text

    # POP3 — "+OK Dovecot ready"
    if raw.startswith(b"+OK"):
        line = raw.split(b"\n")[0].decode(errors="replace").strip()
        return "POP3", line[3:60].strip(), banner_text

    # IMAP — "* OK Dovecot ready"
    if raw.startswith(b"* OK"):
        line = raw.split(b"\n")[0].decode(errors="replace").strip()
        return "IMAP", line[4:60].strip(), banner_text

    # HTTP response
    if raw.startswith(b"HTTP/"):
        m   = re.search(rb"[Ss]erver:\s*([^\r\n]+)", raw)
        srv = m.group(1).decode(errors="replace").strip()[:60] if m else ""
        svc = "HTTPS" if port in _SSL_PORTS else "HTTP"
        return svc, srv, banner_text

    # Telnet — IAC negotiations
    if raw[0] == 0xFF and len(raw) >= 2 and raw[1] in (0xFD, 0xFB, 0xFA, 0xFC, 0xFE):
        return "Telnet", "", banner_text

    # SMB — signature après 4 octets NetBIOS length
    if len(raw) > 8:
        sig = raw[4:8]
        if sig == b"\xff\x53\x4d\x42":
            return "SMB", "SMBv1", banner_text
        if sig == b"\xfe\x53\x4d\x42":
            return "SMB", "SMBv2/3", banner_text

    # VNC — "RFB 003.008\n"
    if raw.startswith(b"RFB "):
        return "VNC", raw[:12].decode(errors="replace").strip(), banner_text

    # Redis — réponse inline ou RESP
    if raw[:4] in (b"-ERR", b"+PON", b"+OK\r") or (raw[0:1] in (b"*", b"$", b":")):
        return "Redis", "", banner_text

    # MySQL — greeting packet : 4B header + 0x0a + version\0
    if len(raw) > 5 and raw[4] == 0x0A:
        try:
            end = raw.index(b"\x00", 5)
            ver = raw[5:end].decode(errors="replace")
            if re.match(r"[\d.]+", ver):
                return "MySQL", ver[:30], banner_text
        except ValueError:
            pass

    # PostgreSQL — 'N' (SSL neg. refused) suivi de rien, ou message d'erreur
    if len(raw) > 1 and raw[0] == ord("E") and b"PostgreSQL" in raw:
        return "PostgreSQL", "", banner_text

    return "unknown", "", banner_text


# ── Connexion ──────────────────────────────────────────────────────────────────

def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx

_SSL_CTX = _make_ssl_ctx()


def grab(ip: str, port: int, timeout: float = 2.0) -> dict:
    """
    Établit une connexion TCP réelle et lit les premiers octets.
    Retourne {'service': str, 'version': str, 'banner': str}.

    Stratégie :
    1. Connexion TCP (timeout global)
    2. Si port SSL : TLS handshake
    3. Lecture 2048 B avec timeout court (1.5 s)
    4. Si rien reçu → probe HTTP GET, lecture à nouveau
    5. Identification du service par pattern matching
    """
    result = {"service": "unknown", "version": "", "banner": ""}
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))

        sock: socket.socket | ssl.SSLSocket
        if port in _SSL_PORTS:
            sock = _SSL_CTX.wrap_socket(raw_sock, server_hostname=ip)
        else:
            sock = raw_sock

        sock.settimeout(min(timeout, 1.5))

        # Lecture initiale (le serveur parle en premier)
        try:
            raw = sock.recv(2048)
        except socket.timeout:
            raw = b""

        # Si rien reçu : probe HTTP
        if not raw:
            probe = _HTTP_PROBE.replace(b"{host}", ip.encode())
            try:
                sock.sendall(probe)
                raw = sock.recv(4096)
            except (socket.timeout, OSError):
                raw = b""

        sock.close()

        if raw:
            svc, ver, banner = _identify(raw, port)
            result = {"service": svc, "version": ver, "banner": banner}

    except ssl.SSLError:
        # Retry without TLS (some ports respond to plain on 443 in lab setups)
        result = {"service": "HTTPS", "version": "(TLS error)", "banner": ""}
    except (ConnectionRefusedError, OSError, socket.timeout):
        pass

    return result


def grab_all(ip: str, ports: list[int], timeout: float = 2.0, workers: int = 8) -> dict[int, dict]:
    """
    Lance le banner grabbing en parallèle sur tous les ports fournis.
    Retourne {port: {'service', 'version', 'banner'}}.
    """
    results: dict[int, dict] = {}
    n = min(len(ports), workers)
    if n == 0:
        return results
    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = {pool.submit(grab, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                results[port] = future.result()
            except Exception:
                results[port] = {"service": "unknown", "version": "", "banner": ""}
    return results


# ── Standalone ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 banner.py <ip> <port>[,port,...]", file=sys.stderr)
        sys.exit(1)
    target = sys.argv[1]
    plist  = list(map(int, sys.argv[2].split(",")))
    print(f"Banner grabbing {target} — ports {plist}\n")
    res = grab_all(target, plist)
    for p in sorted(res):
        r = res[p]
        print(f"  {p}/tcp  {r['service']:<12} {r['version'][:40]}")
        if r["banner"]:
            print(f"         {r['banner'][:80]}")
