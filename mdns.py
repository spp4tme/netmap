#!/usr/bin/env python3
"""
mDNS/Bonjour discovery — stdlib uniquement.
Multicast DNS (RFC 6762) : 224.0.0.251:5353.
Envoie une requête PTR pour _services._dns-sd._udp.local et collecte
les réponses (PTR, SRV, A) pendant LISTEN_TIMEOUT secondes.
"""

import socket
import struct
import time

MDNS_ADDR      = "224.0.0.251"
MDNS_PORT      = 5353
LISTEN_TIMEOUT = 5.0
SERVICES_NAME  = "_services._dns-sd._udp.local"

_TYPE_A   = 1
_TYPE_PTR = 12
_TYPE_SRV = 33


# ── DNS wire format ───────────────────────────────────────────────────────────

def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode()
        out += bytes([len(enc)]) + enc
    return out + b"\x00"


def _decode_name(data: bytes, offset: int, _depth: int = 0) -> tuple[str, int]:
    if _depth > 16:
        return "", offset
    labels: list[str] = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            sub, _ = _decode_name(data, ptr, _depth + 1)
            if sub:
                labels.append(sub)
            break
        offset += 1
        end = offset + length
        if end > len(data):
            break
        labels.append(data[offset:end].decode("utf-8", errors="replace"))
        offset = end
    return ".".join(labels), offset


def _build_ptr_query(name: str) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", _TYPE_PTR, 1)


def _parse_packet(data: bytes) -> dict:
    """
    Retourne {"a": [(name, ip)], "ptr": [(name, target)], "srv": [(name, port, target)]}.
    """
    out: dict = {"a": [], "ptr": [], "srv": []}
    if len(data) < 12:
        return out
    try:
        qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHH", data, 4)
        offset = 12

        for _ in range(qdcount):
            _, offset = _decode_name(data, offset)
            offset += 4  # QTYPE + QCLASS

        for _ in range(ancount + nscount + arcount):
            if offset >= len(data):
                break
            name, offset = _decode_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            rdata_start = offset
            offset += rdlen
            if offset > len(data):
                break

            if rtype == _TYPE_A and rdlen == 4:
                out["a"].append((name, socket.inet_ntoa(data[rdata_start:rdata_start + 4])))

            elif rtype == _TYPE_PTR:
                target, _ = _decode_name(data, rdata_start)
                out["ptr"].append((name, target))

            elif rtype == _TYPE_SRV and rdlen >= 7:
                port = struct.unpack_from("!H", data, rdata_start + 4)[0]
                target, _ = _decode_name(data, rdata_start + 6)
                out["srv"].append((name, port, target))
    except Exception:
        pass
    return out


# ── Scanner ───────────────────────────────────────────────────────────────────

def scan(timeout: float = LISTEN_TIMEOUT) -> dict[str, dict]:
    """
    Découvre les appareils via mDNS/Bonjour.
    Retourne {ip: {"hostname": str, "services": [str]}}.
    """
    seen:         dict[str, dict] = {}  # ip → {hostname, services}
    host_to_ips:  dict[str, set]  = {}  # hostname → {ip, …}
    ip_to_host:   dict[str, str]  = {}  # ip → hostname (enregistrements A)
    inst_to_svc:  dict[str, str]  = {}  # instance_service → type_service (PTR)
    inst_to_host: dict[str, str]  = {}  # instance_service → hostname (SRV)

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.bind(("", MDNS_PORT))
        mreq = struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.settimeout(0.5)

        print(f"  Requête PTR → {SERVICES_NAME}")
        print(f"  Écoute {timeout:.0f}s sur {MDNS_ADDR}:{MDNS_PORT} …", flush=True)
        sock.sendto(_build_ptr_query(SERVICES_NAME), (MDNS_ADDR, MDNS_PORT))

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            if src_ip.startswith("127.") or src_ip.startswith("169.254."):
                continue

            seen.setdefault(src_ip, {"hostname": "", "services": []})
            recs = _parse_packet(data)

            for name, ip in recs["a"]:
                h = name.lower().rstrip(".")
                host_to_ips.setdefault(h, set()).add(ip)
                ip_to_host.setdefault(ip, h)

            for name, target in recs["ptr"]:
                nl = name.lower().rstrip(".")
                tl = target.lower().rstrip(".")
                if "_services._dns-sd" not in nl:
                    inst_to_svc.setdefault(tl, nl)

            for name, _port, target in recs["srv"]:
                inst_to_host.setdefault(name.lower().rstrip("."), target.lower().rstrip("."))

    except OSError as exc:
        print(f"  [mDNS] Avertissement : {exc}")
    finally:
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP,
                                struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY))
            except OSError:
                pass
            sock.close()

    # ── Post-traitement ───────────────────────────────────────────────────────

    # Hostname depuis enregistrements A (src_ip direct)
    for ip, entry in seen.items():
        if not entry["hostname"]:
            entry["hostname"] = ip_to_host.get(ip, "")

    # Services via chaîne PTR → SRV → A
    for inst, svc in inst_to_svc.items():
        host = inst_to_host.get(inst)
        if not host:
            continue
        for ip in host_to_ips.get(host, set()):
            if ip.startswith("127.") or ip.startswith("169.254."):
                continue
            if ip not in seen:
                seen[ip] = {"hostname": host, "services": []}
            if svc not in seen[ip]["services"]:
                seen[ip]["services"].append(svc)

    # Appareils connus uniquement via enregistrements A (pas de src_ip direct)
    for host, ips in host_to_ips.items():
        for ip in ips:
            if not ip.startswith("127.") and not ip.startswith("169.254.") and ip not in seen:
                seen[ip] = {"hostname": host, "services": []}

    return seen
