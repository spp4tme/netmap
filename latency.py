#!/usr/bin/env python3
"""
Mesure de latence ICMP — raw sockets, stdlib uniquement.
Envoie N paquets ICMP echo request par hôte et retourne la latence moyenne.
Usage standalone : sudo python3 latency.py 192.168.1.1 192.168.1.254
"""

import os
import socket
import struct
import sys
import threading
import time

PACKET_COUNT = 5
INTER_PACKET = 0.05    # secondes entre deux paquets vers le même hôte
RECV_TIMEOUT = 1.0     # timeout par paquet
ICMP_ECHO_REQ = 8
ICMP_ECHO_REP = 0


# ── ICMP helpers ──────────────────────────────────────────────────────────────

def _checksum(data: bytes) -> int:
    s, n = 0, len(data)
    for i in range(0, n - 1, 2):
        s += (data[i] << 8) | data[i + 1]
    if n & 1:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _build_packet(ident: int, seq: int) -> bytes:
    payload = b'netmap00' + bytes(range(24))           # 32 octets de données
    hdr     = struct.pack('!BBHHH', ICMP_ECHO_REQ, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    cs      = _checksum(hdr + payload)
    return struct.pack('!BBHHH', ICMP_ECHO_REQ, 0, cs, ident & 0xFFFF, seq & 0xFFFF) + payload


def _recv_reply(sock: socket.socket, ident: int, seq: int,
                t_send: float, deadline: float) -> float | None:
    """Attend la réponse ICMP echo reply correspondant à (ident, seq)."""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        sock.settimeout(remaining)
        try:
            data, _ = sock.recvfrom(1024)
        except socket.timeout:
            return None
        t_recv = time.monotonic()
        ihl = (data[0] & 0x0F) * 4
        if len(data) < ihl + 8:
            continue
        if data[ihl] != ICMP_ECHO_REP:
            continue
        r_ident, r_seq = struct.unpack_from('!HH', data, ihl + 4)
        if r_ident == (ident & 0xFFFF) and r_seq == (seq & 0xFFFF):
            return (t_recv - t_send) * 1000.0


def _measure_host(ip: str, ident: int, count: int) -> float | None:
    """
    Envoie `count` paquets ICMP vers `ip` et retourne la latence moyenne en ms.
    Retourne None si aucune réponse n'est reçue.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except OSError:
        return None

    rtts: list[float] = []
    try:
        for seq in range(count):
            pkt    = _build_packet(ident, seq)
            t_send = time.monotonic()
            try:
                sock.sendto(pkt, (ip, 0))
            except OSError:
                break
            rtt = _recv_reply(sock, ident, seq, t_send, t_send + RECV_TIMEOUT)
            if rtt is not None:
                rtts.append(rtt)
            if seq < count - 1:
                time.sleep(INTER_PACKET)
    finally:
        sock.close()

    return round(sum(rtts) / len(rtts), 3) if rtts else None


# ── Scanner ───────────────────────────────────────────────────────────────────

def scan(ips: list[str], count: int = PACKET_COUNT) -> dict[str, float | None]:
    """
    Mesure la latence ICMP de chaque IP en parallèle.
    Retourne {ip: latence_ms} — None si l'hôte est injoignable.
    """
    results: dict[str, float | None] = {}
    lock       = threading.Lock()
    base_ident = os.getpid() & 0xFFFF

    def _worker(ip: str, idx: int) -> None:
        ident = (base_ident + idx) & 0xFFFF
        rtt   = _measure_host(ip, ident, count)
        with lock:
            results[ip] = rtt

    threads = [
        threading.Thread(target=_worker, args=(ip, i), daemon=True)
        for i, ip in enumerate(ips)
    ]
    for t in threads:
        t.start()

    max_wait = count * (RECV_TIMEOUT + INTER_PACKET) + 1.0
    for t in threads:
        t.join(timeout=max_wait)

    for ip in ips:
        results.setdefault(ip, None)

    return results


# ── Point d'entrée standalone ─────────────────────────────────────────────────

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Erreur : raw sockets requièrent les droits root.", file=sys.stderr)
        sys.exit(1)

    targets = sys.argv[1:] if len(sys.argv) > 1 else []
    if not targets:
        print("Usage : sudo python3 latency.py <ip1> [ip2 ...]")
        sys.exit(0)

    print(f"\n  {'IP':<20} Latence")
    print("  " + "─" * 32)
    results = scan(targets)
    for ip in sorted(results):
        ms = results[ip]
        ms_str = f"{ms:.3f} ms" if ms is not None else "injoignable"
        print(f"  {ip:<20} {ms_str}")
    print()
