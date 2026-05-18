#!/usr/bin/env python3
"""
TCP SYN port scanner — raw sockets, stdlib uniquement.
Usage standalone: sudo python3 syn_scan.py [iface] <target_ip> [port,port,...]
"""

import os
import random
import socket
import struct
import sys
import threading
import time
from datetime import datetime

import os_detect

# ── Constantes ────────────────────────────────────────────────────────────────

INTER_PACKET_DELAY = 0.001   # 1 ms entre chaque SYN
IP_HDRINCL         = 3

TCP_FLAGS_SYN    = 0x02
TCP_FLAGS_RST    = 0x04
TCP_FLAGS_ACK    = 0x10
TCP_FLAGS_SYNACK = 0x12

PORT_STATES = ("open", "closed", "filtered")

# ── Checksum ──────────────────────────────────────────────────────────────────

def checksum(data: bytes) -> int:
    """Complément à un 16 bits — utilisé pour IP et TCP."""
    if len(data) % 2:
        data += b"\x00"
    s = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

# ── Construction de paquets ───────────────────────────────────────────────────

def _build_ip_header(src_ip: str, dst_ip: str, total_len: int, ip_id: int) -> bytes:
    """IP header (20 B) avec checksum calculé — format !BBHHHBBH4s4s."""
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,                        # version=4, IHL=5
        0,                           # DSCP/ECN
        total_len,                   # longueur totale
        ip_id,                       # identification
        0,                           # flags + fragment offset
        64,                          # TTL
        6,                           # protocole TCP
        0,                           # checksum (placeholder)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    csum = checksum(hdr)
    # Réinjecter le checksum aux octets 10-11
    return hdr[:10] + struct.pack("!H", csum) + hdr[12:]


def _build_tcp_header(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack_num: int,
    flags: int,
    window: int,
) -> bytes:
    """TCP header (20 B) avec checksum calculé — format !HHIIBBHHH."""
    tcp = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack_num,
        0x50,       # data offset = 5 (5×4=20 B), reserved = 0
        flags,
        window,
        0,          # checksum placeholder
        0,          # urgent pointer
    )
    # Pseudo-header pour le calcul du checksum TCP
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,          # zéro
        6,          # protocole TCP
        20,         # longueur du segment TCP (header seul, pas de données)
    )
    csum = checksum(pseudo + tcp)
    return tcp[:16] + struct.pack("!H", csum) + tcp[18:]


def build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int) -> bytes:
    """
    Paquet IP+TCP SYN complet (40 B).
    Construit IP et TCP headers à la main avec checksums valides.
    """
    tcp = _build_tcp_header(src_ip, dst_ip, src_port, dst_port,
                            seq, 0, TCP_FLAGS_SYN, 65535)
    ip  = _build_ip_header(src_ip, dst_ip, 40, random.randint(1, 65535))
    return ip + tcp


def build_rst_packet(
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    seq: int,
) -> bytes:
    """
    Paquet RST pour clore une demi-connexion après réception d'un SYN-ACK.
    seq = valeur du champ ACK du SYN-ACK reçu (ce que le serveur a acquitté).
    """
    tcp = _build_tcp_header(src_ip, dst_ip, src_port, dst_port,
                            seq, 0, TCP_FLAGS_RST, 0)
    ip  = _build_ip_header(src_ip, dst_ip, 40, random.randint(1, 65535))
    return ip + tcp

# ── Parsing ───────────────────────────────────────────────────────────────────

def parse_response(packet: bytes):
    """
    Parse un datagramme IP brut reçu via AF_INET/IPPROTO_TCP.
    Retourne (src_ip, src_port, dst_port, flags, ttl, tcp_ack) ou None.

    Offsets :
      packet[0]      → version+IHL   →  ihl = (octet & 0x0F) * 4
      packet[8]      → TTL
      packet[9]      → protocole     → doit être 6 (TCP)
      packet[12:16]  → adresse source
      ihl+0  (2B)    → port source TCP
      ihl+2  (2B)    → port destination TCP
      ihl+4  (4B)    → numéro de séquence
      ihl+8  (4B)    → numéro d'acquittement
      ihl+13 (1B)    → flags TCP
    """
    if len(packet) < 20:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if ihl < 20 or len(packet) < ihl + 20:
        return None
    if packet[9] != 6:          # pas TCP
        return None
    ttl      = packet[8]
    src_ip   = socket.inet_ntoa(packet[12:16])
    src_port,  = struct.unpack_from("!H", packet, ihl)
    dst_port,  = struct.unpack_from("!H", packet, ihl + 2)
    tcp_ack,   = struct.unpack_from("!I", packet, ihl + 8)
    flags      = packet[ihl + 13]
    return src_ip, src_port, dst_port, flags, ttl, tcp_ack

# ── Détection OS ──────────────────────────────────────────────────────────────

def guess_os(ttl: int) -> str:
    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Network/Cisco"

# ── Scanner principal ─────────────────────────────────────────────────────────

def scan_ports(
    src_ip: str,
    target_ip: str,
    ports: list[int],
    timeout: float = 1.5,
) -> dict[int, dict]:
    """
    Envoie des paquets TCP SYN bruts sur chaque port et analyse les réponses.
    Retourne {port: {'state': 'open'|'closed'|'filtered', 'ttl': int|None}}.

    SYN-ACK (flags & 0x12 == 0x12) → open   + envoi RST
    RST     (flags & 0x04)          → closed
    Timeout                          → filtered (état par défaut)

    Le port source aléatoire unique sert à filtrer le trafic TCP ambiant.
    """
    our_src_port = random.randint(32768, 60999)
    base_seq     = random.randint(0, 0xFFFFFFFF)
    results      = {p: {"state": "filtered", "ttl": None} for p in ports}

    tx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    tx.setsockopt(socket.IPPROTO_IP, IP_HDRINCL, 1)

    rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    rx.settimeout(0.05)

    def sender():
        for i, port in enumerate(ports):
            pkt = build_syn_packet(src_ip, target_ip, our_src_port, port,
                                   (base_seq + i) & 0xFFFFFFFF)
            try:
                tx.sendto(pkt, (target_ip, 0))
            except OSError:
                pass
            time.sleep(INTER_PACKET_DELAY)

    t = threading.Thread(target=sender, daemon=True)
    t.start()

    deadline = time.monotonic() + len(ports) * INTER_PACKET_DELAY + timeout

    try:
        while time.monotonic() < deadline:
            try:
                packet, _ = rx.recvfrom(65535)
            except socket.timeout:
                continue

            parsed = parse_response(packet)
            if parsed is None:
                continue
            p_src_ip, p_src_port, p_dst_port, flags, ttl, tcp_ack = parsed

            # Filtrage : paquet provenant de la cible, adressé à notre port source
            if p_src_ip != target_ip:
                continue
            if p_dst_port != our_src_port:
                continue
            if p_src_port not in results:
                continue
            # Ne pas reclassifier un port déjà identifié
            if results[p_src_port]["state"] != "filtered":
                continue

            if flags & TCP_FLAGS_SYNACK == TCP_FLAGS_SYNACK:
                p_ihl   = (packet[0] & 0x0F) * 4
                win     = struct.unpack_from("!H", packet, p_ihl + 14)[0] if len(packet) >= p_ihl + 16 else 0
                tcp_opts = os_detect.parse_tcp_opts(packet, p_ihl)
                results[p_src_port] = {"state": "open", "ttl": ttl, "window": win, "tcp_opts": tcp_opts}
                # Envoyer RST pour libérer la demi-connexion côté serveur
                rst = build_rst_packet(src_ip, target_ip, our_src_port, p_src_port, tcp_ack)
                try:
                    tx.sendto(rst, (target_ip, 0))
                except OSError:
                    pass
            elif flags & TCP_FLAGS_RST:
                results[p_src_port] = {"state": "closed", "ttl": ttl}
    finally:
        tx.close()
        rx.close()

    t.join(timeout=1)
    return results

# ── Affichage ─────────────────────────────────────────────────────────────────

_STATE_LABEL = {
    "open":     "ouvert  ",
    "closed":   "fermé   ",
    "filtered": "filtré  ",
}

def print_port_table(results: dict[int, dict], target_ip: str):
    open_ports = [p for p, r in results.items() if r["state"] == "open"]
    os_guess   = "?"
    ref_ttl    = None
    for r in results.values():
        if r["ttl"] is not None:
            ref_ttl = r["ttl"]
            os_guess = guess_os(ref_ttl)
            break

    ttl_str = f"TTL={ref_ttl}" if ref_ttl else "TTL=?"
    print(f"\n  {target_ip}  {ttl_str}  OS: {os_guess}")
    print(f"  {'PORT':<10} {'ÉTAT':<10} TTL")
    print("  " + "─" * 30)
    for port in sorted(results):
        r     = results[port]
        label = _STATE_LABEL.get(r["state"], r["state"])
        ttl   = str(r["ttl"]) if r["ttl"] else "-"
        print(f"  {port}/tcp  {label}  {ttl}")
    if open_ports:
        print(f"\n  → {len(open_ports)} port(s) ouvert(s) : {', '.join(str(p) for p in sorted(open_ports))}")

# ── Point d'entrée standalone ──────────────────────────────────────────────────

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Erreur : raw sockets requièrent les droits root.", file=sys.stderr)
        sys.exit(1)

    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from arp_scan import default_iface, get_iface_info

    args = sys.argv[1:]
    if len(args) == 0 or (len(args) == 1 and not args[0].replace(".", "").isdigit()):
        iface = args[0] if args else default_iface()
        print(f"Usage: sudo python3 syn_scan.py [iface] <target_ip> [port,port,...]",
              file=sys.stderr)
        sys.exit(1)

    # Détecter si le premier argument est une interface ou une IP
    if args[0].replace(".", "").isdigit() or len(args[0].split(".")) == 4:
        iface      = default_iface()
        target     = args[0]
        ports_arg  = args[1] if len(args) > 1 else None
    else:
        iface      = args[0]
        target     = args[1] if len(args) > 1 else None
        ports_arg  = args[2] if len(args) > 2 else None

    if not target:
        print("Erreur : IP cible manquante.", file=sys.stderr)
        sys.exit(1)

    DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                     443, 445, 3306, 3389, 5432, 5900, 8080, 8443]
    ports = list(map(int, ports_arg.split(","))) if ports_arg else DEFAULT_PORTS

    src_ip, _, _ = get_iface_info(iface)
    print(f"SYN scan  {target}  via {iface} ({src_ip})")
    print(f"Ports : {', '.join(map(str, ports))}")

    results = scan_ports(src_ip, target, ports)
    print_port_table(results, target)
