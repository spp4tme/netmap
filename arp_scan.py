#!/usr/bin/env python3
"""
ARP scanner - raw sockets, stdlib uniquement.
Usage: sudo python3 arp_scan.py [interface]
"""

import fcntl
import ipaddress
import os
import socket
import struct
import sys
import threading
import time
from datetime import datetime

# ── Constantes ARP / Ethernet ────────────────────────────────────────────────

ETH_P_ARP  = 0x0806
ARP_HW_ETH = 0x0001
ARP_PR_IP  = 0x0800
ARP_OP_REQ = 0x0001
ARP_OP_REP = 0x0002

# ioctl Linux
SIOCGIFADDR    = 0x8915
SIOCGIFHWADDR  = 0x8927
SIOCGIFNETMASK = 0x891b

# ── Interface ─────────────────────────────────────────────────────────────────

def get_iface_info(iface: str) -> tuple[str, bytes, str]:
    """Retourne (ip, mac_bytes, netmask) pour l'interface donnée."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        buf = struct.pack("256s", iface[:15].encode())
        ip      = socket.inet_ntoa(fcntl.ioctl(s, SIOCGIFADDR,    buf)[20:24])
        mac     = fcntl.ioctl(s, SIOCGIFHWADDR,  buf)[18:24]
        netmask = socket.inet_ntoa(fcntl.ioctl(s, SIOCGIFNETMASK, buf)[20:24])
    finally:
        s.close()
    return ip, mac, netmask


def default_iface() -> str:
    """Détecte l'interface de la route par défaut via /proc/net/route."""
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            fields = line.split()
            if fields[1] == "00000000" and int(fields[3], 16) & 0x2:  # RTF_GATEWAY
                return fields[0]
    # fallback : première iface non-lo
    with open("/proc/net/dev") as f:
        for line in f.readlines()[2:]:
            name = line.split(":")[0].strip()
            if name != "lo":
                return name
    raise RuntimeError("Impossible de détecter l'interface réseau.")

# ── Craft / parse ─────────────────────────────────────────────────────────────

def build_arp_request(src_mac: bytes, src_ip: str, dst_ip: str) -> bytes:
    """
    Construit une trame Ethernet brute contenant une ARP Request.

    Ethernet header (14 octets)
    ├── dst MAC  6 B  → broadcast ff:ff:ff:ff:ff:ff
    ├── src MAC  6 B
    └── EtherType 2 B → 0x0806

    ARP payload (28 octets pour IPv4)
    ├── hw type   2 B  → 1 (Ethernet)
    ├── proto     2 B  → 0x0800 (IPv4)
    ├── hw len    1 B  → 6
    ├── proto len 1 B  → 4
    ├── opcode    2 B  → 1 (request)
    ├── src MAC   6 B
    ├── src IP    4 B
    ├── dst MAC   6 B  → 00:00:00:00:00:00 (inconnu)
    └── dst IP    4 B
    """
    eth = (
        b"\xff\xff\xff\xff\xff\xff"          # dst : broadcast
        + src_mac                            # src
        + struct.pack("!H", ETH_P_ARP)       # EtherType
    )
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        ARP_HW_ETH,                          # hardware type
        ARP_PR_IP,                           # protocol type
        6,                                   # hw addr len
        4,                                   # proto addr len
        ARP_OP_REQ,                          # opcode : request
        src_mac,                             # sender MAC
        socket.inet_aton(src_ip),            # sender IP
        b"\x00" * 6,                         # target MAC (inconnu)
        socket.inet_aton(dst_ip),            # target IP
    )
    return eth + arp


def parse_arp_reply(frame: bytes) -> tuple[str, bytes] | None:
    """
    Extrait (sender_ip, sender_mac) d'une trame si c'est une ARP Reply.
    Retourne None sinon.
    """
    if len(frame) < 42:
        return None
    eth_type, = struct.unpack_from("!H", frame, 12)
    if eth_type != ETH_P_ARP:
        return None
    opcode, = struct.unpack_from("!H", frame, 20)
    if opcode != ARP_OP_REP:
        return None
    sender_mac = frame[22:28]
    sender_ip  = socket.inet_ntoa(frame[28:32])
    return sender_ip, sender_mac

# ── Affichage ─────────────────────────────────────────────────────────────────

def fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)

def print_header():
    print(f"\n{'IP':<18} {'MAC ADDRESS':<19} TIMESTAMP")
    print("─" * 55)

def print_device(ip: str, mac: bytes):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"{ip:<18} {fmt_mac(mac):<19} {ts}")

# ── Scanner ───────────────────────────────────────────────────────────────────

INTER_PACKET_DELAY = 0.002   # 2 ms entre chaque requête

def scan(iface: str, timeout: float = 2.0):
    ip, mac, netmask = get_iface_info(iface)
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    hosts   = list(network.hosts())

    print(f"Interface : {iface}  |  MAC : {fmt_mac(mac)}")
    print(f"IP locale : {ip}  |  Réseau : {network}  |  {len(hosts)} hôtes à scanner")
    print_header()

    discovered: dict[str, bytes] = {}
    lock = threading.Lock()

    # Socket d'envoi
    tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    tx.bind((iface, 0))

    # Socket de réception
    rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    rx.bind((iface, 0))
    rx.settimeout(0.1)

    def sender():
        for host in hosts:
            frame = build_arp_request(mac, ip, str(host))
            tx.send(frame)
            time.sleep(INTER_PACKET_DELAY)

    t = threading.Thread(target=sender, daemon=True)
    t.start()

    # Durée totale = envoi + timeout de réponse
    deadline = time.monotonic() + len(hosts) * INTER_PACKET_DELAY + timeout

    try:
        while time.monotonic() < deadline:
            try:
                frame, _ = rx.recvfrom(65535)
            except socket.timeout:
                continue

            result = parse_arp_reply(frame)
            if result is None:
                continue

            host_ip, host_mac = result
            with lock:
                if host_ip not in discovered:
                    discovered[host_ip] = host_mac
                    print_device(host_ip, host_mac)
    finally:
        tx.close()
        rx.close()

    t.join(timeout=1)
    print(f"\n{len(discovered)} device(s) découvert(s) sur {network}.\n")
    return discovered

# ── Point d'entrée ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Erreur : raw sockets requièrent les droits root.", file=sys.stderr)
        sys.exit(1)

    iface = sys.argv[1] if len(sys.argv) > 1 else default_iface()

    try:
        scan(iface)
    except KeyboardInterrupt:
        print("\nScan interrompu.")
    except OSError as e:
        print(f"Erreur réseau : {e}", file=sys.stderr)
        sys.exit(1)
