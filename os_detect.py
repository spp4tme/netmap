#!/usr/bin/env python3
"""
Advanced OS detection via TCP fingerprinting.
Analyses TTL, TCP window size, MSS, SACK, timestamps, window scale.
Stdlib only — no external dependencies.
"""

import struct

# ── TCP options parser ─────────────────────────────────────────────────────────

def parse_tcp_opts(packet: bytes, ihl: int) -> dict:
    """
    Parse TCP options from a raw IP+TCP packet.
    ihl: IP header length in bytes (packet[0] & 0x0F) * 4.
    Returns dict with keys: mss, scale, sack, timestamps (bool).
    """
    opts: dict = {"mss": 0, "scale": 0, "sack": False, "timestamps": False}
    if len(packet) < ihl + 20:
        return opts

    data_offset = (packet[ihl + 12] >> 4) * 4
    opts_start  = ihl + 20
    opts_end    = ihl + data_offset
    if opts_end <= opts_start or len(packet) < opts_end:
        return opts

    i = opts_start
    while i < opts_end:
        kind = packet[i]
        if kind == 0:    # End of options
            break
        if kind == 1:    # NOP
            i += 1
            continue
        if i + 1 >= opts_end:
            break
        length = packet[i + 1]
        if length < 2 or i + length > opts_end:
            break
        if kind == 2 and length == 4:    # MSS
            opts["mss"] = struct.unpack_from("!H", packet, i + 2)[0]
        elif kind == 3 and length == 3:  # Window scale
            opts["scale"] = packet[i + 2]
        elif kind == 4:                  # SACK permitted
            opts["sack"] = True
        elif kind == 8 and length == 10: # Timestamps
            opts["timestamps"] = True
        i += length
    return opts

# ── Fingerprint database ────────────────────────────────────────────────────────
#
# Each entry: (ttl_range, window_range, mss_range, scale_present, sack, timestamps)
# → (os_family, os_detail)
#
# Matching order matters: more specific first.

_SIGS = [
    # Linux 5.x — large window, timestamps, SACK, scale
    {"ttl": (56, 65), "win": (28000, 70000), "mss": (1360, 1461),
     "sack": True, "ts": True, "scale": (6, 9),
     "os": "Linux/Unix", "detail": "Linux 5.x"},

    # Linux 4.x — similar but slightly different window ranges
    {"ttl": (56, 65), "win": (14000, 30000), "mss": (1360, 1461),
     "sack": True, "ts": True, "scale": (5, 8),
     "os": "Linux/Unix", "detail": "Linux 4.x"},

    # Linux generic (container, WSL, etc.)
    {"ttl": (56, 65), "win": (4096, 65535), "mss": (536, 1460),
     "sack": None, "ts": None, "scale": None,
     "os": "Linux/Unix", "detail": "Linux"},

    # macOS (Ventura / Sonoma) — window 65535, scale 6, MSS 1460
    {"ttl": (60, 65), "win": (65535, 65535), "mss": (1440, 1460),
     "sack": True, "ts": True, "scale": (6, 6),
     "os": "Linux/Unix", "detail": "macOS"},

    # macOS older
    {"ttl": (60, 65), "win": (65535, 65535), "mss": (1400, 1460),
     "sack": True, "ts": True, "scale": (3, 5),
     "os": "Linux/Unix", "detail": "macOS (older)"},

    # iOS / iPadOS
    {"ttl": (60, 65), "win": (65535, 65535), "mss": (1380, 1460),
     "sack": True, "ts": True, "scale": (6, 6),
     "os": "Linux/Unix", "detail": "iOS/iPadOS"},

    # Android — various manufacturers, often TTL=64, win≈65535
    {"ttl": (60, 65), "win": (65535, 65535), "mss": (1360, 1460),
     "sack": True, "ts": False, "scale": (7, 9),
     "os": "Linux/Unix", "detail": "Android"},

    # Windows 10 — window 65535, scale 8, MSS 1460, SACK, no TS
    {"ttl": (120, 128), "win": (65535, 65535), "mss": (1460, 1460),
     "sack": True, "ts": False, "scale": (8, 8),
     "os": "Windows", "detail": "Windows 10"},

    # Windows 11 — window 64240, scale 8, MSS 1460
    {"ttl": (120, 128), "win": (64240, 64240), "mss": (1460, 1460),
     "sack": True, "ts": False, "scale": (8, 8),
     "os": "Windows", "detail": "Windows 11"},

    # Windows Server 2019/2022
    {"ttl": (120, 128), "win": (65535, 65535), "mss": (1460, 1460),
     "sack": True, "ts": False, "scale": (7, 9),
     "os": "Windows", "detail": "Windows Server"},

    # Windows generic
    {"ttl": (112, 128), "win": (8192, 65535), "mss": (536, 1460),
     "sack": None, "ts": None, "scale": None,
     "os": "Windows", "detail": "Windows"},

    # Cisco IOS — large TTL, small window, no options
    {"ttl": (240, 255), "win": (4096, 16384), "mss": (536, 1460),
     "sack": None, "ts": None, "scale": None,
     "os": "Network/Cisco", "detail": "Cisco IOS"},

    # Cisco IOS-XE
    {"ttl": (240, 255), "win": (16384, 32768), "mss": (1460, 1460),
     "sack": False, "ts": False, "scale": None,
     "os": "Network/Cisco", "detail": "Cisco IOS-XE"},

    # Juniper JunOS
    {"ttl": (240, 255), "win": (16384, 65535), "mss": (1452, 1460),
     "sack": True, "ts": True, "scale": None,
     "os": "Network/Cisco", "detail": "Juniper JunOS"},

    # FreeBSD / OpenBSD
    {"ttl": (60, 65), "win": (65535, 65535), "mss": (1460, 1460),
     "sack": True, "ts": True, "scale": (6, 7),
     "os": "Linux/Unix", "detail": "FreeBSD/OpenBSD"},
]


def _match(sig: dict, ttl: int, win: int, mss: int, sack: bool, ts: bool, scale: int) -> bool:
    tlo, thi = sig["ttl"]
    if not (tlo <= ttl <= thi):
        return False
    wlo, whi = sig["win"]
    if not (wlo <= win <= whi):
        return False
    mlo, mhi = sig["mss"]
    if not (mlo <= mss <= mhi):
        return False
    if sig["sack"] is not None and sig["sack"] != sack:
        return False
    if sig["ts"] is not None and sig["ts"] != ts:
        return False
    if sig["scale"] is not None:
        slo, shi = sig["scale"]
        if not (slo <= scale <= shi):
            return False
    return True


def fingerprint(ttl: int, window: int, tcp_opts: dict) -> tuple[str, str]:
    """
    Given TTL, TCP window and parsed options, return (os_family, os_detail).
    os_family matches the existing guess_os() categories.
    """
    mss   = tcp_opts.get("mss",        0)
    scale = tcp_opts.get("scale",      0)
    sack  = tcp_opts.get("sack",   False)
    ts    = tcp_opts.get("timestamps", False)

    for sig in _SIGS:
        if _match(sig, ttl, window, mss, sack, ts, scale):
            return sig["os"], sig["detail"]

    # Fallback to TTL only
    if ttl <= 64:
        return "Linux/Unix", "Linux/Unix"
    if ttl <= 128:
        return "Windows", "Windows"
    return "Network/Cisco", "Network/Cisco"


def from_port_results(port_results: dict) -> tuple[str, str]:
    """
    Derive OS fingerprint from the best open-port result that has TCP fingerprint data.
    Returns (os_family, os_detail).
    """
    for r in port_results.values():
        if r.get("state") == "open" and r.get("ttl") and r.get("window"):
            return fingerprint(r["ttl"], r["window"], r.get("tcp_opts", {}))

    # Fallback: TTL only from any result
    for r in port_results.values():
        ttl = r.get("ttl")
        if ttl:
            if ttl <= 64:
                return "Linux/Unix", "Linux/Unix"
            if ttl <= 128:
                return "Windows", "Windows"
            return "Network/Cisco", "Network/Cisco"

    return "?", "?"


if __name__ == "__main__":
    # Quick smoke test
    tests = [
        (64,  65535, {"mss": 1460, "scale": 8, "sack": False, "timestamps": False}),
        (64,  65535, {"mss": 1460, "scale": 6, "sack": True,  "timestamps": True}),
        (128, 65535, {"mss": 1460, "scale": 8, "sack": True,  "timestamps": False}),
        (128, 64240, {"mss": 1460, "scale": 8, "sack": True,  "timestamps": False}),
        (255, 4096,  {"mss": 1460, "scale": 0, "sack": False, "timestamps": False}),
    ]
    for ttl, win, opts in tests:
        fam, det = fingerprint(ttl, win, opts)
        print(f"TTL={ttl:3d}  win={win:5d}  mss={opts['mss']}  → {fam} / {det}")
