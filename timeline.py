#!/usr/bin/env python3
"""
Scan timeline: persist each scan as JSON, diff successive scans.
Storage: .history/<timestamp>.json in the netmap directory.
Stdlib only.
"""

import json
import os
from datetime import datetime, timezone

_HISTORY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".history")

# ── Serialization helpers ──────────────────────────────────────────────────────

def _fmt_mac(b) -> str:
    if isinstance(b, (bytes, bytearray)):
        return ":".join(f"{x:02x}" for x in b)
    return str(b)


def to_record(full_results: dict, scanner_ip: str, scanner_mac,
              network: str) -> dict:
    """
    Convert a netmap full_results dict to a storable JSON-safe record.
    """
    ts = datetime.now(timezone.utc).isoformat()
    hosts = {}
    for ip, entry in full_results.items():
        ports = {}
        for port, r in entry["ports"].items():
            ports[str(port)] = {
                "state":   r.get("state", "filtered"),
                "service": r.get("service", ""),
                "version": r.get("version", ""),
            }
        hosts[ip] = {
            "mac":        _fmt_mac(entry.get("mac", b"")),
            "os":         entry.get("os_guess", "?"),
            "os_detail":  entry.get("os_detail", ""),
            "vendor":     entry.get("vendor", ""),
            "risk_score": entry.get("risk_score", 0.0),
            "risk_level": entry.get("risk_level", "NONE"),
            "total_cves": entry.get("total_cves", 0),
            "ports":      ports,
        }
    return {
        "ts":          ts,
        "scanner_ip":  scanner_ip,
        "scanner_mac": _fmt_mac(scanner_mac),
        "network":     network,
        "hosts":       hosts,
    }

# ── Persistence ────────────────────────────────────────────────────────────────

def save(record: dict) -> str:
    """
    Write record to .history/<timestamp>.json.
    Returns the path of the saved file.
    """
    os.makedirs(_HISTORY_DIR, exist_ok=True)
    safe_ts = record["ts"].replace(":", "-").replace("+", "")
    path = os.path.join(_HISTORY_DIR, f"{safe_ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)
    return path


def load_last(n: int = 10) -> list[dict]:
    """
    Load the N most recent scan records from .history/.
    Returns list sorted oldest-first.
    """
    if not os.path.isdir(_HISTORY_DIR):
        return []
    files = sorted(
        (f for f in os.listdir(_HISTORY_DIR) if f.endswith(".json")),
        reverse=True
    )[:n]
    records = []
    for fname in reversed(files):
        path = os.path.join(_HISTORY_DIR, fname)
        try:
            with open(path, encoding="utf-8") as f:
                records.append(json.load(f))
        except Exception:
            pass
    return records

# ── Diff ───────────────────────────────────────────────────────────────────────

def diff(prev: dict, curr: dict) -> dict:
    """
    Compare two scan records. Returns a diff dict describing changes.
    """
    prev_hosts = set(prev.get("hosts", {}).keys())
    curr_hosts = set(curr.get("hosts", {}).keys())

    new_hosts  = sorted(curr_hosts - prev_hosts)
    gone_hosts = sorted(prev_hosts - curr_hosts)
    changed    = {}

    for ip in sorted(curr_hosts & prev_hosts):
        ph = prev["hosts"][ip]
        ch = curr["hosts"][ip]

        prev_open = {int(p) for p, r in ph["ports"].items() if r["state"] == "open"}
        curr_open = {int(p) for p, r in ch["ports"].items() if r["state"] == "open"}

        new_ports    = sorted(curr_open - prev_open)
        closed_ports = sorted(prev_open - curr_open)

        service_changes = []
        for p_str, cr in ch["ports"].items():
            pr = ph["ports"].get(p_str, {})
            if cr.get("service") and cr["service"] != pr.get("service", ""):
                service_changes.append({
                    "port":    int(p_str),
                    "before":  pr.get("service", ""),
                    "after":   cr["service"],
                })

        os_changed = ph.get("os") != ch.get("os")
        risk_changed = ph.get("risk_level") != ch.get("risk_level")

        if new_ports or closed_ports or service_changes or os_changed or risk_changed:
            changed[ip] = {
                "new_ports":      new_ports,
                "closed_ports":   closed_ports,
                "service_changes": service_changes,
                "os_before":      ph.get("os", "?"),
                "os_after":       ch.get("os", "?"),
                "risk_before":    ph.get("risk_level", "NONE"),
                "risk_after":     ch.get("risk_level", "NONE"),
            }

    return {
        "prev_ts":    prev.get("ts", ""),
        "curr_ts":    curr.get("ts", ""),
        "new_hosts":  new_hosts,
        "gone_hosts": gone_hosts,
        "changed":    changed,
    }


def latest_diff() -> dict | None:
    """
    Return diff between the two most recent scans, or None if fewer than 2 exist.
    """
    records = load_last(2)
    if len(records) < 2:
        return None
    return diff(records[-2], records[-1])


if __name__ == "__main__":
    records = load_last()
    print(f"{len(records)} record(s) in history")
    for r in records:
        n_hosts = len(r.get("hosts", {}))
        print(f"  {r['ts']}  {r['network']}  {n_hosts} host(s)")
    if len(records) >= 2:
        d = diff(records[-2], records[-1])
        print(f"\nDiff {d['prev_ts'][:16]} → {d['curr_ts'][:16]}")
        print(f"  New hosts:  {d['new_hosts']}")
        print(f"  Gone hosts: {d['gone_hosts']}")
        for ip, ch in d["changed"].items():
            print(f"  Changed {ip}: +ports={ch['new_ports']} -ports={ch['closed_ports']}")
