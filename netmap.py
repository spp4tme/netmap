#!/usr/bin/env python3
"""
netmap — ARP discovery + TCP SYN port scan.
Usage: sudo python3 netmap.py [iface] [--ports 22,80,443,...] [--timeout 1.5]
Stdlib uniquement, aucune dépendance externe.
"""

import argparse
import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import arp_scan
import banner
import local_vuln
import os_detect
import oui
import report
import syn_scan
import timeline
import vuln
from arp_scan import default_iface, fmt_mac, get_iface_info

# ── CLI ───────────────────────────────────────────────────────────────────────

DEFAULT_PORTS = "21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5432,8080,8443"

def parse_args():
    p = argparse.ArgumentParser(
        description="netmap : ARP scan puis TCP SYN scan sur chaque hôte découvert."
    )
    p.add_argument("iface", nargs="?", default=None,
                   help="Interface réseau (détection automatique si omise)")
    p.add_argument("--ports", "-p", default=DEFAULT_PORTS,
                   help=f"Ports à scanner, séparés par des virgules (défaut : {DEFAULT_PORTS})")
    p.add_argument("--timeout", "-t", type=float, default=1.5,
                   help="Timeout TCP par hôte en secondes (défaut : 1.5)")
    p.add_argument("--no-banner", action="store_true",
                   help="Désactiver le banner grabbing")
    p.add_argument("--no-vuln", action="store_true",
                   help="Désactiver la recherche CVE (NVD)")
    p.add_argument("--no-local-vuln", action="store_true",
                   help="Désactiver les vérifications de vulnérabilités locales")
    p.add_argument("--no-timeline", action="store_true",
                   help="Ne pas sauvegarder l'historique ni calculer le diff")
    p.add_argument("--nvd-key", default=os.environ.get("NVD_API_KEY", ""),
                   metavar="KEY",
                   help="Clé API NVD (ou export NVD_API_KEY) — accélère ×9 le rate-limit")
    _default_report = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.html")
    p.add_argument("--output", "-o", default=_default_report,
                   help=f"Chemin du rapport HTML (défaut : {_default_report})")
    return p.parse_args()

# ── Affichage ─────────────────────────────────────────────────────────────────

_SEP = "═" * 62

_STATE_ICON = {"open": "●", "closed": "○", "filtered": "·"}

def _section(title: str):
    print(f"\n{_SEP}")
    print(f"  {title}")
    print(_SEP)


def _print_host_result(ip: str, mac: bytes, results: dict[int, dict]):
    ref_ttl  = next((r["ttl"] for r in results.values() if r["ttl"]), None)
    os_guess = syn_scan.guess_os(ref_ttl) if ref_ttl else "?"
    ttl_str  = f"TTL={ref_ttl}" if ref_ttl else "TTL=?"

    print(f"\n  ┌─ {ip}  {fmt_mac(mac)}  {ttl_str}  OS: {os_guess}")
    for port in sorted(results):
        r     = results[port]
        icon  = _STATE_ICON.get(r["state"], "?")
        state = r["state"]
        svc   = r.get("service", "")
        ver   = r.get("version", "")
        svc_str = f"  {svc}" if svc and svc != "unknown" else ""
        ver_str = f"/{ver[:40]}" if ver else ""
        print(f"  │  {icon} {port}/tcp  {state}{svc_str}{ver_str}")
    open_ports = sorted(p for p, r in results.items() if r["state"] == "open")
    if open_ports:
        print(f"  └─ Ouverts : {', '.join(map(str, open_ports))}")
    else:
        print(f"  └─ Aucun port ouvert")


def _print_summary(full_results: dict):
    _section("Résumé")
    print(f"\n  {'IP':<18} {'MAC':<20} {'OS':<20} {'Fabricant':<16} {'Risque':<13} Ports ouverts")
    print("  " + "─" * 90)
    for ip in sorted(full_results):
        entry      = full_results[ip]
        mac_str    = fmt_mac(entry["mac"])
        os_detail  = entry.get("os_detail") or entry.get("os_guess", "?")
        vendor     = entry.get("vendor", "")
        open_ports = sorted(p for p, r in entry["ports"].items() if r["state"] == "open")
        ports_str  = ", ".join(map(str, open_ports)) if open_ports else "—"
        risk_score = entry.get("risk_score", 0.0)
        risk_level = entry.get("risk_level", "NONE")
        n_cves     = entry.get("total_cves", 0)
        n_local    = len(entry.get("local_vulns", []))
        total_issues = n_cves + n_local
        if risk_level != "NONE" or n_local:
            risk_str = f"{risk_score:.1f} {risk_level} ({total_issues})"
        else:
            risk_str = "—"
        print(f"  {ip:<18} {mac_str:<20} {os_detail:<20} {vendor:<16} {risk_str:<13} {ports_str}")
    total_open = sum(
        1
        for e in full_results.values()
        for r in e["ports"].values()
        if r["state"] == "open"
    )
    print(f"\n  {len(full_results)} hôte(s)  |  {total_open} port(s) ouvert(s) au total\n")

# ── Orchestrateur ─────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        print("Erreur : raw sockets requièrent les droits root.", file=sys.stderr)
        sys.exit(1)

    args   = parse_args()
    iface  = args.iface or default_iface()
    ports  = [int(x.strip()) for x in args.ports.split(",")]

    # ── Phase 1 : ARP scan ────────────────────────────────────────────────────
    _section(f"Phase 1 : ARP scan  —  interface {iface}")
    discovered = arp_scan.scan(iface)

    if not discovered:
        print("Aucun hôte découvert. Abandon.")
        sys.exit(0)

    # ── Phase 2 : TCP SYN scan ────────────────────────────────────────────────
    src_ip, src_mac, netmask = get_iface_info(iface)
    network     = str(ipaddress.IPv4Network(f"{src_ip}/{netmask}", strict=False))
    ports_label = ", ".join(map(str, ports))

    _section(f"Phase 2 : TCP SYN scan  —  {len(discovered)} hôte(s)  |  ports : {ports_label}")

    full_results: dict[str, dict] = {}

    for ip, mac in sorted(discovered.items()):
        print(f"\n  → Scan {ip} ({fmt_mac(mac)}) …", flush=True)
        port_results = syn_scan.scan_ports(src_ip, ip, ports, timeout=args.timeout)

        # ── Phase 2b : Banner grabbing ─────────────────────────────────────
        if not args.no_banner:
            open_ports = [p for p, r in port_results.items() if r["state"] == "open"]
            if open_ports:
                print(f"  → Banner grabbing {len(open_ports)} port(s) …", flush=True)
                banners = banner.grab_all(ip, open_ports)
                for p, bdata in banners.items():
                    port_results[p].update(bdata)

        # OUI manufacturer lookup
        vendor = oui.lookup(mac)

        # Advanced OS fingerprinting (TCP window + options)
        os_family, os_detail = os_detect.from_port_results(port_results)

        full_results[ip] = {
            "mac":       mac,
            "vendor":    vendor,
            "os_guess":  os_family,
            "os_detail": os_detail,
            "ports":     port_results,
        }
        _print_host_result(ip, mac, port_results)

    # ── Phase 3 : Analyse CVE (NVD) ──────────────────────────────────────────
    if not args.no_vuln:
        _section("Phase 3 : Analyse de vulnérabilités (NVD)")
        vuln.enrich(full_results, api_key=args.nvd_key, verbose=True)
    else:
        for entry in full_results.values():
            entry.setdefault("risk_score", 0.0)
            entry.setdefault("risk_level", "NONE")
            entry.setdefault("total_cves", 0)

    # ── Phase 3b : Vulnérabilités locales ─────────────────────────────────────
    if not args.no_local_vuln:
        _section("Phase 3b : Vérifications locales de sécurité")
        for ip, entry in sorted(full_results.items()):
            print(f"\n  → Audit local {ip} …", flush=True)
            findings = local_vuln.audit(ip, entry["ports"])
            entry["local_vulns"] = findings
            for f in findings:
                print(f"    [{f['severity']:8}] {f['title']}")
    else:
        for entry in full_results.values():
            entry.setdefault("local_vulns", [])

    # ── Phase 4 : Résumé ──────────────────────────────────────────────────────
    _print_summary(full_results)

    # ── Phase 4b : Timeline ────────────────────────────────────────────────────
    scan_diff = None
    if not args.no_timeline:
        record       = timeline.to_record(full_results, src_ip, src_mac, network)
        prev_records = timeline.load_last(2)
        hist_path    = timeline.save(record)
        print(f"\n  Historique sauvegardé : {hist_path}")
        if len(prev_records) >= 1:
            scan_diff = timeline.diff(prev_records[-1], record)
            n_new  = len(scan_diff["new_hosts"])
            n_gone = len(scan_diff["gone_hosts"])
            n_chg  = len(scan_diff["changed"])
            print(f"  Diff vs scan précédent : +{n_new} hôte(s)  -{n_gone} hôte(s)  ~{n_chg} modifié(s)")

    # ── Phase 5 : Rapport HTML ────────────────────────────────────────────────
    _section("Phase 5 : Génération du rapport HTML")
    history = timeline.load_last(20) if not args.no_timeline else []
    path = report.generate(src_ip, src_mac, network, full_results,
                           output=args.output,
                           history=history, scan_diff=scan_diff)
    print(f"\n  Rapport généré : {path}\n")


if __name__ == "__main__":
    main()
