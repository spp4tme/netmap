#!/usr/bin/env python3
"""
Enrichissement CVE via l'API NVD (nvd.nist.gov) v2.
Pour chaque port ouvert avec service identifié, récupère les CVE associées
et calcule un score de risque CVSS global par device.
Stdlib uniquement — urllib.request, json, re.
"""

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ── Config ────────────────────────────────────────────────────────────────────

_NVD_URL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_MAX_RESULTS  = 10       # CVEs max par requête
_TIMEOUT      = 25       # timeout HTTP en secondes

# Rate limit NVD : 5 req/30s sans clé, 50 req/30s avec clé API
_DELAY_PUBLIC = 6.5
_DELAY_KEYED  = 0.7

_last_req: float = 0.0
_cache: dict[str, list] = {}

# ── CVSS ──────────────────────────────────────────────────────────────────────

def cvss_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "NONE"

# ── Normalisation service/version → keyword NVD ────────────────────────────────

def _ver(s: str, parts: int = 2) -> str:
    """Extrait le numéro de version (ex. '8.9p1 Ubuntu-3' → '8.9')."""
    m = re.search(r"(\d+(?:\.\d+){0," + str(parts - 1) + r"})", s)
    return m.group(1) if m else ""

def search_keyword(service: str, version: str) -> str | None:
    """
    Construit le terme de recherche NVD depuis le service et la version.
    Retourne None si le service est trop générique pour une recherche utile.
    """
    svc = service.strip().upper()
    ver = version.strip()

    if svc == "SSH":
        v = _ver(ver)
        return f"OpenSSH {v}".strip() if v else "OpenSSH"

    if svc in ("HTTP", "HTTPS"):
        vl = ver.lower()
        if not vl:
            return None
        if "nginx" in vl:
            v = _ver(ver)
            return f"nginx {v}".strip()
        if "apache" in vl:
            v = _ver(ver, 3)
            return f"Apache HTTP Server {v}".strip()
        if "lighttpd" in vl:
            return f"lighttpd {_ver(ver)}".strip()
        if "iis" in vl or "microsoft-iis" in vl:
            return f"Microsoft IIS {_ver(ver)}".strip()
        if "werkzeug" in vl:
            return f"Werkzeug {_ver(ver)}".strip()
        # Header générique : garder juste le nom du logiciel
        name = re.split(r"[/\s;(]", ver)[0].strip()
        return name if len(name) >= 3 else None

    if svc == "FTP":
        vl = ver.lower()
        if "vsftpd"   in vl: return f"vsftpd {_ver(ver)}".strip()
        if "proftpd"  in vl: return f"ProFTPD {_ver(ver)}".strip()
        if "filezilla" in vl: return "FileZilla Server"
        return None

    if svc == "SMTP":
        vl = ver.lower()
        if "postfix"  in vl: return f"Postfix {_ver(ver)}".strip()
        if "exim"     in vl: return f"Exim {_ver(ver)}".strip()
        if "sendmail" in vl: return "Sendmail"
        return None

    if svc in ("POP3", "IMAP"):
        if "dovecot" in ver.lower():
            return f"Dovecot {_ver(ver)}".strip()
        return None

    if svc == "MYSQL":
        v = _ver(ver, 2)
        return f"MySQL {v}".strip() if v else "MySQL"

    if svc == "POSTGRESQL":
        v = _ver(ver)
        return f"PostgreSQL {v}".strip() if v else "PostgreSQL"

    if svc == "REDIS":
        v = _ver(ver)
        return f"Redis {v}".strip() if v else "Redis"

    if svc == "SMB":
        return "Samba" if "v1" in ver.lower() else "Samba SMB"

    if svc == "VNC":
        return "RealVNC"

    if svc == "TELNET":
        return "Telnet"

    if svc == "RDP":
        return "Remote Desktop Protocol Windows"

    return None

# ── Requête NVD ────────────────────────────────────────────────────────────────

def _rate_limit(api_key: str) -> None:
    global _last_req
    delay   = _DELAY_KEYED if api_key else _DELAY_PUBLIC
    elapsed = time.monotonic() - _last_req
    wait    = delay - elapsed
    if wait > 0:
        time.sleep(wait)
    _last_req = time.monotonic()


def _fetch_cves(keyword: str, api_key: str = "") -> list[dict]:
    """
    Interroge NVD API v2.
    Retourne une liste de CVEs triées par CVSS décroissant, mise en cache.
    Chaque entrée : {id, desc, cvss, severity, published, url}.
    """
    cache_key = f"{keyword}|{bool(api_key)}"
    if cache_key in _cache:
        return _cache[cache_key]

    _rate_limit(api_key)

    params = {"keywordSearch": keyword, "resultsPerPage": _MAX_RESULTS}
    url    = f"{_NVD_URL}?{urllib.parse.urlencode(params)}"
    hdrs   = {"User-Agent": "netmap/1.0", "Accept": "application/json"}
    if api_key:
        hdrs["apiKey"] = api_key

    req = urllib.request.Request(url, headers=hdrs)

    def _call() -> dict:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))

    try:
        data = _call()
    except urllib.error.HTTPError as e:
        if e.code == 429:
            # Rate limited → pause forcée + retry unique
            time.sleep(35)
            _last_req = time.monotonic()
            try:
                data = _call()
            except Exception:
                _cache[cache_key] = []
                return []
        else:
            _cache[cache_key] = []
            return []
    except Exception:
        _cache[cache_key] = []
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if cve.get("vulnStatus") == "Rejected":
            continue

        cve_id = cve.get("id", "")
        desc   = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            ""
        )

        # CVSS v3.1 > v3.0 > v2
        cvss  = 0.0
        mets  = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = mets.get(key, [])
            if entries:
                cvss = entries[0].get("cvssData", {}).get("baseScore", 0.0)
                break
        if cvss == 0.0:
            for entry in mets.get("cvssMetricV2", []):
                cvss = entry.get("cvssData", {}).get("baseScore", 0.0)
                break

        cves.append({
            "id":        cve_id,
            "desc":      desc[:250],
            "cvss":      round(float(cvss), 1),
            "severity":  cvss_severity(float(cvss)),
            "published": cve.get("published", "")[:10],
            "url":       f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    cves.sort(key=lambda c: c["cvss"], reverse=True)
    _cache[cache_key] = cves
    return cves

# ── Score de risque ────────────────────────────────────────────────────────────

def device_risk(all_cves: list[dict]) -> tuple[float, str]:
    """
    Score de risque global d'un device (0.0–10.0).

    base  = CVSS max parmi tous les CVEs
    bonus = min(1.5, nb_critical × 0.25)   [criticité de masse]
    score = min(10.0, base + bonus)
    """
    scores = [c["cvss"] for c in all_cves if c.get("cvss", 0) > 0]
    if not scores:
        return 0.0, "NONE"
    base   = max(scores)
    n_crit = sum(1 for c in all_cves if c.get("severity") == "CRITICAL")
    risk   = round(min(10.0, base + min(1.5, n_crit * 0.25)), 1)
    return risk, cvss_severity(risk)

# ── API publique ───────────────────────────────────────────────────────────────

def enrich(full_results: dict, api_key: str = "", verbose: bool = True) -> dict:
    """
    Enrichit full_results en place :
      - Ajoute port_result["cves"] pour chaque port ouvert avec service identifié
      - Ajoute entry["risk_score"], entry["risk_level"], entry["total_cves"] par device

    api_key : clé NVD optionnelle (export NVD_API_KEY ou --nvd-key).
              Accélère le rate-limit de 6.5s → 0.7s entre requêtes.
    """
    queries: list[tuple[str, str, int]] = []
    seen_kw: set[str] = set()

    for ip, entry in full_results.items():
        for port, r in entry["ports"].items():
            if r.get("state") != "open":
                continue
            kw = search_keyword(r.get("service", ""), r.get("version", ""))
            if kw:
                queries.append((kw, ip, port))
                seen_kw.add(kw)

    # Initialiser les champs de risque (cas sans ports ouverts ou sans keyword)
    for entry in full_results.values():
        entry.setdefault("risk_score", 0.0)
        entry.setdefault("risk_level", "NONE")
        entry.setdefault("total_cves", 0)

    if not queries:
        return full_results

    delay_s = _DELAY_KEYED if api_key else _DELAY_PUBLIC
    eta_s   = len(seen_kw) * delay_s
    if verbose:
        print(f"\n  → NVD : {len(seen_kw)} requête(s) unique(s) · {len(queries)} port(s) concerné(s)")
        print(f"    ETA ~{eta_s:.0f}s  (delay={delay_s}s/req"
              + ("  — posez NVD_API_KEY pour accélérer ×9)" if not api_key else ")"))

    for kw, ip, port in queries:
        cache_key = f"{kw}|{bool(api_key)}"
        if cache_key not in _cache:
            if verbose:
                print(f"    NVD ← {kw!r} …", end=" ", flush=True)
            cves = _fetch_cves(kw, api_key)
            if verbose:
                print(f"{len(cves)} CVE(s)")
        else:
            cves = _cache[cache_key]

        full_results[ip]["ports"][port]["cves"] = cves

    # Score de risque global par device
    for ip, entry in full_results.items():
        all_cves = [
            c
            for r in entry["ports"].values()
            for c in r.get("cves", [])
        ]
        score, level       = device_risk(all_cves)
        entry["risk_score"] = score
        entry["risk_level"] = level
        entry["total_cves"] = len(all_cves)

    return full_results

# ── Standalone ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 vuln.py <service> [version]   — ex: vuln.py SSH 'OpenSSH_8.9p1'",
              file=sys.stderr)
        sys.exit(1)
    svc     = sys.argv[1]
    ver     = sys.argv[2] if len(sys.argv) > 2 else ""
    api_key = os.environ.get("NVD_API_KEY", "")
    kw      = search_keyword(svc, ver)
    if not kw:
        print(f"Aucun keyword NVD pour service={svc!r} version={ver!r}", file=sys.stderr)
        sys.exit(1)
    print(f"Recherche NVD : {kw!r}\n")
    cves = _fetch_cves(kw, api_key)
    print(f"{len(cves)} CVE(s) trouvée(s)\n")
    for c in cves:
        print(f"  {c['id']:<20}  CVSS={c['cvss']:<5}  {c['severity']:<9}  {c['desc'][:80]}")
