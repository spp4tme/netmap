# NETMAP

![Status](https://img.shields.io/badge/statut-fonctionnel-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Licence](https://img.shields.io/badge/licence-MIT-lightgrey)
![Dépendances](https://img.shields.io/badge/dépendances-aucune-success)

> Scanner réseau offensif écrit en Python pur — zéro dépendance externe.  
> Découverte ARP, port scan TCP SYN, banner grabbing, fingerprinting OS, enrichissement CVE, rapport HTML interactif.

---

## Table des matières

1. [Comment ça marche](#comment-ça-marche)
2. [Fonctionnalités](#fonctionnalités)
3. [Prérequis et installation](#prérequis-et-installation)
4. [Utilisation](#utilisation)
5. [Rapport HTML](#rapport-html)
6. [Architecture du projet](#architecture-du-projet)
7. [BTS SIO SISR — Compétences couvertes](#bts-sio-sisr--compétences-couvertes)

---

## Comment ça marche

NETMAP orchestre quatre phases successives, chacune alimentant la suivante.

### Phase 1 — Découverte ARP (couche 2)

```
┌─────────────────────────────────────────────────────────────────┐
│  Interface réseau  (ex. eth0)                                   │
│                                                                 │
│  Scanner                          Cibles sur le LAN            │
│  ┌──────────┐  ARP Request (broadcast)  ┌──────────────────┐   │
│  │          │ ────────────────────────► │ 192.168.1.0/24   │   │
│  │  netmap  │                           │                  │   │
│  │          │ ◄──────────────────────── │ ARP Reply        │   │
│  └──────────┘  IP + MAC addr           └──────────────────┘   │
│                                                                 │
│  Raw socket AF_PACKET — trame Ethernet brute construite         │
│  manuellement (struct !HHBBH6s4s6s4s) + fcntl.ioctl()         │
└─────────────────────────────────────────────────────────────────┘
```

Le scanner forge des trames ARP `who-has` pour chaque adresse du sous-réseau, écoute les réponses via un socket `AF_PACKET` et construit un dictionnaire `{IP → MAC}`.

---

### Phase 2 — Port scan TCP SYN (couche 3)

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Scanner (src_port aléatoire)         Cible                    │
│                                                                 │
│  ──── SYN ──────────────────────────►                          │
│                                                                 │
│       ◄──── SYN-ACK ─────────────── port OUVERT               │
│  ──── RST ──────────────────────────►  (demi-connexion fermée) │
│                                                                 │
│       ◄──── RST ────────────────────  port FERMÉ              │
│                                                                 │
│       (timeout)                        port FILTRÉ             │
│                                                                 │
│  Raw socket AF_INET/IPPROTO_RAW — IP header + TCP header        │
│  construits à la main avec checksums one's complement valides   │
│  Analyse du TTL → fingerprinting OS (Linux / Windows / Cisco)   │
└─────────────────────────────────────────────────────────────────┘
```

Un thread émetteur envoie les SYN en rafale (délai 1 ms entre paquets). Le thread principal écoute les réponses via `IPPROTO_TCP` en filtrant sur le port source aléatoire. Après SYN-ACK, un RST est renvoyé immédiatement pour ne pas laisser de connexions semi-ouvertes.

Les options TCP du SYN-ACK reçu (MSS, window scale, SACK, timestamps) alimentent le fingerprinting OS avancé.

---

### Phase 3 — Banner grabbing (couche 4/7)

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Pour chaque port OUVERT :                                      │
│                                                                 │
│  ┌──────────────────────────────────────────────┐              │
│  │  1. Connexion TCP (socket standard)           │              │
│  │  2. Si port SSL (443, 8443…) → TLS handshake │              │
│  │  3. Lecture 2048 B (serveur parle en premier) │              │
│  │  4. Sinon → probe HTTP GET /                  │              │
│  │  5. Identification par pattern matching :     │              │
│  │     SSH-2.0-…  →  SSH + version              │              │
│  │     220 vsftpd →  FTP + version              │              │
│  │     HTTP/1.1   →  HTTP/S + Server header     │              │
│  │     \xff\xSMB  →  SMBv1 / SMBv2/3            │              │
│  │     \x0a MySQL →  MySQL + version             │              │
│  └──────────────────────────────────────────────┘              │
│                                                                 │
│  ThreadPoolExecutor(workers=8) — grabbing parallèle             │
└─────────────────────────────────────────────────────────────────┘
```

---

### Phase 4 — Enrichissement CVE (NVD API v2)

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Service identifié       Keyword NVD          Résultat          │
│  ─────────────────────────────────────────────────────────────  │
│  SSH  OpenSSH_8.9p1  →  "OpenSSH 8.9"   →  CVE-2023-38408     │
│  HTTP nginx/1.18.0   →  "nginx 1.18"    →  CVE-2021-23017     │
│  FTP  vsftpd 3.0.3   →  "vsftpd 3.0"   →  CVE-2021-3618      │
│                                                                 │
│  Rate limiting :  6,5 s/req (sans clé)  ·  0,7 s/req (avec)   │
│  Cache en mémoire : même keyword → une seule requête           │
│                                                                 │
│  Score de risque par device :                                   │
│    base  = CVSS max parmi tous les CVE                          │
│    bonus = min(1,5 ; nb_CRITICAL × 0,25)                       │
│    score = min(10,0 ; base + bonus)                             │
│                                                                 │
│  urllib.request — HTTPS stdlib, zéro librairie externe          │
└─────────────────────────────────────────────────────────────────┘
```

En parallèle, des règles locales détectent sans réseau : Telnet ouvert (CRITICAL), FTP non chiffré (HIGH), SMBv1 (CRITICAL), certificats SSL expirés ou auto-signés, accès FTP anonyme, chemins HTTP non authentifiés (`/admin`, `/phpmyadmin`…).

---

## Fonctionnalités

| Catégorie | Détail |
|---|---|
| **Découverte** | ARP scan couche 2 — raw socket `AF_PACKET`, détection auto de l'interface |
| **Port scan** | TCP SYN stealth sur liste de ports configurable, états : ouvert / fermé / filtré |
| **OS detection** | TTL + TCP window + MSS + SACK + timestamps → Linux 4.x/5.x, Windows 10/11, macOS, iOS, Android, Cisco, Juniper |
| **Fabricant** | Base OUI embarquée (300+ entrées) → Apple, Samsung, Raspberry Pi, Espressif, Freebox… |
| **Banner grabbing** | SSH, FTP, SMTP, POP3, IMAP, HTTP/S, Telnet, SMB, VNC, Redis, MySQL, PostgreSQL |
| **CVE** | NVD API v2 — CVSS v3.1 prioritaire, rate limiting, cache, score de risque global |
| **Vulns locales** | Règles hors-ligne — Telnet, FTP clair, SMBv1, RDP, VNC, FTP anonyme, chemins HTTP admin, SSL expiré/self-signed |
| **Timeline** | Historique JSON des scans, diff automatique : nouveaux hôtes, ports ouverts/fermés, changements de service |
| **Rapport** | HTML statique 3 onglets — graphe force-directed canvas, tableau vulnérabilités, timeline diff — zéro framework JS |
| **Stdlib only** | `socket`, `struct`, `fcntl`, `ssl`, `ftplib`, `urllib.request`, `concurrent.futures` — aucun `pip install` |

---

## Prérequis et installation

### Prérequis système

| Élément | Version minimale |
|---|---|
| Python | 3.10 (type hints `X \| Y`, `match`) |
| OS | Linux (raw sockets `AF_PACKET` Linux-only) |
| Privilèges | `root` obligatoire (raw sockets) |
| Réseau | Interface connectée au LAN cible |

### Installation

```bash
# Cloner le dépôt
git clone https://github.com/utilisateur/netmap.git
cd netmap

# Aucune dépendance à installer — stdlib Python uniquement
python3 --version   # vérifier >= 3.10
```

### Clé API NVD (optionnelle mais recommandée)

Sans clé : 5 requêtes / 30 s → délai forcé de 6,5 s entre chaque requête.  
Avec clé : 50 requêtes / 30 s → délai réduit à 0,7 s (×9 plus rapide).

```bash
# Obtenir une clé gratuite sur https://nvd.nist.gov/developers/request-an-api-key
export NVD_API_KEY="votre-clé-ici"
```

---

## Utilisation

> Tous les scans nécessitent les droits root (`sudo`).

### Scan complet (recommandé)

```bash
sudo python3 netmap.py
```

Détection automatique de l'interface, ports par défaut, toutes les phases activées.

### Spécifier l'interface et les ports

```bash
sudo python3 netmap.py eth0 --ports 22,80,443,3306,3389
```

### Scan rapide sans CVE ni vulns locales

```bash
sudo python3 netmap.py --no-vuln --no-local-vuln --no-banner
```

### Scan avec clé NVD et rapport personnalisé

```bash
sudo python3 netmap.py --nvd-key "$NVD_API_KEY" --output /var/www/html/rapport.html
```

### Timeout ajusté (réseau lent ou distant)

```bash
sudo python3 netmap.py --timeout 3.0 --ports 22,80,443
```

### Référence complète des flags

```
usage: netmap.py [iface] [options]

Arguments positionnels :
  iface                   Interface réseau (détection auto si omise)

Options :
  -p, --ports PORTS       Ports à scanner, séparés par virgules
                          défaut : 21,22,23,25,53,80,110,135,139,
                                   143,443,445,3306,3389,5432,8080,8443
  -t, --timeout SEC       Timeout TCP par hôte en secondes (défaut : 1.5)
  -o, --output FICHIER    Chemin du rapport HTML (défaut : ./report.html)
      --nvd-key KEY        Clé API NVD (ou export NVD_API_KEY)
      --no-banner          Désactiver le banner grabbing
      --no-vuln            Désactiver la recherche CVE (NVD)
      --no-local-vuln      Désactiver les vérifications locales de sécurité
      --no-timeline        Ne pas sauvegarder l'historique ni calculer le diff
```

### Modules standalone

Chaque module peut être exécuté indépendamment pour des tests ciblés :

```bash
# ARP scan uniquement
sudo python3 arp_scan.py eth0

# SYN scan sur une IP précise
sudo python3 syn_scan.py eth0 192.168.1.1 22,80,443,8080

# Banner grabbing sur des ports ouverts
sudo python3 banner.py 192.168.1.1 22,80,443

# Recherche CVE pour un service
python3 vuln.py SSH "OpenSSH_8.9p1 Ubuntu-3"

# Audit local (test hors réseau)
python3 local_vuln.py 192.168.1.1

# Historique des scans
python3 timeline.py

# Test OUI
python3 oui.py B8:27:EB:12:34:56   # → Raspberry Pi

# Test fingerprinting OS
python3 os_detect.py
```

### Exemple de sortie console

```
══════════════════════════════════════════════════════════════
  Phase 1 : ARP scan  —  interface eth0
══════════════════════════════════════════════════════════════

  192.168.1.1     a4:91:b1:xx:xx:xx   (routeur)
  192.168.1.42    b8:27:eb:xx:xx:xx   (Raspberry Pi)
  192.168.1.100   dc:a6:32:xx:xx:xx   (Raspberry Pi)

══════════════════════════════════════════════════════════════
  Phase 2 : TCP SYN scan  —  3 hôte(s)  |  ports : 22, 80, 443
══════════════════════════════════════════════════════════════

  → Scan 192.168.1.1 (a4:91:b1:xx:xx:xx) …
  → Banner grabbing 2 port(s) …

  ┌─ 192.168.1.1  a4:91:b1:xx:xx:xx  TTL=62  OS: Cisco IOS
  │  ● 22/tcp   open    SSH/OpenSSH_8.9p1
  │  ● 80/tcp   open    HTTP/nginx 1.18.0
  │  ○ 443/tcp  closed
  └─ Ouverts : 22, 80

══════════════════════════════════════════════════════════════
  Résumé
══════════════════════════════════════════════════════════════

  IP               MAC                  OS                   Fabricant        Risque        Ports ouverts
  ────────────────────────────────────────────────────────────────────────────────────────────────────
  192.168.1.1      a4:91:b1:xx:xx:xx    Cisco IOS            Cisco            8.4 HIGH (6)  22, 80
  192.168.1.42     b8:27:eb:xx:xx:xx    Linux 5.x            Raspberry Pi     3.1 LOW (1)   22
  192.168.1.100    dc:a6:32:xx:xx:xx    Linux 5.x            Raspberry Pi     —             22, 80, 443
```

---

## Rapport HTML

Le rapport `report.html` est généré automatiquement à la fin de chaque scan.  
Il est **entièrement statique** (aucun serveur requis) et fonctionne en ouvrant le fichier dans un navigateur.

```bash
xdg-open report.html       # Linux
```

### Onglet Réseau

![Onglet Réseau](docs/screenshots/tab_network.png)

Graphe force-directed interactif (algorithme de Fruchterman-Reingold, canvas vanilla JS).  
Chaque nœud est cliquable : ports, service, version, CVE, vulnérabilités locales, OS, fabricant.  
Anneau coloré autour du nœud = niveau de risque (rouge = CRITICAL, orange = HIGH…).

### Onglet Vulnérabilités

![Onglet Vulnérabilités](docs/screenshots/tab_vuln.png)

Toutes les CVE et règles locales regroupées par hôte, triées par criticité.  
Lien direct vers la fiche NVD pour chaque CVE.

### Onglet Timeline

![Onglet Timeline](docs/screenshots/tab_timeline.png)

Historique de tous les scans (fichiers JSON dans `.history/`).  
Diff visuel entre le scan précédent et l'actuel : nouveaux hôtes, ports apparus/disparus, changements de service.

---

## Architecture du projet

```
netmap/
│
├── netmap.py          # Orchestrateur principal — 5 phases, CLI argparse
│
├── arp_scan.py        # Phase 1 — découverte ARP via raw AF_PACKET sockets
│                      #   get_iface_info() · default_iface() · scan()
│
├── syn_scan.py        # Phase 2 — port scanner TCP SYN via raw AF_INET sockets
│                      #   build_syn_packet() · build_rst_packet() · scan_ports()
│                      #   parse_response() · guess_os()
│
├── banner.py          # Phase 2b — banner grabbing TCP réel
│                      #   grab() · grab_all() · _identify()
│
├── os_detect.py       # Fingerprinting OS avancé — TCP opts + window + TTL
│                      #   parse_tcp_opts() · fingerprint() · from_port_results()
│
├── oui.py             # Base OUI embarquée (300+ fabricants)
│                      #   lookup(mac_bytes) → str
│
├── vuln.py            # Phase 3 — enrichissement CVE via NVD API v2
│                      #   search_keyword() · _fetch_cves() · device_risk() · enrich()
│
├── local_vuln.py      # Phase 3b — règles locales hors CVE
│                      #   audit() → list[dict]
│
├── timeline.py        # Historique et diff des scans
│                      #   to_record() · save() · load_last() · diff()
│
├── report.py          # Générateur de rapport HTML statique 3 onglets
│                      #   generate(scanner_ip, scanner_mac, network, full_results, …)
│
├── report.html        # Rapport du dernier scan (régénéré à chaque run)
│
└── .history/          # Scans précédents au format JSON (créé automatiquement)
    ├── 2025-01-15T14-32-00.json
    └── 2025-01-16T09-10-22.json
```

### Flux de données

```
                    ┌─────────────────────────────────────────┐
                    │              netmap.py                  │
                    └──────────────────┬──────────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
              ▼                        ▼                        ▼
        arp_scan.py             syn_scan.py               banner.py
    {IP → MAC, ts}       {port → state, ttl,          {port → service,
                          window, tcp_opts}              version, banner}
              │                        │                        │
              └────────────────────────┴────────────────────────┘
                                       │
                                       ▼
                              full_results : dict
                     {IP → {mac, os_guess, os_detail,
                            vendor, ports → {…}}}
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
              ▼                        ▼                        ▼
          oui.py               os_detect.py             vuln.py
        fabricant             (os_family,             CVE + CVSS
                               os_detail)              par port
              │                        │                        │
              └────────────────────────┴────────────────────────┘
                                       │
                               local_vuln.py
                          règles locales (Telnet,
                          SMBv1, SSL, FTP anon…)
                                       │
                               timeline.py
                          save() · diff() vs
                          scan précédent
                                       │
                               report.py
                          report.html (3 onglets)
```

---

## BTS SIO SISR — Compétences couvertes

Ce projet a été développé dans le cadre du BTS SIO option SISR (Solutions d'Infrastructure, Systèmes et Réseaux). Il mobilise l'ensemble des blocs de compétences du référentiel.

### B1 — Support et mise à disposition de services informatiques

| Compétence | Mise en œuvre dans NETMAP |
|---|---|
| Recenser et identifier les ressources numériques | ARP scan : découverte automatique de tous les équipements du LAN (IP, MAC, fabricant) |
| Exploiter des outils de supervision | Rapport HTML interactif exportable, timeline des scans, score de risque par hôte |
| Mettre en place une documentation | Ce README, docstrings de chaque module, rapport HTML auto-généré |

### B2 — Cybersécurité des services informatiques

| Compétence | Mise en œuvre dans NETMAP |
|---|---|
| Protéger les données à caractère personnel | Aucune donnée externe transmise — scan local uniquement, rapport stocké localement |
| Détecter des attaques et réagir | Identification de Telnet, SMBv1, FTP anonyme, certificats expirés, chemins admin exposés |
| Étude des vulnérabilités | Interrogation de la base CVE NVD, score CVSS, priorisation par criticité (CRITICAL à LOW) |
| Sécuriser un équipement | Rapport identifie les ports à fermer, services à mettre à jour, protocoles à remplacer |

### B3 — Conception d'une infrastructure réseau

| Compétence | Mise en œuvre dans NETMAP |
|---|---|
| Modèle OSI — couche 2 | Raw socket `AF_PACKET` : manipulation directe des trames Ethernet (ARP) |
| Modèle OSI — couche 3 | Raw socket `AF_INET` : construction manuelle des headers IP avec checksum |
| Modèle OSI — couche 4 | Construction des headers TCP (SYN, RST), pseudo-header pour checksum |
| Modèle OSI — couches 5-7 | Banner grabbing : identification des protocoles applicatifs (SSH, HTTP, FTP, SMB…) |
| Adressage et sous-réseaux | Calcul automatique du réseau (`ipaddress.IPv4Network`) depuis IP + masque |
| Protocole ARP | Compréhension et implémentation complète du protocole (opcode, hardware type, format) |
| Protocole TCP | Flags SYN/ACK/RST, numéros de séquence, fenêtre, options TCP |

### B4 — Travaux pratiques et projets

| Aspect | Détail |
|---|---|
| Langage | Python 3.10+ — typage, dataclasses implicites, `struct`, `fcntl`, `ssl`, `socket` |
| Algorithmes | Force-directed graph (Fruchterman-Reingold), checksums one's complement, rate limiting |
| Architecture | Modules découplés, chaque fichier utilisable en standalone |
| Tests | Chaque module dispose d'un point d'entrée `__main__` pour validation unitaire |
| Rapport | Génération automatique HTML/JS, graphe interactif sans framework |
| Veille technologique | Utilisation de l'API NVD NIST, suivi de la base CVE nationale américaine |

### Protocoles et RFC étudiés

| Protocole | RFC | Implémenté dans |
|---|---|---|
| ARP | RFC 826 | `arp_scan.py` |
| IP v4 | RFC 791 | `syn_scan.py` — `_build_ip_header()` |
| TCP | RFC 793 | `syn_scan.py` — `_build_tcp_header()`, `parse_response()` |
| ICMP (filtrage passif) | RFC 792 | `syn_scan.py` — paquet[9] != 6 → ignoré |
| SSH banner | RFC 4253 | `banner.py` — `b"SSH-"` prefix |
| HTTP/1.0 probe | RFC 1945 | `banner.py` — `_HTTP_PROBE` |
| SMB | MS-SMB2 | `banner.py` — signature `\xfe\x53\x4d\x42` |
| TLS | RFC 8446 | `local_vuln.py` — `ssl.create_default_context()` |
| CVE / CVSS | NIST NVD | `vuln.py` — API v2 |

---

## Avertissement légal

NETMAP est un outil à des fins **pédagogiques et d'audit de son propre réseau**.  
L'utilisation de ce scanner sur des réseaux sans autorisation explicite du propriétaire est **illégale** (article 323-1 du Code pénal — accès frauduleux à un système de traitement automatisé de données).  

**N'utilisez cet outil que sur des réseaux dont vous êtes responsable ou sur lesquels vous avez une autorisation écrite.**

---

*Projet développé dans le cadre du BTS SIO option SISR — Python stdlib uniquement, zéro dépendance externe.*
