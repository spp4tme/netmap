# NETMAP

![Status](https://img.shields.io/badge/statut-fonctionnel-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Licence](https://img.shields.io/badge/licence-MIT-lightgrey)
![Dépendances](https://img.shields.io/badge/dépendances-aucune-success)

> Scanner réseau offensif écrit en Python pur — zéro dépendance externe.  
> Découverte ARP + mDNS/Bonjour, mesure de latence ICMP, port scan TCP SYN, banner grabbing, fingerprinting OS, enrichissement CVE, rapport WebGL 3D interactif.

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

NETMAP orchestre six phases successives, chacune alimentant la suivante.

### Phase 0 — Découverte mDNS/Bonjour (couche application)

```
┌─────────────────────────────────────────────────────────────────┐
│  Groupe multicast 224.0.0.251 : 5353  (RFC 6762)               │
│                                                                 │
│  Scanner                          Appareils sur le LAN          │
│  ┌──────────┐  PTR query → _services._dns-sd._udp.local        │
│  │          │ ────────────────────────►                         │
│  │  netmap  │                                                   │
│  │          │ ◄──── réponses PTR / SRV / A ──────────          │
│  └──────────┘  hostname + services Bonjour                     │
│                                                                 │
│  UDP socket multicast — format wire DNS construit manuellement  │
│  Décodage des labels compressés (pointeurs 0xC0) de la RFC 1035 │
│  Chaîne PTR → SRV → A pour résoudre hostname ↔ IP             │
└─────────────────────────────────────────────────────────────────┘
```

Le scanner envoie une requête PTR pour `_services._dns-sd._udp.local`, puis écoute les annonces spontanées pendant 5 secondes.  
Chaque réponse enrichit l'inventaire avec le nom d'hôte Bonjour (ex. `iphone-de-alice.local`) et la liste des services annoncés (`_airplay._tcp`, `_http._tcp`…).  
Les appareils iOS et Android qui n'avaient pas répondu à l'ARP (mode veille, isolation client Wi-Fi) sont ainsi retrouvés.

---

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

### Phase 1b — Mesure de latence ICMP (couche 3)

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Pour chaque hôte découvert (en parallèle) :                   │
│                                                                 │
│  Scanner                          Cible                         │
│  ──── ICMP Echo Request ─────────────────────────►             │
│       ◄──── ICMP Echo Reply ──── RTT mesuré en ms              │
│       × N paquets (défaut : 5) → latence moyenne               │
│                                                                 │
│  Raw socket AF_INET / IPPROTO_ICMP — paquet ICMP construit      │
│  manuellement (struct !BBHHH) + checksum one's complement       │
│  Identifiant unique par hôte (PID + index) pour démultiplexage  │
│  Un thread par cible — mesures simultanées sur tout le LAN      │
└─────────────────────────────────────────────────────────────────┘
```

La latence sert ensuite au layout 3D : plus un appareil est proche de la gateway en RTT, plus son icône est proche du centre dans le graphe WebGL.  
Les hôtes injoignables en ICMP (firewall) sont placés en périphérie.

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
| **Découverte ARP** | ARP scan couche 2 — raw socket `AF_PACKET`, détection auto de l'interface |
| **Découverte mDNS** | Multicast DNS/Bonjour (RFC 6762) — hostname + services Bonjour, révèle les iOS/Android en veille |
| **Latence ICMP** | Ping from scratch (raw IPPROTO_ICMP) — N paquets par hôte en parallèle, RTT moyen en ms |
| **Port scan** | TCP SYN stealth sur liste de ports configurable, états : ouvert / fermé / filtré |
| **OS detection** | TTL + TCP window + MSS + SACK + timestamps → Linux 4.x/5.x, Windows 10/11, macOS, iOS, Android, Cisco, Juniper |
| **Fabricant** | Base OUI embarquée (300+ entrées) → Apple, Samsung, Raspberry Pi, Espressif, Freebox… |
| **Banner grabbing** | SSH, FTP, SMTP, POP3, IMAP, HTTP/S, Telnet, SMB, VNC, Redis, MySQL, PostgreSQL |
| **CVE** | NVD API v2 — CVSS v3.1 prioritaire, rate limiting, cache, score de risque global |
| **Vulns locales** | Règles hors-ligne — Telnet, FTP clair, SMBv1, RDP, VNC, FTP anonyme, chemins HTTP admin, SSL expiré/self-signed |
| **Timeline** | Historique JSON des scans, diff automatique : nouveaux hôtes, ports ouverts/fermés, changements de service |
| **Rapport WebGL 3D** | Canvas WebGL — graphe 3D interactif, icônes SDF par type, caméra orbitale, shaders GLSL écrits à la main |
| **Layout latence** | Gateway au centre, distance des nœuds ∝ RTT ICMP — proche = faible latence |
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
# Découverte mDNS/Bonjour (5 s d'écoute)
sudo python3 mdns.py

# Mesure de latence ICMP
sudo python3 latency.py 192.168.1.1 192.168.1.42 192.168.1.100

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

### Onglet Réseau — graphe WebGL 3D

Rendu WebGL natif — aucune bibliothèque JS (pas de Three.js, pas de D3).  
Trois programmes GLSL compilés à la volée dans le navigateur (`webgl_shaders.js`, `webgl_engine.js`, `webgl_controls.js`).

**Layout basé sur la latence ICMP**

La gateway (`.254` ou `.1`) est placée à l'origine `(0, 0, 0)`.  
Chaque autre nœud est disposé sur un cercle dans le plan XZ à un rayon proportionnel à son RTT mesuré :

```
rayon = R_MIN + (RTT - RTT_min) / (RTT_max - RTT_min) × (R_MAX - R_MIN)
        [3,5 u]                                              [14 u]
```

Les hôtes injoignables en ICMP sont placés à `R_MAX` (périphérie).  
Le résultat : un coup d'œil suffit pour identifier les appareils les plus proches physiquement de la gateway.

**Icônes SDF (Signed Distance Field)**

Chaque nœud est rendu comme un billboard 2D face caméra, dont la forme est calculée entièrement en GLSL dans le fragment shader.  
Aucune texture — les primitives SDF permettent un rendu net à toute résolution.

| Type | Icône GLSL | Couleur |
|---|---|---|
| Gateway | Hexagone isométrique 3 faces + 3 antennes | Or |
| Smartphone (iOS / Android) | Portrait arrondi, écran sombre, bouton home | Cyan |
| PC Windows | Moniteur large + pied + logo 4 fenêtres colorées | Bleu |
| Linux / Tux | Corps sombre, ventre crème, yeux jaunes, bec orange | Bleu ardoise |
| Routeur | Boîtier plat + 2 antennes + 3 LEDs (verte / orange / bleue) | Orange |
| IoT / Ampoule | Bulle + socle + filament + reflet | Jaune |
| Inconnu | Sphère 3D (diffuse + spéculaire + rim light) | Gris |

Les nœuds à risque élevé (score ≥ 6) reçoivent un halo lumineux (`glowFrag`) dont l'intensité est proportionnelle au score.  
La taille des icônes augmente légèrement avec le nombre de ports ouverts.

**Caméra orbitale interactive**

| Geste | Action |
|---|---|
| Clic-glisser | Rotation en orbite (θ, φ) |
| Molette | Zoom (rayon 3 – 60 unités) |
| Clic simple | Sélection du nœud + panneau de détails |
| Pinch (tactile) | Zoom sur mobile |
| Glisser (tactile) | Rotation sur mobile |

Au lancement, la caméra tourne lentement automatiquement. Le premier clic-glisser coupe l'auto-rotation.  
La sélection utilise un raycasting CPU précis (inversion des matrices projection et vue, test d'intersection rayon/sphère).

### Onglet Vulnérabilités

Toutes les CVE et règles locales regroupées par hôte, triées par criticité.  
Lien direct vers la fiche NVD pour chaque CVE.

### Onglet Timeline

Historique de tous les scans (fichiers JSON dans `.history/`).  
Diff visuel entre le scan précédent et l'actuel : nouveaux hôtes, ports apparus/disparus, changements de service.

---

## Architecture du projet

```
netmap/
│
├── netmap.py          # Orchestrateur principal — 6 phases, CLI argparse
│
├── mdns.py            # Phase 0 — découverte mDNS/Bonjour (RFC 6762)
│                      #   _build_ptr_query() · _parse_packet() · scan()
│                      #   Format wire DNS encodé/décodé manuellement (labels + pointeurs)
│
├── arp_scan.py        # Phase 1 — découverte ARP via raw AF_PACKET sockets
│                      #   get_iface_info() · default_iface() · scan()
│
├── latency.py         # Phase 1b — mesure RTT ICMP from scratch
│                      #   _build_packet() · _recv_reply() · _measure_host() · scan()
│                      #   Raw IPPROTO_ICMP, checksum, un thread par hôte
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
│                      #   Injecte les données JSON + inline les 3 fichiers JS WebGL
│
├── report.html        # Rapport du dernier scan (régénéré à chaque run)
│
├── webgl/
│   ├── webgl_shaders.js   # Shaders GLSL : iconVert/Frag · edgeVert/Frag · glowVert/Frag
│   │                      #   Fragment SDF : 7 types d'icônes (gateway, phone, windows,
│   │                      #   linux, router, bulb, unknown) — zéro texture
│   ├── webgl_engine.js    # Moteur WebGL : Mat4 · layout latence · classifyNode()
│   │                      #   starLayout() · boucle de rendu requestAnimationFrame
│   └── webgl_controls.js  # Caméra orbitale · raycasting · pickNode() · initWebGL()
│                          #   Support souris + tactile (pinch-zoom)
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
         ┌─────────────────────────────┼──────────────────────────┐
         │                             │                          │
         ▼                             ▼                          ▼
     mdns.py                     arp_scan.py                latency.py
 {IP → hostname,              {IP → MAC, ts}           {IP → RTT ms | None}
  services Bonjour}
         │                             │                          │
         └─────────────────────────────┴──────────────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
              ▼                        ▼                        ▼
        syn_scan.py             banner.py               os_detect.py
    {port → state, ttl,    {port → service,          (os_family,
     window, tcp_opts}       version, banner}          os_detail)
              │                        │                        │
              └────────────────────────┴────────────────────────┘
                                       │
                                       ▼
                              full_results : dict
                     {IP → {mac, os_guess, os_detail, vendor,
                            hostname, latency_ms, ports → {…}}}
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
              ▼                        ▼                        ▼
          oui.py                   vuln.py              local_vuln.py
        fabricant             CVE + CVSS              règles locales
                               par port              (Telnet, SMBv1…)
              │                        │                        │
              └────────────────────────┴────────────────────────┘
                                       │
                               timeline.py
                          save() · diff() vs
                          scan précédent
                                       │
                               report.py
                    report.html (3 onglets) :
                    ├── WebGL 3D (layout latence,
                    │   icônes SDF, caméra orbitale)
                    ├── Vulnérabilités (CVE + règles)
                    └── Timeline (diff JSON)
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
| Modèle OSI — couche 3 | Raw socket `AF_INET` : headers IP + ICMP construits manuellement avec checksum |
| Modèle OSI — couche 4 | Construction des headers TCP (SYN, RST), pseudo-header pour checksum |
| Modèle OSI — couches 5-7 | Banner grabbing : identification des protocoles applicatifs (SSH, HTTP, FTP, SMB…) |
| Modèle OSI — couche 7 (DNS) | Format wire DNS encodé/décodé manuellement (labels, pointeurs 0xC0) pour mDNS |
| Adressage et sous-réseaux | Calcul automatique du réseau (`ipaddress.IPv4Network`) depuis IP + masque |
| Protocole ARP | Compréhension et implémentation complète du protocole (opcode, hardware type, format) |
| Protocole TCP | Flags SYN/ACK/RST, numéros de séquence, fenêtre, options TCP |
| Protocole ICMP | Echo Request/Reply construits from scratch — mesure de RTT par identifiant/séquence |
| Protocole mDNS | Multicast DNS RFC 6762 — requêtes PTR, réponses SRV/A, résolution hostname ↔ IP |

### B4 — Travaux pratiques et projets

| Aspect | Détail |
|---|---|
| Langage | Python 3.10+ — typage, dataclasses implicites, `struct`, `fcntl`, `ssl`, `socket` |
| Algorithmes | Layout basé sur la latence ICMP, checksums one's complement, rate limiting CVE |
| Rendu 3D temps réel | WebGL natif — 3 programmes GLSL (icônes, arêtes, halos), boucle `requestAnimationFrame` |
| Mathématiques 3D | Matrices 4×4 écrites à la main : perspective, lookAt, inversion, raycasting |
| Graphismes SDF | Signed Distance Fields en GLSL pour 7 types d'icônes, rendu net sans texture |
| Architecture | Modules découplés, chaque fichier utilisable en standalone |
| Tests | Chaque module dispose d'un point d'entrée `__main__` pour validation unitaire |
| Rapport | Génération automatique HTML/JS/WebGL, graphe 3D interactif sans framework |
| Veille technologique | Utilisation de l'API NVD NIST, suivi de la base CVE nationale américaine |

### Protocoles et RFC étudiés

| Protocole | RFC | Implémenté dans |
|---|---|---|
| mDNS / Bonjour | RFC 6762 + RFC 1035 | `mdns.py` — socket UDP multicast, format wire DNS complet |
| ARP | RFC 826 | `arp_scan.py` |
| IP v4 | RFC 791 | `syn_scan.py` — `_build_ip_header()` |
| ICMP | RFC 792 | `latency.py` — Echo Request/Reply from scratch, checksum, RTT |
| TCP | RFC 793 | `syn_scan.py` — `_build_tcp_header()`, `parse_response()` |
| SSH banner | RFC 4253 | `banner.py` — `b"SSH-"` prefix |
| HTTP/1.0 probe | RFC 1945 | `banner.py` — `_HTTP_PROBE` |
| SMB | MS-SMB2 | `banner.py` — signature `\xfe\x53\x4d\x42` |
| TLS | RFC 8446 | `local_vuln.py` — `ssl.create_default_context()` |
| CVE / CVSS | NIST NVD | `vuln.py` — API v2 |
| WebGL / GLSL ES 1.0 | Khronos | `webgl/` — shaders compilés dans le navigateur, SDF, billboard |

---

## Avertissement légal

NETMAP est un outil à des fins **pédagogiques et d'audit de son propre réseau**.  
L'utilisation de ce scanner sur des réseaux sans autorisation explicite du propriétaire est **illégale** (article 323-1 du Code pénal — accès frauduleux à un système de traitement automatisé de données).  

**N'utilisez cet outil que sur des réseaux dont vous êtes responsable ou sur lesquels vous avez une autorisation écrite.**

---

*Projet développé dans le cadre du BTS SIO option SISR — Python stdlib uniquement + WebGL/GLSL natif, zéro dépendance externe.*
