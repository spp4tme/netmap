#!/usr/bin/env python3
"""
Générateur de rapport HTML statique pour netmap.
3 onglets : Réseau (graphe), Vulnérabilités, Timeline.
Vanilla JS, zéro dépendance externe.
"""

import json
import os
from datetime import datetime

# ── Helpers ────────────────────────────────────────────────────────────────────

def _fmt_mac(b) -> str:
    if isinstance(b, (bytes, bytearray)):
        return ":".join(f"{x:02x}" for x in b)
    return str(b)


def _build_data(scanner_ip: str, scanner_mac, network: str,
                scan_time: str, full_results: dict) -> dict:
    hosts = []
    for ip in sorted(full_results):
        entry = full_results[ip]
        ref_ttl = next((r["ttl"] for r in entry["ports"].values() if r.get("ttl")), None)
        ports = []
        for port in sorted(entry["ports"]):
            r = entry["ports"][port]
            ports.append({
                "port":    port,
                "state":   r["state"],
                "ttl":     r.get("ttl"),
                "service": r.get("service", ""),
                "version": r.get("version", ""),
                "banner":  r.get("banner",  ""),
                "cves":    r.get("cves",    []),
            })
        hosts.append({
            "ip":          ip,
            "mac":         _fmt_mac(entry["mac"]),
            "os":          entry.get("os_guess", "?"),
            "os_detail":   entry.get("os_detail", ""),
            "vendor":      entry.get("vendor", ""),
            "ttl":         ref_ttl,
            "risk_score":  entry.get("risk_score", 0.0),
            "risk_level":  entry.get("risk_level", "NONE"),
            "total_cves":  entry.get("total_cves", 0),
            "local_vulns": entry.get("local_vulns", []),
            "ports":       ports,
        })
    return {
        "scanner_ip":  scanner_ip,
        "scanner_mac": _fmt_mac(scanner_mac),
        "network":     network,
        "scan_time":   scan_time,
        "hosts":       hosts,
    }


def _build_history_json(history: list) -> str:
    safe = []
    for rec in history:
        safe.append({
            "ts":      rec.get("ts", ""),
            "network": rec.get("network", ""),
            "hosts":   {
                ip: {
                    "os":         h.get("os", "?"),
                    "vendor":     h.get("vendor", ""),
                    "risk_level": h.get("risk_level", "NONE"),
                    "risk_score": h.get("risk_score", 0.0),
                    "open_ports": [
                        int(p) for p, r in h.get("ports", {}).items()
                        if r.get("state") == "open"
                    ],
                }
                for ip, h in rec.get("hosts", {}).items()
            },
        })
    return json.dumps(safe, ensure_ascii=False)


def _build_diff_json(scan_diff) -> str:
    if not scan_diff:
        return "null"
    return json.dumps(scan_diff, ensure_ascii=False)


# ── Template HTML ──────────────────────────────────────────────────────────────

_HTML = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>netmap · __NETWORK__</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Consolas','Courier New',monospace;background:#0f172a;color:#e2e8f0;
  height:100vh;display:flex;flex-direction:column;overflow:hidden}

/* ── Header ── */
header{padding:10px 18px;background:#1e293b;border-bottom:1px solid #334155;
  display:flex;align-items:center;gap:14px;flex-shrink:0;flex-wrap:wrap}
h1{font-size:15px;color:#38bdf8;letter-spacing:3px;font-weight:bold}
.meta{font-size:11px;color:#64748b}
.badge{font-size:11px;padding:2px 9px;border-radius:10px;background:#0c2a47;color:#7dd3fc}

/* Risk gauge */
#gauge-wrap{display:flex;align-items:center;gap:8px;margin-left:auto}
#gauge-label{font-size:11px;color:#64748b}
#gauge-val{font-size:13px;font-weight:bold}

/* ── Tabs ── */
#tabs{display:flex;background:#1e293b;border-bottom:1px solid #334155;flex-shrink:0}
.tab{padding:8px 20px;font-size:12px;cursor:pointer;color:#64748b;
  border-bottom:2px solid transparent;letter-spacing:1px;transition:color .15s}
.tab:hover{color:#94a3b8}
.tab.active{color:#38bdf8;border-bottom-color:#38bdf8}

/* ── Main panels ── */
#main{flex:1;overflow:hidden;display:flex;min-height:0}

/* ── Network tab ── */
#tab-network{flex:1;display:flex;overflow:hidden}
#wrap{flex:1;position:relative;overflow:hidden}
canvas{width:100%;height:100%;display:block;cursor:default}
#panel{width:300px;background:#1e293b;border-left:1px solid #334155;
  overflow-y:auto;flex-shrink:0;display:flex;flex-direction:column}
#p-empty{flex:1;display:flex;align-items:center;justify-content:center;
  color:#475569;font-size:12px;text-align:center;padding:20px;line-height:1.8}
#p-content{display:none;padding:14px}

/* ── Vuln tab ── */
#tab-vuln{flex:1;overflow-y:auto;padding:18px;display:none}
.vuln-host{margin-bottom:18px;background:#1e293b;border:1px solid #334155;border-radius:6px;overflow:hidden}
.vuln-host-hdr{padding:10px 14px;background:#0f172a;display:flex;align-items:center;gap:10px;cursor:pointer}
.vuln-host-hdr:hover{background:#162032}
.vuln-host-body{padding:10px 0;display:none}
.vuln-host-body.open{display:block}
.vuln-row{display:grid;grid-template-columns:90px 52px 70px 1fr;gap:6px;
  padding:5px 14px;font-size:11px;align-items:start;border-bottom:1px solid #1a2e45}
.vuln-row:last-child{border-bottom:none}
.vuln-row:hover{background:#162032}
.v-port{color:#7dd3fc}
.v-cvss{color:#94a3b8}
.v-title{color:#cbd5e1}
.v-desc{color:#64748b;font-size:10px;margin-top:2px}
.v-src-local{color:#a78bfa;font-size:9px}
.v-src-nvd{color:#38bdf8;font-size:9px}

/* ── Timeline tab ── */
#tab-tl{flex:1;overflow-y:auto;padding:18px;display:none}
.tl-entry{margin-bottom:14px;background:#1e293b;border:1px solid #334155;border-radius:6px;padding:12px 16px}
.tl-ts{font-size:12px;color:#38bdf8;margin-bottom:8px}
.tl-stats{display:flex;gap:16px;font-size:11px;color:#64748b}
.tl-stat{display:flex;flex-direction:column;gap:2px}
.tl-stat-v{color:#e2e8f0;font-size:14px;font-weight:bold}
.diff-card{background:#162032;border:1px solid #1d4ed8;border-radius:6px;padding:12px 16px;margin-bottom:14px}
.diff-card h3{font-size:12px;color:#60a5fa;margin-bottom:10px;letter-spacing:1px}
.diff-row{display:flex;gap:8px;font-size:11px;padding:3px 0;border-bottom:1px solid #1a2e45}
.diff-row:last-child{border-bottom:none}
.diff-lbl{color:#64748b;width:90px;flex-shrink:0}
.diff-val{color:#e2e8f0}
.tag-new{color:#4ade80}.tag-gone{color:#f87171}.tag-chg{color:#fbbf24}

/* ── Shared ── */
.hidden{display:none!important}
.p-ip{font-size:17px;font-weight:bold;color:#38bdf8;margin-bottom:10px;
  padding-bottom:10px;border-bottom:1px solid #334155}
.p-row{display:flex;gap:8px;margin-bottom:5px;font-size:12px}
.p-lbl{color:#64748b;width:50px;flex-shrink:0}
.p-val{color:#cbd5e1;word-break:break-all}
.os-badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:bold}
.sec{margin:12px 0 6px;font-size:10px;color:#64748b;letter-spacing:1px;text-transform:uppercase}
table{width:100%;border-collapse:collapse;font-size:11px}
th{text-align:left;color:#475569;padding:3px 3px;border-bottom:1px solid #334155;
  font-weight:normal;font-size:10px}
td{padding:4px 3px;border-bottom:1px solid #1a2e45;vertical-align:top}
.o{color:#4ade80}.c{color:#f87171}.f{color:#64748b}
.sv{color:#7dd3fc}.vr{color:#94a3b8;font-size:10px}
.bn{color:#4b5563;font-size:10px;font-style:italic;max-width:200px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.CRITICAL{color:#ef4444}.HIGH{color:#f97316}.MEDIUM{color:#eab308}
.LOW{color:#22c55e}.NONE{color:#475569}.INFO{color:#94a3b8}
.risk-b{border:1px solid currentColor;border-radius:10px;padding:1px 8px;
  font-size:11px;font-weight:bold;display:inline-block;margin:4px 0}
a.cv{color:#7dd3fc;text-decoration:none;font-size:11px}a.cv:hover{text-decoration:underline}
.cvd{color:#475569;font-size:10px;max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
footer{padding:6px 18px;background:#1e293b;border-top:1px solid #334155;
  font-size:11px;color:#475569;display:flex;gap:18px;flex-shrink:0;align-items:center}
#legend{display:flex;gap:12px;align-items:center}
.li{display:flex;align-items:center;gap:5px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
</style>
</head>
<body>

<header>
  <h1>NETMAP</h1>
  <span class="meta">__NETWORK__ &nbsp;·&nbsp; __SCAN_TIME__</span>
  <span class="badge">__HOST_COUNT__ host(s)</span>
  <span class="badge">__OPEN_COUNT__ port(s) ouverts</span>

  <!-- Animated risk gauge (SVG) -->
  <div id="gauge-wrap">
    <span id="gauge-label">Risque global</span>
    <svg width="44" height="44" viewBox="0 0 44 44">
      <circle cx="22" cy="22" r="16" fill="none" stroke="#1e3a5f" stroke-width="5"/>
      <circle id="gauge-ring" cx="22" cy="22" r="16" fill="none" stroke="#ef4444"
        stroke-width="5" stroke-linecap="round"
        stroke-dasharray="100.53" stroke-dashoffset="100.53"
        transform="rotate(-90 22 22)" style="transition:stroke-dashoffset 1.2s ease,stroke 1.2s"/>
    </svg>
    <span id="gauge-val" class="NONE">0.0</span>
  </div>
</header>

<div id="tabs">
  <div class="tab active" data-tab="network" onclick="switchTab('network')">&#9737; Réseau</div>
  <div class="tab"        data-tab="vuln"    onclick="switchTab('vuln')"   >&#9888; Vulnérabilités</div>
  <div class="tab"        data-tab="tl"      onclick="switchTab('tl')"     >&#9783; Timeline</div>
</div>

<div id="main">

  <!-- ── Tab Réseau ── -->
  <div id="tab-network">
    <div id="wrap"><canvas id="g"></canvas></div>
    <div id="panel">
      <div id="p-empty">&#8592; Cliquez sur un nœud<br>pour afficher les détails</div>
      <div id="p-content"></div>
    </div>
  </div>

  <!-- ── Tab Vulnérabilités ── -->
  <div id="tab-vuln"></div>

  <!-- ── Tab Timeline ── -->
  <div id="tab-tl"></div>

</div>

<footer>
  <div id="legend">
    <span class="li"><span class="dot" style="background:#a78bfa"></span>Scanner</span>
    <span class="li"><span class="dot" style="background:#22d3ee"></span>Linux/Unix</span>
    <span class="li"><span class="dot" style="background:#60a5fa"></span>Windows</span>
    <span class="li"><span class="dot" style="background:#fb923c"></span>Network/Cisco</span>
    <span class="li"><span class="dot" style="background:#94a3b8"></span>Inconnu</span>
  </div>
  <span>Glisser pour déplacer · Cliquer pour détails</span>
</footer>

<script>
const DATA    = __DATA_JSON__;
const HISTORY = __HISTORY_JSON__;
const DIFF    = __DIFF_JSON__;

const OC = {
  'Linux/Unix':    '#22d3ee',
  'Windows':       '#60a5fa',
  'Network/Cisco': '#fb923c',
  'scanner':       '#a78bfa',
  '?':             '#94a3b8',
};
const SC  = {'open':'o','closed':'c','filtered':'f'};
const RC  = {'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e'};
const SEV = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];

// ── Gauge ─────────────────────────────────────────────────────────────────────

function initGauge(){
  const scores = DATA.hosts.map(h=>h.risk_score||0);
  const max    = scores.length ? Math.max(...scores) : 0;
  const pct    = max / 10;
  const circ   = 2 * Math.PI * 16;
  const offset = circ * (1 - pct);
  const ring   = document.getElementById('gauge-ring');
  const val    = document.getElementById('gauge-val');
  const col    = pct>=0.9?'#ef4444':pct>=0.7?'#f97316':pct>=0.4?'#eab308':pct>0?'#22c55e':'#475569';
  const lev    = pct>=0.9?'CRITICAL':pct>=0.7?'HIGH':pct>=0.4?'MEDIUM':pct>0?'LOW':'NONE';
  setTimeout(()=>{
    ring.style.strokeDashoffset = offset;
    ring.style.stroke           = col;
  }, 120);
  val.textContent = max.toFixed(1);
  val.className   = lev;
}
initGauge();

// ── Tab switching ─────────────────────────────────────────────────────────────

function switchTab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('active', t.dataset.tab===name));
  document.getElementById('tab-network').style.display = name==='network' ? 'flex'  : 'none';
  document.getElementById('tab-vuln')   .style.display = name==='vuln'    ? 'block' : 'none';
  document.getElementById('tab-tl')     .style.display = name==='tl'      ? 'block' : 'none';
  if(name==='vuln' && !document.getElementById('tab-vuln').dataset.built) buildVulnTab();
  if(name==='tl'   && !document.getElementById('tab-tl').dataset.built)   buildTimelineTab();
  if(name==='network'){resize();settled=false;iter=0;}
}

// ── Vuln tab ──────────────────────────────────────────────────────────────────

function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function buildVulnTab(){
  const el = document.getElementById('tab-vuln');
  el.dataset.built = '1';

  // Collect all findings per host
  const hostFindings = DATA.hosts.map(h=>{
    const nvd = (h.ports||[]).flatMap(p=>(p.cves||[]).map(c=>({
      title:    c.id,
      desc:     c.desc,
      cvss:     c.cvss,
      severity: c.severity,
      port:     p.port,
      url:      c.url,
      source:   'nvd',
    })));
    const local = (h.local_vulns||[]).map(v=>({...v, source:'local'}));
    const all   = [...nvd,...local].sort((a,b)=>{
      const si = x=>SEV.indexOf(x.severity);
      return si(a)!==si(b) ? si(a)-si(b) : b.cvss-a.cvss;
    });
    return {host:h, findings:all};
  }).filter(x=>x.findings.length>0)
    .sort((a,b)=>{
      const si=x=>SEV.indexOf(x.findings[0]?.severity||'INFO');
      return si(a)-si(b);
    });

  if(!hostFindings.length){
    el.innerHTML='<div style="padding:30px;color:#475569;text-align:center">Aucune vulnérabilité détectée</div>';
    return;
  }

  let html='';
  hostFindings.forEach(({host:h, findings})=>{
    const top = findings[0];
    const rl  = top?.severity||'NONE';
    html+=`<div class="vuln-host">
      <div class="vuln-host-hdr" onclick="this.nextElementSibling.classList.toggle('open')">
        <span class="${rl}" style="font-weight:bold">${esc(h.ip)}</span>
        <span class="os-badge" style="background:${(OC[h.os]||'#475569')}22;color:${OC[h.os]||'#475569'}">${esc(h.os_detail||h.os)}</span>
        ${h.vendor?`<span style="color:#64748b;font-size:11px">${esc(h.vendor)}</span>`:''}
        <span class="${rl} risk-b" style="margin-left:auto">${Number(h.risk_score).toFixed(1)} · ${rl}</span>
        <span style="color:#64748b;font-size:11px">${findings.length} finding(s)</span>
      </div>
      <div class="vuln-host-body open">`;

    html+=`<div style="display:grid;grid-template-columns:90px 52px 70px 1fr;gap:6px;
      padding:5px 14px;font-size:10px;color:#475569;border-bottom:1px solid #334155">
      <span>PORT</span><span>CVSS</span><span>SÉVÉRITÉ</span><span>TITRE</span></div>`;

    findings.forEach(f=>{
      const src = f.source==='local'
        ? '<span class="v-src-local">&#9679; local</span>'
        : `<a class="cv v-src-nvd" href="${esc(f.url||'')}" target="_blank">${esc(f.title)}</a>`;
      html+=`<div class="vuln-row">
        <span class="v-port">${f.port?f.port+'/tcp':'—'}</span>
        <span class="v-cvss">${Number(f.cvss||0).toFixed(1)}</span>
        <span class="${f.severity}">${esc(f.severity)}</span>
        <div>
          ${f.source==='local'?`<div class="v-title">${esc(f.title)}</div>`:''}
          ${src}
          <div class="v-desc">${esc((f.desc||'').slice(0,120))}</div>
        </div>
      </div>`;
    });

    html+='</div></div>';
  });
  el.innerHTML = html;
}

// ── Timeline tab ──────────────────────────────────────────────────────────────

function buildTimelineTab(){
  const el = document.getElementById('tab-tl');
  el.dataset.built = '1';
  let html = '';

  // Diff card
  if(DIFF){
    const {new_hosts,gone_hosts,changed,prev_ts,curr_ts} = DIFF;
    html+=`<div class="diff-card">
      <h3>DIFF SCAN PRÉCÉDENT → ACTUEL</h3>
      <div style="font-size:10px;color:#64748b;margin-bottom:8px">${prev_ts.slice(0,16)} → ${curr_ts.slice(0,16)}</div>`;
    if(new_hosts.length){
      html+=`<div class="diff-row"><span class="diff-lbl tag-new">+ Nouveaux</span>
        <span class="diff-val">${new_hosts.map(esc).join(', ')}</span></div>`;
    }
    if(gone_hosts.length){
      html+=`<div class="diff-row"><span class="diff-lbl tag-gone">− Disparus</span>
        <span class="diff-val">${gone_hosts.map(esc).join(', ')}</span></div>`;
    }
    Object.entries(changed).forEach(([ip,ch])=>{
      let details=[];
      if(ch.new_ports.length)    details.push(`<span class="tag-new">+ports ${ch.new_ports.join(',')}</span>`);
      if(ch.closed_ports.length) details.push(`<span class="tag-gone">-ports ${ch.closed_ports.join(',')}</span>`);
      if(ch.os_before!==ch.os_after) details.push(`OS: ${esc(ch.os_before)}→${esc(ch.os_after)}`);
      if(ch.risk_before!==ch.risk_after) details.push(`Risk: <span class="${ch.risk_after}">${esc(ch.risk_before)}→${esc(ch.risk_after)}</span>`);
      ch.service_changes.forEach(s=>{
        details.push(`port ${s.port}: ${esc(s.before||'?')}→<span class="sv">${esc(s.after)}</span>`);
      });
      html+=`<div class="diff-row"><span class="diff-lbl tag-chg">~ ${esc(ip)}</span>
        <span class="diff-val">${details.join('  ')}</span></div>`;
    });
    if(!new_hosts.length && !gone_hosts.length && !Object.keys(changed).length){
      html+=`<div style="color:#64748b;font-size:11px;padding:4px 0">Aucun changement détecté</div>`;
    }
    html+='</div>';
  }

  // History cards (most recent first)
  if(!HISTORY.length){
    html+='<div style="color:#475569;padding:20px;text-align:center">Aucun historique disponible</div>';
  } else {
    [...HISTORY].reverse().forEach((rec,i)=>{
      const ts        = rec.ts.slice(0,16).replace('T',' ');
      const hosts     = Object.keys(rec.hosts);
      const n_hosts   = hosts.length;
      const n_open    = hosts.reduce((a,ip)=>(rec.hosts[ip].open_ports||[]).length+a, 0);
      const max_risk  = hosts.reduce((a,ip)=>Math.max(a,rec.hosts[ip].risk_score||0), 0);
      const risk_lev  = max_risk>=9?'CRITICAL':max_risk>=7?'HIGH':max_risk>=4?'MEDIUM':max_risk>0?'LOW':'NONE';
      html+=`<div class="tl-entry">
        <div class="tl-ts">${esc(ts)} ${i===0?'<span style="color:#4ade80;font-size:10px">● actuel</span>':''}</div>
        <div class="tl-stats">
          <div class="tl-stat"><span class="tl-stat-v">${n_hosts}</span><span>hôtes</span></div>
          <div class="tl-stat"><span class="tl-stat-v">${n_open}</span><span>ports ouverts</span></div>
          <div class="tl-stat"><span class="tl-stat-v ${risk_lev}">${max_risk.toFixed(1)}</span><span>risque max</span></div>
          <div class="tl-stat"><span class="tl-stat-v" style="color:#64748b">${esc(rec.network||'')}</span><span>réseau</span></div>
        </div>
        <div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:6px">
          ${hosts.map(ip=>{
            const h   = rec.hosts[ip];
            const rl  = h.risk_level||'NONE';
            const col = RC[rl]||'#475569';
            return `<span style="font-size:10px;padding:2px 8px;border-radius:10px;
              background:${col}22;color:${col};border:1px solid ${col}44">${esc(ip)}</span>`;
          }).join('')}
        </div>
      </div>`;
    });
  }

  el.innerHTML = html;
}

// ── Force graph ────────────────────────────────────────────────────────────────

const canvas = document.getElementById('g');
const ctx    = canvas.getContext('2d');
let W, H;

function resize(){
  const w = document.getElementById('wrap');
  W = canvas.width  = w.clientWidth;
  H = canvas.height = w.clientHeight;
}
window.addEventListener('resize', ()=>{resize();settled=false;iter=0;});
resize();

class N {
  constructor(d,x,y){
    this.d=d; this.x=x; this.y=y; this.vx=0; this.vy=0;
    this.open   =(d.ports||[]).filter(p=>p.state==='open').length;
    this.r      =Math.max(26,26+Math.min(this.open*3,18));
    this.col    =d.role==='scanner'?OC['scanner']:(OC[d.os]||OC['?']);
    this.sel    =false; this.pinned=false;
  }
}

const nodes=[];
nodes.push(new N({ip:DATA.scanner_ip,mac:DATA.scanner_mac,os:'scanner',role:'scanner',ports:[]},W/2,H/2));
DATA.hosts.forEach((h,i)=>{
  const a=(2*Math.PI*i)/DATA.hosts.length;
  const rr=Math.min(W,H)*0.30;
  nodes.push(new N(h,W/2+rr*Math.cos(a),H/2+rr*Math.sin(a)));
});
const edges=nodes.slice(1).map(n=>({s:nodes[0],t:n}));

let iter=0,settled=false;

function step(){
  if(settled) return;
  const K=Math.sqrt(W*H/Math.max(nodes.length,1))*1.3, K2=K*K;
  nodes.forEach(n=>{n.fx=0;n.fy=0;});
  for(let i=0;i<nodes.length;i++)
    for(let j=i+1;j<nodes.length;j++){
      const a=nodes[i],b=nodes[j];
      let dx=b.x-a.x,dy=b.y-a.y,d=Math.sqrt(dx*dx+dy*dy)||1;
      const f=K2/d,ux=dx/d,uy=dy/d;
      a.fx-=f*ux;a.fy-=f*uy;b.fx+=f*ux;b.fy+=f*uy;
    }
  edges.forEach(e=>{
    const a=e.s,b=e.t;
    let dx=b.x-a.x,dy=b.y-a.y,d=Math.sqrt(dx*dx+dy*dy)||1;
    const f=d*d/K*0.07,ux=dx/d,uy=dy/d;
    if(!a.pinned){a.fx+=f*ux;a.fy+=f*uy;}
    if(!b.pinned){b.fx-=f*ux;b.fy-=f*uy;}
  });
  nodes.forEach(n=>{
    if(n.pinned) return;
    n.fx+=(W/2-n.x)*0.003;n.fy+=(H/2-n.y)*0.003;
    n.vx=(n.vx+n.fx)*0.78;n.vy=(n.vy+n.fy)*0.78;
    n.x=Math.max(n.r+4,Math.min(W-n.r-4,n.x+n.vx));
    n.y=Math.max(n.r+4,Math.min(H-n.r-4,n.y+n.vy));
    const mv=Math.abs(n.vx)+Math.abs(n.vy);
    if(mv>0.15) settled=false;
  });
  iter++;
  if(iter>400) settled=true;
}

function adj(hex,v){
  let r=parseInt(hex.slice(1,3),16),g=parseInt(hex.slice(3,5),16),b=parseInt(hex.slice(5,7),16);
  r=Math.min(255,Math.max(0,Math.round(r+255*v)));
  g=Math.min(255,Math.max(0,Math.round(g+255*v)));
  b=Math.min(255,Math.max(0,Math.round(b+255*v)));
  return `rgb(${r},${g},${b})`;
}

function drawEdge(e){
  const{s:a,t:b}=e;
  ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);
  ctx.strokeStyle=b.open>0?'rgba(56,189,248,0.22)':'rgba(71,85,105,0.35)';
  ctx.lineWidth=1+Math.min(b.open*0.25,1.8);ctx.stroke();
}

function drawNode(n){
  const{x,y,r,col,sel,d}=n;
  if(sel){
    const g=ctx.createRadialGradient(x,y,r,x,y,r+12);
    g.addColorStop(0,col+'60');g.addColorStop(1,'transparent');
    ctx.beginPath();ctx.arc(x,y,r+12,0,Math.PI*2);ctx.fillStyle=g;ctx.fill();
  }
  const rc=RC[d.risk_level];
  if(rc){
    ctx.beginPath();ctx.arc(x,y,r+4,0,Math.PI*2);
    ctx.strokeStyle=rc+'cc';ctx.lineWidth=3;ctx.stroke();
  }
  const gr=ctx.createRadialGradient(x-r*0.28,y-r*0.28,0,x,y,r);
  gr.addColorStop(0,adj(col,0.35));gr.addColorStop(1,adj(col,-0.25));
  ctx.beginPath();ctx.arc(x,y,r,0,Math.PI*2);ctx.fillStyle=gr;ctx.fill();
  ctx.beginPath();ctx.arc(x,y,r,0,Math.PI*2);
  ctx.strokeStyle=sel?'#ffffff':col+'bb';ctx.lineWidth=sel?2:1.5;ctx.stroke();
  ctx.fillStyle='#fff';ctx.textAlign='center';ctx.textBaseline='middle';
  if(d.role==='scanner'){
    ctx.font=`bold ${Math.floor(r*0.48)}px monospace`;ctx.fillText('S',x,y);
  } else {
    ctx.font=`bold ${Math.floor(r*0.55)}px monospace`;
    ctx.fillText(n.open>0?String(n.open):'·',x,y);
  }
  ctx.fillStyle=sel?'#e2e8f0':'#64748b';
  ctx.font=`${Math.max(9,Math.floor(r*0.36))}px monospace`;
  ctx.textBaseline='top';ctx.fillText(d.ip,x,y+r+4);
}

function draw(){
  ctx.clearRect(0,0,W,H);
  ctx.strokeStyle='rgba(51,65,85,0.25)';ctx.lineWidth=0.5;
  for(let x=0;x<W;x+=40){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();}
  for(let y=0;y<H;y+=40){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}
  edges.forEach(drawEdge);nodes.forEach(drawNode);
}

function loop(){step();draw();requestAnimationFrame(loop);}
requestAnimationFrame(loop);

// ── Interaction ────────────────────────────────────────────────────────────────

let drag=null,dox=0,doy=0,downX=0,downY=0;

function hitNode(mx,my){
  for(let i=nodes.length-1;i>=0;i--){
    const n=nodes[i],dx=mx-n.x,dy=my-n.y;
    if(dx*dx+dy*dy<=n.r*n.r) return n;
  }
  return null;
}
function coords(e){
  const rect=canvas.getBoundingClientRect();
  return[(e.clientX-rect.left)*W/rect.width,(e.clientY-rect.top)*H/rect.height];
}
canvas.addEventListener('mousedown',e=>{
  const[mx,my]=coords(e);downX=mx;downY=my;
  const n=hitNode(mx,my);
  if(n){drag=n;dox=n.x-mx;doy=n.y-my;n.pinned=true;canvas.style.cursor='grabbing';}
});
canvas.addEventListener('mousemove',e=>{
  const[mx,my]=coords(e);
  if(drag){drag.x=mx+dox;drag.y=my+doy;drag.vx=0;drag.vy=0;settled=false;iter=0;}
  else canvas.style.cursor=hitNode(mx,my)?'pointer':'default';
});
canvas.addEventListener('mouseup',e=>{
  const[mx,my]=coords(e);
  if(drag){
    if(Math.abs(mx-downX)+Math.abs(my-downY)<5) selectNode(drag);
    drag.pinned=false;drag=null;canvas.style.cursor='pointer';
  }
});
canvas.addEventListener('mouseleave',()=>{if(drag){drag.pinned=false;drag=null;}});

// ── Detail panel ──────────────────────────────────────────────────────────────

function selectNode(n){
  nodes.forEach(x=>x.sel=false);n.sel=true;
  renderPanel(n.d);
}

function renderPanel(d){
  document.getElementById('p-empty').style.display='none';
  const c=document.getElementById('p-content');
  c.style.display='block';
  const col=OC[d.os]||OC['?'];
  const ports=d.ports||[];
  const open=ports.filter(p=>p.state==='open').length;

  let rows='';
  if(ports.length){
    rows=`<div class="sec">Ports (${ports.length} scannés · ${open} ouverts)</div>
<table><tr><th>Port</th><th>État</th><th>Service / version</th></tr>`;
    ports.forEach(p=>{
      const cls=SC[p.state]||'';
      let svcHtml='<span style="color:#475569">—</span>';
      if(p.service&&p.service!=='unknown'){
        svcHtml=`<span class="sv">${esc(p.service)}</span>`;
        if(p.version) svcHtml+=`<br><span class="vr">${esc(p.version.slice(0,50))}</span>`;
        if(p.banner)  svcHtml+=`<br><span class="bn" title="${esc(p.banner)}">${esc(p.banner.slice(0,60))}</span>`;
      }
      rows+=`<tr><td>${p.port}/tcp</td><td class="${cls}">${p.state}</td><td>${svcHtml}</td></tr>`;
    });
    rows+='</table>';
  } else {
    rows='<div class="sec">Hôte local (scanner)</div>';
  }

  // CVE section
  const allCves=(d.ports||[]).flatMap(p=>(p.cves||[]).map(c=>({...c,_p:p.port})));
  allCves.sort((a,b)=>b.cvss-a.cvss);
  let cveHtml='';
  if(allCves.length){
    const rl=d.risk_level||'NONE',rs=Number(d.risk_score||0).toFixed(1);
    cveHtml=`<div class="sec">CVE (${allCves.length})</div>
<div><span class="${rl} risk-b">${rs}/10 · ${rl}</span></div>
<table style="margin-top:8px"><tr><th>CVE</th><th>CVSS</th><th>Sév.</th><th>Description</th></tr>`;
    allCves.forEach(c=>{
      cveHtml+=`<tr>
        <td><a class="cv" href="${c.url}" target="_blank">${esc(c.id)}</a>
            <div style="color:#334155;font-size:9px">port ${c._p}/tcp</div></td>
        <td>${Number(c.cvss).toFixed(1)}</td>
        <td class="${c.severity}">${c.severity}</td>
        <td class="cvd" title="${esc(c.desc)}">${esc(c.desc.slice(0,90))}</td>
      </tr>`;
    });
    cveHtml+='</table>';
  }

  // Local vuln section
  const lvulns = d.local_vulns||[];
  let lvHtml='';
  if(lvulns.length){
    lvHtml=`<div class="sec">Vulns locales (${lvulns.length})</div>
<table><tr><th>Sév.</th><th>Port</th><th>Titre</th></tr>`;
    lvulns.forEach(v=>{
      lvHtml+=`<tr>
        <td class="${v.severity}">${v.severity}</td>
        <td>${v.port?v.port+'/tcp':'—'}</td>
        <td class="v-title" title="${esc(v.desc)}">${esc(v.title)}</td>
      </tr>`;
    });
    lvHtml+='</table>';
  }

  const osDetail = d.os_detail||d.os||'?';
  c.innerHTML=`
    <div class="p-ip">${esc(d.ip)}</div>
    <div class="p-row"><span class="p-lbl">MAC</span><span class="p-val">${esc(d.mac||'—')}</span></div>
    ${d.vendor?`<div class="p-row"><span class="p-lbl">Fab.</span><span class="p-val" style="color:#a78bfa">${esc(d.vendor)}</span></div>`:''}
    ${d.os&&d.role!=='scanner'?`<div class="p-row"><span class="p-lbl">OS</span>
      <span class="os-badge" style="background:${col}22;color:${col}">${esc(osDetail)}</span></div>`:''}
    ${d.ttl?`<div class="p-row"><span class="p-lbl">TTL</span><span class="p-val">${d.ttl}</span></div>`:''}
    ${rows}${cveHtml}${lvHtml}`;
}

// Must be last: canvas, W, H, settled, iter are all defined by now.
switchTab('network');
</script>
</body>
</html>"""

# ── API publique ───────────────────────────────────────────────────────────────

def generate(
    scanner_ip:  str,
    scanner_mac,
    network:     str,
    full_results: dict,
    output:      str  = "report.html",
    history:     list = None,
    scan_diff           = None,
) -> str:
    scan_time  = datetime.now().strftime("%Y-%m-%d %H:%M")
    data       = _build_data(scanner_ip, scanner_mac, network, scan_time, full_results)
    data_json  = json.dumps(data, ensure_ascii=False, indent=2)
    hist_json  = _build_history_json(history or [])
    diff_json  = _build_diff_json(scan_diff)

    host_count = len(data["hosts"])
    open_count = sum(1 for h in data["hosts"] for p in h["ports"] if p["state"] == "open")

    html = (
        _HTML
        .replace("__NETWORK__",    network)
        .replace("__SCAN_TIME__",  scan_time)
        .replace("__HOST_COUNT__", str(host_count))
        .replace("__OPEN_COUNT__", str(open_count))
        .replace("__DATA_JSON__",  data_json)
        .replace("__HISTORY_JSON__", hist_json)
        .replace("__DIFF_JSON__",  diff_json)
    )

    path = os.path.abspath(output)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
