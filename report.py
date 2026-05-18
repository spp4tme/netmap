#!/usr/bin/env python3
"""
Générateur de rapport HTML statique pour netmap.
Graphe interactif canvas vanilla JS — zéro dépendance externe.
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
            "ip":         ip,
            "mac":        _fmt_mac(entry["mac"]),
            "os":         entry.get("os_guess", "?"),
            "ttl":        ref_ttl,
            "risk_score": entry.get("risk_score", 0.0),
            "risk_level": entry.get("risk_level", "NONE"),
            "total_cves": entry.get("total_cves", 0),
            "ports":      ports,
        })
    return {
        "scanner_ip":  scanner_ip,
        "scanner_mac": _fmt_mac(scanner_mac),
        "network":     network,
        "scan_time":   scan_time,
        "hosts":       hosts,
    }

# ── Template HTML ──────────────────────────────────────────────────────────────
# Substitutions : __NETWORK__ __SCAN_TIME__ __HOST_COUNT__ __OPEN_COUNT__ __DATA_JSON__

_HTML = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>netmap · __NETWORK__</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Consolas','Courier New',monospace;background:#0f172a;color:#e2e8f0;
  height:100vh;display:flex;flex-direction:column;overflow:hidden}
header{padding:10px 18px;background:#1e293b;border-bottom:1px solid #334155;
  display:flex;align-items:center;gap:14px;flex-shrink:0}
h1{font-size:15px;color:#38bdf8;letter-spacing:3px;font-weight:bold}
.meta{font-size:11px;color:#64748b}
.badge{font-size:11px;padding:2px 9px;border-radius:10px;background:#0c2a47;color:#7dd3fc}
#main{flex:1;display:flex;overflow:hidden;min-height:0}
#wrap{flex:1;position:relative;overflow:hidden}
canvas{width:100%;height:100%;display:block;cursor:default}
#panel{width:300px;background:#1e293b;border-left:1px solid #334155;
  overflow-y:auto;flex-shrink:0;display:flex;flex-direction:column}
#p-empty{flex:1;display:flex;align-items:center;justify-content:center;
  color:#475569;font-size:12px;text-align:center;padding:20px;line-height:1.8}
#p-content{display:none;padding:14px}
.p-ip{font-size:17px;font-weight:bold;color:#38bdf8;margin-bottom:10px;
  padding-bottom:10px;border-bottom:1px solid #334155}
.p-row{display:flex;gap:8px;margin-bottom:5px;font-size:12px}
.p-lbl{color:#64748b;width:38px;flex-shrink:0}
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
.CRITICAL{color:#ef4444}.HIGH{color:#f97316}.MEDIUM{color:#eab308}.LOW{color:#22c55e}.NONE{color:#475569}
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
</header>
<div id="main">
  <div id="wrap"><canvas id="g"></canvas></div>
  <div id="panel">
    <div id="p-empty">← Cliquez sur un nœud<br>pour afficher les détails</div>
    <div id="p-content"></div>
  </div>
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
const DATA = __DATA_JSON__;

const OC = {
  'Linux/Unix':    '#22d3ee',
  'Windows':       '#60a5fa',
  'Network/Cisco': '#fb923c',
  'scanner':       '#a78bfa',
  '?':             '#94a3b8',
};
const SC = {'open':'o','closed':'c','filtered':'f'};
const RC = {'CRITICAL':'#ef4444','HIGH':'#f97316','MEDIUM':'#eab308','LOW':'#22c55e'};

const canvas = document.getElementById('g');
const ctx    = canvas.getContext('2d');
let W, H;

function resize(){
  const w = document.getElementById('wrap');
  W = canvas.width  = w.clientWidth;
  H = canvas.height = w.clientHeight;
}
window.addEventListener('resize', resize);
resize();

// ── Nodes & edges ─────────────────────────────────────────────────────────────

class N {
  constructor(d, x, y){
    this.d  = d;
    this.x  = x; this.y  = y;
    this.vx = 0; this.vy = 0;
    this.open    = (d.ports||[]).filter(p=>p.state==='open').length;
    this.r       = Math.max(26, 26 + Math.min(this.open*3, 18));
    this.col     = d.role==='scanner' ? OC['scanner'] : (OC[d.os]||OC['?']);
    this.sel     = false;
    this.pinned  = false;
  }
}

const nodes = [];
nodes.push(new N({
  ip: DATA.scanner_ip, mac: DATA.scanner_mac,
  os: 'scanner', role: 'scanner', ports: []
}, W/2, H/2));

DATA.hosts.forEach((h, i) => {
  const a = (2*Math.PI*i) / DATA.hosts.length;
  const rr = Math.min(W,H) * 0.30;
  nodes.push(new N(h, W/2 + rr*Math.cos(a), H/2 + rr*Math.sin(a)));
});

const edges = nodes.slice(1).map(n => ({s: nodes[0], t: n}));

// ── Force simulation ──────────────────────────────────────────────────────────

let iter = 0, settled = false;

function step(){
  if (settled) return;
  const K  = Math.sqrt(W * H / Math.max(nodes.length, 1)) * 1.3;
  const K2 = K * K;

  nodes.forEach(n => { n.fx = 0; n.fy = 0; });

  // Répulsion entre toutes les paires
  for(let i=0;i<nodes.length;i++){
    for(let j=i+1;j<nodes.length;j++){
      const a=nodes[i], b=nodes[j];
      let dx=b.x-a.x, dy=b.y-a.y;
      let d=Math.sqrt(dx*dx+dy*dy)||1;
      const f=K2/d, ux=dx/d, uy=dy/d;
      a.fx-=f*ux; a.fy-=f*uy;
      b.fx+=f*ux; b.fy+=f*uy;
    }
  }

  // Attraction sur les arêtes (ressort)
  edges.forEach(e => {
    const a=e.s, b=e.t;
    let dx=b.x-a.x, dy=b.y-a.y;
    let d=Math.sqrt(dx*dx+dy*dy)||1;
    const f=d*d/K*0.07, ux=dx/d, uy=dy/d;
    if(!a.pinned){ a.fx+=f*ux; a.fy+=f*uy; }
    if(!b.pinned){ b.fx-=f*ux; b.fy-=f*uy; }
  });

  // Gravité vers le centre
  nodes.forEach(n => {
    if(n.pinned) return;
    n.fx += (W/2-n.x)*0.003;
    n.fy += (H/2-n.y)*0.003;
  });

  // Intégration + amortissement
  let mv=0;
  nodes.forEach(n => {
    if(n.pinned) return;
    n.vx = (n.vx+n.fx)*0.78;
    n.vy = (n.vy+n.fy)*0.78;
    n.x  = Math.max(n.r+4, Math.min(W-n.r-4, n.x+n.vx));
    n.y  = Math.max(n.r+4, Math.min(H-n.r-4, n.y+n.vy));
    mv = Math.max(mv, Math.abs(n.vx)+Math.abs(n.vy));
  });
  iter++;
  if(iter>400||mv<0.15) settled=true;
}

// ── Couleur ───────────────────────────────────────────────────────────────────

function adj(hex, v){
  let r=parseInt(hex.slice(1,3),16), g=parseInt(hex.slice(3,5),16), b=parseInt(hex.slice(5,7),16);
  r=Math.min(255,Math.max(0,Math.round(r+255*v)));
  g=Math.min(255,Math.max(0,Math.round(g+255*v)));
  b=Math.min(255,Math.max(0,Math.round(b+255*v)));
  return `rgb(${r},${g},${b})`;
}

// ── Rendu ─────────────────────────────────────────────────────────────────────

function drawEdge(e){
  const {s:a,t:b}=e;
  ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y);
  ctx.strokeStyle = b.open>0 ? 'rgba(56,189,248,0.22)' : 'rgba(71,85,105,0.35)';
  ctx.lineWidth   = 1 + Math.min(b.open*0.25, 1.8);
  ctx.stroke();
}

function drawNode(n){
  const {x,y,r,col,sel,d}=n;

  if(sel){
    const g=ctx.createRadialGradient(x,y,r,x,y,r+12);
    g.addColorStop(0, col+'60'); g.addColorStop(1,'transparent');
    ctx.beginPath(); ctx.arc(x,y,r+12,0,Math.PI*2);
    ctx.fillStyle=g; ctx.fill();
  }

  // Anneau de risque CVE (rouge=Critical … vert=Low)
  const rc=RC[d.risk_level];
  if(rc){
    ctx.beginPath();ctx.arc(x,y,r+4,0,Math.PI*2);
    ctx.strokeStyle=rc+'cc';ctx.lineWidth=3;ctx.stroke();
  }

  // Fond
  const gr=ctx.createRadialGradient(x-r*0.28,y-r*0.28,0,x,y,r);
  gr.addColorStop(0, adj(col, 0.35));
  gr.addColorStop(1, adj(col,-0.25));
  ctx.beginPath(); ctx.arc(x,y,r,0,Math.PI*2);
  ctx.fillStyle=gr; ctx.fill();

  // Contour
  ctx.beginPath(); ctx.arc(x,y,r,0,Math.PI*2);
  ctx.strokeStyle = sel ? '#ffffff' : col+'bb';
  ctx.lineWidth   = sel ? 2 : 1.5;
  ctx.stroke();

  // Icône / compteur
  ctx.fillStyle='#fff';
  ctx.textAlign='center'; ctx.textBaseline='middle';
  if(d.role==='scanner'){
    ctx.font=`bold ${Math.floor(r*0.48)}px monospace`;
    ctx.fillText('S', x, y);
  } else {
    ctx.font=`bold ${Math.floor(r*0.55)}px monospace`;
    ctx.fillText(n.open>0 ? String(n.open) : '·', x, y);
  }

  // Label IP
  ctx.fillStyle = sel ? '#e2e8f0' : '#64748b';
  ctx.font=`${Math.max(9,Math.floor(r*0.36))}px monospace`;
  ctx.textBaseline='top';
  ctx.fillText(d.ip, x, y+r+4);
}

function draw(){
  ctx.clearRect(0,0,W,H);

  // Grille fond
  ctx.strokeStyle='rgba(51,65,85,0.25)'; ctx.lineWidth=0.5;
  for(let x=0;x<W;x+=40){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();}
  for(let y=0;y<H;y+=40){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}

  edges.forEach(drawEdge);
  nodes.forEach(drawNode);
}

function loop(){ step(); draw(); requestAnimationFrame(loop); }
requestAnimationFrame(loop);

// ── Interaction ───────────────────────────────────────────────────────────────

let drag=null, dox=0, doy=0, downX=0, downY=0;

function hitNode(mx,my){
  for(let i=nodes.length-1;i>=0;i--){
    const n=nodes[i];
    const dx=mx-n.x, dy=my-n.y;
    if(dx*dx+dy*dy<=n.r*n.r) return n;
  }
  return null;
}

function coords(e){
  const rect=canvas.getBoundingClientRect();
  return [(e.clientX-rect.left)*W/rect.width, (e.clientY-rect.top)*H/rect.height];
}

canvas.addEventListener('mousedown', e=>{
  const [mx,my]=coords(e); downX=mx; downY=my;
  const n=hitNode(mx,my);
  if(n){ drag=n; dox=n.x-mx; doy=n.y-my; n.pinned=true; canvas.style.cursor='grabbing'; }
});

canvas.addEventListener('mousemove', e=>{
  const [mx,my]=coords(e);
  if(drag){
    drag.x=mx+dox; drag.y=my+doy;
    drag.vx=0; drag.vy=0;
    settled=false; iter=0;
  } else {
    canvas.style.cursor = hitNode(mx,my) ? 'pointer' : 'default';
  }
});

canvas.addEventListener('mouseup', e=>{
  const [mx,my]=coords(e);
  if(drag){
    const moved=Math.abs(mx-downX)+Math.abs(my-downY);
    if(moved<5) selectNode(drag);
    drag.pinned=false; drag=null;
    canvas.style.cursor='pointer';
  }
});

canvas.addEventListener('mouseleave',()=>{ if(drag){drag.pinned=false;drag=null;} });

// ── Panneau détail ────────────────────────────────────────────────────────────

function selectNode(n){
  nodes.forEach(x=>x.sel=false); n.sel=true;
  renderPanel(n.d);
}

function esc(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
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
      if(p.service && p.service!=='unknown'){
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

  // Section CVE
  const allCves=(d.ports||[]).flatMap(p=>(p.cves||[]).map(c=>({...c,_p:p.port})));
  allCves.sort((a,b)=>b.cvss-a.cvss);
  let cveHtml='';
  if(allCves.length){
    const rl=d.risk_level||'NONE', rs=Number(d.risk_score||0).toFixed(1);
    cveHtml=`<div class="sec">CVE détectées (${allCves.length})</div>
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

  c.innerHTML=`
    <div class="p-ip">${esc(d.ip)}</div>
    <div class="p-row"><span class="p-lbl">MAC</span><span class="p-val">${esc(d.mac||'—')}</span></div>
    ${d.os&&d.role!=='scanner'?`<div class="p-row"><span class="p-lbl">OS</span>
      <span class="os-badge" style="background:${col}22;color:${col}">${esc(d.os)}</span></div>`:''}
    ${d.ttl?`<div class="p-row"><span class="p-lbl">TTL</span><span class="p-val">${d.ttl}</span></div>`:''}
    ${rows}${cveHtml}`;
}
</script>
</body>
</html>"""

# ── API publique ───────────────────────────────────────────────────────────────

def generate(
    scanner_ip:  str,
    scanner_mac,
    network:     str,
    full_results: dict,
    output:      str = "report.html",
) -> str:
    """
    Génère report.html à partir des résultats de scan complets.
    Retourne le chemin absolu du fichier créé.
    """
    scan_time  = datetime.now().strftime("%Y-%m-%d %H:%M")
    data       = _build_data(scanner_ip, scanner_mac, network, scan_time, full_results)
    data_json  = json.dumps(data, ensure_ascii=False, indent=2)

    host_count = len(data["hosts"])
    open_count = sum(1 for h in data["hosts"] for p in h["ports"] if p["state"] == "open")

    html = (
        _HTML
        .replace("__NETWORK__",    network)
        .replace("__SCAN_TIME__",  scan_time)
        .replace("__HOST_COUNT__", str(host_count))
        .replace("__OPEN_COUNT__", str(open_count))
        .replace("__DATA_JSON__",  data_json)
    )

    path = os.path.abspath(output)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
