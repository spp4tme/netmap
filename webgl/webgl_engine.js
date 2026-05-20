// ─── NETMAP WebGL Engine ────────────────────────────────────────────────────

// ── Matrix math (no external lib) ────────────────────────────────────────────
const Mat4 = {
  identity() {
    return new Float32Array([1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1]);
  },
  multiply(a, b) {
    const r = new Float32Array(16);
    for (let i = 0; i < 4; i++)
      for (let j = 0; j < 4; j++)
        for (let k = 0; k < 4; k++)
          r[i*4+j] += a[i*4+k] * b[k*4+j];
    return r;
  },
  perspective(fov, aspect, near, far) {
    const f = 1.0 / Math.tan(fov / 2);
    const r = new Float32Array(16);
    r[0]  = f / aspect;
    r[5]  = f;
    r[10] = (far + near) / (near - far);
    r[11] = -1;
    r[14] = (2 * far * near) / (near - far);
    return r;
  },
  lookAt(eye, center, up) {
    const f = norm(sub3(center, eye));
    const s = norm(cross3(f, up));
    const u = cross3(s, f);
    const r = new Float32Array(16);
    r[0]=s[0]; r[4]=s[1]; r[8]=s[2];   r[12]=-dot3(s,eye);
    r[1]=u[0]; r[5]=u[1]; r[9]=u[2];   r[13]=-dot3(u,eye);
    r[2]=-f[0];r[6]=-f[1];r[10]=-f[2]; r[14]= dot3(f,eye);
    r[15]=1;
    return r;
  },
  translation(x, y, z) {
    const r = Mat4.identity();
    r[12]=x; r[13]=y; r[14]=z;
    return r;
  },
  scale(s) {
    const r = Mat4.identity();
    r[0]=s; r[5]=s; r[10]=s;
    return r;
  }
};

function sub3(a,b){ return [a[0]-b[0],a[1]-b[1],a[2]-b[2]]; }
function dot3(a,b){ return a[0]*b[0]+a[1]*b[1]+a[2]*b[2]; }
function cross3(a,b){ return [a[1]*b[2]-a[2]*b[1], a[2]*b[0]-a[0]*b[2], a[0]*b[1]-a[1]*b[0]]; }
function norm(v){ const l=Math.hypot(...v)||1; return v.map(x=>x/l); }

// ── Billboard quad (partagé : glow + icônes) ──────────────────────────────────
const QUAD = new Float32Array([-1,-1, 1,-1, -1,1, 1,-1, 1,1, -1,1]);

// ── Shader helpers ────────────────────────────────────────────────────────────
function compileShader(gl, type, src) {
  const s = gl.createShader(type);
  gl.shaderSource(s, src);
  gl.compileShader(s);
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS))
    throw new Error(gl.getShaderInfoLog(s));
  return s;
}

function buildProgram(gl, vert, frag) {
  const p = gl.createProgram();
  gl.attachShader(p, compileShader(gl, gl.VERTEX_SHADER, vert));
  gl.attachShader(p, compileShader(gl, gl.FRAGMENT_SHADER, frag));
  gl.linkProgram(p);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS))
    throw new Error(gl.getProgramInfoLog(p));
  return p;
}

function uploadBuffer(gl, data, target=null) {
  const buf = gl.createBuffer();
  gl.bindBuffer(target||gl.ARRAY_BUFFER, buf);
  gl.bufferData(target||gl.ARRAY_BUFFER, data, gl.STATIC_DRAW);
  return buf;
}

// ── Classification et couleurs des nœuds ──────────────────────────────────────
const TYPE_COLOR = {
  gateway: [1.00, 0.75, 0.00],   // or
  phone:   [0.00, 0.75, 1.00],   // cyan
  windows: [0.25, 0.55, 1.00],   // bleu
  router:  [1.00, 0.50, 0.10],   // orange
  bulb:    [1.00, 0.95, 0.30],   // jaune
  unknown: [0.50, 0.52, 0.62],   // gris
  linux:   [0.28, 0.42, 0.62],   // bleu ardoise (corps Tux)
};

const ICON_TYPE = { gateway: 0, phone: 1, windows: 2, router: 3, bulb: 4, unknown: 5, linux: 6 };

function classifyNode(node) {
  const v = (node.vendor || (node._data && node._data.vendor) || '').toLowerCase();
  const o = (node.os || '').toLowerCase();
  const ip = node.id || '';
  const last = parseInt(ip.split('.').pop(), 10);

  if (last === 254 || (last === 1 && ip.split('.').length === 4)) return 'gateway';
  if (v.includes('philips') || v.includes('signify') || v.includes('hue'))
    return 'bulb';
  if (v.includes('apple')    || v.includes('samsung')   || v.includes('xiaomi')   ||
      v.includes('oppo')     || v.includes('huawei')    || v.includes('motorola') ||
      o.includes('android')  || o.includes('ios'))
    return 'phone';
  if (v.includes('cisco')    || v.includes('freebox')   || v.includes('livebox')  ||
      v.includes('ubiquiti') || v.includes('netgear')   || v.includes('tp-link')  ||
      v.includes('linksys')  || v.includes('zyxel')     || v.includes('d-link'))
    return 'router';
  if (o.includes('linux')   || o.includes('ubuntu')    || o.includes('debian')   ||
      o.includes('centos')  || o.includes('fedora')    || o.includes('arch'))
    return 'linux';
  if (o.includes('windows') || o.includes('macos')     || o.includes('mac os')   ||
      o.includes('scanner'))
    return 'windows';
  return 'unknown';
}

function typeColor(type) {
  return TYPE_COLOR[type] || TYPE_COLOR.unknown;
}

// ── Layout latence : gateway au centre, distance ∝ latence ICMP ──────────────
//   node.latency = latence en ms (null → placé au rayon maximum)
const LAYOUT_R_MIN = 3.5;
const LAYOUT_R_MAX = 14.0;

function starLayout(nodes, gatewayIp = '192.168.1.254') {
  const n = nodes.length;
  if (n === 0) return [];

  // Centre : IP exacte → dernier octet 254 → premier nœud
  let cIdx = nodes.findIndex(nd => nd.id === gatewayIp);
  if (cIdx < 0)
    cIdx = nodes.findIndex(nd => parseInt((nd.id || '').split('.').pop(), 10) === 254);
  if (cIdx < 0) cIdx = 0;

  const pos    = new Array(n);
  pos[cIdx]    = [0, 0, 0];

  const others = nodes.map((_, i) => i).filter(i => i !== cIdx);
  if (others.length === 0) return pos;

  // Latences valides pour normalisation
  const lats      = others.map(ni => (typeof nodes[ni].latency === 'number') ? nodes[ni].latency : null);
  const validLats = lats.filter(l => l !== null);

  // Fallback : aucune latence → cercle fixe comme avant
  if (validLats.length === 0) {
    const r = Math.max(4, Math.sqrt(others.length) * 2.2);
    others.forEach((ni, i) => {
      const a = (2 * Math.PI * i) / others.length;
      pos[ni] = [r * Math.cos(a), 0, r * Math.sin(a)];
    });
    return pos;
  }

  const latMin   = Math.min(...validLats);
  const latMax   = Math.max(...validLats);
  const latRange = Math.max(latMax - latMin, 0.1);    // évite la division par 0

  others.forEach((ni, i) => {
    const a   = (2 * Math.PI * i) / others.length;
    const lat = lats[i] !== null ? lats[i] : latMax;  // injoignable → bord
    const t   = Math.min(1.0, (lat - latMin) / latRange);
    const r   = LAYOUT_R_MIN + t * (LAYOUT_R_MAX - LAYOUT_R_MIN);
    pos[ni]   = [r * Math.cos(a), 0, r * Math.sin(a)];
  });
  return pos;
}
