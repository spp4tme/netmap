// ─── NETMAP WebGL Shaders ───────────────────────────────────────────────────

const SHADERS = {

  // ── Billboard icône — vertex ───────────────────────────────────────────────
  iconVert: `
    attribute vec2 aPosition;
    uniform vec3  uCenter;
    uniform mat4  uView;
    uniform mat4  uProjection;
    uniform float uSize;
    varying vec2  vUV;
    void main() {
      vUV = aPosition;
      vec4 clip   = uProjection * uView * vec4(uCenter, 1.0);
      vec2 offset = aPosition * uSize * clip.w;
      gl_Position = clip + vec4(offset, 0.0, 0.0);
    }
  `,

  // ── Billboard icône — fragment (SDF par type) ─────────────────────────────
  //   uIconType : 0=gateway  1=phone  2=windows  3=router  4=bulb  5=unknown  6=linux
  iconFrag: `
    precision mediump float;
    uniform vec3  uColor;
    uniform float uIconType;
    uniform float uSelected;
    uniform float uGlow;
    varying vec2  vUV;

    float sdRR(vec2 p, vec2 b, float r) {
      vec2 q = abs(p) - b + r;
      return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - r;
    }
    float sdCircle(vec2 p, float r) { return length(p) - r; }
    float sdBox(vec2 p, vec2 b) {
      vec2 d = abs(p) - b;
      return length(max(d, 0.0)) + min(max(d.x, d.y), 0.0);
    }
    float sdHex(vec2 p, float s) {
      vec2 k = vec2(-0.866025, 0.5);
      p = abs(p);
      p -= 2.0 * min(dot(k, p), 0.0) * k;
      p -= vec2(clamp(p.x, -0.57735 * s, 0.57735 * s), s);
      return length(p) * sign(p.y);
    }

    void main() {
      vec2  p = vUV;
      float d = 1.0;
      vec3  c = uColor;

      if (uIconType < 0.5) {
        // 0 — Gateway : cube isométrique 3 faces + 3 antennes
        vec2 ph = p * vec2(1.0, 0.60);
        d = sdHex(ph, 0.58);
        if (d < 0.0) {
          if (p.y > 0.02) {
            c = uColor * 1.65;
          } else if (p.x > 0.02) {
            c = uColor;
          } else {
            c = uColor * 0.52;
          }
          if (abs(p.y) < 0.022) c = mix(c, vec3(0.0), 0.50);
          if (abs(p.x) < 0.018 && p.y < 0.0) c = mix(c, vec3(0.0), 0.45);
        }
        float ant0 = sdBox(p - vec2( 0.00, 0.82), vec2(0.048, 0.18));
        float ant1 = sdBox(p - vec2( 0.38, 0.68), vec2(0.040, 0.13));
        float ant2 = sdBox(p - vec2(-0.38, 0.68), vec2(0.040, 0.13));
        float ants = min(ant0, min(ant1, ant2));
        if (ants < d) { c = uColor * 1.25; d = ants; }

      } else if (uIconType < 1.5) {
        // 1 — Smartphone : portrait arrondi, écran sombre, bouton home
        d = sdRR(p, vec2(0.33, 0.73), 0.12);
        if (d < 0.0) {
          float screen = sdBox(p - vec2(0.0,  0.08), vec2(0.22, 0.43));
          float btn    = sdCircle(p + vec2(0.0, 0.58), 0.08);
          if (screen < 0.0) c = uColor * 0.22 + vec3(0.0, 0.09, 0.20);
          if (btn    < 0.0) c = uColor * 0.55;
        }

      } else if (uIconType < 2.5) {
        // 2 — Windows/PC : moniteur large + pied + base + logo 4 fenêtres
        float screen = sdRR(p - vec2(0.0,  0.28), vec2(0.60, 0.38), 0.05);
        float neck   = sdBox(p - vec2(0.0, -0.22), vec2(0.08, 0.12));
        float foot   = sdBox(p - vec2(0.0, -0.42), vec2(0.32, 0.07));
        d = min(screen, min(neck, foot));
        if (screen < 0.0) {
          c = uColor * 0.18 + vec3(0.0, 0.05, 0.12);
          float gx = p.x;
          float gy = p.y - 0.28;
          if (abs(gx) > 0.05 && abs(gy) > 0.05 && abs(gx) < 0.48 && abs(gy) < 0.26) {
            if (gx < 0.0 && gy > 0.0) c = vec3(0.90, 0.25, 0.05);
            if (gx > 0.0 && gy > 0.0) c = vec3(0.10, 0.60, 0.10);
            if (gx < 0.0 && gy < 0.0) c = vec3(0.08, 0.40, 0.90);
            if (gx > 0.0 && gy < 0.0) c = vec3(0.95, 0.72, 0.05);
          }
        }

      } else if (uIconType < 3.5) {
        // 3 — Routeur : boîtier plat + 2 antennes + 3 LEDs colorées
        float box  = sdRR(p + vec2(0.0, 0.28), vec2(0.58, 0.24), 0.08);
        float ant1 = sdBox(p - vec2( 0.30, -0.34), vec2(0.048, 0.26));
        float ant2 = sdBox(p - vec2(-0.30, -0.34), vec2(0.048, 0.26));
        d = min(box, min(ant1, ant2));
        if (box < 0.0) {
          float led1 = sdCircle(p - vec2(-0.26, -0.20), 0.055);
          float led2 = sdCircle(p - vec2(-0.08, -0.20), 0.055);
          float led3 = sdCircle(p - vec2( 0.10, -0.20), 0.055);
          if      (led1 < 0.0) c = vec3(0.10, 1.00, 0.30);
          else if (led2 < 0.0) c = vec3(1.00, 0.75, 0.10);
          else if (led3 < 0.0) c = vec3(0.20, 0.70, 1.00);
        }

      } else if (uIconType < 4.5) {
        // 4 — Ampoule géométrique : bulle + socle + filament + reflet
        float bulb  = sdCircle(p - vec2(0.0,  0.20), 0.52);
        float neck1 = sdBox(p + vec2(0.0, 0.44), vec2(0.21, 0.10));
        float neck2 = sdBox(p + vec2(0.0, 0.60), vec2(0.17, 0.08));
        float base  = sdBox(p + vec2(0.0, 0.76), vec2(0.21, 0.07));
        d = min(bulb, min(neck1, min(neck2, base)));
        if (d < 0.0) {
          c = mix(uColor, vec3(1.0, 0.97, 0.60), 0.52);
          if (bulb < 0.0) {
            float fil = sdCircle(p - vec2(0.0,   0.16), 0.14);
            float ref = sdCircle(p - vec2(-0.18, 0.44), 0.11);
            if (fil < 0.0) c = vec3(1.0, 0.99, 0.88);
            if (ref < 0.0) c = mix(c, vec3(1.0), 0.55);
          }
        }

      } else if (uIconType < 5.5) {
        // 5 — Inconnu : sphère 3D (diffuse + spéculaire + rim)
        d = sdCircle(p, 0.72);
        if (d < 0.0) {
          vec2  ldir = normalize(vec2(-0.55, 0.72));
          float diff = dot(normalize(p), ldir) * 0.5 + 0.5;
          float spec = pow(clamp(dot(normalize(p - vec2(-0.28, 0.34)), ldir), 0.0, 1.0), 14.0);
          float rim  = smoothstep(0.38, 0.72, length(p));
          c = uColor * (0.30 + 0.70 * diff) + vec3(0.65) * spec;
          c = mix(c, uColor * 0.15, rim * 0.65);
        }

      } else {
        // 6 — Linux (Tux) : corps sombre + ventre crème + yeux jaunes + bec/pieds orange
        float body  = sdRR(p + vec2(0.0,  0.16), vec2(0.36, 0.44), 0.14);
        float belly = sdRR(p + vec2(0.0,  0.12), vec2(0.22, 0.30), 0.10);
        float head  = sdCircle(p - vec2(0.0,  0.48), 0.30);
        float eye1  = sdCircle(p - vec2(-0.10, 0.52), 0.066);
        float eye2  = sdCircle(p - vec2( 0.10, 0.52), 0.066);
        float beak  = sdRR(p - vec2(0.0,  0.37), vec2(0.10, 0.07), 0.03);
        float foot1 = sdRR(p - vec2(-0.20, -0.72), vec2(0.13, 0.06), 0.03);
        float foot2 = sdRR(p - vec2( 0.20, -0.72), vec2(0.13, 0.06), 0.03);
        d = min(min(body, head), min(foot1, foot2));
        c = uColor;
        if (belly < 0.0 && body < 0.0) c = vec3(0.93, 0.90, 0.78);
        if (eye1  < 0.0 || eye2  < 0.0) c = vec3(1.00, 0.90, 0.10);
        if (beak  < 0.0) c = vec3(1.00, 0.62, 0.05);
        if (foot1 < 0.0 || foot2 < 0.0) c = vec3(1.00, 0.62, 0.05);
      }

      float alpha = smoothstep(0.03, -0.025, d);
      if (alpha < 0.01) discard;
      c += uColor * clamp(-d * 0.8, 0.0, 1.0) * uGlow * 0.45;
      c += vec3(0.45) * uSelected;
      gl_FragColor = vec4(min(c, vec3(1.0)), alpha);
    }
  `,

  // ── Edge vertex shader ────────────────────────────────────────────────────
  edgeVert: `
    attribute vec3 aPosition;
    uniform mat4 uView;
    uniform mat4 uProjection;
    void main() {
      gl_Position = uProjection * uView * vec4(aPosition, 1.0);
    }
  `,

  // ── Edge fragment shader ──────────────────────────────────────────────────
  edgeFrag: `
    precision mediump float;
    uniform vec3  uColor;
    uniform float uAlpha;
    void main() {
      gl_FragColor = vec4(uColor, uAlpha);
    }
  `,

  // ── Glow halo — vertex (billboard constant-screen-size) ───────────────────
  glowVert: `
    attribute vec2 aPosition;
    uniform vec3  uCenter;
    uniform mat4  uView;
    uniform mat4  uProjection;
    uniform float uSize;
    varying vec2  vUV;
    void main() {
      vUV = aPosition * 0.5 + 0.5;
      vec4 clip   = uProjection * uView * vec4(uCenter, 1.0);
      vec2 offset = aPosition * uSize * clip.w;
      gl_Position = clip + vec4(offset, 0.0, 0.0);
    }
  `,

  // ── Glow halo — fragment ──────────────────────────────────────────────────
  glowFrag: `
    precision mediump float;
    uniform vec3  uColor;
    uniform float uIntensity;
    varying vec2  vUV;
    void main() {
      float d     = distance(vUV, vec2(0.5));
      float alpha = smoothstep(0.5, 0.0, d) * uIntensity;
      gl_FragColor = vec4(uColor, alpha);
    }
  `
};
