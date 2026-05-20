// ─── NETMAP WebGL Controls & Main ───────────────────────────────────────────

// ── Camera orbit state ────────────────────────────────────────────────────────
function createOrbitCamera(radius=8) {
  return {
    theta: 0.3,
    phi: 1.1,
    radius,
    autoRotate: true,
    dragging: false,
    lastX: 0, lastY: 0,

    getEye() {
      return [
        this.radius * Math.sin(this.phi) * Math.cos(this.theta),
        this.radius * Math.cos(this.phi),
        this.radius * Math.sin(this.phi) * Math.sin(this.theta)
      ];
    },

    bindEvents(canvas) {
      canvas.addEventListener('mousedown', e => {
        this.dragging = true;
        this.autoRotate = false;
        this.lastX = e.clientX;
        this.lastY = e.clientY;
      });
      window.addEventListener('mouseup', () => { this.dragging = false; });
      canvas.addEventListener('mousemove', e => {
        if (!this.dragging) return;
        const dx = e.clientX - this.lastX;
        const dy = e.clientY - this.lastY;
        this.theta -= dx * 0.005;
        this.phi   = Math.max(0.2, Math.min(Math.PI-0.2, this.phi + dy*0.005));
        this.lastX = e.clientX;
        this.lastY = e.clientY;
      });
      canvas.addEventListener('wheel', e => {
        this.radius = Math.max(3, Math.min(60, this.radius + e.deltaY*0.01));
        e.preventDefault();
      }, { passive: false });

      // Touch support
      let lastTouchDist = 0;
      canvas.addEventListener('touchstart', e => {
        if (e.touches.length === 1) {
          this.dragging = true; this.autoRotate = false;
          this.lastX = e.touches[0].clientX;
          this.lastY = e.touches[0].clientY;
        } else if (e.touches.length === 2) {
          lastTouchDist = Math.hypot(
            e.touches[0].clientX - e.touches[1].clientX,
            e.touches[0].clientY - e.touches[1].clientY
          );
        }
      });
      canvas.addEventListener('touchmove', e => {
        e.preventDefault();
        if (e.touches.length === 1 && this.dragging) {
          const dx = e.touches[0].clientX - this.lastX;
          const dy = e.touches[0].clientY - this.lastY;
          this.theta -= dx * 0.005;
          this.phi = Math.max(0.2, Math.min(Math.PI-0.2, this.phi + dy*0.005));
          this.lastX = e.touches[0].clientX;
          this.lastY = e.touches[0].clientY;
        } else if (e.touches.length === 2) {
          const dist = Math.hypot(
            e.touches[0].clientX - e.touches[1].clientX,
            e.touches[0].clientY - e.touches[1].clientY
          );
          this.radius = Math.max(3, Math.min(60, this.radius - (dist-lastTouchDist)*0.02));
          lastTouchDist = dist;
        }
      }, { passive: false });
      canvas.addEventListener('touchend', () => { this.dragging = false; });
    }
  };
}

// ── Raycasting : pick node depuis un clic souris ──────────────────────────────
function pickNode(canvas, mouseX, mouseY, nodePositions, nodeRadius, camera, projMatrix) {
  const rect = canvas.getBoundingClientRect();
  const nx = ((mouseX - rect.left) / rect.width)  * 2 - 1;
  const ny = -(((mouseY - rect.top)  / rect.height) * 2 - 1);

  const invProj = invertMat4(projMatrix);
  const eye     = camera.getEye();
  const viewMat = Mat4.lookAt(eye, [0, 0, 0], [0, 1, 0]);
  const invView = invertMat4(viewMat);

  const clipNear = [nx, ny, -1, 1];
  const viewNear = mulMat4Vec4(invProj, clipNear);
  viewNear[2] = -1; viewNear[3] = 0;
  const worldDir = mulMat4Vec4(invView, viewNear);
  const rayDir   = norm([worldDir[0], worldDir[1], worldDir[2]]);

  let closest = -1, minDist = Infinity;
  for (let i = 0; i < nodePositions.length; i++) {
    const p  = nodePositions[i];
    const oc = sub3(eye, p);
    const b  = dot3(oc, rayDir);
    const c  = dot3(oc, oc) - nodeRadius * nodeRadius;
    const disc = b*b - c;
    if (disc >= 0) {
      const t = -b - Math.sqrt(disc);
      if (t > 0 && t < minDist) { minDist = t; closest = i; }
    }
  }
  return closest;
}

function mulMat4Vec4(m, v) {
  return [
    m[0]*v[0]+m[4]*v[1]+m[8]*v[2]+m[12]*v[3],
    m[1]*v[0]+m[5]*v[1]+m[9]*v[2]+m[13]*v[3],
    m[2]*v[0]+m[6]*v[1]+m[10]*v[2]+m[14]*v[3],
    m[3]*v[0]+m[7]*v[1]+m[11]*v[2]+m[15]*v[3],
  ];
}

function invertMat4(m) {
  const out = new Float32Array(16);
  const m00=m[0],m01=m[1],m02=m[2],m03=m[3];
  const m10=m[4],m11=m[5],m12=m[6],m13=m[7];
  const m20=m[8],m21=m[9],m22=m[10],m23=m[11];
  const m30=m[12],m31=m[13],m32=m[14],m33=m[15];
  const b00=m00*m11-m01*m10, b01=m00*m12-m02*m10;
  const b02=m00*m13-m03*m10, b03=m01*m12-m02*m11;
  const b04=m01*m13-m03*m11, b05=m02*m13-m03*m12;
  const b06=m20*m31-m21*m30, b07=m20*m32-m22*m30;
  const b08=m20*m33-m23*m30, b09=m21*m32-m22*m31;
  const b10=m21*m33-m23*m31, b11=m22*m33-m23*m32;
  let det=b00*b11-b01*b10+b02*b09+b03*b08-b04*b07+b05*b06;
  if(!det) return out;
  det=1/det;
  out[0]=(m11*b11-m12*b10+m13*b09)*det;
  out[1]=(m02*b10-m01*b11-m03*b09)*det;
  out[2]=(m31*b05-m32*b04+m33*b03)*det;
  out[3]=(m22*b04-m21*b05-m23*b03)*det;
  out[4]=(m12*b08-m10*b11-m13*b07)*det;
  out[5]=(m00*b11-m02*b08+m03*b07)*det;
  out[6]=(m32*b02-m30*b05-m33*b01)*det;
  out[7]=(m20*b05-m22*b02+m23*b01)*det;
  out[8]=(m10*b10-m11*b08+m13*b06)*det;
  out[9]=(m01*b08-m00*b10-m03*b06)*det;
  out[10]=(m30*b04-m31*b02+m33*b00)*det;
  out[11]=(m21*b02-m20*b04-m23*b00)*det;
  out[12]=(m11*b07-m10*b09-m12*b06)*det;
  out[13]=(m00*b09-m01*b07+m02*b06)*det;
  out[14]=(m31*b01-m30*b03-m32*b00)*det;
  out[15]=(m20*b03-m21*b01+m22*b00)*det;
  return out;
}

// ── Main entry point ──────────────────────────────────────────────────────────
let _onNodeClick = null;

function onNodeClick(cb) { _onNodeClick = cb; }

function initWebGL(canvasId, graphData) {
  const canvas = document.getElementById(canvasId);
  const gl = canvas.getContext('webgl', { antialias: true, alpha: true });
  if (!gl) { console.error('WebGL not supported'); return; }

  gl.enable(gl.DEPTH_TEST);
  gl.enable(gl.BLEND);
  gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

  // Programmes GLSL
  const iconProg = buildProgram(gl, SHADERS.iconVert, SHADERS.iconFrag);
  const edgeProg = buildProgram(gl, SHADERS.edgeVert, SHADERS.edgeFrag);
  const glowProg = buildProgram(gl, SHADERS.glowVert, SHADERS.glowFrag);

  // Quad partagé : glow halos + icônes billboard
  const quadBuf = uploadBuffer(gl, QUAD);

  const nodes = graphData.nodes || [];
  const edges = graphData.edges || [];

  const edgeIndices = edges.map(e => ({
    source: nodes.findIndex(n => n.id === e.source),
    target: nodes.findIndex(n => n.id === e.target)
  })).filter(e => e.source >= 0 && e.target >= 0);

  const positions = starLayout(nodes);

  // Caméra — rayon calé sur le nœud le plus éloigné du centre
  const maxPosR  = positions.reduce((m, p) => Math.max(m, Math.hypot(p[0], p[2])), 0);
  const camera   = createOrbitCamera(Math.max(8, maxPosR + 5));
  camera.bindEvents(canvas);

  let selectedNode = -1;

  canvas.addEventListener('click', e => {
    if (camera.dragging) return;
    const proj = Mat4.perspective(Math.PI/4, canvas.width/canvas.height, 0.1, 200);
    const hit  = pickNode(canvas, e.clientX, e.clientY, positions, 0.60, camera, proj);
    selectedNode = hit;
    if (hit >= 0 && _onNodeClick) _onNodeClick(nodes[hit], hit);
  });

  // Buffer des arêtes (construit une seule fois)
  const edgeVerts = [];
  for (const e of edgeIndices) {
    const s = positions[e.source], t = positions[e.target];
    edgeVerts.push(...s, ...t);
  }
  const edgeVertBuf = uploadBuffer(gl, new Float32Array(edgeVerts));

  function resize() {
    canvas.width  = canvas.clientWidth;
    canvas.height = canvas.clientHeight;
    gl.viewport(0, 0, canvas.width, canvas.height);
  }
  window.addEventListener('resize', resize);
  resize();

  // ── Render loop ─────────────────────────────────────────────────────────────
  let lastTime = 0;
  function render(time) {
    const dt = (time - lastTime) / 1000;
    lastTime = time;

    if (camera.autoRotate) camera.theta += dt * 0.12;

    gl.clearColor(0, 0, 0, 0);
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

    const proj = Mat4.perspective(Math.PI/4, canvas.width/canvas.height, 0.1, 200);
    const eye  = camera.getEye();
    const view = Mat4.lookAt(eye, [0, 0, 0], [0, 1, 0]);

    // ── Arêtes ────────────────────────────────────────────────────────────
    gl.useProgram(edgeProg);
    gl.uniformMatrix4fv(gl.getUniformLocation(edgeProg,'uView'),       false, view);
    gl.uniformMatrix4fv(gl.getUniformLocation(edgeProg,'uProjection'), false, proj);
    gl.uniform3fv(gl.getUniformLocation(edgeProg,'uColor'), [0.3, 0.6, 0.8]);
    gl.uniform1f (gl.getUniformLocation(edgeProg,'uAlpha'), 0.35);
    gl.bindBuffer(gl.ARRAY_BUFFER, edgeVertBuf);
    const ePos = gl.getAttribLocation(edgeProg, 'aPosition');
    gl.enableVertexAttribArray(ePos);
    gl.vertexAttribPointer(ePos, 3, gl.FLOAT, false, 0, 0);
    gl.drawArrays(gl.LINES, 0, edgeIndices.length * 2);

    // ── Glow halos (nœuds à risque élevé) ────────────────────────────────
    gl.useProgram(glowProg);
    gl.uniformMatrix4fv(gl.getUniformLocation(glowProg,'uView'),       false, view);
    gl.uniformMatrix4fv(gl.getUniformLocation(glowProg,'uProjection'), false, proj);
    gl.bindBuffer(gl.ARRAY_BUFFER, quadBuf);
    const gPos = gl.getAttribLocation(glowProg, 'aPosition');
    gl.enableVertexAttribArray(gPos);
    gl.vertexAttribPointer(gPos, 2, gl.FLOAT, false, 0, 0);

    for (let i = 0; i < nodes.length; i++) {
      const risk = nodes[i].risk || 0;
      if (risk < 6) continue;
      const intensity = Math.min(1.0, (risk - 6) / 4) * 0.6;
      const col = typeColor(classifyNode(nodes[i]));
      gl.uniform3fv(gl.getUniformLocation(glowProg,'uCenter'),    positions[i]);
      gl.uniform3fv(gl.getUniformLocation(glowProg,'uColor'),     col);
      gl.uniform1f (gl.getUniformLocation(glowProg,'uSize'),      0.10 + intensity * 0.06);
      gl.uniform1f (gl.getUniformLocation(glowProg,'uIntensity'), intensity);
      gl.drawArrays(gl.TRIANGLES, 0, 6);
    }

    // ── Icônes billboard 2D ───────────────────────────────────────────────
    gl.useProgram(iconProg);
    gl.uniformMatrix4fv(gl.getUniformLocation(iconProg,'uView'),       false, view);
    gl.uniformMatrix4fv(gl.getUniformLocation(iconProg,'uProjection'), false, proj);
    gl.bindBuffer(gl.ARRAY_BUFFER, quadBuf);
    const iPos = gl.getAttribLocation(iconProg, 'aPosition');
    gl.enableVertexAttribArray(iPos);
    gl.vertexAttribPointer(iPos, 2, gl.FLOAT, false, 0, 0);

    for (let i = 0; i < nodes.length; i++) {
      const itype = classifyNode(nodes[i]);
      const col   = typeColor(itype);
      const risk  = nodes[i].risk || 0;
      const glow  = risk >= 7 ? 1.0 : risk >= 5 ? 0.4 : 0.0;
      const sel   = selectedNode === i ? 1.0 : 0.0;
      const base  = itype === 'gateway' ? 0.075 : 0.050;
      const size  = base + Math.min(0.020, (nodes[i].openPorts || 0) * 0.003);

      gl.uniform3fv(gl.getUniformLocation(iconProg,'uCenter'),   positions[i]);
      gl.uniform3fv(gl.getUniformLocation(iconProg,'uColor'),    col);
      gl.uniform1f (gl.getUniformLocation(iconProg,'uIconType'), ICON_TYPE[itype]);
      gl.uniform1f (gl.getUniformLocation(iconProg,'uSize'),     size);
      gl.uniform1f (gl.getUniformLocation(iconProg,'uGlow'),     glow);
      gl.uniform1f (gl.getUniformLocation(iconProg,'uSelected'), sel);

      gl.drawArrays(gl.TRIANGLES, 0, 6);
    }

    requestAnimationFrame(render);
  }

  requestAnimationFrame(render);

  return { camera, positions, nodes };
}
