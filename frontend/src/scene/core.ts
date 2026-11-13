/**
 * The central object: an original voxel "decision core".
 * - A luminous core (the agent) with blocky arms radiating outward (tool channels).
 * - A thin ring gate on one arm (the monitor) that periodically flashes: a denial.
 * - A faint offset copy that fades in and out (a counterfactual branch).
 * - An orbiting particle field (information flow).
 */
import * as THREE from "three";
import { RoundedBoxGeometry } from "three/examples/jsm/geometries/RoundedBoxGeometry.js";

const V = 0.2; // voxel size (world units)

type Vec = [number, number, number];

function buildVoxels(): Vec[] {
  const set = new Map<string, Vec>();
  const add = (v: Vec) => set.set(v.join(","), v);

  // Core: 3x3x3 without corners
  for (let x = -1; x <= 1; x++)
    for (let y = -1; y <= 1; y++)
      for (let z = -1; z <= 1; z++) if (Math.abs(x) + Math.abs(y) + Math.abs(z) < 3) add([x, y, z]);

  // Arms: [direction, length, thickness axes]
  const arms: [Vec, number][] = [
    [[1, 0, 0], 5],
    [[-1, 0, 0], 5],
    [[0, 1, 0], 4],
    [[0, -1, 0], 4],
    [[1, 1, 0], 4],
    [[-1, -1, 0], 4],
    [[1, -1, 0], 4],
    [[-1, 1, 0], 3],
    [[0, 0, 1], 4],
    [[0, 0, -1], 4],
    [[1, 0, 1], 3],
    [[-1, 0, -1], 3],
    [[0, 1, -1], 3],
    [[0, -1, 1], 2],
  ];
  for (const [d, len] of arms) {
    const diag = Math.abs(d[0]) + Math.abs(d[1]) + Math.abs(d[2]) > 1;
    for (let i = 1; i <= len; i++) {
      const c: Vec = [d[0] * i, d[1] * i, d[2] * i];
      add(c);
      // thickness: one neighbour perpendicular to the arm, stepped for diagonals
      if (!diag) {
        const p: Vec = d[0] ? [0, 1, 0] : d[1] ? [1, 0, 0] : [1, 0, 0];
        if (i < len) add([c[0] + p[0], c[1] + p[1], c[2] + p[2]]);
        if (i < len - 1) add([c[0], c[1], c[2] + (d[2] ? 0 : 1)]);
      } else {
        add([c[0] - d[0], c[1], c[2]]); // staircase step
        if (i === len) add([c[0] + d[0], c[1], c[2]]);
      }
    }
  }
  // A few stray voxels for an organic, slightly broken silhouette
  for (const v of [
    [6, 1, 0],
    [1, 5, 0],
    [-6, -1, 0],
    [5, 5, 0],
    [2, -5, 1],
    [0, 1, 5],
  ] as Vec[])
    add(v);
  return [...set.values()];
}

export interface CoreHandles {
  group: THREE.Group;
  /** call each frame; energy 0..1 = pointer proximity, flash 0..1 = denial pulse */
  update(t: number, dt: number, energy: number, flash: number): void;
  setPixelRatio(pr: number): void;
  coreLight: THREE.PointLight;
}

export function buildCore(lowPower: boolean): CoreHandles {
  const group = new THREE.Group();
  const voxels = buildVoxels();
  const maxR = Math.max(...voxels.map((v) => Math.hypot(...v)));

  const geo = new RoundedBoxGeometry(V * 0.94, V * 0.94, V * 0.94, 2, V * 0.12);
  const mat = new THREE.MeshPhysicalMaterial({
    color: 0xffffff,
    metalness: 0.35,
    roughness: 0.22,
    clearcoat: 1,
    clearcoatRoughness: 0.08,
    iridescence: 0.6,
    iridescenceIOR: 1.5,
    iridescenceThicknessRange: [250, 650],
    emissive: new THREE.Color(0x3a0f96),
    emissiveIntensity: 0.75,
    envMapIntensity: 0.55,
  });
  const mesh = new THREE.InstancedMesh(geo, mat, voxels.length);
  const m = new THREE.Matrix4();
  const c = new THREE.Color();
  const hot = new THREE.Color(0xff8fc0);
  const mid = new THREE.Color(0x7d3cff);
  const cold = new THREE.Color(0x3b19b0);
  voxels.forEach((v, i) => {
    m.makeTranslation(v[0] * V, v[1] * V, v[2] * V);
    mesh.setMatrixAt(i, m);
    const r = Math.hypot(...v) / maxR;
    if (r < 0.35) c.copy(hot).lerp(mid, r / 0.35);
    else c.copy(mid).lerp(cold, (r - 0.35) / 0.65);
    mesh.setColorAt(i, c);
  });
  group.add(mesh);

  // Counterfactual ghost: same structure, offset and faint
  const ghostMat = new THREE.MeshBasicMaterial({
    color: 0x9f7bff,
    transparent: true,
    opacity: 0,
    wireframe: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });
  const ghost = new THREE.InstancedMesh(new THREE.BoxGeometry(V, V, V), ghostMat, voxels.length);
  for (let i = 0; i < voxels.length; i++) {
    mesh.getMatrixAt(i, m);
    ghost.setMatrixAt(i, m);
  }
  ghost.scale.setScalar(1.06);
  group.add(ghost);

  // Luminous core
  const core = new THREE.Mesh(
    new THREE.IcosahedronGeometry(V * 0.95, 2),
    new THREE.MeshBasicMaterial({ color: new THREE.Color(3.2, 2.2, 2.6) }),
  );
  group.add(core);
  const halo = new THREE.Sprite(
    new THREE.SpriteMaterial({
      map: radialTexture(),
      color: 0xffb3d1,
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      opacity: 0.85,
    }),
  );
  halo.scale.setScalar(1.3);
  group.add(halo);

  const coreLight = new THREE.PointLight(0xff9a73, 9, 6, 1.6);
  group.add(coreLight);
  const pink = new THREE.PointLight(0xd47bff, 6, 7, 1.6);
  pink.position.set(-1.2, 0.9, 1.4);
  group.add(pink);

  // Monitor gate on the +x arm
  const gate = new THREE.Mesh(
    new THREE.TorusGeometry(V * 1.9, V * 0.07, 12, 64),
    new THREE.MeshBasicMaterial({ color: new THREE.Color(1.2, 1.0, 2.2), transparent: true, opacity: 0.9 }),
  );
  gate.position.set(V * 3.5, V * 0.5, 0);
  gate.rotation.y = Math.PI / 2;
  group.add(gate);
  const gateFlash = new THREE.Sprite(
    new THREE.SpriteMaterial({
      map: radialTexture(),
      color: 0xc9b6ff,
      transparent: true,
      opacity: 0,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    }),
  );
  gateFlash.position.copy(gate.position);
  gateFlash.scale.setScalar(1.4);
  group.add(gateFlash);

  // Orbiting particles (information flow)
  const count = lowPower ? 380 : 900;
  const pGeo = new THREE.BufferGeometry();
  const radius = new Float32Array(count);
  const angle = new Float32Array(count);
  const height = new Float32Array(count);
  const speed = new Float32Array(count);
  const size = new Float32Array(count);
  const color = new Float32Array(count * 3);
  const pal = [new THREE.Color(0xb59bff), new THREE.Color(0xff9fcb), new THREE.Color(0xffffff), new THREE.Color(0x7c5cff)];
  for (let i = 0; i < count; i++) {
    const r = 0.9 + Math.pow(Math.random(), 0.7) * 2.6;
    radius[i] = r;
    angle[i] = Math.random() * Math.PI * 2;
    height[i] = (Math.random() - 0.5) * 1.4 * (1.2 - r / 4);
    speed[i] = (0.12 + Math.random() * 0.25) * (Math.random() < 0.5 ? 1 : -1) * (1.6 / r);
    size[i] = 0.6 + Math.random() * 1.8;
    const col = pal[(Math.random() * pal.length) | 0];
    color.set([col.r, col.g, col.b], i * 3);
  }
  pGeo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(count * 3), 3));
  pGeo.setAttribute("aRadius", new THREE.BufferAttribute(radius, 1));
  pGeo.setAttribute("aAngle", new THREE.BufferAttribute(angle, 1));
  pGeo.setAttribute("aHeight", new THREE.BufferAttribute(height, 1));
  pGeo.setAttribute("aSpeed", new THREE.BufferAttribute(speed, 1));
  pGeo.setAttribute("aSize", new THREE.BufferAttribute(size, 1));
  pGeo.setAttribute("aColor", new THREE.BufferAttribute(color, 3));
  const pMat = new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
    uniforms: { uTime: { value: 0 }, uPR: { value: 1 }, uEnergy: { value: 0 } },
    vertexShader: /* glsl */ `
      attribute float aRadius; attribute float aAngle; attribute float aHeight;
      attribute float aSpeed; attribute float aSize; attribute vec3 aColor;
      uniform float uTime; uniform float uPR; uniform float uEnergy;
      varying vec3 vColor; varying float vAlpha;
      void main() {
        float a = aAngle + uTime * aSpeed * (1.0 + uEnergy * 1.5);
        float r = aRadius * (1.0 - 0.06 * sin(uTime * 0.7 + aAngle * 3.0));
        vec3 p = vec3(cos(a) * r, aHeight + 0.08 * sin(uTime + aAngle * 5.0), sin(a) * r * 0.75);
        vec4 mv = modelViewMatrix * vec4(p, 1.0);
        gl_Position = projectionMatrix * mv;
        gl_PointSize = aSize * uPR * (14.0 / -mv.z);
        float tw = 0.55 + 0.45 * sin(uTime * 2.0 + aAngle * 13.0);
        vAlpha = tw * smoothstep(3.8, 1.2, aRadius) * (0.55 + uEnergy * 0.6);
        vColor = aColor;
      }`,
    fragmentShader: /* glsl */ `
      varying vec3 vColor; varying float vAlpha;
      void main() {
        float d = length(gl_PointCoord - 0.5);
        float a = smoothstep(0.5, 0.0, d);
        gl_FragColor = vec4(vColor * a, a * vAlpha);
      }`,
  });
  const particles = new THREE.Points(pGeo, pMat);
  particles.frustumCulled = false;
  group.add(particles);

  const coreMat = core.material as THREE.MeshBasicMaterial;
  const gateMat = gate.material as THREE.MeshBasicMaterial;
  const flashMat = gateFlash.material as THREE.SpriteMaterial;
  const haloMat = halo.material as THREE.SpriteMaterial;

  return {
    group,
    coreLight,
    update(t, _dt, energy, flash) {
      const pulse = 0.5 + 0.5 * Math.sin(t * 1.6);
      coreMat.color.setRGB(1.7 + pulse * 0.4 + energy * 0.35, 1.0 + pulse * 0.2 + energy * 0.2, 1.15 + pulse * 0.3 + energy * 0.3);
      coreLight.intensity = 4 + pulse * 2 + energy * 3;
      haloMat.opacity = 0.32 + pulse * 0.16 + energy * 0.2;
      halo.scale.setScalar(1.2 + pulse * 0.2 + energy * 0.4);
      mat.emissiveIntensity = 0.7 + energy * 0.45 + flash * 0.4;
      gateMat.color.setRGB(1.1 + flash * 3, 0.9 + flash * 1.6, 2.0 + flash * 3);
      gate.scale.setScalar(1 + flash * 0.25);
      flashMat.opacity = flash * 0.95;
      gateFlash.scale.setScalar(1.2 + flash * 1.6);
      ghostMat.opacity = 0.05 + 0.07 * (0.5 + 0.5 * Math.sin(t * 0.5)) + flash * 0.12;
      ghost.rotation.set(Math.sin(t * 0.3) * 0.08, Math.sin(t * 0.21) * 0.12 + 0.06, 0);
      pMat.uniforms.uTime.value = t;
      pMat.uniforms.uEnergy.value = energy;
    },
    setPixelRatio(pr: number) {
      pMat.uniforms.uPR.value = pr;
    },
  };
}

let _radial: THREE.Texture | null = null;
function radialTexture(): THREE.Texture {
  if (_radial) return _radial;
  const s = 128;
  const cv = document.createElement("canvas");
  cv.width = cv.height = s;
  const g = cv.getContext("2d")!;
  const grd = g.createRadialGradient(s / 2, s / 2, 0, s / 2, s / 2, s / 2);
  grd.addColorStop(0, "rgba(255,255,255,1)");
  grd.addColorStop(0.2, "rgba(255,255,255,0.45)");
  grd.addColorStop(0.5, "rgba(255,255,255,0.1)");
  grd.addColorStop(1, "rgba(255,255,255,0)");
  g.fillStyle = grd;
  g.fillRect(0, 0, s, s);
  _radial = new THREE.CanvasTexture(cv);
  _radial.colorSpace = THREE.SRGBColorSpace;
  return _radial;
}
