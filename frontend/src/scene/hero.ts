/**
 * Hero WebGL scene: bloom-lit 3D core + ambient dust, with the dotted hands drawn in a
 * second (non-bloomed) orthographic pass on the same canvas.
 */
import * as THREE from "three";
import { EffectComposer } from "three/examples/jsm/postprocessing/EffectComposer.js";
import { RenderPass } from "three/examples/jsm/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/examples/jsm/postprocessing/UnrealBloomPass.js";
import { OutputPass } from "three/examples/jsm/postprocessing/OutputPass.js";
import { RoomEnvironment } from "three/examples/jsm/environments/RoomEnvironment.js";
import { addTick, clamp, env, pointer, smoothstep } from "../runtime";
import { buildCore } from "./core";
import { TIP, dotColor, sampleHand, type HandStyle } from "./hands";

interface HandLayout {
  tipX: number; // fraction of width
  tipY: number; // fraction of height
  widthFrac: number; // hand template width as fraction of viewport width
  angle: number; // radians
  mirror: boolean;
}

interface HandObj {
  style: HandStyle;
  points: THREE.Points;
  mat: THREE.ShaderMaterial;
  dots: ReturnType<typeof sampleHand>;
  layout: (w: number, h: number) => HandLayout;
}

export function initHero(canvas: HTMLCanvasElement, hero: HTMLElement, onReady: () => void): void {
  let renderer: THREE.WebGLRenderer;
  try {
    renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: !env.lowPower,
      alpha: false,
      powerPreference: "high-performance",
    });
  } catch {
    document.documentElement.classList.add("no-webgl");
    onReady();
    return;
  }
  renderer.setClearColor(0x030305, 1);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.05;
  renderer.outputColorSpace = THREE.SRGBColorSpace;

  let maxPR = env.lowPower ? 1.25 : 1.6;
  let bloomOn = true;

  /* ---------- 3D scene ---------- */
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(32, 1, 0.1, 100);
  camera.position.set(0, 0, 13);

  const pmrem = new THREE.PMREMGenerator(renderer);
  scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
  pmrem.dispose();

  scene.add(new THREE.AmbientLight(0x5b3bd6, 0.18));
  const key = new THREE.DirectionalLight(0xc9b6ff, 1.05);
  key.position.set(-3, 4, 6);
  scene.add(key);
  const rim = new THREE.DirectionalLight(0xff8fb8, 1.2);
  rim.position.set(4, -2, -3);
  scene.add(rim);

  const core = buildCore(env.lowPower);
  const pivot = new THREE.Group(); // positioned in screen space; rotated by pointer
  pivot.add(core.group);
  scene.add(pivot);

  // Soft floor glow under the object (reflection hint)
  const floor = new THREE.Mesh(
    new THREE.PlaneGeometry(9, 9),
    new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      uniforms: { uPulse: { value: 0 } },
      vertexShader: `varying vec2 vUv; void main(){ vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.); }`,
      fragmentShader: `varying vec2 vUv; uniform float uPulse;
        void main(){ float d = length(vUv - .5) * 2.; float a = smoothstep(1., 0., d);
          a = pow(a, 3.) * (0.22 + uPulse * 0.1);
          gl_FragColor = vec4(vec3(.45,.25,.95) * a, a); }`,
    }),
  );
  floor.rotation.x = -Math.PI / 2;
  scene.add(floor);

  // Ambient dust (background depth)
  const dustCount = env.lowPower ? 500 : 1300;
  const dustPos = new Float32Array(dustCount * 3);
  const dustSeed = new Float32Array(dustCount);
  for (let i = 0; i < dustCount; i++) {
    dustPos.set([(Math.random() - 0.5) * 34, (Math.random() - 0.5) * 20, -4 - Math.random() * 18], i * 3);
    dustSeed[i] = Math.random();
  }
  const dustGeo = new THREE.BufferGeometry();
  dustGeo.setAttribute("position", new THREE.BufferAttribute(dustPos, 3));
  dustGeo.setAttribute("aSeed", new THREE.BufferAttribute(dustSeed, 1));
  const dustMat = new THREE.ShaderMaterial({
    transparent: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
    uniforms: { uTime: { value: 0 }, uPR: { value: 1 } },
    vertexShader: `attribute float aSeed; uniform float uTime; uniform float uPR; varying float vA;
      void main(){ vec3 p = position; p.y += sin(uTime*.12 + aSeed*40.)*.4; p.x += cos(uTime*.09 + aSeed*30.)*.3;
        vec4 mv = modelViewMatrix * vec4(p,1.); gl_Position = projectionMatrix * mv;
        gl_PointSize = (1. + aSeed*1.6) * uPR * (16. / -mv.z);
        vA = (.25 + .55*aSeed) * (.5 + .5*sin(uTime*.8 + aSeed*60.)); }`,
    fragmentShader: `varying float vA; void main(){ float d = length(gl_PointCoord-.5); float a = smoothstep(.5,0.,d)*vA*.5;
      gl_FragColor = vec4(vec3(.72,.66,1.)*a, a); }`,
  });
  const dust = new THREE.Points(dustGeo, dustMat);
  dust.frustumCulled = false;
  scene.add(dust);

  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new UnrealBloomPass(new THREE.Vector2(256, 256), 0.55, 0.32, 0.82);
  composer.addPass(bloom);
  composer.addPass(new OutputPass());

  /* ---------- Hands (screen-space pass) ---------- */
  const handScene = new THREE.Scene();
  const ortho = new THREE.OrthographicCamera(0, 1, 1, 0, -10, 10);
  const step = env.lowPower ? 11 : 9;

  const makeHand = (style: HandStyle, layout: HandObj["layout"]): HandObj => {
    const dots = sampleHand(style, step);
    const n = dots.length;
    const geo = new THREE.BufferGeometry();
    const color = new Float32Array(n * 3);
    const seed = new Float32Array(n);
    const lum = new Float32Array(n);
    dots.forEach((d, i) => {
      const c = dotColor(style, d.lum * (0.35 + 0.65 * d.edge));
      color.set(c, i * 3);
      // reveal order: wrist first, fingertips last, with a little noise
      seed[i] = d.x / 720 + Math.random() * 0.12;
      lum[i] = d.lum * (0.25 + 0.75 * d.edge);
    });
    geo.setAttribute("position", new THREE.BufferAttribute(new Float32Array(n * 3), 3));
    geo.setAttribute("aSize", new THREE.BufferAttribute(new Float32Array(n), 1));
    geo.setAttribute("aColor", new THREE.BufferAttribute(color, 3));
    geo.setAttribute("aSeed", new THREE.BufferAttribute(seed, 1));
    geo.setAttribute("aLum", new THREE.BufferAttribute(lum, 1));
    const mat = new THREE.ShaderMaterial({
      transparent: true,
      depthTest: false,
      uniforms: {
        uMouse: { value: new THREE.Vector2(-9999, -9999) },
        uTime: { value: 0 },
        uPR: { value: 1 },
        uReveal: { value: 0 },
        uRadius: { value: 130 },
        uOffset: { value: new THREE.Vector2() },
        uMotion: { value: 1 },
      },
      vertexShader: /* glsl */ `
        attribute float aSize; attribute vec3 aColor; attribute float aSeed; attribute float aLum;
        uniform vec2 uMouse; uniform float uTime; uniform float uPR; uniform float uReveal;
        uniform float uRadius; uniform vec2 uOffset; uniform float uMotion;
        varying vec3 vColor; varying float vAlpha; varying float vBoost;
        void main() {
          vec2 p = position.xy + uOffset;
          vec2 d = p - uMouse;
          float dist = length(d);
          float f = smoothstep(uRadius, 0.0, dist) * uMotion;
          p += normalize(d + 0.0001) * f * 22.0;
          p += vec2(sin(uTime * 0.7 + aSeed * 40.0), cos(uTime * 0.6 + aSeed * 31.0)) * 0.7 * uMotion;
          vBoost = f;
          float r = smoothstep(aSeed - 0.08, aSeed + 0.02, uReveal);
          vAlpha = r;
          vColor = aColor;
          gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 0.0, 1.0);
          gl_PointSize = aSize * uPR * (0.6 + 0.4 * r) * (1.0 + 0.45 * f);
        }`,
      fragmentShader: /* glsl */ `
        varying vec3 vColor; varying float vAlpha; varying float vBoost;
        void main() {
          float d = length(gl_PointCoord - 0.5);
          float a = smoothstep(0.5, 0.36, d) * vAlpha;
          vec3 c = vColor * (1.0 + vBoost * 0.7) + vec3(0.35, 0.22, 0.6) * vBoost * 0.5;
          gl_FragColor = vec4(c, a);
        }`,
    });
    const points = new THREE.Points(geo, mat);
    points.frustumCulled = false;
    handScene.add(points);
    return { style, points, mat, dots, layout };
  };

  // Hero width excludes a classic scrollbar, so 768px tablets can measure ~753px.
  const isNarrow = (w: number) => w < 720;
  const isPortrait = (w: number, h: number) => !isNarrow(w) && w / h < 0.95;
  const hands: HandObj[] = [
    makeHand("agent", (w, h) =>
      isNarrow(w)
        ? { tipX: 0.35, tipY: 0.665, widthFrac: 0.86, angle: 0.2, mirror: false }
        : isPortrait(w, h)
          ? { tipX: 0.36, tipY: 0.56, widthFrac: 0.62, angle: 0.18, mirror: false }
          : { tipX: 0.385, tipY: 0.585, widthFrac: 0.45, angle: 0.15, mirror: false },
    ),
    makeHand("human", (w, h) =>
      isNarrow(w)
        ? { tipX: 0.66, tipY: 0.81, widthFrac: 0.86, angle: 0.3, mirror: true }
        : isPortrait(w, h)
          ? { tipX: 0.64, tipY: 0.7, widthFrac: 0.62, angle: 0.3, mirror: true }
          : { tipX: 0.618, tipY: 0.735, widthFrac: 0.45, angle: 0.3, mirror: true },
    ),
  ];

  /* ---------- Layout ---------- */
  let W = 1;
  let H = 1;
  let PR = 1;
  const corePos = { x: 0.5, y: 0.6 };

  function layoutHands(): void {
    for (const h of hands) {
      const L = h.layout(W, H);
      const k = Math.min((L.widthFrac * W) / 720, (0.95 * H) / 440);
      const cos = Math.cos(L.angle);
      const sin = Math.sin(L.angle);
      const pos = h.points.geometry.getAttribute("position") as THREE.BufferAttribute;
      const size = h.points.geometry.getAttribute("aSize") as THREE.BufferAttribute;
      const lum = h.points.geometry.getAttribute("aLum") as THREE.BufferAttribute;
      h.dots.forEach((d, i) => {
        let lx = (d.x - TIP.x) * k;
        const ly = (d.y - TIP.y) * k;
        if (L.mirror) lx = -lx;
        // rotate in screen space (y down)
        const sx = L.tipX * W + lx * cos - ly * sin;
        const sy = L.tipY * H + lx * sin + ly * cos;
        pos.setXYZ(i, sx, H - sy, 0); // ortho camera has y up
        size.setX(i, step * k * (0.22 + 0.78 * Math.pow(lum.getX(i), 0.8)));
      });
      pos.needsUpdate = true;
      size.needsUpdate = true;
      h.mat.uniforms.uRadius.value = Math.max(90, Math.min(W, H) * 0.16);
    }
  }

  function placeCore(): void {
    const narrow = isNarrow(W);
    const portrait = isPortrait(W, H);
    corePos.y = narrow ? 0.72 : portrait ? 0.62 : 0.655;
    const dist = camera.position.z;
    const halfH = Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)) * dist;
    const ndcY = -(corePos.y - 0.5) * 2;
    pivot.position.set(0, ndcY * halfH, 0);
    const s = narrow
      ? Math.min(0.9, (W / H) * 1.2) * 0.85
      : portrait
        ? 0.85
        : Math.min(0.95, Math.max(0.7, W / H / 1.85));
    pivot.userData.baseScale = s;
    floor.position.set(0, pivot.position.y - 1.9 * s, -0.5);
  }

  function resize(): void {
    const r = hero.getBoundingClientRect();
    W = Math.max(1, Math.round(r.width));
    H = Math.max(1, Math.round(r.height));
    PR = Math.min(window.devicePixelRatio || 1, maxPR);
    renderer.setPixelRatio(PR);
    renderer.setSize(W, H, false);
    composer.setPixelRatio(PR);
    composer.setSize(W, H);
    const bloomScale = env.lowPower ? 0.5 : 0.75;
    bloom.resolution.set(W * bloomScale, H * bloomScale);
    camera.aspect = W / H;
    camera.updateProjectionMatrix();
    ortho.right = W;
    ortho.top = H;
    ortho.updateProjectionMatrix();
    core.setPixelRatio(PR);
    dustMat.uniforms.uPR.value = PR;
    for (const h of hands) h.mat.uniforms.uPR.value = PR;
    placeCore();
    layoutHands();
  }

  /* ---------- Interaction state ---------- */
  let visible = true;
  let reveal = 0;
  let flash = 0;
  let nextFlash = 2.5;
  let energy = 0;
  let rotY = 0.6;
  let spin = 0;
  let startTime = -1;
  const motion = () => !env.reducedMotion;

  const coreScreen = () => ({ x: W * corePos.x, y: H * corePos.y });

  // Click on the core triggers a denial pulse.
  hero.addEventListener("pointerdown", (e) => {
    const r = hero.getBoundingClientRect();
    const c = coreScreen();
    if (Math.hypot(e.clientX - r.left - c.x, e.clientY - r.top - c.y) < Math.min(W, H) * 0.14) flash = 1;
  });

  const cursorEl = document.querySelector<HTMLElement>(".cursor");

  function render(t: number, dt: number): void {
    if (startTime < 0) startTime = t;
    const time = t - startTime;
    const m = motion();
    const r = hero.getBoundingClientRect();
    const scrollP = m ? clamp(-r.top / Math.max(1, r.height)) : 0;

    // pointer relative to hero
    const px = pointer.x - r.left;
    const py = pointer.y - r.top;
    const c = coreScreen();
    const near = pointer.active && m ? 1 - smoothstep(0, Math.min(W, H) * 0.32, Math.hypot(px - c.x, py - c.y)) : 0;
    energy += (near - energy) * (1 - Math.exp(-dt * 3));
    cursorEl?.classList.toggle("is-core", near > 0.55);

    // denial pulse (periodic + on click)
    if (m && time > nextFlash) {
      flash = 1;
      nextFlash = time + 5.5 + Math.random() * 2;
    }
    flash = Math.max(0, flash - dt * 1.4);

    // core motion
    const base = pivot.userData.baseScale ?? 1;
    spin += dt * (0.18 + energy * 0.45) * (m ? 1 : 0);
    const targetX = m ? pointer.ny * 0.35 : 0.18;
    const targetZ = m ? -pointer.nx * 0.12 : 0;
    rotY += ((m ? pointer.nx * 0.6 : 0) + spin - rotY) * (1 - Math.exp(-dt * 2.5));
    core.group.rotation.set(
      core.group.rotation.x + (targetX + 0.25 - core.group.rotation.x) * (1 - Math.exp(-dt * 2.5)),
      rotY + 0.6,
      core.group.rotation.z + (targetZ - core.group.rotation.z) * (1 - Math.exp(-dt * 2.5)),
    );
    const float = m ? Math.sin(time * 0.9) * 0.08 : 0;
    core.group.position.set(0, float + scrollP * 2.2, scrollP * 2.5);
    core.group.scale.setScalar(base * (1 + scrollP * 0.25));
    core.update(time, dt, energy, flash);
    core.coreLight.position.set(m ? pointer.nx * 0.6 : 0, m ? -pointer.ny * 0.6 : 0, 0.4);
    (floor.material as THREE.ShaderMaterial).uniforms.uPulse.value = flash + energy;

    dustMat.uniforms.uTime.value = time;
    dust.position.set(m ? -pointer.nx * 0.5 : 0, m ? pointer.ny * 0.3 + scrollP * 2 : 0, 0);
    bloom.strength = (env.lowPower ? 0.34 : 0.5) + energy * 0.2 + flash * 0.3;

    // hands
    // Wall-clock based so throttled frames cannot stall the intro.
    reveal = m ? Math.min(1.3, 0.05 + time * 0.55) : 1.3;
    hands.forEach((h, i) => {
      const dir = i === 0 ? -1 : 1;
      const u = h.mat.uniforms;
      u.uTime.value = time;
      u.uReveal.value = reveal;
      u.uMotion.value = m ? 1 : 0;
      u.uMouse.value.set(pointer.active && m ? px : -9999, H - py);
      u.uOffset.value.set(
        dir * scrollP * W * 0.22 + (m ? -pointer.nx * 10 * (i ? 1.4 : 1) : 0),
        -dir * scrollP * H * 0.08 + (m ? pointer.ny * 6 : 0),
      );
    });

    if (bloomOn) composer.render();
    else renderer.render(scene, camera);
    renderer.autoClear = false;
    renderer.render(handScene, ortho);
    renderer.autoClear = true;

    adaptQuality(dt);
  }

  // Adaptive quality: if frames are consistently slow, lower resolution, then drop bloom.
  let acc = 0;
  let frames = 0;
  let downgrades = 0;
  let slowWindows = 0;
  function adaptQuality(dt: number): void {
    if (!motion() || downgrades >= 2 || document.hidden || dt >= 0.05) return;
    acc += dt;
    frames++;
    if (acc < 2.5) return;
    const avg = acc / frames;
    acc = 0;
    frames = 0;
    // Only degrade after three consecutive windows below ~26 fps.
    slowWindows = avg > 1 / 26 ? slowWindows + 1 : 0;
    if (slowWindows >= 3) {
      slowWindows = 0;
      downgrades++;
      if (downgrades === 1) {
        maxPR = 1;
        resize();
      } else bloomOn = false;
    }
  }

  // Visibility: only animate while the hero is on screen and the tab is visible.
  new IntersectionObserver(([e]) => (visible = e.isIntersecting), { threshold: 0 }).observe(hero);

  let stop: (() => void) | null = null;
  const start = () => {
    stop?.();
    stop = addTick((t, dt) => {
      if (!visible || document.hidden) return;
      render(t, dt);
      if (!motion()) {
        // reduced motion: one settled frame, then stop the loop
        stop?.();
        stop = null;
      }
    });
  };

  resize();
  let rt = 0;
  window.addEventListener("resize", () => {
    cancelAnimationFrame(rt);
    rt = requestAnimationFrame(() => {
      resize();
      if (!stop) start();
    });
  });
  window.matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", start);
  window.addEventListener("scroll", () => {
    if (!stop && visible) start();
  }, { passive: true });

  start();
  requestAnimationFrame(() => onReady());
}
