/** Shared runtime: environment detection, one animation loop, smoothed pointer state. */

const mqReduce = window.matchMedia("(prefers-reduced-motion: reduce)");
const mqFine = window.matchMedia("(hover: hover) and (pointer: fine)");

type NavigatorExtras = Navigator & { deviceMemory?: number; connection?: { saveData?: boolean } };
const nav = navigator as NavigatorExtras;

export const env = {
  get reducedMotion(): boolean {
    return mqReduce.matches;
  },
  get finePointer(): boolean {
    return mqFine.matches;
  },
  /** Heuristic for phones, low-core laptops and data-saver mode. */
  lowPower:
    (nav.hardwareConcurrency ?? 8) <= 4 ||
    (nav.deviceMemory ?? 8) <= 4 ||
    nav.connection?.saveData === true ||
    window.matchMedia("(max-width: 760px)").matches,
};

export function onReducedMotionChange(cb: (reduced: boolean) => void): void {
  mqReduce.addEventListener("change", () => cb(mqReduce.matches));
}

/* ---------- Single requestAnimationFrame loop ---------- */
type Tick = (t: number, dt: number) => void;
const ticks = new Set<Tick>();
let last = performance.now();
let running = false;

function frame(now: number): void {
  const dt = Math.min(0.05, (now - last) / 1000);
  last = now;
  ticks.forEach((fn) => fn(now / 1000, dt));
  if (ticks.size) requestAnimationFrame(frame);
  else running = false;
}

export function addTick(fn: Tick): () => void {
  ticks.add(fn);
  if (!running) {
    running = true;
    last = performance.now();
    requestAnimationFrame(frame);
  }
  return () => ticks.delete(fn);
}

/* ---------- Pointer ---------- */
export const pointer = {
  x: window.innerWidth / 2,
  y: window.innerHeight / 2,
  /** -1..1, smoothed */
  nx: 0,
  ny: 0,
  tx: 0,
  ty: 0,
  active: false,
  down: false,
};

window.addEventListener(
  "pointermove",
  (e) => {
    pointer.x = e.clientX;
    pointer.y = e.clientY;
    pointer.tx = (e.clientX / window.innerWidth) * 2 - 1;
    pointer.ty = (e.clientY / window.innerHeight) * 2 - 1;
    pointer.active = true;
  },
  { passive: true },
);
document.addEventListener("pointerleave", () => {
  pointer.active = false;
});
window.addEventListener("pointerdown", () => (pointer.down = true), { passive: true });
window.addEventListener("pointerup", () => (pointer.down = false), { passive: true });

addTick((_t, dt) => {
  const k = 1 - Math.exp(-dt * 4);
  pointer.nx += (pointer.tx - pointer.nx) * k;
  pointer.ny += (pointer.ty - pointer.ny) * k;
});

export const clamp = (v: number, a = 0, b = 1): number => Math.min(b, Math.max(a, v));
export const smoothstep = (a: number, b: number, v: number): number => {
  const t = clamp((v - a) / (b - a));
  return t * t * (3 - 2 * t);
};
