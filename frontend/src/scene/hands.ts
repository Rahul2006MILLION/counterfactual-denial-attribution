/**
 * Procedural dotted hands. Each hand is drawn once as a shaded silhouette on an
 * offscreen 2D canvas (original artwork, no image assets), then sampled on a regular
 * grid into halftone dots whose size and colour follow the shading.
 *
 * Template space: 720 x 440, wrist on the left, index finger pointing right.
 */

export const TEMPLATE_W = 720;
export const TEMPLATE_H = 440;
export const TIP = { x: 606, y: 168 };

export type HandStyle = "agent" | "human";

export interface Dot {
  x: number; // template coords
  y: number;
  lum: number; // 0..1 shading
  edge: number; // 0..1 fade toward the wrist
}

type Pt = [number, number];

interface Finger {
  pts: Pt[];
  widths: number[];
}

const FINGERS: Record<string, Finger> = {
  pinky: { pts: [[345, 266], [402, 290], [434, 316], [446, 342]], widths: [33, 27, 23, 20] },
  ring: { pts: [[360, 238], [434, 256], [482, 286], [500, 318]], widths: [38, 32, 27, 23] },
  middle: { pts: [[368, 206], [456, 214], [518, 238], [552, 270]], widths: [41, 35, 30, 25] },
  index: { pts: [[362, 172], [452, 160], [534, 160], [TIP.x, 168]], widths: [42, 35, 31, 27] },
  thumb: { pts: [[248, 252], [322, 266], [384, 254], [426, 238]], widths: [50, 40, 33, 28] },
};

function shadedCapsule(
  ctx: CanvasRenderingContext2D,
  a: Pt,
  b: Pt,
  wa: number,
  wb: number,
  bright = 1,
): void {
  const dx = b[0] - a[0];
  const dy = b[1] - a[1];
  const len = Math.hypot(dx, dy) || 1;
  let nx = -dy / len;
  let ny = dx / len;
  if (ny > 0) {
    nx = -nx;
    ny = -ny;
  } // normal points "up" (toward the light)
  const ra = wa / 2;
  const rb = wb / 2;
  const ang = Math.atan2(dy, dx);

  ctx.beginPath();
  ctx.arc(a[0], a[1], ra, ang + Math.PI / 2, ang - Math.PI / 2, false);
  ctx.arc(b[0], b[1], rb, ang - Math.PI / 2, ang + Math.PI / 2, false);
  ctx.closePath();

  const mx = (a[0] + b[0]) / 2;
  const my = (a[1] + b[1]) / 2;
  const w = (ra + rb) / 2;
  const g = ctx.createLinearGradient(mx + nx * w, my + ny * w, mx - nx * w, my - ny * w);
  const s = (v: number) => {
    const c = Math.round(Math.min(1, v * bright) * 255);
    return `rgb(${c},${c},${c})`;
  };
  g.addColorStop(0, s(0.62));
  g.addColorStop(0.16, s(1));
  g.addColorStop(0.42, s(0.8));
  g.addColorStop(0.78, s(0.36));
  g.addColorStop(0.93, s(0.2));
  g.addColorStop(1, s(0.42)); // faint rim light
  ctx.fillStyle = g;
  ctx.fill();
}

function shortened(a: Pt, b: Pt, gap: number): [Pt, Pt] {
  const dx = b[0] - a[0];
  const dy = b[1] - a[1];
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len;
  const uy = dy / len;
  return [
    [a[0] + ux * gap, a[1] + uy * gap],
    [b[0] - ux * gap, b[1] - uy * gap],
  ];
}

function finger(ctx: CanvasRenderingContext2D, f: Finger, style: HandStyle, bright: number): void {
  for (let i = 0; i < f.pts.length - 1; i++) {
    if (style === "agent") {
      // Mechanical: separate segments with visible joints.
      const j = f.pts[i];
      ctx.fillStyle = "rgb(70,70,70)";
      ctx.beginPath();
      ctx.arc(j[0], j[1], f.widths[i] * 0.42, 0, Math.PI * 2);
      ctx.fill();
      const [a, b] = shortened(f.pts[i], f.pts[i + 1], 6);
      shadedCapsule(ctx, a, b, f.widths[i] * 0.92, f.widths[i + 1] * 0.88, bright);
    } else {
      shadedCapsule(ctx, f.pts[i], f.pts[i + 1], f.widths[i], f.widths[i + 1], bright);
    }
  }
  if (style === "human") {
    // nail highlight
    const n = f.pts.length;
    const a = f.pts[n - 2];
    const b = f.pts[n - 1];
    const t = 0.72;
    ctx.fillStyle = "rgba(255,255,255,0.55)";
    ctx.beginPath();
    ctx.ellipse(
      a[0] + (b[0] - a[0]) * t,
      a[1] + (b[1] - a[1]) * t - f.widths[n - 1] * 0.18,
      f.widths[n - 1] * 0.34,
      f.widths[n - 1] * 0.22,
      Math.atan2(b[1] - a[1], b[0] - a[0]),
      0,
      Math.PI * 2,
    );
    ctx.fill();
  }
}

function palm(ctx: CanvasRenderingContext2D, style: HandStyle): void {
  ctx.beginPath();
  ctx.moveTo(150, 176);
  ctx.bezierCurveTo(220, 150, 300, 146, 352, 156);
  ctx.bezierCurveTo(384, 168, 392, 214, 386, 262);
  ctx.bezierCurveTo(372, 292, 330, 302, 280, 300);
  ctx.bezierCurveTo(220, 298, 176, 292, 150, 286);
  ctx.closePath();
  const g = ctx.createLinearGradient(260, 150, 270, 302);
  g.addColorStop(0, "rgb(205,205,205)");
  g.addColorStop(0.12, "rgb(250,250,250)");
  g.addColorStop(0.45, "rgb(185,185,185)");
  g.addColorStop(0.85, "rgb(80,80,80)");
  g.addColorStop(1, "rgb(110,110,110)");
  ctx.fillStyle = g;
  ctx.fill();

  if (style === "agent") {
    // panel seams and a joint plate
    ctx.strokeStyle = "rgb(40,40,40)";
    ctx.lineWidth = 6;
    ctx.beginPath();
    ctx.moveTo(250, 152);
    ctx.lineTo(244, 298);
    ctx.moveTo(320, 150);
    ctx.lineTo(330, 302);
    ctx.moveTo(150, 232);
    ctx.lineTo(250, 228);
    ctx.stroke();
    ctx.fillStyle = "rgb(240,240,240)";
    ctx.beginPath();
    ctx.arc(286, 196, 12, 0, Math.PI * 2);
    ctx.fill();
  } else {
    // soft knuckle highlights
    ctx.fillStyle = "rgba(255,255,255,0.35)";
    for (const [x, y] of [[352, 176], [362, 210], [356, 240], [342, 266]] as Pt[]) {
      ctx.beginPath();
      ctx.ellipse(x, y, 13, 8, 0.2, 0, Math.PI * 2);
      ctx.fill();
    }
  }
}

function forearm(ctx: CanvasRenderingContext2D, style: HandStyle): void {
  shadedCapsule(ctx, [-60, 252], [178, 230], 128, 112, 0.92);
  if (style === "agent") {
    ctx.strokeStyle = "rgb(35,35,35)";
    ctx.lineWidth = 7;
    for (const x of [30, 82, 134]) {
      ctx.beginPath();
      ctx.moveTo(x, 188);
      ctx.lineTo(x + 6, 308);
      ctx.stroke();
    }
    ctx.fillStyle = "rgb(60,60,60)";
    ctx.beginPath();
    ctx.ellipse(170, 232, 22, 58, 0, 0, Math.PI * 2);
    ctx.fill();
  }
}

/** Draw the hand and sample it into dots on a regular grid. */
export function sampleHand(style: HandStyle, step: number): Dot[] {
  const canvas = document.createElement("canvas");
  canvas.width = TEMPLATE_W;
  canvas.height = TEMPLATE_H;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  if (!ctx) return [];

  finger(ctx, FINGERS.pinky, style, 0.62);
  finger(ctx, FINGERS.ring, style, 0.72);
  finger(ctx, FINGERS.middle, style, 0.84);
  forearm(ctx, style);
  palm(ctx, style);
  finger(ctx, FINGERS.index, style, 1);
  finger(ctx, FINGERS.thumb, style, 0.9);

  const data = ctx.getImageData(0, 0, TEMPLATE_W, TEMPLATE_H).data;
  const dots: Dot[] = [];
  for (let y = step / 2; y < TEMPLATE_H; y += step) {
    for (let x = step / 2; x < TEMPLATE_W; x += step) {
      const i = (Math.floor(y) * TEMPLATE_W + Math.floor(x)) * 4;
      if (data[i + 3] < 120) continue;
      const lum = data[i] / 255;
      const edge = Math.min(1, Math.max(0, (x - 10) / 230));
      dots.push({ x, y, lum, edge });
    }
  }
  return dots;
}

function mix(a: number[], b: number[], t: number): number[] {
  return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
}

/** Colour ramp per style; values are linear-ish sRGB 0..1. */
export function dotColor(style: HandStyle, lum: number): number[] {
  if (style === "agent") {
    const t = Math.pow(lum, 1.15);
    return mix([0.14, 0.14, 0.17], [0.97, 0.97, 1.0], t);
  }
  const dark = [0.2, 0.09, 0.07];
  const mid = [0.72, 0.43, 0.33];
  const light = [0.99, 0.84, 0.74];
  return lum < 0.55 ? mix(dark, mid, lum / 0.55) : mix(mid, light, (lum - 0.55) / 0.45);
}
