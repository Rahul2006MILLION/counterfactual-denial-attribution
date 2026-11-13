/** Page-level interactions: cursor, magnetic buttons, reveals, nav, scroll-linked sections. */
import { addTick, clamp, env, pointer } from "../runtime";

/* ---------- Custom cursor (fine pointers, motion allowed) ---------- */
export function initCursor(): void {
  const el = document.querySelector<HTMLElement>(".cursor");
  if (!el || !env.finePointer || env.reducedMotion) return;
  document.documentElement.classList.add("has-cursor");
  const dot = el.querySelector<HTMLElement>(".cursor__dot")!;
  const ring = el.querySelector<HTMLElement>(".cursor__ring")!;
  let rx = pointer.x;
  let ry = pointer.y;
  addTick((_t, dt) => {
    const k = 1 - Math.exp(-dt * 14);
    rx += (pointer.x - rx) * k;
    ry += (pointer.y - ry) * k;
    dot.style.transform = `translate3d(${pointer.x}px, ${pointer.y}px, 0)`;
    ring.style.transform = `translate3d(${rx}px, ${ry}px, 0)`;
    el.classList.toggle("is-hidden", !pointer.active);
    el.classList.toggle("is-down", pointer.down);
  });
  const interactive = "a, button, [role='tab'], [data-layer], .conds li, .hero__steps li";
  document.addEventListener("pointerover", (e) => {
    el.classList.toggle("is-hover", !!(e.target as Element).closest?.(interactive));
  });
}

/* ---------- Magnetic buttons ---------- */
export function initMagnetic(): void {
  if (!env.finePointer || env.reducedMotion) return;
  const items = [...document.querySelectorAll<HTMLElement>("[data-magnetic]")];
  addTick(() => {
    for (const el of items) {
      const r = el.getBoundingClientRect();
      if (r.bottom < 0 || r.top > window.innerHeight) continue;
      const cx = r.left + r.width / 2;
      const cy = r.top + r.height / 2;
      const dx = pointer.x - cx;
      const dy = pointer.y - cy;
      const reach = Math.max(r.width, r.height) * 0.5 + 40;
      const inside = Math.abs(dx) < r.width / 2 + 40 && Math.abs(dy) < r.height / 2 + 40 && pointer.active;
      const f = inside ? 1 - Math.min(1, Math.hypot(dx, dy) / (reach * 1.6)) : 0;
      el.style.setProperty("--mx", `${(dx * 0.32 * f).toFixed(2)}px`);
      el.style.setProperty("--my", `${(dy * 0.42 * f).toFixed(2)}px`);
    }
  });
}

/* ---------- Scroll reveals ---------- */
export function initReveal(): void {
  const els = document.querySelectorAll<HTMLElement>("[data-reveal]");
  if (env.reducedMotion || !("IntersectionObserver" in window)) {
    els.forEach((e) => e.classList.add("is-visible"));
    return;
  }
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (e.isIntersecting) {
          e.target.classList.add("is-visible");
          io.unobserve(e.target);
        }
      }
    },
    { threshold: 0.12, rootMargin: "0px 0px -8% 0px" },
  );
  els.forEach((e) => io.observe(e));
}

/* ---------- Header, active nav, mobile menu ---------- */
export function initNav(): void {
  const header = document.querySelector<HTMLElement>("[data-header]")!;
  const links = [...document.querySelectorAll<HTMLAnchorElement>(".nav__link")];
  const onScroll = () => header.classList.toggle("is-scrolled", window.scrollY > 40);
  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });

  const map = new Map(links.map((l) => [l.getAttribute("href")!.slice(1), l]));
  const io = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (!e.isIntersecting) continue;
        links.forEach((l) => {
          l.classList.remove("is-active");
          l.removeAttribute("aria-current");
        });
        const id = e.target.id === "conditions" ? "demo" : e.target.id;
        const l = map.get(id);
        if (l) {
          l.classList.add("is-active");
          l.setAttribute("aria-current", "true");
        }
      }
    },
    { rootMargin: "-45% 0px -50% 0px" },
  );
  document.querySelectorAll("main section[id]").forEach((s) => io.observe(s));

  // Move focus to the target section after in-page navigation (keyboard users).
  document.querySelectorAll<HTMLAnchorElement>('a[href^="#"]').forEach((a) =>
    a.addEventListener("click", () => {
      const id = a.getAttribute("href")!.slice(1);
      const target = document.getElementById(id);
      if (!target || id === "top" || id === "main") return;
      const heading = target.querySelector<HTMLElement>("h2, h1");
      if (heading) {
        heading.setAttribute("tabindex", "-1");
        window.setTimeout(() => heading.focus({ preventScroll: true }), env.reducedMotion ? 0 : 600);
      }
    }),
  );

  const btn = document.querySelector<HTMLButtonElement>("[data-menu-btn]")!;
  const menu = document.querySelector<HTMLElement>("[data-menu]")!;
  const setOpen = (open: boolean) => {
    btn.setAttribute("aria-expanded", String(open));
    menu.hidden = !open;
    btn.querySelector(".menu-btn__label")!.textContent = open ? "Close" : "Menu";
  };
  btn.addEventListener("click", () => setOpen(menu.hidden));
  menu.addEventListener("click", (e) => {
    if ((e.target as Element).closest("a")) setOpen(false);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !menu.hidden) {
      setOpen(false);
      btn.focus();
    }
  });
}

/* ---------- Hero content parallax ---------- */
export function initHeroParallax(): void {
  const content = document.querySelector<HTMLElement>("[data-hero-content]");
  const hero = document.querySelector<HTMLElement>("[data-hero]");
  if (!content || !hero) return;
  const update = () => {
    if (env.reducedMotion) {
      content.style.transform = "";
      content.style.opacity = "";
      return;
    }
    const p = clamp(window.scrollY / hero.offsetHeight);
    content.style.transform = `translate3d(0, ${(-p * 90).toFixed(1)}px, 0)`;
    content.style.opacity = String(1 - p * 1.4);
  };
  window.addEventListener("scroll", update, { passive: true });
  update();
}

/* ---------- Section progress (flow wire, layer stack) ---------- */
function progress(el: HTMLElement, start = 0.85, span = 0.7): number {
  const r = el.getBoundingClientRect();
  const vh = window.innerHeight;
  return clamp((vh * start - r.top) / (r.height * span));
}

export function initFlow(): void {
  const section = document.querySelector<HTMLElement>("[data-flow]");
  if (!section) return;
  const steps = [...section.querySelectorAll<HTMLElement>(".flow__step")];
  const wire = section.querySelector<SVGElement>(".flow__wire");
  const track = section.querySelector<HTMLElement>(".flow__track");
  const fitWire = () => {
    if (!wire || !track) return;
    const nodes = section.querySelectorAll<HTMLElement>(".flow__node");
    const t = track.getBoundingClientRect();
    const a = nodes[0].getBoundingClientRect();
    const b = nodes[nodes.length - 1].getBoundingClientRect();
    wire.style.left = `${a.left + a.width / 2 - t.left}px`;
    wire.style.width = `${b.left + b.width / 2 - (a.left + a.width / 2)}px`;
    wire.style.top = `${a.top + a.height / 2 - t.top - 60}px`;
  };
  fitWire();
  window.addEventListener("resize", fitWire);
  const update = () => {
    const p = env.reducedMotion ? 1 : progress(section, 0.75, 0.55);
    section.style.setProperty("--flow", String(1 - p));
    steps.forEach((s, i) => s.classList.toggle("is-lit", p > (i + 0.35) / steps.length));
  };
  window.addEventListener("scroll", update, { passive: true });
  window.addEventListener("resize", update);
  update();
}

export function initStack(): void {
  const section = document.querySelector<HTMLElement>("[data-security]");
  const scene = document.querySelector<HTMLElement>(".stack__scene");
  if (!section || !scene) return;
  const plates = [...document.querySelectorAll<HTMLElement>("[data-plate]")];
  const items = [...document.querySelectorAll<HTMLElement>("[data-layer]")];
  let manual = false;
  let current = 0;
  const activate = (n: number) => {
    current = n;
    plates.forEach((p) => p.classList.toggle("is-active", p.dataset.plate === String(n)));
    items.forEach((i) => i.classList.toggle("is-active", i.dataset.layer === String(n)));
  };
  items.forEach((item) => {
    const n = Number(item.dataset.layer);
    item.addEventListener("pointerenter", () => {
      manual = true;
      activate(n);
    });
    item.addEventListener("focus", () => {
      manual = true;
      activate(n);
    });
    item.addEventListener("pointerleave", () => (manual = false));
    item.addEventListener("blur", () => (manual = false));
  });
  activate(0);

  let visible = false;
  new IntersectionObserver(([e]) => (visible = e.isIntersecting)).observe(section);
  if (!env.reducedMotion) {
    window.setInterval(() => {
      if (visible && !manual) activate((current + 1) % plates.length);
    }, 2400);
  }

  const update = () => {
    const p = env.reducedMotion ? 0.6 : progress(section, 0.9, 0.6);
    scene.style.setProperty("--sep", p.toFixed(3));
  };
  window.addEventListener("scroll", update, { passive: true });
  update();

  if (env.finePointer && !env.reducedMotion) {
    const stack = scene.parentElement!;
    addTick(() => {
      if (!visible) return;
      const r = stack.getBoundingClientRect();
      const nx = clamp((pointer.x - r.left) / r.width, -0.5, 1.5) - 0.5;
      const ny = clamp((pointer.y - r.top) / r.height, -0.5, 1.5) - 0.5;
      scene.style.transform = `rotateX(${58 - ny * 8}deg) rotateZ(${-42 + nx * 10}deg)`;
    });
  }
}

/* ---------- Pointer-tracked glow on condition cards ---------- */
export function initCardGlow(): void {
  document.querySelectorAll<HTMLElement>(".conds li").forEach((card) => {
    card.addEventListener("pointermove", (e) => {
      const r = card.getBoundingClientRect();
      card.style.setProperty("--px", `${e.clientX - r.left}px`);
      card.style.setProperty("--py", `${e.clientY - r.top}px`);
    });
  });
}
