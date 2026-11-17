/**
 * Replays verbatim output captured from the Python terminal demo
 * (frontend/scripts/capture_demo.py). Text is never altered; only colour is added.
 */
import transcript from "../data/demo-transcript.json";
import { env } from "../runtime";

interface Task {
  id: string;
  label: string;
  input: string;
  output: string;
}

const PROMPT = "Enter your task: ";

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

function colorLine(line: string): string {
  const e = esc(line);
  const m = /^(\s+Security decision\s+:\s)(ALLOW|DENY)$/.exec(line);
  if (m) return `${esc(m[1])}<span class="t-${m[2].toLowerCase()}">${m[2]}</span>`;
  if (/^\s+(policy layer|rule|reason category)\s+:/.test(line)) return `<span class="t-key">${e}</span>`;
  if (/^-{10,}$|^={10,}$/.test(line)) return `<span class="t-dim">${e}</span>`;
  if (/^\s+Tool executed\s+:\s+NO/.test(line)) return `<span class="t-deny">${e}</span>`;
  if (/^\s+Tool executed\s+:\s+YES/.test(line)) return `<span class="t-allow">${e}</span>`;
  return e;
}

function kind(t: Task): "deny" | "allow" | "none" {
  if (/Security decision\s+:\s+DENY/.test(t.output)) return "deny";
  if (/Security decision\s+:\s+ALLOW/.test(t.output)) return "allow";
  return "none";
}

export function initDemo(): void {
  const root = document.querySelector<HTMLElement>("[data-terminal]");
  if (!root) return;
  const tabsEl = root.querySelector<HTMLElement>("[data-terminal-tabs]")!;
  const screen = root.querySelector<HTMLElement>("[data-terminal-screen]")!;
  const meta = root.querySelector<HTMLElement>("[data-terminal-meta]")!;

  const tasks = transcript.tasks as Task[];
  const entries: { id: string; label: string; dot: string; play: () => Promise<void> }[] = [
    { id: "banner", label: "Startup banner", dot: "none", play: () => play(null) },
    ...tasks.map((t) => ({ id: t.id, label: t.label, dot: kind(t), play: () => play(t) })),
  ];

  let token = 0;
  const wait = (ms: number) => new Promise((r) => window.setTimeout(r, ms));

  async function play(task: Task | null): Promise<void> {
    const my = ++token;
    const instant = env.reducedMotion;
    screen.innerHTML = "";
    const lines = task ? task.output.split("\n") : transcript.banner.split("\n");

    if (task) {
      const promptLine = document.createElement("div");
      promptLine.innerHTML = `<span class="t-prompt">${esc(PROMPT)}</span><span class="t-input"></span><span class="caret"></span>`;
      screen.appendChild(promptLine);
      const input = promptLine.querySelector<HTMLElement>(".t-input")!;
      if (instant) input.textContent = task.input;
      else {
        for (const ch of task.input) {
          if (my !== token) return;
          input.textContent += ch;
          await wait(18 + Math.random() * 26);
        }
        await wait(260);
      }
      promptLine.querySelector(".caret")?.remove();
    }
    const frag = document.createDocumentFragment();
    for (const line of lines) {
      if (my !== token) return;
      const div = document.createElement("div");
      div.innerHTML = colorLine(line) || "&nbsp;";
      if (instant) frag.appendChild(div);
      else {
        screen.appendChild(div);
        screen.scrollTop = screen.scrollHeight;
        await wait(line.startsWith("Step ") ? 160 : 34);
      }
    }
    if (instant) screen.appendChild(frag);
    if (task && my === token) {
      const tail = document.createElement("div");
      tail.innerHTML = `&nbsp;\n<span class="t-prompt">${esc(PROMPT)}</span><span class="caret"></span>`;
      screen.appendChild(tail);
      if (!instant) screen.scrollTop = screen.scrollHeight;
    }
  }

  // Tabs (WAI-ARIA tablist with roving tabindex)
  const tabs: HTMLButtonElement[] = entries.map((e, i) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "terminal__tab";
    b.setAttribute("role", "tab");
    b.id = `demo-tab-${e.id}`;
    b.setAttribute("aria-controls", "demo-screen");
    b.setAttribute("aria-selected", String(i === 0));
    b.tabIndex = i === 0 ? 0 : -1;
    b.innerHTML = `<i class="${e.dot}" aria-hidden="true"></i>${esc(e.label)}`;
    b.addEventListener("click", () => select(i));
    tabsEl.appendChild(b);
    return b;
  });
  screen.id = "demo-screen";
  screen.setAttribute("role", "tabpanel");

  function select(i: number, focus = false): void {
    tabs.forEach((t, j) => {
      t.setAttribute("aria-selected", String(i === j));
      t.tabIndex = i === j ? 0 : -1;
    });
    screen.setAttribute("aria-labelledby", tabs[i].id);
    if (focus) tabs[i].focus();
    tabs[i].scrollIntoView({ block: "nearest", inline: "nearest", behavior: env.reducedMotion ? "auto" : "smooth" });
    void entries[i].play();
  }
  tabsEl.addEventListener("keydown", (e) => {
    const i = tabs.indexOf(document.activeElement as HTMLButtonElement);
    if (i < 0) return;
    const n = tabs.length;
    const keys: Record<string, number> = { ArrowRight: (i + 1) % n, ArrowLeft: (i - 1 + n) % n, Home: 0, End: n - 1 };
    const to = keys[e.key];
    if (to !== undefined) {
      e.preventDefault();
      select(to, true);
    }
  });

  // Provenance of the recording (exact source state, no invented revision).
  const src = transcript.source;
  const digests = Object.entries(src.src_demo_sha256 as Record<string, string>)
    .map(([f, h]) => `${esc(f)}  ${h}`)
    .join("\n");
  meta.innerHTML = `
    <strong>Recorded output, replayed in your browser.</strong> Not live execution, not an LLM.<br />
    Captured ${esc(transcript.captured_at_utc)} with Python ${esc(transcript.python)} from branch
    <strong>${esc(src.git_branch)}</strong> at HEAD <strong title="${esc(src.git_head)}">${esc(src.git_head.slice(0, 12))}</strong>;
    ${esc(src.src_demo_state)}.
    <details><summary>SHA-256 of the src/demo files used</summary><pre>${digests}</pre></details>`;

  // Start the replay the first time the terminal scrolls into view.
  let started = false;
  const io = new IntersectionObserver(
    ([e]) => {
      if (e.isIntersecting && !started) {
        started = true;
        select(0);
        io.disconnect();
      }
    },
    { threshold: 0.35 },
  );
  io.observe(root);

  // Copy command
  const copyBtn = document.querySelector<HTMLButtonElement>("[data-copy]");
  const cmd = document.querySelector<HTMLElement>("[data-cmd]");
  copyBtn?.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(cmd?.textContent ?? "");
      copyBtn.textContent = "Copied";
    } catch {
      copyBtn.textContent = "Select & copy";
    }
    window.setTimeout(() => (copyBtn.textContent = "Copy"), 1800);
  });
}
