/**
 * Live agent console. Talks to the FastAPI backend (src/live/api.py) and renders the
 * Server-Sent Events it emits. Nothing here is simulated: if the backend or Ollama is
 * unavailable the console says so and stays disabled (no recorded fallback).
 */

const API = (import.meta.env.VITE_API_BASE as string | undefined) ?? "";

interface Health {
  status: string;
  ollama: { reachable: boolean; version?: string; url: string; error?: { kind: string; message: string } };
  model: { selected: string | null; configured: string | null };
  limits: { max_upload_mb: number; max_files_per_task: number };
}
interface ModelInfo {
  name: string;
  size_gb: number;
  parameter_size?: string;
  chat_capable: boolean;
}
interface Uploaded {
  file_id: string;
  name: string;
  size: number;
  kind: string;
}
interface Ev {
  seq: number;
  ts: string;
  type: string;
  stage: number | null;
  stage_label: string | null;
  message: string;
  data: Record<string, any>;
}

const STAGES = [
  "File received",
  "Extracting document contents",
  "Sending context to the model",
  "AI analysing task",
  "Generating execution plan",
  "Security policy evaluation",
  "Executing approved tool",
  "Verifying result",
  "Task completed",
];

const EVENT_TYPES = [
  "queued", "stage", "model", "security", "tool_start", "tool_result", "tool_error", "tool_skipped",
  "extracted", "extract_error", "plan", "chunk", "compose", "answer", "approval_required",
  "approval_decision", "retry", "verify_warning", "error", "audit",
];

const esc = (s: unknown) =>
  String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** Tiny, safe Markdown subset: everything is escaped first. */
function md(text: string): string {
  const lines = esc(text).split("\n");
  const out: string[] = [];
  let list = false;
  const inline = (s: string) =>
    s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/`([^`]+)`/g, "<code>$1</code>");
  for (const raw of lines) {
    const line = raw.trimEnd();
    const bullet = /^\s*[-*•]\s+(.*)$/.exec(line) || /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (bullet) {
      if (!list) out.push("<ul>");
      list = true;
      out.push(`<li>${inline(bullet[1])}</li>`);
      continue;
    }
    if (list) {
      out.push("</ul>");
      list = false;
    }
    const h = /^#{1,4}\s+(.*)$/.exec(line);
    if (h) out.push(`<h4>${inline(h[1])}</h4>`);
    else if (line.trim()) out.push(`<p>${inline(line)}</p>`);
  }
  if (list) out.push("</ul>");
  return out.join("");
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(API + path, init);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error((body as any).detail || `HTTP ${r.status}`);
  return body as T;
}

export function initAgent(): void {
  const root = document.querySelector<HTMLElement>("[data-agent]");
  if (!root) return;
  const $ = <T extends Element>(sel: string) => root.querySelector<T>(sel)!;

  const modeBadge = $<HTMLElement>("[data-agent-mode]");
  const ollamaEl = $<HTMLElement>("[data-agent-ollama]");
  const modelSel = $<HTMLSelectElement>("[data-agent-model]");
  const offline = $<HTMLElement>("[data-agent-offline]");
  const offlineDetail = $<HTMLElement>("[data-agent-offline-detail]");
  const form = $<HTMLFormElement>("[data-agent-form]");
  const fileInput = $<HTMLInputElement>("[data-agent-file]");
  const drop = $<HTMLElement>("[data-drop]");
  const filesEl = $<HTMLUListElement>("[data-agent-files]");
  const taskEl = $<HTMLTextAreaElement>("[data-agent-task]");
  const runBtn = $<HTMLButtonElement>("[data-agent-run]");
  const stagesEl = $<HTMLOListElement>("[data-agent-stages]");
  const consoleEl = $<HTMLElement>("[data-agent-console]");
  const resultEl = $<HTMLElement>("[data-agent-result]");
  const resultBody = $<HTMLElement>("[data-agent-result-body]");
  const resultMeta = $<HTMLElement>("[data-agent-result-meta]");
  const approvalEl = $<HTMLElement>("[data-agent-approval]");

  let live = false;
  let running = false;
  let uploads: Uploaded[] = [];
  let currentTask: string | null = null;
  let source: EventSource | null = null;

  // ---------- stages ----------
  stagesEl.innerHTML = STAGES.map((s, i) => `<li data-stage="${i + 1}"><span>${i + 1}</span>${esc(s)}</li>`).join("");
  const setStage = (n: number | null, failed = false) => {
    stagesEl.querySelectorAll<HTMLElement>("li").forEach((li) => {
      const k = Number(li.dataset.stage);
      li.classList.toggle("is-done", n !== null && k < n);
      li.classList.toggle("is-active", n !== null && k === n && !failed);
      li.classList.toggle("is-failed", failed && k === n);
    });
  };

  // ---------- status ----------
  const setOllama = (state: "ok" | "down" | "checking", text: string) => {
    ollamaEl.dataset.state = state;
    ollamaEl.querySelector("span")!.textContent = text;
  };
  const refreshRun = () => {
    runBtn.disabled = !live || running || !taskEl.value.trim();
  };

  async function checkHealth(): Promise<void> {
    try {
      const h = await api<Health>("/api/health");
      offline.hidden = true;
      if (h.ollama.reachable) {
        live = true;
        modeBadge.textContent = "LIVE EXECUTION";
        modeBadge.dataset.state = "live";
        setOllama("ok", `Ollama ${h.ollama.version ?? ""} · connected`);
        await loadModels(h.model.selected);
      } else {
        live = false;
        modeBadge.textContent = "UNAVAILABLE";
        modeBadge.dataset.state = "down";
        setOllama("down", "Ollama not reachable");
        offline.hidden = false;
        offline.querySelector("p strong")!.textContent = "Ollama is not running.";
        offlineDetail.textContent = h.ollama.error?.message ?? "";
        modelSel.innerHTML = "<option>unavailable</option>";
        modelSel.disabled = true;
      }
    } catch (err) {
      live = false;
      modeBadge.textContent = "BACKEND OFFLINE";
      modeBadge.dataset.state = "down";
      setOllama("down", "Backend not reachable");
      offline.hidden = false;
      offlineDetail.textContent = String((err as Error).message || err);
      modelSel.innerHTML = "<option>unavailable</option>";
      modelSel.disabled = true;
    }
    refreshRun();
  }

  async function loadModels(selected: string | null): Promise<void> {
    const { models } = await api<{ models: ModelInfo[]; default: string | null }>("/api/models");
    const chat = models.filter((m) => m.chat_capable);
    modelSel.innerHTML = chat
      .map((m) => `<option value="${esc(m.name)}"${m.name === selected ? " selected" : ""}>${esc(m.name)} · ${m.size_gb} GB</option>`)
      .join("");
    modelSel.disabled = running;
  }

  // ---------- console ----------
  const time = (ts: string) => new Date(ts).toLocaleTimeString([], { hour12: false });
  function line(cls: string, html: string): HTMLElement {
    consoleEl.querySelector(".console__idle")?.remove();
    const div = document.createElement("div");
    div.className = `cl ${cls}`;
    div.innerHTML = html;
    consoleEl.appendChild(div);
    consoleEl.scrollTop = consoleEl.scrollHeight;
    return div;
  }
  const verdictBadge = (v: string) => {
    const label = v === "REQUIRE_APPROVAL" ? "REQUIRE APPROVAL" : v;
    return `<b class="v v--${v.toLowerCase()}">${esc(label)}</b>`;
  };

  function render(ev: Ev): void {
    const tag = ev.stage ? `[${ev.stage}]` : "[·]";
    const head = `<span class="cl__t">${time(ev.ts)}</span><span class="cl__s">${tag}</span>`;
    const d = ev.data || {};
    switch (ev.type) {
      case "security": {
        const sec = d.security || {};
        line(
          `cl--sec cl--${String(sec.verdict).toLowerCase()}`,
          `${head}Security · <code>${esc(d.tool)}</code> ${verdictBadge(sec.verdict)} <span class="cl__dim">${esc(sec.layer)}${sec.rule ? " / " + esc(sec.rule) : ""}</span>` +
            (sec.verdict !== "ALLOW" ? `<div class="cl__sub">${esc(sec.reason)}</div>` : ""),
        );
        break;
      }
      case "plan": {
        const steps = (d.steps || []) as any[];
        line(
          "cl--plan",
          `${head}Plan (${esc(d.task_type)}): ${esc(d.understanding)}` +
            `<ol class="cl__steps">${steps.map((s) => `<li><code>${esc(s.tool)}</code> ${esc(JSON.stringify(s.arguments))} <span class="cl__dim">${esc(s.purpose)}</span></li>`).join("") || "<li>No tool steps: answer directly.</li>"}</ol>`,
        );
        break;
      }
      case "tool_result":
        line("cl--ok", `${head}${esc(ev.message)}<details><summary>Output</summary><pre>${esc(d.output_preview)}</pre></details>`);
        break;
      case "extracted": {
        const inj = (d.injection_findings || []) as any[];
        line(
          inj.length ? "cl--warn" : "cl--ok",
          `${head}${esc(ev.message)}` +
            (inj.length ? `<div class="cl__sub">Flagged: ${inj.map((f) => `line ${f.line} (${esc(f.kind)})`).join(", ")} · trust ${esc(d.trust)}</div>` : ""),
        );
        break;
      }
      case "approval_required":
        line("cl--appr", `${head}${verdictBadge("REQUIRE_APPROVAL")} ${esc(ev.message)}`);
        showApproval(d);
        break;
      case "approval_decision":
        hideApproval();
        line(d.approved ? "cl--ok" : "cl--deny", `${head}${esc(ev.message)}`);
        break;
      case "error":
      case "extract_error":
      case "tool_error":
        line("cl--err", `${head}${esc(ev.message)}`);
        break;
      case "verify_warning":
        line("cl--warn", `${head}Verification: ${esc(ev.message)}`);
        break;
      case "audit":
        line("cl--dim", `${head}${esc(ev.message)}`);
        break;
      default:
        line(ev.type === "stage" ? "cl--stage" : "", `${head}${esc(ev.message)}`);
    }
    if (ev.stage) setStage(ev.stage, ev.type === "error");
  }

  // ---------- approval ----------
  function showApproval(d: any): void {
    approvalEl.hidden = false;
    approvalEl.querySelector("[data-approval-reason]")!.textContent = `${d.tool}: ${d.reason}`;
    approvalEl.querySelector("[data-approval-preview]")!.textContent = d.preview || "";
    approvalEl.querySelector<HTMLButtonElement>('[data-approve="true"]')!.focus();
  }
  function hideApproval(): void {
    approvalEl.hidden = true;
  }
  approvalEl.addEventListener("click", async (e) => {
    const btn = (e.target as Element).closest<HTMLButtonElement>("[data-approve]");
    if (!btn || !currentTask) return;
    approvalEl.querySelectorAll("button").forEach((b) => (b.disabled = true));
    try {
      await api(`/api/tasks/${currentTask}/approve`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ approve: btn.dataset.approve === "true" }),
      });
    } catch (err) {
      line("cl--err", `Approval failed: ${esc((err as Error).message)}`);
    } finally {
      approvalEl.querySelectorAll("button").forEach((b) => (b.disabled = false));
    }
  });

  // ---------- uploads ----------
  function renderFiles(): void {
    filesEl.innerHTML = uploads
      .map(
        (f, i) =>
          `<li><span class="files__id">D${i + 1}</span><span class="files__name">${esc(f.name)}</span><span class="files__meta">${esc(f.kind)} · ${(f.size / 1024).toFixed(1)} KB</span><button type="button" aria-label="Remove ${esc(f.name)}" data-remove="${i}">×</button></li>`,
      )
      .join("");
  }
  filesEl.addEventListener("click", (e) => {
    const b = (e.target as Element).closest<HTMLButtonElement>("[data-remove]");
    if (!b || running) return;
    uploads.splice(Number(b.dataset.remove), 1);
    renderFiles();
  });
  async function upload(list: FileList | File[]): Promise<void> {
    const files = Array.from(list);
    if (!files.length) return;
    if (!live) {
      line("cl--err", "Cannot upload: the live backend is not available.");
      return;
    }
    const fd = new FormData();
    files.slice(0, 5 - uploads.length).forEach((f) => fd.append("files", f, f.name));
    drop.classList.add("is-busy");
    try {
      const res = await api<{ files: Uploaded[]; rejected: { name: string; error: string }[] }>("/api/upload", { method: "POST", body: fd });
      uploads = uploads.concat(res.files).slice(0, 5);
      res.rejected.forEach((r) => line("cl--err", `Upload rejected: ${esc(r.name)}: ${esc(r.error)}`));
      renderFiles();
    } catch (err) {
      line("cl--err", `Upload rejected: ${esc((err as Error).message)}`);
    } finally {
      drop.classList.remove("is-busy");
      fileInput.value = "";
    }
  }
  fileInput.addEventListener("change", () => fileInput.files && upload(fileInput.files));
  ["dragenter", "dragover"].forEach((t) =>
    drop.addEventListener(t, (e) => {
      e.preventDefault();
      drop.classList.add("is-over");
    }),
  );
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, () => drop.classList.remove("is-over")));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    if ((e as DragEvent).dataTransfer?.files) upload((e as DragEvent).dataTransfer!.files);
  });

  root.querySelector("[data-agent-examples]")!.addEventListener("click", (e) => {
    const b = (e.target as Element).closest("button");
    if (!b) return;
    taskEl.value = b.textContent || "";
    refreshRun();
    taskEl.focus();
  });
  taskEl.addEventListener("input", refreshRun);

  // ---------- run ----------
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (runBtn.disabled) return;
    running = true;
    refreshRun();
    modelSel.disabled = true;
    resultEl.hidden = true;
    hideApproval();
    consoleEl.innerHTML = "";
    setStage(null);
    try {
      const res = await api<{ task_id: string }>("/api/tasks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ instruction: taskEl.value.trim(), file_ids: uploads.map((u) => u.file_id), model: modelSel.value || null }),
      });
      currentTask = res.task_id;
      line("cl--dim", `Task ${esc(res.task_id)} submitted · streaming live events`);
      stream(res.task_id);
    } catch (err) {
      line("cl--err", `Could not start task: ${esc((err as Error).message)}`);
      running = false;
      modelSel.disabled = false;
      refreshRun();
    }
  });

  function stream(taskId: string): void {
    source?.close();
    const es = new EventSource(`${API}/api/tasks/${taskId}/events`);
    source = es;
    const onEvent = (msg: MessageEvent) => render(JSON.parse(msg.data) as Ev);
    EVENT_TYPES.forEach((t) => es.addEventListener(t, onEvent as EventListener));
    es.addEventListener("end", async () => {
      es.close();
      await finish(taskId);
    });
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) {
        line("cl--err", "Event stream closed unexpectedly.");
        void finish(taskId);
      }
    };
  }

  async function finish(taskId: string): Promise<void> {
    try {
      const t = await api<any>(`/api/tasks/${taskId}`);
      if (t.status === "completed" && t.result) {
        setStage(10); // every stage, including "Task completed", is done
        resultEl.hidden = false;
        resultEl.dataset.state = "ok";
        const r = t.result;
        const rep = r.report
          ? `<p class="result__report">Report: ${
              r.report.status === "executed" ? `saved as <code>${esc(r.report.filename)}</code> in the task output folder` : `${esc(r.report.status)} (${esc(r.report.security?.layer)}${r.report.security?.rule ? " / " + esc(r.report.security.rule) : ""})`
            }</p>`
          : "";
        const warn = (r.verification_warnings || []).map((w: string) => `<p class="result__warn">${esc(w)}</p>`).join("");
        resultBody.innerHTML = md(r.answer) + rep + warn;
        resultMeta.textContent = `${t.model} · ${r.tools_executed.length} tool(s) · ${r.blocked_steps.length} blocked`;
      } else if (t.status === "failed") {
        resultEl.hidden = false;
        resultEl.dataset.state = "err";
        resultBody.innerHTML = `<p><strong>Task failed.</strong> ${esc(t.error?.message)}</p><p class="result__warn">No recorded or simulated output is shown in its place.</p>`;
        resultMeta.textContent = t.error?.kind || "";
      }
    } finally {
      running = false;
      modelSel.disabled = false;
      refreshRun();
      void checkHealth();
    }
  }

  void checkHealth();
}

/** Live / recorded mode tabs (recorded replay is never shown automatically). */
export function initModes(): void {
  const tabs = [...document.querySelectorAll<HTMLButtonElement>("[data-mode]")];
  const select = (t: HTMLButtonElement, focus = false) => {
    tabs.forEach((b) => {
      const on = b === t;
      b.setAttribute("aria-selected", String(on));
      b.tabIndex = on ? 0 : -1;
      document.getElementById(b.getAttribute("aria-controls")!)!.hidden = !on;
    });
    if (focus) t.focus();
  };
  tabs.forEach((t, i) => {
    t.addEventListener("click", () => select(t));
    t.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
        e.preventDefault();
        select(tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length], true);
      }
    });
  });
}
