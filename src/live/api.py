"""HTTP API for the live agent (FastAPI).

Run:  uv run uvicorn src.live.api:app --host 127.0.0.1 --port 8000

Endpoints
  GET  /api/health                     Ollama connectivity, selected model, limits
  GET  /api/models                     locally installed Ollama models
  POST /api/upload                     multipart upload (one or more files)
  POST /api/tasks                      {"instruction", "file_ids", "model"?} -> task id
  GET  /api/tasks/{task_id}            task snapshot
  GET  /api/tasks/{task_id}/events     Server-Sent Events stream of real backend events
  POST /api/tasks/{task_id}/approve    {"approve", "approval_id", "action_digest"} for the pending action
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from src.live.agent import TaskManager
from src.live.config import get_settings
from src.live.ollama import OllamaClient, OllamaError
from src.live.workspace import UploadRejected

TERMINAL = {"completed", "failed"}


class TaskIn(BaseModel):
    instruction: str = Field(..., min_length=1, max_length=2000)
    file_ids: list[str] = Field(default_factory=list, max_length=20)
    model: str | None = Field(default=None, max_length=120)


class ApproveIn(BaseModel):
    """A decision is bound to one pending action: its approval id and the SHA-256 of the
    exact tool call shown to the reviewer (both from the approval_required event)."""

    model_config = {"extra": "forbid"}
    approve: bool
    approval_id: str = Field(..., pattern=r"^a_[0-9a-f]{16}$")
    action_digest: str = Field(..., pattern=r"^[0-9a-f]{64}$")


def create_app(manager: TaskManager | None = None) -> FastAPI:
    settings = manager.settings if manager else get_settings()
    mgr = manager or TaskManager(settings, OllamaClient(settings))
    app = FastAPI(title="Counterfactual Denial Attribution — Live Agent", version="0.1.0")
    app.state.manager = mgr
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$",
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Last-Event-ID"],
    )

    def fail(exc: UploadRejected) -> HTTPException:
        return HTTPException(status_code=exc.status, detail=str(exc))

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        client = mgr.client
        out: dict[str, Any] = {
            "status": "ok",
            "mode": "live",
            "ollama": {"url": settings.ollama_url, "reachable": False},
            "model": {"configured": settings.ollama_model or None, "selected": None},
            "limits": {
                "max_upload_mb": settings.max_upload_bytes // (1024 * 1024),
                "max_files_per_task": settings.max_files_per_task,
                "num_ctx": settings.num_ctx,
                "chunk_chars": settings.chunk_chars,
            },
        }
        try:
            out["ollama"]["version"] = client.version()
            out["ollama"]["reachable"] = True
            models = client.list_models()
            out["model"]["available"] = len(models)
            out["model"]["selected"] = client.select_model(None, models)
        except OllamaError as exc:
            out["status"] = "degraded"
            out["ollama"]["error"] = {"kind": exc.kind, "message": str(exc)}
        return out

    @app.get("/api/models")
    def models() -> dict[str, Any]:
        try:
            items = mgr.client.list_models()
        except OllamaError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        try:
            default = mgr.client.select_model(None, items)
        except OllamaError:
            default = None
        return {"models": items, "default": default}

    @app.post("/api/upload")
    async def upload(files: list[UploadFile] = File(...)) -> dict[str, Any]:
        if not files:
            raise HTTPException(status_code=400, detail="No files received.")
        if len(files) > settings.max_files_per_task:
            raise HTTPException(status_code=400, detail=f"At most {settings.max_files_per_task} files per upload.")
        stored, rejected = [], []
        for f in files:
            data = await f.read(settings.max_upload_bytes + 1)
            try:
                stored.append(mgr.workspace.save_upload(f.filename or "upload", data).to_dict())
            except UploadRejected as exc:
                rejected.append({"name": f.filename, "error": str(exc), "status": exc.status})
        if not stored and rejected:
            raise HTTPException(status_code=rejected[0]["status"], detail=rejected[0]["error"])
        return {"files": stored, "rejected": rejected}

    @app.post("/api/tasks", status_code=202)
    def create_task(body: TaskIn) -> dict[str, Any]:
        try:
            task = mgr.create(body.instruction, body.file_ids, body.model)
        except UploadRejected as exc:
            raise fail(exc) from exc
        return {"task_id": task.id, "status": task.status, "events_url": f"/api/tasks/{task.id}/events"}

    @app.get("/api/tasks/{task_id}")
    def get_task(task_id: str) -> dict[str, Any]:
        try:
            return mgr.get(task_id).snapshot()
        except UploadRejected as exc:
            raise fail(exc) from exc

    @app.post("/api/tasks/{task_id}/approve")
    def approve(task_id: str, body: ApproveIn) -> dict[str, Any]:
        try:
            task = mgr.decide(task_id, body.approve, body.approval_id, body.action_digest)
        except UploadRejected as exc:
            raise fail(exc) from exc
        return {"task_id": task.id, "approve": body.approve, "approval_id": body.approval_id}

    @app.get("/api/tasks/{task_id}/events")
    async def events(task_id: str, request: Request) -> StreamingResponse:
        try:
            task = mgr.get(task_id)
        except UploadRejected as exc:
            raise fail(exc) from exc
        try:
            start = int(request.headers.get("last-event-id", "-1")) + 1
        except ValueError:
            start = 0

        async def stream():
            i = max(0, start)
            idle = 0.0
            yield "retry: 2000\n\n"
            while True:
                while i < len(task.events):
                    ev = task.events[i]
                    yield f"id: {ev['seq']}\nevent: {ev['type']}\ndata: {json.dumps(ev, default=str)}\n\n"
                    i += 1
                    idle = 0.0
                if task.status in TERMINAL and i >= len(task.events):
                    # Give the worker a moment to emit its final audit event.
                    await asyncio.sleep(0.3)
                    if i >= len(task.events):
                        yield f"event: end\ndata: {json.dumps({'status': task.status})}\n\n"
                        return
                if await request.is_disconnected():
                    return
                await asyncio.sleep(0.2)
                idle += 0.2
                if idle >= 15:
                    yield ": keep-alive\n\n"
                    idle = 0.0

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return app


app = create_app()
