"""Minimal Ollama HTTP client (standard library only; local server, no cloud APIs)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from src.live.config import PREFERRED_MODELS, Settings


class OllamaError(RuntimeError):
    """Base error with a user-facing message."""

    kind = "ollama_error"


class OllamaUnavailable(OllamaError):
    kind = "ollama_unavailable"


class ModelNotFound(OllamaError):
    kind = "model_not_found"


class ModelOutputError(OllamaError):
    kind = "model_output_error"


@dataclass
class ChatResult:
    content: str
    model: str
    done_reason: str | None
    total_seconds: float
    prompt_tokens: int | None
    output_tokens: int | None


# Models that cannot do chat (embedding models) are never auto-selected.
_NON_CHAT_FAMILIES = {"bert", "nomic-bert"}


class OllamaClient:
    def __init__(self, settings: Settings) -> None:
        self.s = settings

    # ---------- low level ----------
    def _request(self, path: str, payload: dict[str, Any] | None = None, timeout: float | None = None) -> dict[str, Any]:
        url = f"{self.s.ollama_url}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(
            url, data=data, method="POST" if data else "GET", headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.s.request_timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            try:
                msg = json.loads(body).get("error", body)
            except json.JSONDecodeError:
                msg = body
            if exc.code == 404 and "not found" in msg.lower():
                raise ModelNotFound(msg) from exc
            raise OllamaError(f"Ollama returned HTTP {exc.code}: {msg}") from exc
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as exc:
            raise OllamaUnavailable(
                f"Cannot reach Ollama at {self.s.ollama_url} ({getattr(exc, 'reason', exc)}). "
                "Start it with `ollama serve` or open the Ollama app."
            ) from exc

    # ---------- discovery ----------
    def version(self) -> str:
        return str(self._request("/api/version", timeout=5).get("version", "unknown"))

    def list_models(self) -> list[dict[str, Any]]:
        models = self._request("/api/tags", timeout=10).get("models", [])
        out = []
        for m in models:
            d = m.get("details", {}) or {}
            out.append(
                {
                    "name": m.get("name"),
                    "size_gb": round((m.get("size") or 0) / 1e9, 2),
                    "family": d.get("family"),
                    "parameter_size": d.get("parameter_size"),
                    "quantization": d.get("quantization_level"),
                    "chat_capable": d.get("family") not in _NON_CHAT_FAMILIES,
                }
            )
        return out

    def select_model(self, requested: str | None = None, models: list[dict[str, Any]] | None = None) -> str:
        """Return the model to use, verifying it exists locally."""
        models = models if models is not None else self.list_models()
        names = [m["name"] for m in models if m["chat_capable"]]
        wanted = (requested or self.s.ollama_model or "").strip()
        if wanted:
            if wanted in names or f"{wanted}:latest" in names:
                return wanted if wanted in names else f"{wanted}:latest"
            raise ModelNotFound(
                f"Model '{wanted}' is not installed in Ollama. Available: {', '.join(names) or 'none'}. "
                f"Install it with `ollama pull {wanted}` or choose another model."
            )
        for pref in PREFERRED_MODELS:
            if pref in names:
                return pref
        qwen = [n for n in names if "qwen" in n.lower() and "vl" not in n.lower()]
        if qwen:
            return sorted(qwen, key=lambda n: next((m["size_gb"] for m in models if m["name"] == n), 99))[0]
        if names:
            return names[0]
        raise ModelNotFound("No chat-capable models are installed in Ollama. Run `ollama pull qwen3:4b`.")

    # ---------- inference ----------
    def chat(
        self,
        model: str,
        messages: list[dict[str, str]],
        schema: dict[str, Any] | None = None,
        num_predict: int | None = None,
    ) -> ChatResult:
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "think": False,
            "options": {
                "temperature": self.s.temperature,
                "num_ctx": self.s.num_ctx,
                "num_predict": num_predict or self.s.num_predict,
            },
        }
        if schema is not None:
            payload["format"] = schema
        resp = self._request("/api/chat", payload)
        if "error" in resp:
            raise OllamaError(str(resp["error"]))
        content = (resp.get("message") or {}).get("content", "")
        return ChatResult(
            content=content,
            model=resp.get("model", model),
            done_reason=resp.get("done_reason"),
            total_seconds=round((resp.get("total_duration") or 0) / 1e9, 2),
            prompt_tokens=resp.get("prompt_eval_count"),
            output_tokens=resp.get("eval_count"),
        )

    def chat_json(self, model: str, messages: list[dict[str, str]], schema: dict[str, Any], num_predict: int | None = None) -> tuple[dict[str, Any], ChatResult]:
        """Structured output; raises ModelOutputError on invalid or truncated JSON."""
        res = self.chat(model, messages, schema=schema, num_predict=num_predict)
        if res.done_reason == "length":
            raise ModelOutputError("The model's structured reply was truncated (num_predict reached).")
        try:
            data = json.loads(res.content)
        except json.JSONDecodeError as exc:
            raise ModelOutputError(f"The model returned invalid JSON: {res.content[:200]!r}") from exc
        if not isinstance(data, dict):
            raise ModelOutputError("The model's structured reply was not a JSON object.")
        return data, res
