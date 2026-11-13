"""Upload storage with validation, size limits and path confinement.

Layout (all under Settings.workspace, which is gitignored):
  uploads/<file_id>/original.<ext>   raw upload (never executed)
  uploads/<file_id>/meta.json        validated metadata
  tasks/<task_id>/outputs/           files written by approved tools only
  tasks/<task_id>/audit.jsonl        hash-chained audit log
  tasks/<task_id>/events.jsonl       every event streamed to the UI
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path

from src.live.config import Settings

TEXT_EXTS = {
    ".txt", ".md", ".markdown", ".csv", ".json", ".log",
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".c", ".h", ".cpp", ".hpp", ".cs",
    ".go", ".rs", ".rb", ".php", ".sh", ".sql", ".html", ".css", ".yaml", ".yml",
    ".toml", ".ini", ".xml", ".kt", ".swift",
}
BINARY_EXTS = {".pdf", ".docx", ".xlsx"}
ALLOWED_EXTS = TEXT_EXTS | BINARY_EXTS
CODE_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".c", ".h", ".cpp", ".hpp", ".cs",
    ".go", ".rs", ".rb", ".php", ".sh", ".sql", ".kt", ".swift",
}

# Magic numbers for binary formats (content must match the extension).
_MAGIC = {".pdf": b"%PDF-", ".docx": b"PK\x03\x04", ".xlsx": b"PK\x03\x04"}

FILE_ID_RE = re.compile(r"^f_[0-9a-f]{16}$")
TASK_ID_RE = re.compile(r"^t_[0-9a-f]{16}$")


class UploadRejected(ValueError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class StoredFile:
    file_id: str
    name: str  # sanitized display name
    ext: str
    size: int
    sha256: str
    kind: str  # "pdf" | "docx" | "xlsx" | "csv" | "code" | "text" | "json"

    def to_dict(self) -> dict:
        return asdict(self)


def safe_display_name(name: str) -> str:
    """Strip any directory components and unsafe characters from an uploaded name."""
    base = re.split(r"[\\/]", name or "")[-1]
    base = re.sub(r"[^A-Za-z0-9._ -]", "_", base).strip(" .")
    return (base or "upload")[:120]


def confine(root: Path, *parts: str) -> Path:
    """Join parts under root and refuse anything that escapes it (path traversal)."""
    root = root.resolve()
    p = root.joinpath(*parts).resolve()
    if p != root and root not in p.parents:
        raise UploadRejected("Path escapes the workspace.", 400)
    return p


def kind_for(ext: str) -> str:
    if ext in (".pdf", ".docx", ".xlsx", ".csv", ".json"):
        return ext[1:]
    if ext in CODE_EXTS:
        return "code"
    return "text"


class Workspace:
    def __init__(self, settings: Settings) -> None:
        self.s = settings
        self.root = settings.workspace
        (self.root / "uploads").mkdir(parents=True, exist_ok=True)
        (self.root / "tasks").mkdir(parents=True, exist_ok=True)

    # ---------- uploads ----------
    def save_upload(self, filename: str, data: bytes) -> StoredFile:
        name = safe_display_name(filename)
        ext = Path(name).suffix.lower()
        if ext not in ALLOWED_EXTS:
            raise UploadRejected(
                f"Unsupported file type '{ext or '(none)'}'. Allowed: PDF, DOCX, XLSX, TXT, MD, CSV, JSON and source code.",
                415,
            )
        if not data:
            raise UploadRejected("The file is empty.", 400)
        if len(data) > self.s.max_upload_bytes:
            raise UploadRejected(
                f"File is {len(data) / 1e6:.1f} MB; the limit is {self.s.max_upload_bytes / 1e6:.0f} MB.", 413
            )
        magic = _MAGIC.get(ext)
        if magic and not data.startswith(magic):
            raise UploadRejected(f"File content does not match its '{ext}' extension.", 415)
        if ext in TEXT_EXTS:
            if b"\x00" in data[:4096]:
                raise UploadRejected("Text file contains binary data.", 415)
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    data.decode("latin-1")
                except UnicodeDecodeError as exc:  # pragma: no cover - latin-1 decodes any bytes
                    raise UploadRejected("Text file is not valid UTF-8.", 415) from exc

        file_id = f"f_{secrets.token_hex(8)}"
        folder = confine(self.root, "uploads", file_id)
        folder.mkdir(parents=False, exist_ok=False)
        with open(folder / f"original{ext}", "xb") as fh:  # exclusive create
            fh.write(data)
        meta = StoredFile(file_id, name, ext, len(data), hashlib.sha256(data).hexdigest(), kind_for(ext))
        (folder / "meta.json").write_text(json.dumps(meta.to_dict()), encoding="utf-8")
        return meta

    def get_file(self, file_id: str) -> tuple[StoredFile, Path]:
        if not FILE_ID_RE.match(file_id or ""):
            raise UploadRejected("Invalid file id.", 400)
        folder = confine(self.root, "uploads", file_id)
        meta_path = folder / "meta.json"
        if not meta_path.is_file():
            raise UploadRejected("Unknown file id.", 404)
        meta = StoredFile(**json.loads(meta_path.read_text(encoding="utf-8")))
        return meta, confine(folder, f"original{meta.ext}")

    # ---------- tasks ----------
    def task_dir(self, task_id: str) -> Path:
        if not TASK_ID_RE.match(task_id or ""):
            raise UploadRejected("Invalid task id.", 400)
        d = confine(self.root, "tasks", task_id)
        (d / "outputs").mkdir(parents=True, exist_ok=True)
        return d
