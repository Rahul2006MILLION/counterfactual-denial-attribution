"""Text extraction for uploaded documents.

PDF uses pypdf. DOCX and XLSX are Office Open XML zip files and are parsed with the
standard library (zipfile + ElementTree), so no extra dependencies are needed.
Extraction never executes document content.
"""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

MAX_ZIP_ENTRY_BYTES = 50 * 1024 * 1024  # zip-bomb guard (uncompressed)
MAX_TEXT_CHARS = 400_000  # cap extracted text kept per document

W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
S_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
R_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"


class ExtractionError(ValueError):
    pass


@dataclass
class Extracted:
    text: str
    kind: str
    pages: int | None = None
    sheets: list[str] = field(default_factory=list)
    table: list[list[str]] | None = None  # CSV / first XLSX sheet, for table_stats
    truncated: bool = False
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "chars": len(self.text),
            "lines": self.text.count("\n") + 1 if self.text else 0,
            "pages": self.pages,
            "sheets": self.sheets or None,
            "table_rows": len(self.table) if self.table else None,
            "truncated": self.truncated,
            "notes": self.notes,
        }


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _safe_zip_read(zf: zipfile.ZipFile, name: str) -> bytes:
    info = zf.getinfo(name)
    if info.file_size > MAX_ZIP_ENTRY_BYTES:
        raise ExtractionError(f"Archive entry '{name}' is too large when uncompressed.")
    return zf.read(name)


def _xml(data: bytes) -> ET.Element:
    """Parse an Office XML part. DTDs are never needed in OOXML, so any DOCTYPE/ENTITY
    declaration is rejected before parsing (blocks XXE and entity-expansion attacks)."""
    head = data[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in data.lower():
        raise ExtractionError("Document XML contains a DTD or entity declaration, which is not allowed.")
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        raise ExtractionError(f"Malformed document XML: {exc}") from exc


def _pdf(path: Path) -> Extracted:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise ExtractionError("PDF support requires the 'pypdf' package.") from exc
    try:
        reader = PdfReader(str(path))
        if reader.is_encrypted:
            raise ExtractionError("Encrypted PDFs are not supported.")
        parts = []
        for i, page in enumerate(reader.pages, 1):
            t = page.extract_text() or ""
            parts.append(f"[Page {i}]\n{t.strip()}")
    except ExtractionError:
        raise
    except Exception as exc:  # noqa: BLE001 - malformed PDFs raise many error types
        raise ExtractionError(f"Could not read PDF: {exc}") from exc
    text = "\n\n".join(parts)
    ex = Extracted(text=text, kind="pdf", pages=len(parts))
    if not re.search(r"\w", re.sub(r"\[Page \d+\]", "", text)):
        ex.notes.append("No extractable text found (the PDF may be scanned images; OCR is not supported).")
    return ex


def _docx(path: Path) -> Extracted:
    try:
        with zipfile.ZipFile(path) as zf:
            xml = _safe_zip_read(zf, "word/document.xml")
    except (zipfile.BadZipFile, KeyError) as exc:
        raise ExtractionError("Not a valid DOCX file.") from exc
    root = _xml(xml)
    paras = []
    for p in root.iter(f"{W_NS}p"):
        runs = []
        for node in p.iter():
            if node.tag == f"{W_NS}t" and node.text:
                runs.append(node.text)
            elif node.tag == f"{W_NS}tab":
                runs.append("\t")
            elif node.tag in (f"{W_NS}br", f"{W_NS}cr"):
                runs.append("\n")
        paras.append("".join(runs))
    return Extracted(text="\n".join(paras).strip(), kind="docx")


def _xlsx(path: Path) -> Extracted:
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise ExtractionError("Not a valid XLSX file.") from exc
    with zf:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in zf.namelist():
            for si in _xml(_safe_zip_read(zf, "xl/sharedStrings.xml")).iter(f"{S_NS}si"):
                shared.append("".join(t.text or "" for t in si.iter(f"{S_NS}t")))
        try:
            wb = _xml(_safe_zip_read(zf, "xl/workbook.xml"))
            rels = _xml(_safe_zip_read(zf, "xl/_rels/workbook.xml.rels"))
        except KeyError as exc:
            raise ExtractionError("XLSX workbook structure is missing.") from exc
        targets = {r.get("Id"): r.get("Target") for r in rels}
        sheets = []
        for s in wb.iter(f"{S_NS}sheet"):
            target = targets.get(s.get(f"{R_NS}id"), "")
            target = target.lstrip("/")
            if not target.startswith("xl/"):
                target = "xl/" + target
            sheets.append((s.get("name") or "Sheet", target))

        def col_index(ref: str) -> int:
            letters = re.match(r"[A-Z]+", ref or "A")
            n = 0
            for ch in letters.group(0) if letters else "A":
                n = n * 26 + (ord(ch) - 64)
            return n - 1

        texts, first_table = [], None
        for name, target in sheets:
            if target not in zf.namelist():
                continue
            rows: list[list[str]] = []
            for row in _xml(_safe_zip_read(zf, target)).iter(f"{S_NS}row"):
                cells: dict[int, str] = {}
                for c in row.iter(f"{S_NS}c"):
                    t = c.get("t")
                    v = c.find(f"{S_NS}v")
                    if t == "s" and v is not None and v.text is not None:
                        val = shared[int(v.text)] if int(v.text) < len(shared) else ""
                    elif t == "inlineStr":
                        val = "".join(x.text or "" for x in c.iter(f"{S_NS}t"))
                    else:
                        val = v.text if v is not None and v.text is not None else ""
                    cells[col_index(c.get("r", "A"))] = val
                if cells:
                    width = max(cells) + 1
                    rows.append([cells.get(i, "") for i in range(width)])
            if first_table is None:
                first_table = rows
            texts.append(f"[Sheet: {name}]\n" + "\n".join(",".join(r) for r in rows))
    return Extracted(text="\n\n".join(texts), kind="xlsx", sheets=[n for n, _ in sheets], table=first_table)


def _csv(data: str) -> Extracted:
    sample = data[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows = [r for r in csv.reader(io.StringIO(data), dialect) if any(cell.strip() for cell in r)]
    return Extracted(text=data, kind="csv", table=rows)


def _json(data: str) -> Extracted:
    try:
        obj = json.loads(data)
    except json.JSONDecodeError as exc:
        ex = Extracted(text=data, kind="json")
        ex.notes.append(f"Invalid JSON: {exc.msg} at line {exc.lineno} column {exc.colno}.")
        return ex
    return Extracted(text=json.dumps(obj, indent=2, ensure_ascii=False), kind="json")


def extract(path: Path, ext: str, kind: str) -> Extracted:
    if ext == ".pdf":
        ex = _pdf(path)
    elif ext == ".docx":
        ex = _docx(path)
    elif ext == ".xlsx":
        ex = _xlsx(path)
    else:
        data = _decode(path.read_bytes())
        if ext == ".csv":
            ex = _csv(data)
        elif ext == ".json":
            ex = _json(data)
        else:
            ex = Extracted(text=data, kind=kind)
    if len(ex.text) > MAX_TEXT_CHARS:
        ex.text = ex.text[:MAX_TEXT_CHARS]
        ex.truncated = True
        ex.notes.append(f"Text truncated to {MAX_TEXT_CHARS:,} characters.")
    return ex


def chunk_text(text: str, size: int) -> list[str]:
    """Split text into chunks of at most `size` characters, preferring line boundaries."""
    if len(text) <= size:
        return [text]
    chunks, buf = [], []
    length = 0
    for line in text.splitlines(keepends=True):
        while len(line) > size:  # very long single line
            if buf:
                chunks.append("".join(buf))
                buf, length = [], 0
            chunks.append(line[:size])
            line = line[size:]
        if length + len(line) > size and buf:
            chunks.append("".join(buf))
            buf, length = [], 0
        buf.append(line)
        length += len(line)
    if buf:
        chunks.append("".join(buf))
    return chunks
