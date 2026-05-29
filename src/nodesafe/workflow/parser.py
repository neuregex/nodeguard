"""Workflow file parser.

Accepts JSON and PNG inputs. PNG parsing is done with stdlib only
(``struct`` + ``zlib``) so we don't add a Pillow dependency for what
amounts to reading a couple of named chunks.

PNG format (the part we care about):

    8-byte signature: 89 50 4E 47 0D 0A 1A 0A
    then chunks repeated to IEND:
        4-byte length (big-endian)
        4-byte type   (ASCII like b"tEXt" or b"zTXt" or b"iTXt")
        N-byte data
        4-byte CRC

For workflow extraction we look at three chunk types:
    tEXt   ASCII text, format ``keyword\\x00 value``
    zTXt   compressed text (zlib), same layout but value is deflated
    iTXt   international text with optional compression flag

ComfyUI typically writes ``workflow`` and ``prompt`` as ``tEXt``. Some
tools (A1111 / re-savers) end up writing ``zTXt`` instead, so we handle
both.
"""

from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path
from typing import Any

from nodesafe.workflow.models import Workflow, WorkflowNode


class WorkflowParseError(Exception):
    """Raised when a workflow file cannot be parsed."""


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
# Keys we want from PNG metadata, in priority order.
_WORKFLOW_KEYS = ("workflow", "prompt", "parameters")


def parse_workflow(path: Path | str) -> Workflow:
    """Parse a workflow from a path. Dispatches on extension."""
    p = Path(path)
    if not p.exists():
        raise WorkflowParseError(f"File does not exist: {p}")
    if not p.is_file():
        raise WorkflowParseError(f"Not a file: {p}")

    suffix = p.suffix.lower()
    if suffix == ".json":
        return _parse_json(p)
    if suffix == ".png":
        return _parse_png(p)
    # Try JSON first as a fallback; some workflows are saved without extension.
    try:
        return _parse_json(p)
    except WorkflowParseError as exc:
        raise WorkflowParseError(
            f"Unknown workflow format for {p.suffix!r}. "
            f"Supported: .json, .png. Underlying error: {exc}"
        ) from exc


def _parse_json(path: Path) -> Workflow:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkflowParseError(f"Could not read JSON from {path}: {exc}") from exc
    return _normalize(data, source=str(path))


def _parse_png(path: Path) -> Workflow:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise WorkflowParseError(f"Could not read PNG {path}: {exc}") from exc

    if not raw.startswith(PNG_SIGNATURE):
        raise WorkflowParseError(f"Not a PNG (bad signature): {path}")

    metadata = _extract_png_text_chunks(raw)
    for key in _WORKFLOW_KEYS:
        if key in metadata:
            try:
                data = json.loads(metadata[key])
            except json.JSONDecodeError as exc:
                raise WorkflowParseError(
                    f"PNG {path} has '{key}' metadata but it isn't valid JSON: {exc}"
                ) from exc
            return _normalize(data, source=f"{path}#{key}")

    raise WorkflowParseError(
        f"No workflow metadata found in PNG {path}. Looked for keys: {', '.join(_WORKFLOW_KEYS)}"
    )


def _extract_png_text_chunks(raw: bytes) -> dict[str, str]:
    """Return a dict of {keyword: text} from tEXt/zTXt/iTXt chunks."""
    out: dict[str, str] = {}
    offset = len(PNG_SIGNATURE)
    while offset + 8 <= len(raw):
        (length,) = struct.unpack(">I", raw[offset : offset + 4])
        chunk_type = raw[offset + 4 : offset + 8]
        data_start = offset + 8
        data_end = data_start + length
        if data_end + 4 > len(raw):
            break  # malformed
        data = raw[data_start:data_end]
        if chunk_type == b"tEXt":
            kw, value = _split_text(data)
            if kw:
                out[kw] = value.decode("utf-8", errors="ignore")
        elif chunk_type == b"zTXt":
            kw, rest = _split_text(data)
            if kw and len(rest) >= 1:
                # First byte is compression method (always 0 = zlib).
                try:
                    decompressed = zlib.decompress(rest[1:])
                    out[kw] = decompressed.decode("utf-8", errors="ignore")
                except zlib.error:
                    pass
        elif chunk_type == b"iTXt":
            kw, rest = _split_text(data)
            if kw and len(rest) >= 4:
                compression_flag = rest[0]
                # Skip compression method (1), language tag (NUL-terminated),
                # translated keyword (NUL-terminated), then the text.
                pos = 2
                # language tag
                end = rest.find(b"\x00", pos)
                if end < 0:
                    continue
                pos = end + 1
                # translated keyword
                end = rest.find(b"\x00", pos)
                if end < 0:
                    continue
                pos = end + 1
                body = rest[pos:]
                if compression_flag == 1:
                    try:
                        body = zlib.decompress(body)
                    except zlib.error:
                        continue
                out[kw] = body.decode("utf-8", errors="ignore")
        elif chunk_type == b"IEND":
            break
        offset = data_end + 4  # +4 for CRC
    return out


def _split_text(data: bytes) -> tuple[str, bytes]:
    """Split a chunk body on the first NUL: keyword + remainder."""
    nul = data.find(b"\x00")
    if nul < 0:
        return "", data
    return data[:nul].decode("latin-1", errors="ignore"), data[nul + 1 :]


def _normalize(data: Any, source: str) -> Workflow:
    """Translate either UI-form or prompt-form JSON into a `Workflow`."""
    if not isinstance(data, dict):
        raise WorkflowParseError(f"Workflow JSON must be an object, got {type(data).__name__}")

    # UI form: { "nodes": [...], "links": [...], ... }
    if isinstance(data.get("nodes"), list):
        return _normalize_ui(data, source)

    # Prompt form: a dict whose keys look like node IDs ("1", "2", ...) and
    # whose values have `class_type` and `inputs`.
    if data and all(isinstance(v, dict) and "class_type" in v for v in data.values()):
        return _normalize_prompt(data, source)

    raise WorkflowParseError(
        f"Workflow JSON from {source} does not look like a ComfyUI workflow. "
        "Expected either a UI export with a 'nodes' list or a prompt-form "
        "dict keyed by node IDs."
    )


def _normalize_ui(data: dict[str, Any], source: str) -> Workflow:
    nodes: list[WorkflowNode] = []
    for entry in data.get("nodes", []):
        if not isinstance(entry, dict):
            continue
        nodes.append(
            WorkflowNode(
                id=str(entry.get("id", "")),
                type=str(entry.get("type", "")),
                widget_values=list(entry.get("widgets_values") or []),
                inputs={},  # UI form doesn't carry inputs the same way
                raw=entry,
            )
        )
    version = data.get("version")
    return Workflow(
        source=source,
        form="ui",
        nodes=nodes,
        version=str(version) if version is not None else None,
    )


def _normalize_prompt(data: dict[str, Any], source: str) -> Workflow:
    nodes: list[WorkflowNode] = []
    for node_id, entry in data.items():
        if not isinstance(entry, dict):
            continue
        nodes.append(
            WorkflowNode(
                id=str(node_id),
                type=str(entry.get("class_type", "")),
                widget_values=[],  # prompt form keeps values inside `inputs`
                inputs=dict(entry.get("inputs") or {}),
                raw=entry,
            )
        )
    return Workflow(source=source, form="prompt", nodes=nodes, version=None)
