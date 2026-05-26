"""Feature extraction for the heuristic risk scorer (Layer 5).

The feature set is deliberately structural (counts of constructs in the AST
plus file metadata). This keeps the layer hermetic and reproducible. The
extracted `NodeFeatures` are the same shape we would feed to a trained ML
classifier in a future version, so the public scorer can swap from heuristic
to learned without breaking the layer's contract.

Design notes:

- AST-based counts: same parser as Layer 3, but the visitor is *counting*
  rather than emitting findings. Cheaper to walk than re-emitting Finding
  objects per call site.
- File-level features (LOC, file count, file size) are walked once per node.
- Manifest features (deps from `requirements.txt` / `pyproject.toml`) are
  best-effort parsed; failures are tolerated.
- "Long encoded string" detection uses small heuristics rather than perfect
  regexes — we want to surface *suspicious looking* embedded payloads, not
  prove they are base64.

The features intentionally overlap with what Layers 2 and 3 already detect.
Layer 5 is meant to look at the *aggregate shape* of the node, not raise
individual call-site findings.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass, field

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - 3.10 fallback
    import tomli as tomllib  # type: ignore[no-redef]

from nodesafe.layers.base import NodeContext

# Calls (by simple name) that are dangerous when invoked directly.
_DIRECT_DANGEROUS = {"eval", "exec", "compile", "__import__"}

# Modules whose mere import is a yellow flag.
_SUSPICIOUS_IMPORTS = {
    "pickle",
    "marshal",
    "cloudpickle",
    "dill",
    "ctypes",
    "_ctypes",
    "winreg",
}

# Qualified-call buckets — same family layout as Layer 3.
_SHELL_QUALIFIED = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "os.system",
    "os.popen",
    "os.execv",
    "os.execvp",
    "os.execve",
    "os.spawnv",
    "pty.spawn",
}

_DESERIAL_QUALIFIED = {
    "pickle.loads",
    "pickle.load",
    "cloudpickle.loads",
    "dill.loads",
    "marshal.loads",
}

_DECODER_QUALIFIED = {
    "base64.b64decode",
    "base64.decodebytes",
    "base64.urlsafe_b64decode",
    "codecs.decode",
    "binascii.unhexlify",
    "binascii.a2b_hex",
}

_NETWORK_QUALIFIED = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "socket.socket",
    "http.client.HTTPSConnection",
    "http.client.HTTPConnection",
}


# Strings of suspicious length whose alphabet is mostly base64 or hex.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/=_-]{100,}")
_HEX_RE = re.compile(r"[0-9a-fA-F]{100,}")


@dataclass
class NodeFeatures:
    """Holistic structural features of a custom_node.

    All counts are *across all .py files* in the node. Manifest fields cover
    `requirements.txt` and `pyproject.toml`.
    """

    # Direct dangerous calls
    eval_calls: int = 0
    exec_calls: int = 0
    compile_calls: int = 0
    import_dunder_calls: int = 0

    # Qualified dangerous calls
    shell_calls: int = 0
    deserialization_calls: int = 0
    decoder_calls: int = 0
    network_calls: int = 0

    # Composed risk signals
    shell_true_count: int = 0  # subprocess with shell=True
    exec_with_decoder_count: int = 0  # exec(b64decode(...))-like chains
    dynamic_getattr_count: int = 0  # getattr(obj, <non-literal>)

    # Imports
    suspicious_import_count: int = 0
    total_import_count: int = 0

    # Obfuscation
    long_base64_string_count: int = 0
    long_hex_string_count: int = 0

    # File metadata
    py_file_count: int = 0
    total_file_count: int = 0
    total_loc: int = 0
    max_file_bytes: int = 0
    syntax_error_count: int = 0

    # Manifest (requirements.txt + pyproject.toml)
    requirements_vcs_count: int = 0
    requirements_url_count: int = 0
    requirements_count: int = 0

    # Free-form bookkeeping (kept for downstream debugging / future ML use)
    notes: list[str] = field(default_factory=list)

    @property
    def dangerous_calls_total(self) -> int:
        return (
            self.eval_calls
            + self.exec_calls
            + self.compile_calls
            + self.import_dunder_calls
            + self.shell_calls
            + self.deserialization_calls
        )

    @property
    def dangerous_call_density(self) -> float:
        """Dangerous calls per 100 lines. 0 if no code was parsed."""
        if self.total_loc <= 0:
            return 0.0
        return 100.0 * self.dangerous_calls_total / self.total_loc

    @property
    def suspicious_import_ratio(self) -> float:
        if self.total_import_count <= 0:
            return 0.0
        return self.suspicious_import_count / self.total_import_count


def extract_features(context: NodeContext) -> NodeFeatures:
    """Walk `context` and aggregate the structural features."""
    features = NodeFeatures()
    features.total_file_count = len(context.files)
    features.py_file_count = len(context.py_files)

    # 1) Walk Python files for AST-based counts.
    for path in context.py_files:
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        features.total_loc += source.count("\n") + 1
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        if size > features.max_file_bytes:
            features.max_file_bytes = size

        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            features.syntax_error_count += 1
            # Still scan the raw text for obfuscation strings.
            _scan_text_for_obfuscation(source, features)
            continue

        visitor = _CountingVisitor(features)
        visitor.visit(tree)
        _scan_text_for_obfuscation(source, features)

    # 2) Manifest features.
    _scan_manifests(context, features)

    return features


def _scan_text_for_obfuscation(source: str, features: NodeFeatures) -> None:
    features.long_base64_string_count += len(_BASE64_RE.findall(source))
    features.long_hex_string_count += len(_HEX_RE.findall(source))


def _scan_manifests(context: NodeContext, features: NodeFeatures) -> None:
    for path in context.text_files:
        name = path.name.lower()
        if name == "requirements.txt":
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for raw in text.splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                features.requirements_count += 1
                if line.startswith(("git+", "hg+", "svn+", "bzr+")):
                    features.requirements_vcs_count += 1
                if "://" in line:
                    features.requirements_url_count += 1
        elif name == "pyproject.toml":
            try:
                raw = path.read_bytes()
                data = tomllib.loads(raw.decode("utf-8", errors="ignore"))
            except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
                continue
            project = data.get("project", {})
            deps = list(project.get("dependencies") or [])
            optional = project.get("optional-dependencies") or {}
            if isinstance(optional, dict):
                for extras in optional.values():
                    if isinstance(extras, list):
                        deps.extend(extras)
            for entry in deps:
                if not isinstance(entry, str):
                    continue
                features.requirements_count += 1
                if entry.startswith(("git+", "hg+", "svn+", "bzr+")):
                    features.requirements_vcs_count += 1
                if "://" in entry:
                    features.requirements_url_count += 1


class _CountingVisitor(ast.NodeVisitor):
    """Visitor that increments counts on `features` rather than emitting findings."""

    def __init__(self, features: NodeFeatures) -> None:
        self._f = features

    # --- helpers ---------------------------------------------------------

    @staticmethod
    def _qualified_name(node: ast.AST) -> str | None:
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
        return None

    @staticmethod
    def _is_decoder_call(node: ast.AST) -> bool:
        cur: ast.AST = node
        # Peel `.decode()`/`.encode()` chains.
        while (
            isinstance(cur, ast.Call)
            and isinstance(cur.func, ast.Attribute)
            and cur.func.attr in {"decode", "encode"}
        ):
            cur = cur.func.value
        if not isinstance(cur, ast.Call):
            return False
        if isinstance(cur.func, ast.Attribute):
            parts: list[str] = []
            walker: ast.AST = cur.func
            while isinstance(walker, ast.Attribute):
                parts.append(walker.attr)
                walker = walker.value
            if isinstance(walker, ast.Name):
                parts.append(walker.id)
                return ".".join(reversed(parts)) in _DECODER_QUALIFIED
        return False

    @staticmethod
    def _has_shell_true(call: ast.Call) -> bool:
        for kw in call.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    # --- visit methods ---------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        if isinstance(func, ast.Name):
            name = func.id
            if name == "eval":
                self._f.eval_calls += 1
                if node.args and self._is_decoder_call(node.args[0]):
                    self._f.exec_with_decoder_count += 1
            elif name == "exec":
                self._f.exec_calls += 1
                if node.args and self._is_decoder_call(node.args[0]):
                    self._f.exec_with_decoder_count += 1
            elif name == "compile":
                self._f.compile_calls += 1
            elif name == "__import__":
                self._f.import_dunder_calls += 1
            elif name == "getattr" and len(node.args) >= 2:
                if not isinstance(node.args[1], ast.Constant):
                    self._f.dynamic_getattr_count += 1

        if isinstance(func, ast.Attribute):
            qualified = self._qualified_name(func)
            if qualified:
                if qualified in _SHELL_QUALIFIED:
                    self._f.shell_calls += 1
                    if qualified.startswith("subprocess.") and self._has_shell_true(node):
                        self._f.shell_true_count += 1
                elif qualified in _DESERIAL_QUALIFIED:
                    self._f.deserialization_calls += 1
                elif qualified in _DECODER_QUALIFIED:
                    self._f.decoder_calls += 1
                elif qualified in _NETWORK_QUALIFIED:
                    self._f.network_calls += 1

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._f.total_import_count += 1
            mod = alias.name.split(".")[0]
            if mod in _SUSPICIOUS_IMPORTS:
                self._f.suspicious_import_count += 1
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self._f.total_import_count += 1
        mod = (node.module or "").split(".")[0]
        if mod in _SUSPICIOUS_IMPORTS:
            self._f.suspicious_import_count += 1
        self.generic_visit(node)
