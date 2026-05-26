"""Layer 3 — AST analysis with a NodeVisitor.

Where Layer 2 catches literal strings, Layer 3 understands the structure of
the code. The visitor walks the AST of every Python file in the target and
emits findings for constructs that are dangerous *in context*, not just
because a substring appeared somewhere.

What this layer detects (high level — see the visitor methods for the precise
matcher logic):

- Direct calls to `eval()`, `exec()`, `compile()`, `__import__()`.
- Qualified calls to known dangerous functions: `subprocess.run`,
  `subprocess.Popen`, `os.system`, `os.popen`, `pty.spawn`, etc.
- `subprocess.*` calls with `shell=True` (a strong amplifier of risk).
- The compound `exec(b64decode(...))` chain — a classic obfuscated loader
  pattern, escalates to CRITICAL when seen together.
- Imports of modules that should not appear in benign diffusion nodes:
  `pickle`, `marshal`, `ctypes`, plus aliased forms.
- Dynamic attribute access via `getattr(obj, <expr>)` where the second
  argument is not a constant string — a common obfuscation pattern.

Design notes:

- Parse failures are silently ignored. We don't want a malformed `.py` file
  to abort a whole scan; the file simply contributes no Layer 3 findings.
  Layer 2 will still pattern-match on its raw contents.
- The visitor never executes code. AST parsing is structural only.
- The detector logic intentionally errs toward *false positives* over
  *false negatives*. Capa 3 is meant to surface things for review; the
  scanner's verdict aggregator (in `report.py`) decides the final severity.
"""

from __future__ import annotations

import ast
import time
from pathlib import Path
from typing import ClassVar

from nodesafe.layers.base import Layer, LayerResult, NodeContext
from nodesafe.report import Finding, Severity


class AstLayer(Layer):
    """Structural AST analysis of Python source files."""

    id = "L3"
    name = "AST analysis"
    weight = 0.85
    cost_estimate_ms = 25

    def scan(self, context: NodeContext) -> LayerResult:
        start = time.perf_counter()
        findings: list[Finding] = []

        for path in context.py_files:
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            try:
                tree = ast.parse(source, filename=str(path))
            except SyntaxError:
                # Unparseable file — skip silently. Layer 2 still scans it.
                continue

            visitor = _SecurityVisitor(path, context.root, source)
            visitor.visit(tree)
            findings.extend(visitor.findings)

        duration_ms = int((time.perf_counter() - start) * 1000)
        return LayerResult(layer_id=self.id, findings=findings, duration_ms=duration_ms)


# Names that, when *called directly* (not just imported), are dangerous.
_DANGEROUS_BUILTIN_CALLS: dict[str, tuple[str, Severity, str | None]] = {
    "eval": ("code_execution", Severity.HIGH, "CWE-95"),
    "exec": ("code_execution", Severity.HIGH, "CWE-95"),
    "compile": ("code_execution", Severity.MEDIUM, "CWE-95"),
    "__import__": ("dynamic_import", Severity.MEDIUM, "CWE-470"),
}

# Qualified function references (module.attr) that are dangerous when called.
_DANGEROUS_QUALIFIED_CALLS: dict[str, tuple[str, Severity, str | None]] = {
    # Shell execution
    "subprocess.run": ("shell_execution", Severity.HIGH, "CWE-78"),
    "subprocess.Popen": ("shell_execution", Severity.HIGH, "CWE-78"),
    "subprocess.call": ("shell_execution", Severity.HIGH, "CWE-78"),
    "subprocess.check_call": ("shell_execution", Severity.HIGH, "CWE-78"),
    "subprocess.check_output": ("shell_execution", Severity.HIGH, "CWE-78"),
    "subprocess.getoutput": ("shell_execution", Severity.HIGH, "CWE-78"),
    "os.system": ("shell_execution", Severity.HIGH, "CWE-78"),
    "os.popen": ("shell_execution", Severity.HIGH, "CWE-78"),
    "os.execv": ("shell_execution", Severity.HIGH, "CWE-78"),
    "os.execvp": ("shell_execution", Severity.HIGH, "CWE-78"),
    "os.execve": ("shell_execution", Severity.HIGH, "CWE-78"),
    "os.spawnv": ("shell_execution", Severity.HIGH, "CWE-78"),
    "pty.spawn": ("shell_execution", Severity.HIGH, "CWE-78"),
    # Deserialization
    "pickle.loads": ("unsafe_deserialization", Severity.HIGH, "CWE-502"),
    "pickle.load": ("unsafe_deserialization", Severity.HIGH, "CWE-502"),
    "cloudpickle.loads": ("unsafe_deserialization", Severity.HIGH, "CWE-502"),
    "dill.loads": ("unsafe_deserialization", Severity.HIGH, "CWE-502"),
    "marshal.loads": ("unsafe_deserialization", Severity.HIGH, "CWE-502"),
    # Decoders commonly used in obfuscation chains
    "base64.b64decode": ("encoded_payload", Severity.MEDIUM, "CWE-506"),
    "base64.decodebytes": ("encoded_payload", Severity.MEDIUM, "CWE-506"),
    "base64.urlsafe_b64decode": ("encoded_payload", Severity.MEDIUM, "CWE-506"),
    "codecs.decode": ("encoded_payload", Severity.LOW, "CWE-506"),
    "binascii.unhexlify": ("encoded_payload", Severity.LOW, "CWE-506"),
}

# Modules that, when imported by a third-party node, deserve attention.
# Not necessarily malicious — many legitimate uses exist — but worth surfacing.
_SUSPICIOUS_IMPORTS: dict[str, tuple[str, Severity]] = {
    "pickle": ("unsafe_deserialization", Severity.MEDIUM),
    "marshal": ("unsafe_deserialization", Severity.MEDIUM),
    "cloudpickle": ("unsafe_deserialization", Severity.MEDIUM),
    "dill": ("unsafe_deserialization", Severity.MEDIUM),
    "ctypes": ("native_invocation", Severity.MEDIUM),
    "_ctypes": ("native_invocation", Severity.MEDIUM),
    "winreg": ("system_persistence", Severity.MEDIUM),
}


class _SecurityVisitor(ast.NodeVisitor):
    """Walks an AST and records suspicious constructs as Findings."""

    # Class-level counter that guarantees globally unique finding IDs
    # across visits (one visitor per file, but the counter is shared so
    # ids remain stable in the aggregate report).
    _counter: ClassVar[int] = 0

    def __init__(self, file_path: Path, root: Path, source: str) -> None:
        self._file = file_path
        self._root = root
        self._source_lines = source.splitlines()
        self.findings: list[Finding] = []

    # --- helpers ---------------------------------------------------------

    def _next_id(self) -> str:
        _SecurityVisitor._counter += 1
        return f"L3-ast-{_SecurityVisitor._counter:04d}"

    def _snippet(self, line: int) -> str:
        idx = line - 1
        if 0 <= idx < len(self._source_lines):
            line_text = self._source_lines[idx].strip()
            return line_text if len(line_text) <= 200 else line_text[:197] + "..."
        return ""

    def _rel_file(self) -> str:
        try:
            return str(self._file.relative_to(self._root))
        except ValueError:
            return str(self._file)

    def _qualified_name(self, node: ast.AST) -> str | None:
        """Resolve `subprocess.run` from an Attribute chain. Returns None
        if the chain isn't a simple module.attr lookup."""
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
        return None

    def _emit(
        self,
        node: ast.AST,
        *,
        category: str,
        severity: Severity,
        title: str,
        explanation: str,
        cwe: str | None = None,
    ) -> None:
        line = getattr(node, "lineno", 1)
        self.findings.append(
            Finding(
                id=self._next_id(),
                layer="L3",
                severity=severity,
                category=category,
                title=title,
                file=self._rel_file(),
                line=line,
                snippet=self._snippet(line),
                explanation=explanation,
                cwe=cwe,
            )
        )

    # --- visit_* methods -------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # Case 1: builtin direct call — eval/exec/compile/__import__
        if isinstance(func, ast.Name) and func.id in _DANGEROUS_BUILTIN_CALLS:
            category, severity, cwe = _DANGEROUS_BUILTIN_CALLS[func.id]
            # Escalate to CRITICAL if the argument is itself a decoder call,
            # e.g. `exec(base64.b64decode(...))` — the obfuscated-loader pattern.
            escalated = severity
            extra_note = ""
            if func.id in {"eval", "exec"} and node.args and self._is_decoder_call(node.args[0]):
                escalated = Severity.CRITICAL
                extra_note = (
                    " This call decodes a payload at runtime and then executes it — "
                    "the classic obfuscated loader pattern."
                )
            self._emit(
                node,
                category=category,
                severity=escalated,
                title=f"Direct call to `{func.id}()`",
                explanation=(
                    f"`{func.id}()` allows running arbitrary Python at runtime. "
                    f"It is rarely needed in a plugin / node implementation and is "
                    f"a frequent component of malicious payloads.{extra_note}"
                ),
                cwe=cwe,
            )

        # Case 2: qualified call — module.attr(...)
        if isinstance(func, ast.Attribute):
            qualified = self._qualified_name(func)
            if qualified and qualified in _DANGEROUS_QUALIFIED_CALLS:
                category, severity, cwe = _DANGEROUS_QUALIFIED_CALLS[qualified]
                # Escalate subprocess calls with `shell=True`.
                escalated = severity
                extra_note = ""
                if qualified.startswith("subprocess.") and self._has_shell_true(node):
                    escalated = Severity.CRITICAL
                    extra_note = (
                        " `shell=True` makes the call vulnerable to command injection "
                        "and is rarely necessary."
                    )
                self._emit(
                    node,
                    category=category,
                    severity=escalated,
                    title=f"Call to `{qualified}()`",
                    explanation=(
                        f"`{qualified}` is a frequent ingredient in malicious "
                        f"plugins. Review whether this call is essential for the "
                        f"node's stated purpose.{extra_note}"
                    ),
                    cwe=cwe,
                )

        # Case 3: getattr(obj, <expr>) with a non-constant attribute name —
        # a common obfuscation pattern.
        if (
            isinstance(func, ast.Name)
            and func.id == "getattr"
            and len(node.args) >= 2
            and not isinstance(node.args[1], ast.Constant)
        ):
            self._emit(
                node,
                category="dynamic_attribute_access",
                severity=Severity.MEDIUM,
                title="Dynamic `getattr` with non-literal attribute name",
                explanation=(
                    "Building the attribute name at runtime is sometimes legitimate "
                    "but is a common obfuscation technique used to evade static "
                    "review. Verify that the constructed name is not derived from "
                    "untrusted input or a decoded payload."
                ),
                cwe="CWE-470",
            )

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            mod = alias.name.split(".")[0]
            if mod in _SUSPICIOUS_IMPORTS:
                category, severity = _SUSPICIOUS_IMPORTS[mod]
                self._emit(
                    node,
                    category=category,
                    severity=severity,
                    title=f"Suspicious import: `{alias.name}`",
                    explanation=(
                        f"`{alias.name}` is occasionally needed but is also a "
                        f"common building block of malicious plugins. Confirm "
                        f"the import is justified by the node's purpose."
                    ),
                    cwe=None,
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = (node.module or "").split(".")[0]
        if mod in _SUSPICIOUS_IMPORTS:
            category, severity = _SUSPICIOUS_IMPORTS[mod]
            self._emit(
                node,
                category=category,
                severity=severity,
                title=f"Suspicious import: `from {node.module} import ...`",
                explanation=(
                    f"`{node.module}` is occasionally needed but is also a common "
                    f"building block of malicious plugins. Confirm the import is "
                    f"justified by the node's purpose."
                ),
                cwe=None,
            )
        self.generic_visit(node)

    # --- internals -------------------------------------------------------

    @staticmethod
    def _is_decoder_call(node: ast.AST) -> bool:
        """True if `node` is a Call to a known decoding function.

        Catches things like `base64.b64decode(...)`, `codecs.decode(...)`,
        `binascii.unhexlify(...)`, even when nested inside `.decode()` calls.
        """
        # Peel off `.decode()` if present: `b64decode(x).decode()` is still a
        # decoder chain.
        cur: ast.AST = node
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
                name = ".".join(reversed(parts))
                return name in {
                    "base64.b64decode",
                    "base64.decodebytes",
                    "base64.urlsafe_b64decode",
                    "codecs.decode",
                    "binascii.unhexlify",
                    "binascii.a2b_hex",
                    "bytes.fromhex",
                }
        if isinstance(cur.func, ast.Name) and cur.func.id == "bytes":
            # `bytes.fromhex(...)` parses as `Attribute(bytes, fromhex)`; this
            # branch covers exotic `bytes(...)` constructor usage.
            return False
        return False

    @staticmethod
    def _has_shell_true(node: ast.Call) -> bool:
        """Whether the Call has a keyword `shell=True`."""
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False
