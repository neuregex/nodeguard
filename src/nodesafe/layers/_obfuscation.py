"""Obfuscation detectors for Layer 3.

These checks complement the AST analysis in `layer_03_ast.py`. They look
for the *shape* of code that has been deliberately disguised, regardless
of whether the disguised payload is doing something harmful in particular.
Obfuscation in a third-party plugin is itself a smell: legitimate code
rarely builds the string ``"eval"`` from individual ``chr()`` calls.

The detectors are scoped narrowly so each one is independently testable:

- ``find_chr_chain_keywords``: ``chr(N) + chr(N) + chr(N)...`` that builds
  a dangerous keyword (``eval``, ``exec``, ``import``, ``system``, etc.).
- ``find_string_concat_keywords``: ``"e" + "v" + "a" + "l"`` style.
- ``find_high_entropy_strings``: long string literals whose Shannon
  entropy is above the threshold for natural-language / source text.
- ``find_suspicious_identifiers``: variables and function names that look
  like minified output (``_a``, ``__``, ``_o0o``).
- ``find_mixed_script_identifiers``: identifiers that mix Unicode scripts
  (Cyrillic ``е`` inside an otherwise-Latin word, a classic homoglyph
  attack).
- ``find_nested_decoder_chain``: nested calls of two or more decoders
  in a single expression, e.g. ``zlib.decompress(b64decode(...))``.
- ``compute_whitespace_ratio``: a file-level heuristic returning the
  ratio of whitespace to non-whitespace. Code minified to one line has
  a very low ratio.

Each function returns a list of (line_number, snippet, message) tuples
or, in the case of ``compute_whitespace_ratio``, a single float in
[0, 1]. The L3 layer wraps these into Finding objects with proper
severities.
"""

from __future__ import annotations

import ast
import math
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable

# --- thresholds ------------------------------------------------------

# String literals at or above this entropy and length are considered
# "high entropy" (potential encoded payloads).
HIGH_ENTROPY_MIN_LEN = 40
HIGH_ENTROPY_THRESHOLD = 4.5

# Identifier-name heuristics.
SUSPICIOUS_IDENT_MAX_LEN = 3
SUSPICIOUS_IDENT_NO_VOWEL_MAX_LEN = 4

# Dangerous keywords we flag when reconstructed via char-code or split-concat.
_DANGEROUS_KEYWORDS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "import",
        "system",
        "popen",
        "spawn",
        "subprocess",
        "pickle",
        "marshal",
        "loads",
    }
)

# Names of decoder functions (qualified or last-component) used to detect
# chains.
_DECODER_NAMES = frozenset(
    {
        "b64decode",
        "decodebytes",
        "urlsafe_b64decode",
        "decode",
        "unhexlify",
        "a2b_hex",
        "fromhex",
        "decompress",  # zlib / lzma
        "loads",  # pickle / marshal / json (last one not dangerous but ambiguous)
    }
)


# --- utilities -------------------------------------------------------


def shannon_entropy(s: str) -> float:
    """Shannon entropy of `s` in bits per character. Empty string -> 0.0."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c)


def compute_whitespace_ratio(source: str) -> float:
    """Ratio of whitespace characters to total characters. 1.0 = all spaces."""
    if not source:
        return 1.0
    ws = sum(1 for c in source if c.isspace())
    return ws / len(source)


def _is_low_vowel(name: str) -> bool:
    return not any(v in name.lower() for v in "aeiouy")


def _identifier_scripts(name: str) -> set[str]:
    """Set of Unicode script names for the letters in `name`."""
    scripts: set[str] = set()
    for ch in name:
        if not ch.isalpha():
            continue
        try:
            full = unicodedata.name(ch, "")
        except ValueError:
            continue
        # First word of the Unicode name is typically the script
        # (e.g. "LATIN", "CYRILLIC", "GREEK").
        if full:
            scripts.add(full.split()[0])
    return scripts


# Characters that are commonly used in obfuscated identifiers because
# they look like digits or other letters: o/0, l/1/I, etc.
_CONFUSABLE_CHARS = frozenset("ol01iIO")


def is_suspicious_identifier(name: str) -> bool:
    """Names that look like minified / obfuscated output.

    Catches three families:
    - All-underscore names like ``__``, ``___``.
    - Underscore-prefixed short consonant runs: ``_qq``, ``_zz``, ``_xy``.
      The underscore prefix is what differentiates them from common
      abbreviations like ``cmd``, ``tmp``, ``ctx`` which we leave alone.
    - Confusable-character salads like ``_o0o``, ``_l1l``, ``_1lI``.
    """
    if not name:
        return False
    # All underscores.
    if all(c == "_" for c in name):
        return True
    stripped = name.lstrip("_")
    if not stripped:
        return True

    # Confusable-character salads of length 2-5: every character is in the
    # confusable set (`o`, `l`, `0`, `1`, `i`, `I`, `O`).
    if 2 <= len(stripped) <= 5 and all(c in _CONFUSABLE_CHARS for c in stripped):
        return True

    # Underscore-prefixed + short + no vowel. The underscore prefix
    # distinguishes deliberate obfuscation (`_qq`, `_zz`) from common short
    # abbreviations (`cmd`, `tmp`, `ctx`) which are not flagged.
    return bool(
        name.startswith("_")
        and 2 <= len(stripped) <= SUSPICIOUS_IDENT_MAX_LEN
        and _is_low_vowel(stripped)
    )


def has_mixed_scripts(name: str) -> bool:
    """True if the identifier mixes Unicode scripts (homoglyph attack)."""
    scripts = _identifier_scripts(name)
    # Allow COMMON (digits, underscores stripped already) but require at most
    # one alphabetic script.
    alpha_scripts = {s for s in scripts if s not in {"COMMON", "DIGIT", "LATIN"}}
    if not alpha_scripts:
        return False
    # Any mix of Latin + non-Latin alphabetic script is suspicious.
    return "LATIN" in scripts and bool(alpha_scripts)


# --- AST-based detectors ---------------------------------------------


def _collect_chr_chain(node: ast.AST) -> list[int] | None:
    """If `node` is a chain of `chr(N) + chr(N) + ...`, return the integer codes.

    Returns None if the chain breaks at any point.
    """
    codes: list[int] = []
    stack: list[ast.AST] = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            stack.append(current.right)
            stack.append(current.left)
            continue
        if (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Name)
            and current.func.id == "chr"
            and len(current.args) == 1
            and isinstance(current.args[0], ast.Constant)
            and isinstance(current.args[0].value, int)
        ):
            codes.append(current.args[0].value)
            continue
        return None
    return codes


def _collect_string_concat(node: ast.AST) -> list[str] | None:
    """If `node` is ``"x" + "y" + "z"``, return the literal pieces; else None."""
    parts: list[str] = []
    stack: list[ast.AST] = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            stack.append(current.right)
            stack.append(current.left)
            continue
        if isinstance(current, ast.Constant) and isinstance(current.value, str):
            parts.append(current.value)
            continue
        return None
    return parts


def _is_keyword(text: str) -> bool:
    return text in _DANGEROUS_KEYWORDS


def find_chr_chain_keywords(tree: ast.AST) -> list[tuple[int, str, str]]:
    """Find ``chr(N)+chr(N)+...`` chains that spell a dangerous keyword."""
    findings: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)):
            continue
        codes = _collect_chr_chain(node)
        if codes is None or len(codes) < 3:
            continue
        try:
            text = "".join(chr(c) for c in codes)
        except (ValueError, OverflowError):
            continue
        if _is_keyword(text):
            findings.append(
                (
                    getattr(node, "lineno", 1),
                    f"chr-chain spelling {text!r}",
                    f"Builds the keyword {text!r} from {len(codes)} chr() calls.",
                )
            )
    return findings


def find_string_concat_keywords(tree: ast.AST) -> list[tuple[int, str, str]]:
    """Find ``"e"+"v"+"a"+"l"`` style concatenations spelling a keyword."""
    findings: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)):
            continue
        parts = _collect_string_concat(node)
        if parts is None or len(parts) < 3:
            continue
        joined = "".join(parts)
        if _is_keyword(joined):
            findings.append(
                (
                    getattr(node, "lineno", 1),
                    f"split-concat spelling {joined!r}",
                    f"Builds the keyword {joined!r} from {len(parts)} string pieces.",
                )
            )
    return findings


def find_high_entropy_strings(tree: ast.AST) -> list[tuple[int, str, str]]:
    """Find string literals long enough and entropic enough to be encoded payloads."""
    findings: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        s = node.value
        if len(s) < HIGH_ENTROPY_MIN_LEN:
            continue
        ent = shannon_entropy(s)
        if ent >= HIGH_ENTROPY_THRESHOLD:
            preview = s[:30] + "..." if len(s) > 30 else s
            findings.append(
                (
                    getattr(node, "lineno", 1),
                    f"high-entropy literal ({len(s)} chars, {ent:.2f} bits/char)",
                    (
                        f"String literal of length {len(s)} has Shannon entropy "
                        f"{ent:.2f} bits/char, well above the natural-text baseline. "
                        f"Likely an encoded payload. Preview: {preview!r}"
                    ),
                )
            )
    return findings


def _iter_defined_names(tree: ast.AST) -> Iterable[tuple[str, int]]:
    """Yield (name, lineno) for definitions and assignment targets in `tree`."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            yield node.name, getattr(node, "lineno", 1)
            for arg in node.args.args + node.args.kwonlyargs + node.args.posonlyargs:
                yield arg.arg, getattr(arg, "lineno", node.lineno)
        elif isinstance(node, ast.ClassDef):
            yield node.name, getattr(node, "lineno", 1)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    yield target.id, getattr(node, "lineno", 1)


def find_suspicious_identifiers(tree: ast.AST) -> list[tuple[int, str, str]]:
    """Find identifiers that look like minified / obfuscated names."""
    findings: list[tuple[int, str, str]] = []
    seen: set[tuple[str, int]] = set()
    for name, line in _iter_defined_names(tree):
        if (name, line) in seen:
            continue
        seen.add((name, line))
        if is_suspicious_identifier(name):
            findings.append(
                (
                    line,
                    f"suspicious identifier {name!r}",
                    (
                        f"Identifier {name!r} matches the shape of minified or "
                        "obfuscated names. Legitimate code uses descriptive names."
                    ),
                )
            )
    return findings


def find_mixed_script_identifiers(tree: ast.AST) -> list[tuple[int, str, str]]:
    """Find identifiers that mix Unicode scripts (homoglyph attack)."""
    findings: list[tuple[int, str, str]] = []
    seen: set[tuple[str, int]] = set()
    for name, line in _iter_defined_names(tree):
        if (name, line) in seen:
            continue
        seen.add((name, line))
        if has_mixed_scripts(name):
            scripts = _identifier_scripts(name)
            findings.append(
                (
                    line,
                    f"mixed-script identifier {name!r}",
                    (
                        f"Identifier {name!r} mixes Unicode scripts {sorted(scripts)}. "
                        "Classic homoglyph attack: a non-Latin character that looks "
                        "Latin (e.g. Cyrillic 'е' U+0435 vs Latin 'e' U+0065)."
                    ),
                )
            )
    return findings


def _qualified_name(node: ast.AST) -> str | None:
    """Resolve `a.b.c` Attribute chains down to their last component."""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def find_nested_decoder_chain(tree: ast.AST) -> list[tuple[int, str, str]]:
    """Find nested calls of two or more known decoder functions."""
    findings: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        outer_name = _qualified_name(node.func)
        if outer_name not in _DECODER_NAMES:
            continue
        # Look at the first positional argument for a nested decoder call.
        if not node.args:
            continue
        inner = node.args[0]
        # Peel string `.encode()` / `.decode()` wrappers.
        while (
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Attribute)
            and inner.func.attr in {"encode", "decode"}
        ):
            inner = inner.func.value
        if not isinstance(inner, ast.Call):
            continue
        inner_name = _qualified_name(inner.func)
        if inner_name and inner_name in _DECODER_NAMES and inner_name != outer_name:
            findings.append(
                (
                    getattr(node, "lineno", 1),
                    f"decoder chain {inner_name} -> {outer_name}",
                    (
                        f"Nested decoder chain detected: {inner_name}(...) "
                        f"passed through {outer_name}(...). Each layer of "
                        "encoding makes the payload harder to inspect; a chain "
                        "is rarely innocent."
                    ),
                )
            )
    return findings


# --- module-level orchestration --------------------------------------


# Catalog of detectors with their default severity tag and category.
# The L3 layer maps these into Finding severities.
OBFUSCATION_DETECTORS: tuple[tuple[str, str, str, ObfuscationFn], ...] = (
    ("code_obfuscation_chr_chain", "critical", "CWE-506", find_chr_chain_keywords),
    ("code_obfuscation_split_concat", "high", "CWE-506", find_string_concat_keywords),
    ("code_obfuscation_high_entropy", "medium", "CWE-506", find_high_entropy_strings),
    ("code_obfuscation_suspicious_ident", "low", "CWE-1109", find_suspicious_identifiers),
    ("code_obfuscation_mixed_script", "critical", "CWE-1007", find_mixed_script_identifiers),
    ("code_obfuscation_decoder_chain", "high", "CWE-506", find_nested_decoder_chain),
)


# Type alias for static analyzers.
from collections.abc import Callable  # noqa: E402

ObfuscationFn = Callable[[ast.AST], list[tuple[int, str, str]]]


# Re-export the regex used to test text for very long base64-looking runs.
# Layer 5 already uses a similar regex; we keep an independent one here so
# the obfuscation module can be lifted out without dragging L5 along.
LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/=_-]{120,}")
