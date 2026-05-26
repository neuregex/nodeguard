# Changelog

All notable changes to nodeguard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Layer 3 (AST analysis):** stdlib-based `ast.NodeVisitor` that finds
  structural risk: direct `eval`/`exec`/`compile`/`__import__` calls,
  qualified calls to dangerous functions (`subprocess.*`, `os.system`,
  `pickle.loads`, `marshal.loads`, base64 decoders, etc.), `shell=True`
  in subprocess calls (escalated to CRITICAL), the `exec(b64decode(...))`
  obfuscated-loader chain (escalated to CRITICAL), suspicious imports
  (`pickle`, `marshal`, `ctypes`, `winreg`), and dynamic `getattr` with
  non-literal attribute names. Unparseable Python files are skipped
  silently. New `default_layers` is `"0,1,2,3"`.
- `tests/fixtures/malicious/synthetic_ast_loader/` exercising all the
  AST detections in inert `if False:` blocks.
- `tests/test_layer_03_ast.py` — 8 tests covering metadata, benign
  pass-through, multi-category detection, CRITICAL escalation for
  obfuscated loaders + shell=True, snippet/line presence, syntax-error
  graceful handling, and false-positive avoidance for static `getattr`.

- **Layer 2 (Aho-Corasick patterns):** multi-pattern matching ov