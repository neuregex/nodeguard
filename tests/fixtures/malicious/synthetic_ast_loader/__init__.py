"""TEST FIXTURE — SYNTHETIC AST LOADER PATTERN. NOT REAL MALWARE.

The dangerous-looking code below lives inside `if False:` blocks or inside
functions that are NEVER called, so importing this module is inert. Layer 3
analyzes the AST — the unreachable code is still parsed and detected, which
is exactly what we want to verify.

Patterns exercised in this fixture:

- `eval(...)` direct call                    → code_execution
- `exec(base64.b64decode(...))` chain        → code_execution CRITICAL (decoder + exec)
- `subprocess.run(..., shell=True)`          → shell_execution CRITICAL (shell=True)
- `os.system(...)`                           → shell_execution
- `pickle.loads(...)`                        → unsafe_deserialization
- `import pickle`                            → suspicious_import
- `from marshal import loads`                → suspicious_import
- `getattr(obj, name_built_at_runtime)`      → dynamic_attribute_access

If you are reading this in a real custom_node you installed: that node is a
TEST FIXTURE from the nodeguard repo and should not be in your ComfyUI
installation. Remove it.
"""

# Suspicious imports — flagged by AST visit_Import / visit_ImportFrom.
import base64  # noqa: F401
import pickle  # noqa: F401  (deliberately unused in this fixture)
from marshal import loads as _unused_marshal_loads  # noqa: F401

# The functions below are NEVER called. They exist only so the AST contains
# the constructs Layer 3 must detect.


def _never_called_eval_chain() -> None:
    if False:
        # exec(base64.b64decode(...)) — the obfuscated loader chain.
        # Layer 3 should escalate this to CRITICAL.
        exec(base64.b64decode(b"cGFzcw==").decode())  # noqa: S102


def _never_called_eval_direct() -> None:
    if False:
        # Plain eval — code_execution HIGH.
        eval("1 + 1")  # noqa: S307


def _never_called_subprocess_shell() -> None:
    if False:
        import subprocess  # noqa: F401

        # subprocess.run with shell=True — escalates to CRITICAL.
        subprocess.run("ls -la", shell=True, check=False)  # noqa: S602


def _never_called_os_system() -> None:
    if False:
        import os

        # os.system — shell_execution HIGH.
        os.system("ls -la")  # noqa: S605


def _never_called_pickle_loads() -> None:
    if False:
        # pickle.loads on untrusted data — unsafe_deserialization HIGH.
        pickle.loads(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00.")  # noqa: S301


def _never_called_dynamic_getattr() -> None:
    if False:
        target = object()
        attr_name = "x" + "y"
        # getattr with a non-literal second arg — dynamic_attribute_access MEDIUM.
        _ = getattr(target, attr_name, None)
