"""TEST FIXTURE — SYNTHETIC PATTERN CHAIN. NOT REAL MALWARE.

This file exists solely to exercise Layer 2 (Aho-Corasick patterns). It
contains literal strings that appear in `signatures/patterns.json` across
several categories so the layer's detection logic can be exercised
end-to-end in tests.

Patterns included (each is inert — the strings live inside other strings or
unreached branches, never executed):

  - `code_execution`:   reference to eval and exec in a string
  - `shell_execution`:  reference to subprocess.run with shell=True
  - `encoded_payload`:  base64.b64decode mention
  - `exfiltration_channel`:  fake Discord webhook URL
  - `wallet_paths`:     wallet.dat path

If you are reading this in a real custom_node you installed: that node is a
TEST FIXTURE from the nodeguard repo and should not be in your ComfyUI
installation. Remove it.
"""

# All references below are intentionally embedded inside strings so the
# fixture is non-functional at import time. Static analysis still picks them
# up — which is exactly the point of Layer 2.

_INERT_CODE = "literal mentions like eval( and exec( appear in obfuscated code"
_INERT_SUBPROCESS = "subprocess.run could be used with shell=True (do not)"
_INERT_DECODE = "base64.b64decode is a common obfuscation primitive"
_INERT_WEBHOOK = "https://discord.com/api/webhooks/000000000000000000/TEST-FIXTURE"
_INERT_WALLET = "wallet.dat is the legacy Bitcoin wallet file name"


def innocuous_function():
    """A function that does nothing real, present so the file isn't empty."""
    return (
        _INERT_CODE,
        _INERT_SUBPROCESS,
        _INERT_DECODE,
        _INERT_WEBHOOK,
        _INERT_WALLET,
    )
