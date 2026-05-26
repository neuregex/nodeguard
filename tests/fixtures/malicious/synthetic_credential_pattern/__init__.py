"""TEST FIXTURE — SYNTHETIC PATTERN. NOT REAL MALWARE.

This file simulates surface-level traits of a malicious node for the sole
purpose of exercising nodesafe's detection layers in tests. It does not
exfiltrate, execute payloads, or perform any harmful action. The patterns
below are inert by design.

What this fixture exercises:
  - Layer 0: its file hash is added to the test signature DB by conftest.py.
  - Layer 1: contains a URL string that matches the test malicious-URL list.

If you are reading this file in a real custom_node you installed: that node
is a TEST FIXTURE from the nodesafe repository and should not be in your
ComfyUI installation. Remove it.
"""

# This URL is in the test malicious_urls.txt — Layer 1 must detect it.
SUSPICIOUS_URL = "https://malicious-test-c2.example.invalid/webhook"


def innocuous_function():
    """A function that does nothing. Present only so the file has content."""
    return None
