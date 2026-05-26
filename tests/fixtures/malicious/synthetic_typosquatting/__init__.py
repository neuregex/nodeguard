"""Synthetic typosquatting fixture.

This fixture exists only to feed Layer 4 a `requirements.txt` and
`pyproject.toml` packed with deliberately misspelled package names. The
package itself does nothing — Layer 4 ignores the .py content and only
reads the manifests next to it.
"""

NODE_CLASS_MAPPINGS = {}
NODE_DISPLAY_NAME_MAPPINGS = {}

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS"]
