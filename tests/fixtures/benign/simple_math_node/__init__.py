"""Benign test fixture: a trivial ComfyUI-style node that does math.

This file is intentionally simple and contains no patterns that should
trigger any nodesafe layer. Used as the negative control in detection tests.
"""

from .nodes import SimpleAddNode

NODE_CLASS_MAPPINGS = {"SimpleAdd": SimpleAddNode}
NODE_DISPLAY_NAME_MAPPINGS = {"SimpleAdd": "Simple Add"}
