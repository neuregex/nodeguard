"""Workflow data model.

ComfyUI workflows come in two shapes that matter to us:

1. The "workflow" form: the UI representation, with `nodes` having
   `type`, `widgets_values`, and visual metadata. This is what gets
   embedded in PNG `tEXt` chunks as `workflow`.

2. The "prompt" form: the execution graph, keyed by string node IDs,
   each entry having `class_type` and `inputs`. This is what ComfyUI
   sends to its API and what gets embedded as `prompt` in PNGs.

We accept either by normalizing into the same `Workflow` shape: a list
of `WorkflowNode`s with `id`, `type`, `widget_values`, `inputs`. The
analyzers then iterate over `widget_values` and `inputs` without
caring which form the source file used.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WorkflowNode:
    """A single node from a workflow."""

    id: str  # always normalized to string
    type: str  # the custom_node class name, e.g. "ExecutePython" or "CLIPTextEncode"
    widget_values: list[Any] = field(default_factory=list)
    inputs: dict[str, Any] = field(default_factory=dict)
    # The raw underlying dict in case an analyzer wants more than what's
    # normalized above.
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Workflow:
    """A parsed workflow."""

    source: str  # path or descriptor, used only for reporting
    form: str  # "ui" or "prompt"
    nodes: list[WorkflowNode] = field(default_factory=list)
    version: str | None = None  # version field if present (UI form has "version": 0.4 etc.)

    def iter_string_widgets(self) -> list[tuple[str, str, int, str]]:
        """Yield (node_id, node_type, widget_index, value) for every string widget."""
        out: list[tuple[str, str, int, str]] = []
        for node in self.nodes:
            for idx, value in enumerate(node.widget_values):
                if isinstance(value, str):
                    out.append((node.id, node.type, idx, value))
            # `inputs` may also carry string values (in prompt form).
            for _key, value in node.inputs.items():
                if isinstance(value, str):
                    out.append((node.id, node.type, -1, value))
                    # widget_index = -1 marks "from inputs dict, not widgets_values"
        return out

    def node_types(self) -> set[str]:
        """Set of distinct node type names referenced by this workflow."""
        return {n.type for n in self.nodes}
