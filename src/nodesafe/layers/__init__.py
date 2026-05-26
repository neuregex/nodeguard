"""Layer implementations for the scanning pipeline.

Each layer is a self-contained detector with a `scan` method that consumes a
NodeContext and returns a list of Findings. Layers are designed to be
composable, replaceable, and independently testable.
"""

from nodesafe.layers.base import Layer, LayerResult, NodeContext
from nodesafe.layers.layer_00_hash import HashLayer
from nodesafe.layers.layer_01_bloom_url import UrlLayer
from nodesafe.layers.layer_02_patterns import PatternLayer
from nodesafe.layers.layer_03_ast import AstLayer
from nodesafe.layers.layer_04_typosquatting import TyposquattingLayer
from nodesafe.layers.layer_05_heuristic import HeuristicLayer

__all__ = [
    "AstLayer",
    "HashLayer",
    "HeuristicLayer",
    "Layer",
    "LayerResult",
    "NodeContext",
    "PatternLayer",
    "TyposquattingLayer",
    "UrlLayer",
]


def default_layers(layer_ids: list[str] | None = None) -> list[Layer]:
    """Build the default layer set for the configured IDs.

    Args:
        layer_ids: List of string IDs like ["0", "1", "2", "3", "4"]. If
            None, returns the layers available in the current minor version.

    Returns:
        Ordered list of Layer instances.
    """
    registry = {
        "0": HashLayer,
        "1": UrlLayer,
        "2": PatternLayer,
        "3": AstLayer,
        "4": TyposquattingLayer,
        "5": HeuristicLayer,
    }
    if layer_ids is None:
        layer_ids = ["0", "1", "2", "3", "4", "5"]
    return [registry[lid]() for lid in layer_ids if lid in registry]
