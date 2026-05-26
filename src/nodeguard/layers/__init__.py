"""Layer implementations for the scanning pipeline.

Each layer is a self-contained detector with a `scan` method that consumes a
NodeContext and returns a list of Findings. Layers are designed to be
composable, replaceable, and independently testable.
"""

from nodeguard.layers.base import Layer, LayerResult, NodeContext
from nodeguard.layers.layer_00_hash import HashLayer
from nodeguard.layers.layer_01_bloom_url import UrlLayer
from nodeguard.layers.layer_02_patterns import PatternLayer
from nodeguard.layers.layer_03_ast import AstLayer

__all__ = [
    "AstLayer",
    "HashLayer",
    "Layer",
    "LayerResult",
    "NodeContext",
    "PatternLayer",
    "UrlLayer",
]


def default_layers(layer_ids: list[str] | None = None) -> list[Layer]:
    """Build the default layer set for the configured IDs.

    Args:
        layer_ids: List of string IDs like ["0", "1", "2", "3"]. If None,
            returns the layers available in the current minor version.

    Returns:
        Ordered list of Layer instances.
    """
    registry = {
        "0": HashLayer,
        "1": UrlLayer,
        "2": PatternLayer,
        "3": AstLayer,
    }
    if layer_ids is None:
        layer_ids = ["0", "1", "2", "3"]
    return [registry[lid]() for lid in layer_ids if lid in registry]
