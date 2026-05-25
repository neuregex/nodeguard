"""Layer implementations for the scanning pipeline.

Each layer is a self-contained detector with a `scan` method that consumes a
NodeContext and returns a list of Findings. Layers are designed to be
composable, replaceable, and independently testable.
"""

from nodeguard.layers.base import Layer, LayerResult, NodeContext
from nodeguard.layers.layer_00_hash import HashLayer
from nodeguard.layers.layer_01_bloom_url import UrlLayer

__all__ = ["HashLayer", "Layer", "LayerResult", "NodeContext", "UrlLayer"]


def default_layers(layer_ids: list[str] | None = None) -> list[Layer]:
    """Build the default layer set for the configured IDs.

    Args:
        layer_ids: List of string IDs like ["0", "1"]. If None, returns Capas 0-1 (MVP).

    Returns:
        Ordered list of Layer instances.
    """
    registry = {
        "0": HashLayer,
        "1": UrlLayer,
    }
    if layer_ids is None:
        layer_ids = ["0", "1"]
    return [registry[lid]() for lid in layer_ids if lid in registry]
