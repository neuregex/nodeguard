"""Abstract base for all detection layers.

Each layer takes a NodeContext (a snapshot of the target directory's contents)
and produces a LayerResult with findings. The Scanner orchestrates layers
and aggregates their results.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from nodeguard.report import Finding


@dataclass
class NodeContext:
    """A snapshot of the target directory passed to each layer.

    Computed once by the Scanner and reused across layers. This avoids each
    layer re-walking the filesystem.
    """

    root: Path
    files: list[Path] = field(default_factory=list)
    py_files: list[Path] = field(default_factory=list)
    text_files: list[Path] = field(default_factory=list)

    @classmethod
    def from_directory(cls, root: Path) -> NodeContext:
        """Build a NodeContext by walking the directory."""
        root = root.resolve()
        files: list[Path] = []
        py_files: list[Path] = []
        text_files: list[Path] = []

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(
                part in {".git", "__pycache__", ".venv", "venv", "node_modules"}
                for part in path.parts
            ):
                continue
            files.append(path)
            if path.suffix == ".py":
                py_files.append(path)
            if path.suffix in {".py", ".txt", ".toml", ".md", ".yaml", ".yml", ".json"}:
                text_files.append(path)

        return cls(root=root, files=files, py_files=py_files, text_files=text_files)


@dataclass
class LayerResult:
    """Output of running a single layer."""

    layer_id: str
    findings: list[Finding] = field(default_factory=list)
    duration_ms: int = 0


class Layer(ABC):
    """Abstract base class for detection layers."""

    id: str  # Short ID like "L0"
    name: str  # Human-readable name
    weight: float = 1.0  # Contribution weight in score composition
    cost_estimate_ms: int = 1  # Typical latency expected

    @abstractmethod
    def scan(self, context: NodeContext) -> LayerResult:
        """Scan the provided context and return findings.

        Implementations MUST be pure (no side effects beyond reading files).
        Implementations MUST NEVER execute scanned code.
        """
        ...
