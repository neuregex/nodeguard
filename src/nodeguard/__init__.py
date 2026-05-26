"""nodeguard — security scanner for node-based workflow plugins.

Public API surface:
    Scanner: main orchestrator
    Config: configuration loader
    Report, Finding, Verdict: output data models
    Layer: base class for detection layers
"""

from nodeguard.config import Config, load_config
from nodeguard.report import Finding, Report, Verdict
from nodeguard.scanner import Scanner

__version__ = "0.2.0"

__all__ = [
    "Config",
    "Finding",
    "Report",
    "Scanner",
    "Verdict",
    "__version__",
    "load_config",
]
