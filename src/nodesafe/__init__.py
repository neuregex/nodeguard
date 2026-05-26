"""nodesafe — security scanner for node-based workflow plugins.

Public API surface:
    Scanner: main orchestrator
    Config: configuration loader
    Report, Finding, Verdict: output data models
    Layer: base class for detection layers
"""

from nodesafe.config import Config, load_config
from nodesafe.report import Finding, Report, Verdict
from nodesafe.scanner import Scanner

__version__ = "0.3.0"

__all__ = [
    "Config",
    "Finding",
    "Report",
    "Scanner",
    "Verdict",
    "__version__",
    "load_config",
]
