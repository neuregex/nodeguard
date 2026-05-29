"""Workflow Auditor module.

Where `nodesafe.layers.*` scans Python source code in a custom_node, this
module scans ComfyUI workflow files (JSON, or PNG with workflow metadata
in tEXt chunks). Workflows ship more freely than custom_nodes, so they
are a higher-volume attack surface: a single workflow shared on Civitai
or Discord can carry malicious widget values, embedded Python in
ExecutePython-style nodes, exfiltration URLs, or references to
custom_nodes that are themselves malware.

Same signatures (patterns.json, malicious_urls.txt) feed the analyzers
here as feed the code-scanning layers. Same Finding / Report data model
flows out.

Public surface:
    Workflow, WorkflowNode      data model
    parse_workflow              parser entry point
    WorkflowScanner             orchestrator (mirrors nodesafe.Scanner)
"""

from nodesafe.workflow.models import Workflow, WorkflowNode
from nodesafe.workflow.parser import WorkflowParseError, parse_workflow
from nodesafe.workflow.scanner import WorkflowScanner

__all__ = [
    "Workflow",
    "WorkflowNode",
    "WorkflowParseError",
    "WorkflowScanner",
    "parse_workflow",
]
