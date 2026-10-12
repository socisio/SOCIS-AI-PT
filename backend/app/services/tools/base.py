import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List

class BaseSecurityTool(ABC):
    """Base class for all security tool plugins."""
    
    id: str = "base_tool"
    name: str = "Base Tool"
    description: str = "Base class for security tools"
    category: str = "general"
    binary_path: str = ""

    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self.results = {
            "findings": [],
            "raw_output": "",
            "success": False
        }

    @abstractmethod
    async def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the tool's primary logic."""
        pass

    # ── Lifecycle Hooks ──────────────────────────────────────
    # Override any of these in your plugin to react to scan events.

    async def on_scan_start(self, scan_id: str, target: str, tool_config: dict):
        """Called when a scan starts. Override to add pre-scan logic."""
        pass

    async def on_tool_complete(self, scan_id: str, tool_name: str, result: dict):
        """Called after each individual tool completes."""
        pass

    async def on_scan_complete(self, scan_id: str, findings: list, risk_level: str):
        """Called when the overall scan finishes."""
        pass

    async def on_critical_vuln(self, scan_id: str, vuln_name: str, severity: str):
        """Called when a critical or high severity vulnerability is found."""
        pass

    async def test_connection(self) -> dict:
        """Optional: test connectivity for builtin plugins. Override to implement."""
        return {"ok": True, "message": "No connection test implemented for this plugin."}

    # ── Result Helpers ───────────────────────────────────────

    def add_vulnerability(self, vulnerability: Dict[str, Any]):
        """Add a finding to the results."""
        self.results["findings"].append(vulnerability)

    def create_vulnerability(self, name: str, description: str, severity: str = "info", **kwargs) -> Dict[str, Any]:
        """Helper to structure a vulnerability finding."""
        return {
            "name": name,
            "description": description,
            "severity": severity,
            "extra": kwargs
        }

    def get_results(self, raw_output: str = "") -> Dict[str, Any]:
        """Finalize and return the tool execution summary."""
        self.results["raw_output"] = raw_output
        self.results["success"] = len(self.results["findings"]) >= 0  # Success is execution completion
        return self.results

