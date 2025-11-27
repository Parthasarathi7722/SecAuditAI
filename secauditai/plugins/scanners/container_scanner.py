"""
Simplified container scanner used for unit tests.
"""
from __future__ import annotations

from typing import Any, Dict


class ContainerScanner:
    """Return deterministic results so tests can assert structure."""

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}

    def scan(self, target: str) -> Dict[str, Any]:
        findings = []
        summary = {
            "total_findings": 0,
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
        }
        return {"findings": findings, "summary": summary, "image": target}