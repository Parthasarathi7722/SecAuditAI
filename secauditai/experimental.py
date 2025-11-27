from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional


class _ExperimentalToggle:
    def __init__(self) -> None:
        self._experimental = False

    def enable_experimental(self) -> None:
        self._experimental = True

    def disable_experimental(self) -> None:
        self._experimental = False

    def is_experimental_enabled(self) -> bool:
        return self._experimental


class SBOMGenerator(_ExperimentalToggle):
    def generate(
        self,
        path: str,
        format: str = "json",
        include_dependencies: bool = False,
        include_licenses: bool = False,
    ) -> Dict[str, Any]:
        root = Path(path)
        if not root.exists():
            raise ValueError(f"Path not found: {path}")
        artifacts: List[str] = [p.name for p in root.rglob("*") if p.is_file()]
        return {
            "format": format,
            "artifacts": artifacts,
            "include_dependencies": include_dependencies,
            "include_licenses": include_licenses,
            "experimental_metadata": {"enabled": self._experimental},
        }


class ComplianceChecker(_ExperimentalToggle):
    def check_cis(
        self,
        framework: str,
        level: int = 1,
        sections: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return {
            "framework": framework,
            "level": level,
            "sections": sections or [],
            "experimental_findings": [
                {"section": section, "status": "PASS"} for section in (sections or [])
            ],
        }

