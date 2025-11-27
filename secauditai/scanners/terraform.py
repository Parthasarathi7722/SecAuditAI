from __future__ import annotations

from typing import Any, Dict


class TerraformScanner:
    """Placeholder Terraform scanner used for tests."""

    def scan(self, config: Dict[str, Any] | None = None, **kwargs) -> Dict[str, Any]:
        return {
            "tool": "terraform",
            "config": (config or {}) | kwargs,
            "findings": [],
        }

