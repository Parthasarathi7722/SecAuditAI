from __future__ import annotations

from typing import Any, Dict


class OnPremScanner:
    """Represents an on-premises infrastructure scanner."""

    def scan(self, config: Dict[str, Any] | None = None, **kwargs) -> Dict[str, Any]:
        effective_config = (config or {}) | kwargs
        return {
            "environment": "on_prem",
            "config": effective_config,
            "findings": [],
        }

