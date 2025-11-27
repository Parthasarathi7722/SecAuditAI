from __future__ import annotations

from typing import Any, Dict, List


class GCPScanner:
    """Stub GCP scanner used for orchestration unit tests."""

    def scan(self, config: Dict[str, Any] | None = None, **kwargs) -> Dict[str, Any]:
        return {
            "provider": "gcp",
            "config": (config or {}) | kwargs,
            "findings": [],
        }

    def supported_services(self) -> List[str]:
        return ["compute", "storage", "sql"]

