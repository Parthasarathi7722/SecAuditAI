from __future__ import annotations

from typing import Any, Dict


class ImageScanner:
    """Simple container image scanner placeholder."""

    def scan(self, config: Dict[str, Any] | None = None, **kwargs) -> Dict[str, Any]:
        return {
            "image": (config or {}).get("image") or kwargs.get("image"),
            "config": (config or {}) | kwargs,
            "findings": [],
        }

