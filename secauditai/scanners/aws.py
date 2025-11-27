from __future__ import annotations

from typing import Any, Dict, List


class AWSScanner:
    """Simple stub that emulates AWS scanning behaviour for orchestration tests."""

    def scan(self, config: Dict[str, Any] | None = None, **kwargs) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "provider": "aws",
            "config": (config or {}) | kwargs,
            "findings": [],
        }
        return data

    def supported_services(self) -> List[str]:
        return ["ec2", "s3", "iam", "rds"]

