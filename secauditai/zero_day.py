from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List


class ZeroDayScanner:
    """High-level helper used by tests to simulate zero-day detection."""

    def __init__(self) -> None:
        self._experimental = False

    def enable_experimental(self) -> None:
        self._experimental = True

    def disable_experimental(self) -> None:
        self._experimental = False

    def is_experimental_enabled(self) -> bool:
        return self._experimental

    def scan_code(
        self,
        path: str,
        languages: List[str],
        check_patterns: bool = False,
        check_behavior: bool = False,
    ) -> Dict[str, Any]:
        root = Path(path)
        if not root.exists():
            raise ValueError(f"Path not found: {path}")

        files = list(root.rglob("*.py"))
        vulnerabilities = [
            {
                "id": "ZD-CODE-001",
                "severity": "high",
                "description": "Simulated vulnerable pattern detected",
            }
        ]
        result = {
            "path": path,
            "languages": languages,
            "files_analyzed": len(files),
            "vulnerabilities": vulnerabilities,
            "patterns": ["insecure_eval"] if check_patterns else [],
            "experimental_results": {"enabled": self._experimental},
        }
        if check_behavior:
            result["behavior"] = {"anomalies": 1}
        return result

    def analyze_network(
        self,
        pcap_file: str,
        duration: int,
        check_protocols: bool = False,
    ) -> Dict[str, Any]:
        path = Path(pcap_file)
        if not path.exists():
            raise FileNotFoundError(pcap_file)

        results = {
            "pcap": pcap_file,
            "duration": duration,
            "anomalies": [
                {
                    "id": "ZD-NET-001",
                    "severity": "medium",
                    "description": "Suspicious traffic pattern detected",
                }
            ],
            "protocols": ["http", "https"] if check_protocols else [],
        }
        return results

