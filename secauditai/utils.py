from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml


def load_config(path: str) -> Dict[str, Any]:
    """Load configuration from JSON or YAML files."""
    path_obj = Path(path)
    if not path_obj.exists():
        raise FileNotFoundError(path)
    text = path_obj.read_text(encoding="utf-8")
    if path_obj.suffix in {".yaml", ".yml"}:
        return yaml.safe_load(text) or {}
    return json.loads(text)


def save_config(config: Dict[str, Any], path: str) -> None:
    """Persist configuration as JSON."""
    path_obj = Path(path)
    path_obj.write_text(json.dumps(config, indent=2), encoding="utf-8")


def validate_config(config: Dict[str, Any]) -> bool:
    scanners = config.get("scanners", {})
    return bool(scanners and isinstance(scanners, dict))


def format_findings(findings: Iterable[Dict[str, Any]]) -> str:
    lines = []
    for finding in findings:
        lines.append(
            f"[{finding.get('severity', 'unknown').upper()}] "
            f"{finding.get('title', 'Untitled')} - {finding.get('description', '')}"
        )
    return "\n".join(lines)


def calculate_risk_score(findings: Iterable[Dict[str, Any]]) -> float:
    weights = {"high": 3, "medium": 2, "low": 1}
    total = 0
    count = 0
    for finding in findings:
        severity = finding.get("severity", "").lower()
        total += weights.get(severity, 0)
        count += 1
    if count == 0:
        return 0.0
    normalized = min(total / (3 * count), 1.0)
    return round(normalized * 100, 2)


def get_language_parser(language: str) -> Optional[str]:
    supported = {
        "python": "tree-sitter-python",
        "javascript": "tree-sitter-javascript",
        "go": "tree-sitter-go",
    }
    return supported.get(language.lower())

