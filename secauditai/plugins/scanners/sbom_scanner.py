"""
SBOM (Software Bill of Materials) scanner plugin.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import requests

from .. import ScannerPlugin


class SBOMScanner(ScannerPlugin):
    """Lightweight SBOM scanner that shells out to Syft and enriches findings."""

    def __init__(self) -> None:
        self.checks = self._load_checks()

    def _load_checks(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "sbom-001",
                "name": "Known Vulnerabilities",
                "description": "Check for known vulnerabilities in dependencies",
                "severity": "high",
            },
            {
                "id": "sbom-002",
                "name": "Outdated Dependencies",
                "description": "Check for outdated dependencies",
                "severity": "medium",
            },
            {
                "id": "sbom-003",
                "name": "License Compliance",
                "description": "Check for license compliance issues",
                "severity": "medium",
            },
        ]

    def _validate_path(self, path: str) -> Path:
        if not path:
            raise ValueError("A path must be provided for SBOM scanning.")
        path_obj = Path(path)
        if not path_obj.exists():
            raise ValueError(f"Invalid path provided: {path}")
        return path_obj

    def _generate_sbom(self, path: str) -> Dict[str, Any]:
        """Invoke Syft (or any SBOM-capable tool) through subprocess."""
        command = ["syft", "-o", "json", path]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr or "Failed to generate SBOM")
        return json.loads(result.stdout or "{}")

    def _check_vulnerabilities(self, sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        artifacts = sbom.get("artifacts", [])
        for artifact in artifacts:
            package = artifact.get("name")
            version = artifact.get("version")
            if not package or not version:
                continue

            resp = requests.get(
                "https://example.com/vulnerabilities",
                params={"package": package, "version": version},
                timeout=5,
            )
            if resp.status_code != 200:
                continue

            for vuln in resp.json():
                findings.append(
                    {
                        "check_id": "sbom-001",
                        "resource": f"{package}@{version}",
                        "status": "failed",
                        "message": vuln.get("description", "Known vulnerability detected"),
                        "severity": vuln.get("severity", "high").lower(),
                        "vulnerability_id": vuln.get("id"),
                    }
                )
        return findings

    def _check_outdated_dependencies(self, sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for artifact in sbom.get("artifacts", []):
            package = artifact.get("name")
            version = artifact.get("version")
            if not package or not version:
                continue

            resp = requests.get(
                f"https://pypi.org/pypi/{package}/json",
                timeout=5,
            )
            if resp.status_code != 200:
                continue

            latest = resp.json().get("info", {}).get("version")
            if latest and latest != version:
                findings.append(
                    {
                        "check_id": "sbom-002",
                        "resource": f"{package}@{version}",
                        "status": "failed",
                        "message": f"Outdated dependency. Latest available version is {latest}",
                        "severity": "medium",
                        "recommendation": f"Upgrade {package} to {latest}",
                    }
                )
        return findings

    def _check_licenses(self, sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        allowed = {"MIT", "Apache-2.0", "BSD-3-Clause"}
        restricted = {"GPL-3.0", "AGPL-3.0"}

        for artifact in sbom.get("artifacts", []):
            licenses = artifact.get("licenses") or []
            for license_id in licenses:
                if license_id in restricted:
                    findings.append(
                        {
                            "check_id": "sbom-003",
                            "resource": f"{artifact.get('name')}@{artifact.get('version')}",
                            "status": "failed",
                            "message": f"Restricted license detected: {license_id}",
                            "severity": "medium",
                        }
                    )
                elif license_id not in allowed:
                    findings.append(
                        {
                            "check_id": "sbom-003",
                            "resource": f"{artifact.get('name')}@{artifact.get('version')}",
                            "status": "warning",
                            "message": f"Unknown license detected: {license_id}",
                            "severity": "low",
                        }
                    )
        return findings

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        path = kwargs.get("path")
        self._validate_path(path)

        sbom = self._generate_sbom(path)

        findings: List[Dict[str, Any]] = []
        findings.extend(self._check_vulnerabilities(sbom))
        findings.extend(self._check_outdated_dependencies(sbom))
        findings.extend(self._check_licenses(sbom))

        summary = {
            "total": len(findings),
            "failed": len([f for f in findings if f["status"] == "failed"]),
            "passed": 0,
            "error": 0,
        }

        return {
            "scanner": self.get_name(),
            "target": target,
            "findings": findings,
            "summary": summary,
        }

    def get_name(self) -> str:
        return "sbom"

    def get_description(self) -> str:
        return "Software Bill of Materials security scanner"