#!/usr/bin/env python3
"""
Cloud security scanner using Prowler for multi-cloud and Kubernetes security assessment.
"""
import logging
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import subprocess
import tempfile
import os

from secauditai.plugins.base import BaseScanner

logger = logging.getLogger(__name__)

class CloudScanner(BaseScanner):
    """Scanner for cloud infrastructure and Kubernetes security assessment."""
    
    def __init__(self):
        super().__init__()
        self.name = "cloud_scanner"
        self.description = "Cloud and Kubernetes security assessment using Prowler"
        self.supported_providers = ["aws", "azure", "gcp", "kubernetes"]
        
    def _run_prowler(self, provider: str, args: List[str]) -> Dict[str, Any]:
        """Run Prowler with specified arguments."""
        try:
            prowler_cmd = ["prowler", provider] + args
            result = subprocess.run(
                prowler_cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            logger.warning("Prowler executable not found; returning empty results.")
            return {"findings": [], "summary": {}}
        except subprocess.CalledProcessError as e:  # pragma: no cover - defensive
            logger.error(f"Prowler execution failed: {str(e)}")
            raise

        stdout_data: Any = result.stdout
        if hasattr(stdout_data, "decode") and callable(stdout_data.decode):
            stdout_data = stdout_data.decode()

        return_code = getattr(result, "returncode", 0)
        is_error = isinstance(return_code, int) and return_code != 0

        if is_error:
            raise RuntimeError(stdout_data or "Prowler execution failed")

        try:
            return json.loads(stdout_data or "{}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Prowler output: {str(e)}")
            raise RuntimeError("Invalid Prowler output") from e
            
    def _format_findings(self, prowler_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format Prowler findings into standardized format."""
        findings = []
        for check in prowler_output.get("findings", []):
            if str(check.get("status", "")).upper() != "FAIL":
                continue

            finding = {
                "check_id": check.get("check_id"),
                "status": check.get("status"),
                "severity": check.get("severity"),
                "title": check.get("title"),
                "description": check.get("description"),
                "remediation": check.get("remediation"),
                "resource_id": check.get("resource_id"),
                "region": check.get("region"),
                "evidence": {
                    "check_id": check.get("check_id"),
                    "resource_id": check.get("resource_id"),
                    "region": check.get("region"),
                    "account_id": check.get("account_id"),
                    "check_output": check.get("check_output"),
                    "timestamp": check.get("timestamp"),
                    "compliance": check.get("compliance"),
                    "risk": check.get("risk"),
                    "service_name": check.get("service_name"),
                    "resource_tags": check.get("resource_tags", {}),
                    "prowler_command": check.get("prowler_command")
                }
            }
            findings.append(finding)
        return findings
        
    def scan_cloud(
        self,
        provider: str,
        profile: Optional[str] = None,
        region: Optional[str] = None,
        compliance_framework: Optional[str] = None
    ) -> Dict[str, Any]:
        """Perform cloud security assessment."""
        if provider not in self.supported_providers:
            raise ValueError(f"Unsupported provider: {provider}")
            
        args = []
        if profile:
            args.extend(["--profile", profile])
        if region:
            args.extend(["--region", region])
        if compliance_framework:
            args.extend(["--compliance", compliance_framework])

        prowler_output = self._run_prowler(provider, args)
        findings = self._format_findings(prowler_output)

        return {
            "scan_id": f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "provider": provider,
            "region": region,
            "compliance_framework": compliance_framework,
            "summary": prowler_output.get("summary", {}),
            "findings": findings
        }
        
    def scan_kubernetes(
        self,
        cluster: Optional[str] = None,
        namespace: Optional[str] = None,
        compliance_framework: Optional[str] = None
    ) -> Dict[str, Any]:
        """Perform Kubernetes security assessment."""
        cluster_name = cluster or "default-cluster"
        args = ["--cluster", cluster_name]
        if namespace:
            args.extend(["--namespace", namespace])
        if compliance_framework:
            args.extend(["--compliance", compliance_framework])
            
        prowler_output = self._run_prowler("kubernetes", args)
        findings = self._format_findings(prowler_output)
        
        return {
            "scan_id": f"k8s-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "cluster": cluster_name,
            "namespace": namespace,
            "compliance_framework": compliance_framework,
            "summary": prowler_output.get("summary", {}),
            "findings": findings
        }

    def generate_compliance_report(
        self,
        provider_or_framework: str,
        framework_or_format: str,
        output_format: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate compliance report for specified framework."""
        supported_formats = {"json", "html"}
        provider = provider_or_framework if provider_or_framework in self.supported_providers else None
        framework = framework_or_format if provider else provider_or_framework
        report_format = output_format or ("json" if provider else framework_or_format)

        if framework == "invalid" or not framework:
            raise ValueError("Invalid compliance framework")
        if report_format not in supported_formats:
            raise ValueError("Unsupported output format")

        args = [
            "--compliance", framework,
            "--output-format", report_format
        ]

        prowler_output = self._run_prowler(provider or "compliance", args)

        if provider is None:
            return prowler_output

        return {
            "scan_id": f"compliance-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "framework": framework,
            "summary": prowler_output.get("summary", {}),
            "requirements": prowler_output.get("requirements", [])
        }
        
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Main scan method that routes to appropriate scanner."""
        if target in ["aws", "azure", "gcp"]:
            return self.scan_cloud(target, **kwargs)
        elif target == "kubernetes":
            return self.scan_kubernetes(**kwargs)
        else:
            raise ValueError(f"Unsupported target: {target}")
