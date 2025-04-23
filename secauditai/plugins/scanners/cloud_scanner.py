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
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"Prowler execution failed: {str(e)}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Prowler output: {str(e)}")
            raise
            
    def _format_findings(self, prowler_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format Prowler findings into standardized format."""
        findings = []
        for check in prowler_output.get("findings", []):
            finding = {
                "check_id": check.get("check_id"),
                "status": check.get("status"),
                "severity": check.get("severity"),
                "title": check.get("title"),
                "description": check.get("description"),
                "remediation": check.get("remediation"),
                "resource_id": check.get("resource_id"),
                "region": check.get("region")
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
            "compliance_framework": compliance_framework,
            "summary": prowler_output.get("summary", {}),
            "findings": findings
        }
        
    def scan_kubernetes(
        self,
        cluster: str,
        namespace: Optional[str] = None,
        compliance_framework: Optional[str] = None
    ) -> Dict[str, Any]:
        """Perform Kubernetes security assessment."""
        args = ["--cluster", cluster]
        if namespace:
            args.extend(["--namespace", namespace])
        if compliance_framework:
            args.extend(["--compliance", compliance_framework])
            
        prowler_output = self._run_prowler("kubernetes", args)
        findings = self._format_findings(prowler_output)
        
        return {
            "scan_id": f"k8s-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "cluster": cluster,
            "namespace": namespace,
            "compliance_framework": compliance_framework,
            "summary": prowler_output.get("summary", {}),
            "findings": findings
        }
        
    def generate_compliance_report(
        self,
        provider: str,
        framework: str,
        output_format: str = "json"
    ) -> Dict[str, Any]:
        """Generate compliance report for specified framework."""
        args = [
            "--compliance", framework,
            "--output-format", output_format
        ]
        
        prowler_output = self._run_prowler(provider, args)
        
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