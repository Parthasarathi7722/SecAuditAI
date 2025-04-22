"""
SBOM (Software Bill of Materials) scanner plugin.
"""
import os
from typing import Dict, Any, List
from pathlib import Path
import syft
from .. import ScannerPlugin

class SBOMScanner(ScannerPlugin):
    """SBOM scanner implementation."""
    
    def __init__(self):
        self.checks = self._load_checks()

    def _load_checks(self) -> List[Dict[str, Any]]:
        """Load SBOM security checks."""
        return [
            {
                "id": "sbom-001",
                "name": "Known Vulnerabilities",
                "description": "Check for known vulnerabilities in dependencies",
                "severity": "high"
            },
            {
                "id": "sbom-002",
                "name": "Outdated Dependencies",
                "description": "Check for outdated dependencies",
                "severity": "medium"
            },
            {
                "id": "sbom-003",
                "name": "License Compliance",
                "description": "Check for license compliance issues",
                "severity": "medium"
            }
        ]

    def _generate_sbom(self, path: str) -> Dict[str, Any]:
        """Generate SBOM for the target."""
        try:
            # Use Syft to generate SBOM
            sbom = syft.scan(path)
            return sbom.to_dict()
        except Exception as e:
            return {
                "error": str(e),
                "status": "error"
            }

    def _check_vulnerabilities(self, sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for known vulnerabilities."""
        findings = []
        
        # TODO: Integrate with vulnerability databases
        # This is a placeholder implementation
        for package in sbom.get('artifacts', []):
            if package.get('vulnerabilities'):
                for vuln in package['vulnerabilities']:
                    findings.append({
                        "check_id": "sbom-001",
                        "resource": f"{package['name']}@{package['version']}",
                        "status": "failed",
                        "message": f"Known vulnerability: {vuln['id']} - {vuln['description']}",
                        "severity": vuln.get('severity', 'high'),
                        "recommendation": f"Update to version {vuln.get('fixed_version', 'latest')}"
                    })
        
        return findings

    def _check_outdated_dependencies(self, sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for outdated dependencies."""
        findings = []
        
        # TODO: Implement version checking against latest versions
        # This is a placeholder implementation
        for package in sbom.get('artifacts', []):
            if package.get('latest_version') and package['version'] != package['latest_version']:
                findings.append({
                    "check_id": "sbom-002",
                    "resource": f"{package['name']}@{package['version']}",
                    "status": "failed",
                    "message": f"Outdated dependency: Current version {package['version']}, Latest version {package['latest_version']}",
                    "severity": "medium",
                    "recommendation": f"Update to version {package['latest_version']}"
                })
        
        return findings

    def _check_licenses(self, sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for license compliance issues."""
        findings = []
        
        # Define allowed and restricted licenses
        allowed_licenses = ['MIT', 'Apache-2.0', 'BSD-3-Clause']
        restricted_licenses = ['GPL-3.0', 'AGPL-3.0']
        
        for package in sbom.get('artifacts', []):
            license = package.get('license')
            if license:
                if license in restricted_licenses:
                    findings.append({
                        "check_id": "sbom-003",
                        "resource": f"{package['name']}@{package['version']}",
                        "status": "failed",
                        "message": f"Restricted license: {license}",
                        "severity": "medium",
                        "recommendation": "Consider using an alternative package with a more permissive license"
                    })
                elif license not in allowed_licenses:
                    findings.append({
                        "check_id": "sbom-003",
                        "resource": f"{package['name']}@{package['version']}",
                        "status": "warning",
                        "message": f"Unknown license: {license}",
                        "severity": "low",
                        "recommendation": "Verify license compatibility with your project"
                    })
        
        return findings

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform SBOM security scan."""
        path = kwargs.get('path')
        
        if not path or not os.path.exists(path):
            return {
                "scanner": self.get_name(),
                "target": target,
                "findings": [{
                    "check_id": "sbom-000",
                    "resource": path,
                    "status": "error",
                    "message": "Invalid path provided"
                }],
                "summary": {
                    "total": 1,
                    "failed": 0,
                    "passed": 0,
                    "error": 1
                }
            }
        
        try:
            # Generate SBOM
            sbom = self._generate_sbom(path)
            if sbom.get('error'):
                return {
                    "scanner": self.get_name(),
                    "target": target,
                    "findings": [{
                        "check_id": "sbom-000",
                        "resource": path,
                        "status": "error",
                        "message": f"Error generating SBOM: {sbom['error']}"
                    }],
                    "summary": {
                        "total": 1,
                        "failed": 0,
                        "passed": 0,
                        "error": 1
                    }
                }
            
            # Run checks
            findings = []
            findings.extend(self._check_vulnerabilities(sbom))
            findings.extend(self._check_outdated_dependencies(sbom))
            findings.extend(self._check_licenses(sbom))
            
            return {
                "scanner": self.get_name(),
                "target": target,
                "findings": findings,
                "summary": {
                    "total": len(findings),
                    "failed": len([f for f in findings if f['status'] == 'failed']),
                    "passed": len([f for f in findings if f['status'] == 'passed']),
                    "error": len([f for f in findings if f['status'] == 'error'])
                }
            }
            
        except Exception as e:
            return {
                "scanner": self.get_name(),
                "target": target,
                "findings": [{
                    "check_id": "sbom-000",
                    "resource": path,
                    "status": "error",
                    "message": f"Error scanning SBOM: {str(e)}"
                }],
                "summary": {
                    "total": 1,
                    "failed": 0,
                    "passed": 0,
                    "error": 1
                }
            }

    def get_name(self) -> str:
        """Get scanner name."""
        return "sbom"

    def get_description(self) -> str:
        """Get scanner description."""
        return "Software Bill of Materials security scanner" 