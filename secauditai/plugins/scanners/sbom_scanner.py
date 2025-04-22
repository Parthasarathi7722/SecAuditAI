"""
SBOM (Software Bill of Materials) scanner plugin.
"""
import os
from typing import Dict, Any, List
from pathlib import Path
import syft
import requests
import json
from datetime import datetime, timedelta
from .. import ScannerPlugin

class SBOMScanner(ScannerPlugin):
    """SBOM scanner implementation."""
    
    def __init__(self):
        self.checks = self._load_checks()
        self.nvd_api_key = os.getenv('NVD_API_KEY')
        self.cache_dir = os.path.expanduser('~/.secauditai/cache/nvd')
        os.makedirs(self.cache_dir, exist_ok=True)

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

    def _fetch_nvd_data(self, cve_id: str) -> Dict[str, Any]:
        """Fetch CVE data from NVD."""
        cache_file = os.path.join(self.cache_dir, f"{cve_id}.json")
        
        # Check cache first
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                return json.load(f)
        
        # Fetch from NVD API
        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key
        
        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            with open(cache_file, 'w') as f:
                json.dump(data, f)
            return data
        return {}

    def _fetch_latest_version(self, package_name: str, package_manager: str) -> str:
        """Fetch latest version of a package from its package manager."""
        try:
            if package_manager == 'npm':
                url = f"https://registry.npmjs.org/{package_name}/latest"
                response = requests.get(url)
                if response.status_code == 200:
                    return response.json()['version']
            elif package_manager == 'pypi':
                url = f"https://pypi.org/pypi/{package_name}/json"
                response = requests.get(url)
                if response.status_code == 200:
                    return response.json()['info']['version']
            elif package_manager == 'maven':
                url = f"https://search.maven.org/solrsearch/select?q=g:{package_name}&rows=1&wt=json"
                response = requests.get(url)
                if response.status_code == 200:
                    return response.json()['response']['docs'][0]['latestVersion']
        except Exception:
            pass
        return "unknown"

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
        
        for package in sbom.get('artifacts', []):
            # Check NVD for vulnerabilities
            if package.get('cpe'):
                nvd_data = self._fetch_nvd_data(package['cpe'])
                if nvd_data and 'result' in nvd_data:
                    for vuln in nvd_data['result']['CVE_Items']:
                        cve_id = vuln['cve']['CVE_data_meta']['ID']
                        severity = vuln['impact'].get('baseMetricV3', {}).get('cvssV3', {}).get('baseSeverity', 'unknown')
                        
                        findings.append({
                            "check_id": "sbom-001",
                            "resource": f"{package['name']}@{package['version']}",
                            "status": "failed",
                            "message": f"Known vulnerability: {cve_id} - {vuln['cve']['description']['description_data'][0]['value']}",
                            "severity": severity.lower(),
                            "recommendation": f"Update to version {vuln.get('fixed_version', 'latest')}",
                            "cve_data": vuln
                        })
        
        return findings

    def _check_outdated_dependencies(self, sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for outdated dependencies."""
        findings = []
        
        for package in sbom.get('artifacts', []):
            package_manager = package.get('type', '').lower()
            latest_version = self._fetch_latest_version(package['name'], package_manager)
            
            if latest_version != "unknown" and package['version'] != latest_version:
                findings.append({
                    "check_id": "sbom-002",
                    "resource": f"{package['name']}@{package['version']}",
                    "status": "failed",
                    "message": f"Outdated dependency: Current version {package['version']}, Latest version {latest_version}",
                    "severity": "medium",
                    "recommendation": f"Update to version {latest_version}"
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