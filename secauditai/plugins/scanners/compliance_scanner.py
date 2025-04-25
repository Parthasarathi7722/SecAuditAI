from typing import Dict, List, Any, Optional
from pathlib import Path
import json
import logging
import subprocess
import os
from ..base import BaseScanner

logger = logging.getLogger(__name__)

class ComplianceScanner(BaseScanner):
    """Scanner for compliance checks against cloud infrastructure and data centers."""
    
    def __init__(self):
        super().__init__()
        self.name = "compliance"
        self.description = "Compliance framework scanner"
        self.supported_frameworks = {
            "cis": "Center for Internet Security",
            "pci": "Payment Card Industry",
            "hipaa": "Health Insurance Portability and Accountability Act",
            "nist": "National Institute of Standards and Technology",
            "iso27001": "ISO/IEC 27001"
        }
        self.supported_targets = ["aws", "azure", "gcp", "onprem"]
        self._load_checks()
        self._setup_tools()
    
    def _setup_tools(self) -> None:
        """Setup required compliance tools"""
        self.tools = {
            "soc2": {
                "openscap": "oscap",
                "aws_config": "aws config",
                "azure_policy": "az policy",
                "gcp_scc": "gcloud scc"
            },
            "gdpr": {
                "dpia": "dpia-tool",
                "pia": "pia-tool",
                "data_mapping": "data-mapper",
                "consent_manager": "consent-checker"
            },
            "pci-dss": {
                "qualys": "qualys-scanner",
                "nessus": "nessus",
                "openvas": "openvas",
                "aws_security_hub": "aws securityhub"
            }
        }
    
    def _run_openscap(self, target: str) -> Dict[str, Any]:
        """Run OpenSCAP compliance check"""
        try:
            result = subprocess.run(
                ["oscap", "xccdf", "eval", "--results", "results.xml", target],
                capture_output=True,
                text=True
            )
            return json.loads(result.stdout)
        except Exception as e:
            logger.error(f"OpenSCAP scan failed: {str(e)}")
            return {}
    
    def _run_aws_config(self, target: str) -> Dict[str, Any]:
        """Run AWS Config compliance check"""
        try:
            result = subprocess.run(
                ["aws", "config", "describe-compliance-by-config-rule", "--config-rule-names", target],
                capture_output=True,
                text=True
            )
            return json.loads(result.stdout)
        except Exception as e:
            logger.error(f"AWS Config scan failed: {str(e)}")
            return {}
    
    def _run_qualys(self, target: str) -> Dict[str, Any]:
        """Run Qualys vulnerability scan"""
        try:
            result = subprocess.run(
                ["qualys-scanner", "--target", target],
                capture_output=True,
                text=True
            )
            return json.loads(result.stdout)
        except Exception as e:
            logger.error(f"Qualys scan failed: {str(e)}")
            return {}
    
    def _check_soc2(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform SOC-2 compliance checks using integrated tools"""
        findings = []
        
        # Run OpenSCAP for system compliance
        oscap_results = self._run_openscap(data.get("system_config", ""))
        if oscap_results:
            findings.extend(self._process_openscap_results(oscap_results))
        
        # Run AWS Config for cloud compliance
        if data.get("aws_config"):
            aws_results = self._run_aws_config(data["aws_config"])
            if aws_results:
                findings.extend(self._process_aws_results(aws_results))
        
        return findings
    
    def _check_gdpr(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform GDPR compliance checks using integrated tools"""
        findings = []
        
        # Run DPIA tool
        dpia_results = self._run_dpia(data.get("data_processing", ""))
        if dpia_results:
            findings.extend(self._process_dpia_results(dpia_results))
        
        # Run data mapping tool
        mapping_results = self._run_data_mapping(data.get("data_flows", ""))
        if mapping_results:
            findings.extend(self._process_mapping_results(mapping_results))
        
        return findings
    
    def _check_pci_dss(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform PCI-DSS compliance checks using integrated tools"""
        findings = []
        
        # Run Qualys vulnerability scan
        qualys_results = self._run_qualys(data.get("network", ""))
        if qualys_results:
            findings.extend(self._process_qualys_results(qualys_results))
        
        # Run Nessus security scan
        nessus_results = self._run_nessus(data.get("systems", ""))
        if nessus_results:
            findings.extend(self._process_nessus_results(nessus_results))
        
        return findings
    
    def scan(self, target: str, framework: str, **kwargs) -> Dict:
        """
        Perform compliance scan against specified target.
        
        Args:
            target: Target infrastructure (aws, azure, gcp, onprem)
            framework: Compliance framework to check against
            **kwargs: Additional parameters for specific targets
            
        Returns:
            Dict containing scan results
        """
        if target not in self.supported_targets:
            raise ValueError(f"Unsupported target: {target}. Must be one of {self.supported_targets}")
            
        if framework not in self.supported_frameworks:
            raise ValueError(f"Unsupported framework: {framework}. Must be one of {list(self.supported_frameworks.keys())}")

        try:
            if target == "aws":
                return self._scan_aws(framework, **kwargs)
            elif target == "azure":
                return self._scan_azure(framework, **kwargs)
            elif target == "gcp":
                return self._scan_gcp(framework, **kwargs)
            else:
                return self._scan_onprem(framework, **kwargs)
        except Exception as e:
            return {
                "error": str(e),
                "summary": {
                    "total_checks": 0,
                    "passed": 0,
                    "failed": 0,
                    "not_applicable": 0
                }
            }

    def _scan_aws(self, framework: str, **kwargs) -> Dict:
        """Perform compliance scan against AWS infrastructure."""
        try:
            # Use AWS Config for compliance checks
            cmd = [
                "aws", "configservice", "describe-compliance-by-config-rule",
                "--config-rule-names", f"compliance-{framework}"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise RuntimeError(f"AWS Config error: {result.stderr}")
                
            compliance_data = json.loads(result.stdout)
            return self._format_aws_results(compliance_data)
            
        except Exception as e:
            raise RuntimeError(f"Failed to scan AWS compliance: {str(e)}")

    def _scan_azure(self, framework: str, **kwargs) -> Dict:
        """Perform compliance scan against Azure infrastructure."""
        try:
            # Use Azure Policy for compliance checks
            cmd = [
                "az", "policy", "state", "list",
                "--policy-set-definition", f"compliance-{framework}"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise RuntimeError(f"Azure Policy error: {result.stderr}")
                
            compliance_data = json.loads(result.stdout)
            return self._format_azure_results(compliance_data)
            
        except Exception as e:
            raise RuntimeError(f"Failed to scan Azure compliance: {str(e)}")

    def _scan_gcp(self, framework: str, **kwargs) -> Dict:
        """Perform compliance scan against GCP infrastructure."""
        try:
            # Use GCP Security Command Center for compliance checks
            cmd = [
                "gcloud", "scc", "findings", "list",
                "--filter", f"compliance_standard={framework}"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise RuntimeError(f"GCP SCC error: {result.stderr}")
                
            compliance_data = json.loads(result.stdout)
            return self._format_gcp_results(compliance_data)
            
        except Exception as e:
            raise RuntimeError(f"Failed to scan GCP compliance: {str(e)}")

    def _scan_onprem(self, framework: str, **kwargs) -> Dict:
        """Perform compliance scan against on-premises infrastructure."""
        try:
            # Use OpenSCAP for on-premises compliance checks
            cmd = [
                "oscap", "xccdf", "eval",
                f"--profile {framework}",
                "/usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise RuntimeError(f"OpenSCAP error: {result.stderr}")
                
            return self._format_onprem_results(result.stdout)
            
        except Exception as e:
            raise RuntimeError(f"Failed to scan on-premises compliance: {str(e)}")

    def _format_aws_results(self, data: Dict) -> Dict:
        """Format AWS compliance results."""
        findings = []
        for item in data.get("ComplianceByConfigRules", []):
            findings.append({
                "rule_id": item.get("ConfigRuleName", ""),
                "status": item.get("Compliance", {}).get("ComplianceType", "UNKNOWN"),
                "resource_type": item.get("Compliance", {}).get("ResourceType", ""),
                "resource_id": item.get("Compliance", {}).get("ResourceId", ""),
                "severity": "high" if item.get("Compliance", {}).get("ComplianceType") == "NON_COMPLIANT" else "low"
            })
            
        return {
            "findings": findings,
            "summary": self._generate_summary(findings)
        }

    def _format_azure_results(self, data: Dict) -> Dict:
        """Format Azure compliance results."""
        findings = []
        for item in data:
            findings.append({
                "rule_id": item.get("policyDefinitionName", ""),
                "status": item.get("complianceState", "UNKNOWN"),
                "resource_type": item.get("resourceType", ""),
                "resource_id": item.get("resourceId", ""),
                "severity": "high" if item.get("complianceState") == "NonCompliant" else "low"
            })
            
        return {
            "findings": findings,
            "summary": self._generate_summary(findings)
        }

    def _format_gcp_results(self, data: Dict) -> Dict:
        """Format GCP compliance results."""
        findings = []
        for item in data:
            findings.append({
                "rule_id": item.get("findingClass", ""),
                "status": item.get("state", "UNKNOWN"),
                "resource_type": item.get("resourceType", ""),
                "resource_id": item.get("resourceName", ""),
                "severity": item.get("severity", "low")
            })
            
        return {
            "findings": findings,
            "summary": self._generate_summary(findings)
        }

    def _format_onprem_results(self, data: str) -> Dict:
        """Format on-premises compliance results."""
        findings = []
        # Parse OpenSCAP output and format findings
        # This is a simplified version - actual implementation would need to parse XML output
        for line in data.split("\n"):
            if "Rule Result" in line:
                findings.append({
                    "rule_id": line.split(":")[0].strip(),
                    "status": "PASS" if "pass" in line.lower() else "FAIL",
                    "severity": "high" if "fail" in line.lower() else "low"
                })
                
        return {
            "findings": findings,
            "summary": self._generate_summary(findings)
        }

    def _generate_summary(self, findings: List[Dict]) -> Dict:
        """Generate summary of compliance findings."""
        total = len(findings)
        passed = len([f for f in findings if f["status"] in ["PASS", "Compliant"]])
        failed = len([f for f in findings if f["status"] in ["FAIL", "NonCompliant"]])
        not_applicable = len([f for f in findings if f["status"] == "NotApplicable"])
        
        return {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "not_applicable": not_applicable,
            "compliance_score": (passed / (total - not_applicable)) * 100 if (total - not_applicable) > 0 else 0
        } 