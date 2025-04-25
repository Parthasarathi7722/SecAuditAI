from typing import Dict, List, Any, Optional
from pathlib import Path
import json
import logging
import subprocess
import os
from ..base import BaseScanner

logger = logging.getLogger(__name__)

class IACScanner(BaseScanner):
    """Scanner for Infrastructure as Code security audits"""
    
    def __init__(self):
        super().__init__()
        self.name = "iac"
        self.description = "Infrastructure as Code security scanner"
        self.supported_languages = ["terraform", "cloudformation", "kubernetes", "ansible"]
        self._setup_tools()
    
    def _setup_tools(self) -> None:
        """Setup required IAC security tools"""
        self.tools = {
            "terraform": {
                "checkov": "checkov",
                "tflint": "tflint",
                "terrascan": "terrascan",
                "tfsec": "tfsec"
            },
            "cloudformation": {
                "cfn_lint": "cfn-lint",
                "cfn_nag": "cfn-nag",
                "cfn_guard": "cfn-guard"
            },
            "kubernetes": {
                "kube_bench": "kube-bench",
                "kube_hunter": "kube-hunter",
                "kube_score": "kube-score",
                "kubeaudit": "kubeaudit"
            },
            "ansible": {
                "ansible_lint": "ansible-lint",
                "ansible_review": "ansible-review",
                "ansible_security": "ansible-security"
            }
        }
    
    def _run_checkov(self, target: str) -> Dict[str, Any]:
        """Run Checkov security scan"""
        try:
            result = subprocess.run(
                ["checkov", "-d", target, "-o", "json"],
                capture_output=True,
                text=True
            )
            return json.loads(result.stdout)
        except Exception as e:
            logger.error(f"Checkov scan failed: {str(e)}")
            return {}
    
    def _run_tflint(self, target: str) -> Dict[str, Any]:
        """Run TFLint best practices check"""
        try:
            result = subprocess.run(
                ["tflint", "--format", "json", target],
                capture_output=True,
                text=True
            )
            return json.loads(result.stdout)
        except Exception as e:
            logger.error(f"TFLint scan failed: {str(e)}")
            return {}
    
    def _run_cfn_nag(self, target: str) -> Dict[str, Any]:
        """Run cfn-nag security scan"""
        try:
            result = subprocess.run(
                ["cfn_nag_scan", "--input-path", target, "--output-format", "json"],
                capture_output=True,
                text=True
            )
            return json.loads(result.stdout)
        except Exception as e:
            logger.error(f"cfn-nag scan failed: {str(e)}")
            return {}
    
    def _run_kube_bench(self, target: str) -> Dict[str, Any]:
        """Run kube-bench CIS benchmark check"""
        try:
            result = subprocess.run(
                ["kube-bench", "--json", target],
                capture_output=True,
                text=True
            )
            return json.loads(result.stdout)
        except Exception as e:
            logger.error(f"kube-bench scan failed: {str(e)}")
            return {}
    
    def _check_terraform(self, target: str) -> List[Dict[str, Any]]:
        """Perform Terraform security checks using integrated tools"""
        findings = []
        
        # Run Checkov
        checkov_results = self._run_checkov(target)
        if checkov_results:
            findings.extend(self._process_checkov_results(checkov_results))
        
        # Run TFLint
        tflint_results = self._run_tflint(target)
        if tflint_results:
            findings.extend(self._process_tflint_results(tflint_results))
        
        return findings
    
    def _check_cloudformation(self, target: str) -> List[Dict[str, Any]]:
        """Perform CloudFormation security checks using integrated tools"""
        findings = []
        
        # Run cfn-nag
        cfn_nag_results = self._run_cfn_nag(target)
        if cfn_nag_results:
            findings.extend(self._process_cfn_nag_results(cfn_nag_results))
        
        # Run cfn-lint
        cfn_lint_results = self._run_cfn_lint(target)
        if cfn_lint_results:
            findings.extend(self._process_cfn_lint_results(cfn_lint_results))
        
        return findings
    
    def _check_kubernetes(self, target: str) -> List[Dict[str, Any]]:
        """Perform Kubernetes security checks using integrated tools"""
        findings = []
        
        # Run kube-bench
        kube_bench_results = self._run_kube_bench(target)
        if kube_bench_results:
            findings.extend(self._process_kube_bench_results(kube_bench_results))
        
        # Run kube-hunter
        kube_hunter_results = self._run_kube_hunter(target)
        if kube_hunter_results:
            findings.extend(self._process_kube_hunter_results(kube_hunter_results))
        
        return findings
    
    def _check_ansible(self, target: str) -> List[Dict[str, Any]]:
        """Perform Ansible security checks using integrated tools"""
        findings = []
        
        # Run ansible-lint
        ansible_lint_results = self._run_ansible_lint(target)
        if ansible_lint_results:
            findings.extend(self._process_ansible_lint_results(ansible_lint_results))
        
        # Run ansible-security
        ansible_security_results = self._run_ansible_security(target)
        if ansible_security_results:
            findings.extend(self._process_ansible_security_results(ansible_security_results))
        
        return findings
    
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Perform IAC security scan using integrated tools
        
        Args:
            target: Path to scan
            **kwargs: Additional arguments
            
        Returns:
            Dict containing scan results
        """
        try:
            # Detect IAC language
            language = self._detect_language(target)
            if not language:
                raise ValueError(f"Unsupported IAC language for file: {target}")
            
            # Perform language-specific checks using integrated tools
            if language == "terraform":
                findings = self._check_terraform(target)
            elif language == "cloudformation":
                findings = self._check_cloudformation(target)
            elif language == "kubernetes":
                findings = self._check_kubernetes(target)
            else:  # ansible
                findings = self._check_ansible(target)
            
            # Generate summary
            summary = {
                "language": language,
                "total_findings": len(findings),
                "high_severity": len([f for f in findings if f["severity"] == "high"]),
                "medium_severity": len([f for f in findings if f["severity"] == "medium"]),
                "low_severity": len([f for f in findings if f["severity"] == "low"])
            }
            
            return {
                "success": True,
                "summary": summary,
                "findings": findings,
                "metadata": {
                    "scanner": self.name,
                    "language": language,
                    "timestamp": self._get_timestamp(),
                    "tools_used": list(self.tools[language].keys())
                }
            }
            
        except Exception as e:
            logger.error(f"IAC scan failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "summary": None,
                "findings": [],
                "metadata": {
                    "scanner": self.name,
                    "timestamp": self._get_timestamp()
                }
            } 