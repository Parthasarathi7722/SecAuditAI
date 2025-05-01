#!/usr/bin/env python3
"""
Prowler Integration
-----------------
This module provides integration with Prowler for cloud security scanning.
"""

import subprocess
import json
import os
from typing import Dict, List, Optional
from pathlib import Path
from secauditai.plugins.base import BaseScanner

class ProwlerScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.prowler_path = os.getenv("PROWLER_PATH", "prowler")
        self.aws_profile = os.getenv("AWS_PROFILE")
        self.aws_region = os.getenv("AWS_REGION")
    
    def scan(self,
             checks: Optional[List[str]] = None,
             severity: Optional[str] = None,
             region: Optional[str] = None,
             profile: Optional[str] = None) -> Dict:
        """
        Perform cloud security scan using Prowler
        
        Args:
            checks: Optional list of specific checks to run
            severity: Optional severity level filter (high, medium, low)
            region: Optional AWS region
            profile: Optional AWS profile
            
        Returns:
            Dict containing scan results
        """
        # Build Prowler command
        cmd = [self.prowler_path]
        
        # Add output format
        cmd.extend(["-M", "json"])
        
        # Add region if specified
        if region:
            cmd.extend(["-r", region])
        elif self.aws_region:
            cmd.extend(["-r", self.aws_region])
        
        # Add profile if specified
        if profile:
            cmd.extend(["-p", profile])
        elif self.aws_profile:
            cmd.extend(["-p", self.aws_profile])
        
        # Add severity filter if specified
        if severity:
            cmd.extend(["-S", severity])
        
        # Add specific checks if specified
        if checks:
            cmd.extend(["-c", ",".join(checks)])
        
        try:
            # Run Prowler
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse JSON output
            return self._parse_results(result.stdout)
            
        except subprocess.CalledProcessError as e:
            return {
                "error": f"Prowler execution failed: {str(e)}",
                "stdout": e.stdout,
                "stderr": e.stderr
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _parse_results(self, output: str) -> Dict:
        """Parse Prowler JSON output"""
        try:
            results = json.loads(output)
            
            # Transform results into our format
            transformed = {
                "summary": {
                    "total_checks": len(results),
                    "passed": sum(1 for r in results if r.get("Status") == "PASS"),
                    "failed": sum(1 for r in results if r.get("Status") == "FAIL"),
                    "severity_counts": self._count_severities(results)
                },
                "checks": []
            }
            
            # Process each check
            for check in results:
                transformed["checks"].append({
                    "id": check.get("CheckID"),
                    "title": check.get("CheckTitle"),
                    "status": check.get("Status"),
                    "severity": check.get("Severity"),
                    "region": check.get("Region"),
                    "resource": check.get("ResourceId"),
                    "message": check.get("Message"),
                    "remediation": check.get("Remediation"),
                    "compliance": check.get("Compliance"),
                    "risk": check.get("Risk"),
                    "details": {
                        "service": check.get("Service"),
                        "sub_service": check.get("SubService"),
                        "check_type": check.get("CheckType"),
                        "timestamp": check.get("Timestamp")
                    }
                })
            
            return transformed
            
        except json.JSONDecodeError as e:
            return {"error": f"Failed to parse Prowler output: {str(e)}"}
    
    def _count_severities(self, results: List[Dict]) -> Dict:
        """Count checks by severity"""
        counts = {}
        for check in results:
            severity = check.get("Severity", "unknown")
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def list_checks(self) -> List[Dict]:
        """List available Prowler checks"""
        try:
            result = subprocess.run(
                [self.prowler_path, "-l"],
                capture_output=True,
                text=True,
                check=True
            )
            
            checks = []
            for line in result.stdout.splitlines():
                if " - " in line:
                    check_id, description = line.split(" - ", 1)
                    checks.append({
                        "id": check_id.strip(),
                        "description": description.strip()
                    })
            
            return checks
            
        except subprocess.CalledProcessError as e:
            return [{"error": f"Failed to list checks: {str(e)}"}]
        except Exception as e:
            return [{"error": str(e)}]
    
    def get_check_info(self, check_id: str) -> Dict:
        """Get detailed information about a specific check"""
        try:
            result = subprocess.run(
                [self.prowler_path, "-c", check_id, "-M", "json"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse and return the first check's details
            checks = json.loads(result.stdout)
            if checks:
                return checks[0]
            return {"error": f"Check {check_id} not found"}
            
        except subprocess.CalledProcessError as e:
            return {"error": f"Failed to get check info: {str(e)}"}
        except Exception as e:
            return {"error": str(e)}
    
    def validate_installation(self) -> bool:
        """Validate Prowler installation"""
        try:
            result = subprocess.run(
                [self.prowler_path, "-v"],
                capture_output=True,
                text=True,
                check=True
            )
            return True
        except Exception:
            return False
    
    def install_prowler(self) -> bool:
        """Install Prowler if not already installed"""
        try:
            subprocess.run(
                ["pip", "install", "prowler"],
                check=True
            )
            return True
        except Exception as e:
            print(f"Failed to install Prowler: {str(e)}")
            return False 