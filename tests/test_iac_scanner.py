#!/usr/bin/env python3
"""
Tests for IAC security scanning functionality
"""

import unittest
from unittest.mock import patch, MagicMock
from secauditai import SecAuditAI
import json
import os

class TestIACScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SecAuditAI()
        self.terraform_dir = "test/terraform"
    
    @patch('secauditai.scanners.terraform.TerraformScanner.scan')
    def test_basic_terraform_scan(self, mock_scan):
        # Mock scan results
        mock_scan.return_value = {
            "findings": [
                {
                    "id": "tf-001",
                    "severity": "high",
                    "description": "Terraform finding"
                }
            ]
        }
        
        # Run basic Terraform scan
        results = self.scanner.scan_terraform(
            directory=self.terraform_dir,
            check_variables=True,
            check_resources=True
        )
        
        # Verify results
        self.assertIn("findings", results)
        self.assertEqual(len(results["findings"]), 1)
    
    @patch('subprocess.run')
    def test_checkov_integration(self, mock_run):
        # Mock Checkov results
        mock_run.return_value.stdout = json.dumps({
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_1",
                        "severity": "HIGH",
                        "description": "Checkov finding"
                    }
                ]
            }
        })
        
        # Run Checkov scan
        from docs.examples.iac_security_scanning import run_checkov
        results = run_checkov(self.terraform_dir)
        
        # Verify results
        self.assertIn("results", results)
        self.assertIn("failed_checks", results["results"])
    
    @patch('subprocess.run')
    def test_tfsec_integration(self, mock_run):
        # Mock TFSec results
        mock_run.return_value.stdout = json.dumps({
            "results": [
                {
                    "rule_id": "AWS001",
                    "severity": "HIGH",
                    "description": "TFSec finding"
                }
            ]
        })
        
        # Run TFSec scan
        from docs.examples.iac_security_scanning import run_tfsec
        results = run_tfsec(self.terraform_dir)
        
        # Verify results
        self.assertIn("results", results)
        self.assertEqual(len(results["results"]), 1)
    
    def test_custom_iac_rules(self):
        # Add custom IAC rule
        custom_rules = [
            {
                "id": "iac-001",
                "name": "Secure Storage",
                "description": "Test rule",
                "severity": "high",
                "patterns": ["resource.*aws_s3_bucket"]
            }
        ]
        
        # Run scan with custom rules
        results = self.scanner.scan_terraform(
            directory=self.terraform_dir,
            custom_rules=custom_rules
        )
        
        # Verify rules were applied
        self.assertIn("rules", results)
        self.assertIn("iac-001", results["rules"])
    
    def test_ci_cd_integration(self):
        # Run CI/CD integrated scan
        results = self.scanner.scan_terraform(
            directory=self.terraform_dir,
            ci_cd=True,
            fail_on_high=True,
            output_format="sarif"
        )
        
        # Verify CI/CD specific fields
        self.assertIn("sarif", results)
        self.assertIn("fail_on_high", results)

if __name__ == "__main__":
    unittest.main() 