#!/usr/bin/env python3
"""
Tests for hybrid cloud scanning functionality
"""

import unittest
from unittest.mock import patch, MagicMock
from secauditai import SecAuditAI

class TestHybridCloudScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SecAuditAI()
    
    @patch('secauditai.scanners.on_prem.OnPremScanner.scan')
    @patch('secauditai.scanners.aws.AWSScanner.scan')
    def test_hybrid_cloud_scan_on_prem_aws(self, mock_aws_scan, mock_on_prem_scan):
        # Mock scan results
        mock_on_prem_scan.return_value = {
            "findings": [
                {
                    "id": "on-prem-001",
                    "severity": "high",
                    "description": "On-prem finding"
                }
            ]
        }
        mock_aws_scan.return_value = {
            "findings": [
                {
                    "id": "aws-001",
                    "severity": "high",
                    "description": "AWS finding"
                }
            ]
        }
        
        # Run hybrid cloud scan
        results = self.scanner.scan_hybrid_cloud(
            environments=["on_prem", "aws"],
            config={
                "on_prem": {
                    "servers": ["server1"],
                    "networks": ["network1"]
                },
                "aws": {
                    "profile": "default",
                    "regions": ["us-east-1"]
                }
            }
        )
        
        # Verify results
        self.assertIn("on_prem", results)
        self.assertIn("aws", results)
        self.assertEqual(len(results["on_prem"]["findings"]), 1)
        self.assertEqual(len(results["aws"]["findings"]), 1)
    
    @patch('secauditai.scanners.on_prem.OnPremScanner.scan')
    @patch('secauditai.scanners.aws.AWSScanner.scan')
    @patch('secauditai.scanners.azure.AzureScanner.scan')
    def test_hybrid_cloud_scan_all_environments(self, mock_azure_scan, mock_aws_scan, mock_on_prem_scan):
        # Mock scan results
        mock_on_prem_scan.return_value = {"findings": []}
        mock_aws_scan.return_value = {"findings": []}
        mock_azure_scan.return_value = {"findings": []}
        
        # Run hybrid cloud scan
        results = self.scanner.scan_hybrid_cloud(
            environments=["on_prem", "aws", "azure"],
            config={
                "on_prem": {
                    "servers": ["server1"],
                    "networks": ["network1"]
                },
                "aws": {"profile": "default"},
                "azure": {"subscription_id": "test-subscription"}
            }
        )
        
        # Verify all environments were scanned
        self.assertIn("on_prem", results)
        self.assertIn("aws", results)
        self.assertIn("azure", results)
    
    def test_hybrid_cloud_scan_custom_rules(self):
        # Add custom rule
        rule = {
            "id": "hybrid-001",
            "name": "Cross-Environment Access",
            "description": "Test rule",
            "severity": "high"
        }
        self.scanner.add_rule(rule)
        
        # Run scan with custom rule
        results = self.scanner.scan_hybrid_cloud(
            environments=["on_prem", "aws"],
            rules=["hybrid-001"]
        )
        
        # Verify rule was applied
        self.assertIn("rules", results)
        self.assertIn("hybrid-001", results["rules"])
    
    def test_hybrid_cloud_scan_specific_components(self):
        # Run scan with specific components
        results = self.scanner.scan_hybrid_cloud(
            environments=["on_prem", "aws"],
            components={
                "on_prem": {
                    "servers": ["server1"],
                    "networks": ["network1"]
                },
                "aws": {
                    "services": ["ec2", "s3"]
                }
            }
        )
        
        # Verify components were scanned
        self.assertIn("components", results)
        self.assertIn("on_prem", results["components"])
        self.assertIn("aws", results["components"])
    
    def test_hybrid_cloud_scan_connectivity_checks(self):
        # Run scan with connectivity checks
        results = self.scanner.scan_hybrid_cloud(
            environments=["on_prem", "aws"],
            check_connectivity=True,
            check_security_groups=True,
            check_firewalls=True
        )
        
        # Verify connectivity checks were performed
        self.assertIn("connectivity", results)
        self.assertIn("security_groups", results)
        self.assertIn("firewalls", results)

if __name__ == "__main__":
    unittest.main() 