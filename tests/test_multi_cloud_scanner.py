#!/usr/bin/env python3
"""
Tests for multi-cloud scanning functionality
"""

import unittest
from unittest.mock import patch, MagicMock
from secauditai import SecAuditAI

class TestMultiCloudScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SecAuditAI()
    
    @patch('secauditai.scanners.aws.AWSScanner.scan')
    @patch('secauditai.scanners.azure.AzureScanner.scan')
    def test_multi_cloud_scan_aws_azure(self, mock_azure_scan, mock_aws_scan):
        # Mock scan results
        mock_aws_scan.return_value = {
            "findings": [
                {
                    "id": "aws-001",
                    "severity": "high",
                    "description": "AWS finding"
                }
            ]
        }
        mock_azure_scan.return_value = {
            "findings": [
                {
                    "id": "azure-001",
                    "severity": "high",
                    "description": "Azure finding"
                }
            ]
        }
        
        # Run multi-cloud scan
        results = self.scanner.scan_multi_cloud(
            providers=["aws", "azure"],
            config={
                "aws": {
                    "profile": "default",
                    "regions": ["us-east-1"]
                },
                "azure": {
                    "subscription_id": "test-subscription"
                }
            }
        )
        
        # Verify results
        self.assertIn("aws", results)
        self.assertIn("azure", results)
        self.assertEqual(len(results["aws"]["findings"]), 1)
        self.assertEqual(len(results["azure"]["findings"]), 1)
    
    @patch('secauditai.scanners.aws.AWSScanner.scan')
    @patch('secauditai.scanners.azure.AzureScanner.scan')
    @patch('secauditai.scanners.gcp.GCPScanner.scan')
    def test_multi_cloud_scan_all_providers(self, mock_gcp_scan, mock_azure_scan, mock_aws_scan):
        # Mock scan results
        mock_aws_scan.return_value = {"findings": []}
        mock_azure_scan.return_value = {"findings": []}
        mock_gcp_scan.return_value = {"findings": []}
        
        # Run multi-cloud scan
        results = self.scanner.scan_multi_cloud(
            providers=["aws", "azure", "gcp"],
            config={
                "aws": {"profile": "default"},
                "azure": {"subscription_id": "test-subscription"},
                "gcp": {"project_id": "test-project"}
            }
        )
        
        # Verify all providers were scanned
        self.assertIn("aws", results)
        self.assertIn("azure", results)
        self.assertIn("gcp", results)
    
    def test_multi_cloud_scan_custom_rules(self):
        # Add custom rule
        rule = {
            "id": "multi-cloud-001",
            "name": "Cross-Cloud Access",
            "description": "Test rule",
            "severity": "high"
        }
        self.scanner.add_rule(rule)
        
        # Run scan with custom rule
        results = self.scanner.scan_multi_cloud(
            providers=["aws", "azure"],
            rules=["multi-cloud-001"]
        )
        
        # Verify rule was applied
        self.assertIn("rules", results)
        self.assertIn("multi-cloud-001", results["rules"])
    
    def test_multi_cloud_scan_specific_services(self):
        # Run scan with specific services
        results = self.scanner.scan_multi_cloud(
            providers=["aws", "azure"],
            services={
                "aws": ["ec2", "s3"],
                "azure": ["compute", "storage"]
            }
        )
        
        # Verify services were scanned
        self.assertIn("services", results)
        self.assertIn("aws", results["services"])
        self.assertIn("azure", results["services"])

if __name__ == "__main__":
    unittest.main() 