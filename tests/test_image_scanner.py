#!/usr/bin/env python3
"""
Tests for container image security scanning functionality
"""

import unittest
from unittest.mock import patch, MagicMock
from secauditai import SecAuditAI
import json
import os
import docker

class TestImageScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SecAuditAI()
        self.image_name = "nginx:latest"
    
    @patch('secauditai.scanners.image.ImageScanner.scan')
    def test_basic_image_scan(self, mock_scan):
        # Mock scan results
        mock_scan.return_value = {
            "findings": [
                {
                    "id": "img-001",
                    "severity": "high",
                    "description": "Image finding"
                }
            ]
        }
        
        # Run basic image scan
        results = self.scanner.scan_image(
            image=self.image_name,
            check_vulnerabilities=True,
            check_configuration=True
        )
        
        # Verify results
        self.assertIn("findings", results)
        self.assertEqual(len(results["findings"]), 1)
    
    @patch('subprocess.run')
    def test_trivy_integration(self, mock_run):
        # Mock Trivy results
        mock_run.return_value.stdout = json.dumps({
            "Results": [
                {
                    "Target": "nginx:latest",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "Severity": "HIGH",
                            "Description": "Trivy finding"
                        }
                    ]
                }
            ]
        })
        
        # Run Trivy scan
        from docs.examples.image_security_scanning import run_trivy
        results = run_trivy(self.image_name)
        
        # Verify results
        self.assertIn("Results", results)
        self.assertIn("Vulnerabilities", results["Results"][0])
    
    @patch('docker.from_env')
    @patch('subprocess.run')
    def test_clair_integration(self, mock_run, mock_docker):
        # Mock Docker client
        mock_image = MagicMock()
        mock_docker.return_value.images.get.return_value = mock_image
        
        # Mock Clair results
        mock_run.return_value.stdout = ""
        with open("clair_report.json", "w") as f:
            json.dump({
                "image": "nginx:latest",
                "vulnerabilities": [
                    {
                        "name": "CVE-2023-1234",
                        "severity": "High",
                        "description": "Clair finding"
                    }
                ]
            }, f)
        
        # Run Clair scan
        from docs.examples.image_security_scanning import run_clair
        results = run_clair(self.image_name)
        
        # Clean up
        if os.path.exists("clair_report.json"):
            os.remove("clair_report.json")
        
        # Verify results
        self.assertIn("vulnerabilities", results)
        self.assertEqual(len(results["vulnerabilities"]), 1)
    
    @patch('subprocess.run')
    def test_anchore_integration(self, mock_run):
        # Mock Anchore results
        mock_run.side_effect = [
            MagicMock(stdout="Analysis complete"),
            MagicMock(stdout="Vulnerabilities found")
        ]
        
        # Run Anchore scan
        from docs.examples.image_security_scanning import run_anchore
        results = run_anchore(self.image_name)
        
        # Verify results
        self.assertIn("analysis", results)
        self.assertIn("vulnerabilities", results)
    
    def test_custom_image_rules(self):
        # Add custom image rule
        custom_rules = [
            {
                "id": "image-001",
                "name": "Secure Base Image",
                "description": "Test rule",
                "severity": "high",
                "patterns": ["FROM.*alpine:.*"]
            }
        ]
        
        # Run scan with custom rules
        results = self.scanner.scan_image(
            image=self.image_name,
            custom_rules=custom_rules
        )
        
        # Verify rules were applied
        self.assertIn("rules", results)
        self.assertIn("image-001", results["rules"])
    
    def test_runtime_security(self):
        # Run runtime security scan
        results = self.scanner.scan_image(
            image=self.image_name,
            runtime=True,
            check_processes=True,
            check_network=True
        )
        
        # Verify runtime checks
        self.assertIn("runtime", results)
        self.assertIn("processes", results["runtime"])
        self.assertIn("network", results["runtime"])

if __name__ == "__main__":
    unittest.main() 