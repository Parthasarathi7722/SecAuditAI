import unittest
import json
from unittest.mock import patch, MagicMock
from secauditai.plugins.scanners.sbom_scanner import SBOMScanner

class TestSBOMScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SBOMScanner()
        self.sample_sbom = {
            "artifacts": [
                {
                    "id": "pkg:pypi/requests@2.28.1",
                    "name": "requests",
                    "version": "2.28.1",
                    "type": "python",
                    "licenses": ["Apache-2.0"]
                }
            ]
        }
        self.sample_vulnerabilities = [
            {
                "id": "CVE-2023-1234",
                "severity": "high",
                "description": "Test vulnerability",
                "package": "requests",
                "version": "2.28.1"
            }
        ]

    @patch("subprocess.run")
    def test_generate_sbom(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=json.dumps(self.sample_sbom),
            stderr="",
            returncode=0
        )
        
        sbom = self.scanner._generate_sbom("test_path")
        self.assertEqual(sbom, self.sample_sbom)

    @patch("requests.get")
    def test_check_vulnerabilities(self, mock_get):
        mock_get.return_value = MagicMock(
            json=lambda: self.sample_vulnerabilities,
            status_code=200
        )
        
        findings = self.scanner._check_vulnerabilities(self.sample_sbom)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")

    @patch("requests.get")
    def test_check_outdated_dependencies(self, mock_get):
        mock_get.return_value = MagicMock(
            json=lambda: {"info": {"version": "2.28.2"}},
            status_code=200
        )
        
        findings = self.scanner._check_outdated_dependencies(self.sample_sbom)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "medium")

    def test_check_licenses(self):
        findings = self.scanner._check_licenses(self.sample_sbom)
        self.assertEqual(len(findings), 0)  # Apache-2.0 is allowed

    @patch("subprocess.run")
    @patch("requests.get")
    def test_scan(self, mock_get, mock_run):
        mock_run.return_value = MagicMock(
            stdout=json.dumps(self.sample_sbom),
            stderr="",
            returncode=0
        )
        mock_get.return_value = MagicMock(
            json=lambda: self.sample_vulnerabilities,
            status_code=200
        )
        
        results = self.scanner.scan("test_path")
        self.assertEqual(len(results["findings"]), 1)
        self.assertEqual(results["findings"][0]["severity"], "high")

    def test_invalid_path(self):
        with self.assertRaises(ValueError):
            self.scanner.scan("invalid_path")

    @patch("subprocess.run")
    def test_sbom_generation_error(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="",
            stderr="Error",
            returncode=1
        )
        
        with self.assertRaises(RuntimeError):
            self.scanner._generate_sbom("test_path")

if __name__ == "__main__":
    unittest.main() 