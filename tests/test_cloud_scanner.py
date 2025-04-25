import unittest
from unittest.mock import patch, MagicMock
from secauditai.plugins.scanners.cloud_scanner import CloudScanner

class TestCloudScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = CloudScanner()
        
        # Sample Prowler output
        self.sample_prowler_output = {
            "findings": [
                {
                    "check_id": "check1",
                    "status": "FAIL",
                    "severity": "high",
                    "title": "Security Group Allows All Traffic",
                    "description": "Security group allows all inbound traffic",
                    "remediation": "Restrict inbound traffic to specific ports",
                    "resource_id": "sg-12345678",
                    "region": "us-east-1"
                },
                {
                    "check_id": "check2",
                    "status": "PASS",
                    "severity": "medium",
                    "title": "S3 Bucket Public Access",
                    "description": "S3 bucket has public access",
                    "remediation": "Block public access to the bucket",
                    "resource_id": "bucket-name",
                    "region": "us-east-1"
                }
            ]
        }

    @patch("subprocess.run")
    def test_run_prowler(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=MagicMock(
                decode=lambda: '{"findings": []}'
            ),
            returncode=0
        )
        
        result = self.scanner._run_prowler("aws", ["--checks", "check1"])
        self.assertEqual(result, {"findings": []})

    def test_format_findings(self):
        findings = self.scanner._format_findings(self.sample_prowler_output)
        self.assertEqual(len(findings), 1)  # Only FAIL status
        self.assertEqual(findings[0]["severity"], "high")

    @patch("subprocess.run")
    def test_scan_cloud_aws(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=MagicMock(
                decode=lambda: '{"findings": []}'
            ),
            returncode=0
        )
        
        results = self.scanner.scan_cloud("aws")
        self.assertEqual(len(results["findings"]), 0)

    @patch("subprocess.run")
    def test_scan_cloud_azure(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=MagicMock(
                decode=lambda: '{"findings": []}'
            ),
            returncode=0
        )
        
        results = self.scanner.scan_cloud("azure")
        self.assertEqual(len(results["findings"]), 0)

    @patch("subprocess.run")
    def test_scan_cloud_gcp(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=MagicMock(
                decode=lambda: '{"findings": []}'
            ),
            returncode=0
        )
        
        results = self.scanner.scan_cloud("gcp")
        self.assertEqual(len(results["findings"]), 0)

    @patch("subprocess.run")
    def test_scan_kubernetes(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=MagicMock(
                decode=lambda: '{"findings": []}'
            ),
            returncode=0
        )
        
        results = self.scanner.scan_kubernetes()
        self.assertEqual(len(results["findings"]), 0)

    @patch("subprocess.run")
    def test_generate_compliance_report(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=MagicMock(
                decode=lambda: '{"compliance": "PASS"}'
            ),
            returncode=0
        )
        
        report = self.scanner.generate_compliance_report("cis", "json")
        self.assertEqual(report, {"compliance": "PASS"})

    def test_invalid_provider(self):
        with self.assertRaises(ValueError):
            self.scanner.scan_cloud("invalid")

    def test_invalid_compliance_framework(self):
        with self.assertRaises(ValueError):
            self.scanner.generate_compliance_report("invalid", "json")

    def test_invalid_output_format(self):
        with self.assertRaises(ValueError):
            self.scanner.generate_compliance_report("cis", "invalid")

    @patch("subprocess.run")
    def test_prowler_error(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=MagicMock(
                decode=lambda: 'error'
            ),
            returncode=1
        )
        
        with self.assertRaises(RuntimeError):
            self.scanner._run_prowler("aws", [])

    @patch("subprocess.run")
    def test_invalid_json_output(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=MagicMock(
                decode=lambda: 'invalid json'
            ),
            returncode=0
        )
        
        with self.assertRaises(RuntimeError):
            self.scanner._run_prowler("aws", [])

if __name__ == "__main__":
    unittest.main() 