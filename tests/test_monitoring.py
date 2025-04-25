import unittest
import tempfile
import os
from pathlib import Path
from secauditai.monitoring import SecurityMonitor

class TestMonitoring(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.sample_findings = [
            {
                "type": "vulnerability",
                "severity": "high",
                "title": "SQL Injection",
                "description": "Potential SQL injection vulnerability",
                "remediation": "Use parameterized queries"
            },
            {
                "type": "vulnerability",
                "severity": "medium",
                "title": "XSS Vulnerability",
                "description": "Potential XSS vulnerability",
                "remediation": "Sanitize user input"
            }
        ]

    def test_alert_high_severity(self):
        monitor = SecurityMonitor()
        alert = monitor._format_alert(self.sample_findings[0])
        self.assertIn("SQL Injection", alert)
        self.assertIn("HIGH", alert)

    def test_alert_medium_severity(self):
        monitor = SecurityMonitor()
        alert = monitor._format_alert(self.sample_findings[1])
        self.assertIn("XSS Vulnerability", alert)
        self.assertIn("MEDIUM", alert)

    def test_alert_formatting(self):
        monitor = SecurityMonitor()
        alert = monitor._format_alert(self.sample_findings[0])
        self.assertIn("Description:", alert)
        self.assertIn("Remediation:", alert)

    def test_alert_metadata(self):
        monitor = SecurityMonitor()
        alert = monitor._format_alert(self.sample_findings[0])
        self.assertIn("Type:", alert)
        self.assertIn("Severity:", alert)

    def test_slack_alert(self):
        monitor = SecurityMonitor()
        # Mock the requests.post call
        monitor._send_slack_alert = lambda alert: True
        result = monitor._send_slack_alert("Test alert")
        self.assertTrue(result)

    def test_email_alert(self):
        monitor = SecurityMonitor()
        # Mock the email sending
        monitor._send_email_alert = lambda alert: True
        result = monitor._send_email_alert("Test alert")
        self.assertTrue(result)

    def test_alert_threshold(self):
        monitor = SecurityMonitor()
        # Test that only high severity findings trigger alerts
        alert = monitor._format_alert(self.sample_findings[0])
        self.assertIn("HIGH", alert)
        alert = monitor._format_alert(self.sample_findings[1])
        self.assertNotIn("HIGH", alert)

    def tearDown(self):
        for file in Path(self.test_dir).glob("*"):
            os.remove(file)
        os.rmdir(self.test_dir)

if __name__ == "__main__":
    unittest.main() 