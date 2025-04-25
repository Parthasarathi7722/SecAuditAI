import unittest
import tempfile
import os
from pathlib import Path
from secauditai.monitor import SecurityMonitor

class TestMonitor(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.monitor = SecurityMonitor()
        self.sample_results = {
            "findings": [
                {
                    "type": "vulnerability",
                    "severity": "high",
                    "title": "SQL Injection",
                    "description": "Potential SQL injection vulnerability",
                    "location": "test.py:10",
                    "remediation": "Use parameterized queries"
                }
            ],
            "summary": {
                "total_findings": 1,
                "high_severity": 1,
                "medium_severity": 0,
                "low_severity": 0
            }
        }

    def test_analyze_findings(self):
        analysis = self.monitor.analyze_findings(self.sample_results)
        self.assertIn("total_findings", analysis)
        self.assertIn("severity_distribution", analysis)
        self.assertIn("trends", analysis)

    def test_generate_metrics(self):
        metrics = self.monitor.generate_metrics(self.sample_results)
        self.assertIn("vulnerability_metrics", metrics)
        self.assertIn("compliance_metrics", metrics)
        self.assertIn("risk_metrics", metrics)

    def test_send_alerts(self):
        # Test with mock alert handlers
        self.monitor.alert_handlers = {
            "console": lambda x: None,
            "slack": lambda x: None
        }
        self.monitor.send_alerts(self.sample_results)

    def test_track_scan_history(self):
        self.monitor.track_scan_history(self.sample_results)
        history = self.monitor.get_scan_history()
        self.assertIsInstance(history, list)
        self.assertTrue(len(history) > 0)

    def test_get_scan_history(self):
        history = self.monitor.get_scan_history()
        self.assertIsInstance(history, list)

    def tearDown(self):
        for file in Path(self.test_dir).glob("*"):
            os.remove(file)
        os.rmdir(self.test_dir)

if __name__ == "__main__":
    unittest.main() 