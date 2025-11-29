import unittest
import tempfile
import os
from pathlib import Path
from secauditai.reports import ReportGenerator

class TestReporting(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.sample_results = {
            "scan_type": "code",
            "target": "test.py",
            "findings": [
                {
                    "type": "vulnerability",
                    "severity": "high",
                    "title": "SQL Injection",
                    "description": "Potential SQL injection vulnerability",
                    "remediation": "Use parameterized queries"
                }
            ],
            "metadata": {
                "scanner_version": "1.0.0",
                "scan_duration": "0.5s"
            }
        }

    def test_generate_report_json(self):
        generator = ReportGenerator()
        report_path = os.path.join(self.test_dir, "report.json")
        generator.generate_report(self.sample_results, report_path, "json")
        self.assertTrue(os.path.exists(report_path))

    def test_generate_report_html(self):
        generator = ReportGenerator()
        report_path = os.path.join(self.test_dir, "report.html")
        generator.generate_report(self.sample_results, report_path, "html")
        self.assertTrue(os.path.exists(report_path))

    def test_generate_report_pdf(self):
        generator = ReportGenerator()
        report_path = os.path.join(self.test_dir, "report.pdf")
        generator.generate_report(self.sample_results, report_path, "pdf")
        self.assertTrue(os.path.exists(report_path))

    def test_generate_report_csv(self):
        generator = ReportGenerator()
        report_path = os.path.join(self.test_dir, "report.csv")
        generator.generate_report(self.sample_results, report_path, "csv")
        self.assertTrue(os.path.exists(report_path))

    def test_invalid_format(self):
        generator = ReportGenerator()
        report_path = os.path.join(self.test_dir, "report.txt")
        with self.assertRaises(ValueError):
            generator.generate_report(self.sample_results, report_path, "txt")

    def test_report_metadata(self):
        generator = ReportGenerator()
        report_path = os.path.join(self.test_dir, "report.json")
        generator.generate_report(self.sample_results, report_path, "json")
        
        with open(report_path, "r") as f:
            report = f.read()
            self.assertIn("SQL Injection", report)
            self.assertIn("1.0.0", report)

    def tearDown(self):
        for file in Path(self.test_dir).glob("*"):
            os.remove(file)
        os.rmdir(self.test_dir)

if __name__ == "__main__":
    unittest.main() 