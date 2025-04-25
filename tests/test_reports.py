import unittest
import tempfile
import os
from pathlib import Path
from secauditai.reports import ReportGenerator

class TestReports(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.report_generator = ReportGenerator()
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

    def test_generate_json_report(self):
        report_path = self.report_generator.generate_json_report(
            self.sample_results,
            str(self.test_dir)
        )
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(report_path.endswith(".json"))

    def test_generate_html_report(self):
        report_path = self.report_generator.generate_html_report(
            self.sample_results,
            str(self.test_dir)
        )
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(report_path.endswith(".html"))

    def test_generate_pdf_report(self):
        report_path = self.report_generator.generate_pdf_report(
            self.sample_results,
            str(self.test_dir)
        )
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(report_path.endswith(".pdf"))

    def test_list_reports(self):
        # Generate a report first
        self.report_generator.generate_json_report(
            self.sample_results,
            str(self.test_dir)
        )
        
        reports = self.report_generator.list_reports()
        self.assertIsInstance(reports, list)
        self.assertTrue(len(reports) > 0)

    def tearDown(self):
        for file in Path(self.test_dir).glob("*"):
            os.remove(file)
        os.rmdir(self.test_dir)

if __name__ == "__main__":
    unittest.main() 