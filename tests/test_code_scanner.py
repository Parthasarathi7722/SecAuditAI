import unittest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from secauditai.plugins.scanners.code_scanner import CodeScanner

class TestCodeScanner(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.scanner = CodeScanner()
        
        # Create test files
        self.python_file = Path(self.test_dir) / "test.py"
        self.python_file.write_text("""
password = "secret123"
api_key = "sk_test_1234567890"
        
def query_database(user_input):
    cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")
        
def render_page(user_input):
    document.write(user_input)
    eval(user_input)
        """)
        
        self.js_file = Path(self.test_dir) / "test.js"
        self.js_file.write_text("""
const token = "ghp_1234567890";
        
function queryDB(input) {
    db.query(`SELECT * FROM users WHERE username = '${input}'`);
}
        
function render(input) {
    document.innerHTML = input;
    eval(input);
}
        """)

    def test_load_languages(self):
        languages = self.scanner._load_languages()
        self.assertIn("python", languages)
        self.assertIn("javascript", languages)

    def test_load_checks(self):
        checks = self.scanner._load_checks()
        self.assertIn("hardcoded_secrets", checks)
        self.assertIn("sql_injection", checks)
        self.assertIn("xss", checks)

    def test_check_hardcoded_secrets(self):
        findings = self.scanner._check_hardcoded_secrets(
            self.python_file.read_text(),
            "python"
        )
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["severity"], "high")

    def test_check_sql_injection(self):
        findings = self.scanner._check_sql_injection(
            self.python_file.read_text(),
            "python"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "high")

    def test_check_xss(self):
        findings = self.scanner._check_xss(
            self.python_file.read_text(),
            "python"
        )
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["severity"], "high")

    def test_scan_python(self):
        results = self.scanner.scan(str(self.python_file))
        self.assertEqual(len(results["findings"]), 5)
        self.assertEqual(results["summary"]["total_findings"], 5)

    def test_scan_javascript(self):
        results = self.scanner.scan(str(self.js_file))
        self.assertEqual(len(results["findings"]), 5)
        self.assertEqual(results["summary"]["total_findings"], 5)

    def test_invalid_path(self):
        with self.assertRaises(ValueError):
            self.scanner.scan("invalid/path")

    def test_unsupported_language(self):
        unsupported_file = Path(self.test_dir) / "test.xyz"
        unsupported_file.write_text("some code")
        
        with self.assertRaises(ValueError):
            self.scanner.scan(str(unsupported_file))

    def test_empty_file(self):
        empty_file = Path(self.test_dir) / "empty.py"
        empty_file.write_text("")
        
        results = self.scanner.scan(str(empty_file))
        self.assertEqual(len(results["findings"]), 0)

    def tearDown(self):
        for file in Path(self.test_dir).glob("*"):
            os.remove(file)
        os.rmdir(self.test_dir)

if __name__ == "__main__":
    unittest.main() 