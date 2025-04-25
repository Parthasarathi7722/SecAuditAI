import unittest
import tempfile
import os
from pathlib import Path
from secauditai.plugins.scanners import (
    CodeScanner,
    SBOMScanner,
    ContainerScanner,
    CloudScanner
)

class TestScanners(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.test_file = Path(self.test_dir) / "test.py"
        self.test_file.write_text("""
def vulnerable_function():
    password = "secret123"
    query = "SELECT * FROM users WHERE id = " + user_input
    return query
""")

    def test_code_scanner(self):
        scanner = CodeScanner()
        results = scanner.scan(str(self.test_file))
        self.assertIsNotNone(results)
        self.assertIn("findings", results)
        self.assertIn("summary", results)

    def test_sbom_scanner(self):
        scanner = SBOMScanner()
        results = scanner.scan(str(self.test_dir))
        self.assertIsNotNone(results)
        self.assertIn("findings", results)
        self.assertIn("summary", results)

    def test_container_scanner(self):
        scanner = ContainerScanner()
        results = scanner.scan("nginx:latest")
        self.assertIsNotNone(results)
        self.assertIn("findings", results)
        self.assertIn("summary", results)

    def test_cloud_scanner(self):
        scanner = CloudScanner()
        results = scanner.scan("aws")
        self.assertIsNotNone(results)
        self.assertIn("findings", results)
        self.assertIn("summary", results)

    def tearDown(self):
        os.remove(self.test_file)
        os.rmdir(self.test_dir)

if __name__ == "__main__":
    unittest.main() 