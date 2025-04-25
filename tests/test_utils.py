import unittest
import tempfile
import os
from pathlib import Path
from secauditai.utils import (
    load_config,
    save_config,
    validate_config,
    format_findings,
    calculate_risk_score,
    get_language_parser
)

class TestUtils(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.sample_config = {
            "scanners": {
                "code": {"enabled": True},
                "sbom": {"enabled": True},
                "container": {"enabled": True}
            },
            "reporting": {
                "format": "json",
                "output_dir": str(self.test_dir)
            }
        }

    def test_load_config(self):
        config_path = os.path.join(self.test_dir, "config.json")
        with open(config_path, "w") as f:
            f.write('{"test": "value"}')
        config = load_config(config_path)
        self.assertEqual(config, {"test": "value"})

    def test_save_config(self):
        config_path = os.path.join(self.test_dir, "config.json")
        save_config(self.sample_config, config_path)
        self.assertTrue(os.path.exists(config_path))

    def test_validate_config(self):
        self.assertTrue(validate_config(self.sample_config))
        invalid_config = {"scanners": {}}
        self.assertFalse(validate_config(invalid_config))

    def test_format_findings(self):
        findings = [
            {
                "type": "vulnerability",
                "severity": "high",
                "title": "Test Vulnerability",
                "description": "Test Description"
            }
        ]
        formatted = format_findings(findings)
        self.assertIsInstance(formatted, str)
        self.assertIn("Test Vulnerability", formatted)

    def test_calculate_risk_score(self):
        findings = [
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"}
        ]
        score = calculate_risk_score(findings)
        self.assertIsInstance(score, float)
        self.assertTrue(0 <= score <= 100)

    def test_get_language_parser(self):
        parser = get_language_parser("python")
        self.assertIsNotNone(parser)
        self.assertIsNone(get_language_parser("invalid"))

    def tearDown(self):
        for file in Path(self.test_dir).glob("*"):
            os.remove(file)
        os.rmdir(self.test_dir)

if __name__ == "__main__":
    unittest.main() 