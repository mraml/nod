import unittest
import os
import tempfile
import shutil
from src.nod.config import load_rules
from src.nod.scanner import Scanner
from src.nod.utils import clean_header

class TestNodCore(unittest.TestCase):

    def setUp(self):
        # Create a dummy rule set for testing
        self.test_rules = {
            "profiles": {
                "test_profile": {
                    "badge_label": "Test Profile",
                    "requirements": [
                        {
                            "id": "#+.*Required Header",
                            "severity": "HIGH",
                            "remediation": "Must have header",
                            "must_match": [
                                {"pattern": "Value: \\d+", "message": "Must be number"}
                            ]
                        }
                    ],
                    "red_flags": [
                        {
                            "pattern": "FORBIDDEN_TEXT",
                            "severity": "CRITICAL",
                            "remediation": "Do not include forbidden text"
                        }
                    ]
                }
            }
        }
        self.scanner = Scanner(self.test_rules, ignored_rules=[])

    def test_clean_header(self):
        self.assertEqual(clean_header("#+.*Risk Analysis"), "Risk Analysis")
        self.assertEqual(clean_header("## Data Privacy"), "Data Privacy")
        self.assertEqual(clean_header("Header.*Pattern"), "Header Pattern")

    def test_scanner_pass(self):
        content = "# Required Header\nValue: 123"
        results = self.scanner._audit(content, ".md", strict=True, base_dir=".", def_src="test.md", fmap={})
        checks = results["test_profile"]["checks"]
        
        # Should have 1 check (Requirement)
        self.assertEqual(len(checks), 1)
        self.assertTrue(checks[0]["passed"])
        self.assertEqual(checks[0]["status"], "PASS")

    def test_scanner_fail_missing_header(self):
        content = "# Wrong Header"
        results = self.scanner._audit(content, ".md", strict=True, base_dir=".", def_src="test.md", fmap={})
        checks = results["test_profile"]["checks"]
        
        self.assertFalse(checks[0]["passed"])
        self.assertEqual(checks[0]["status"], "FAIL")

    def test_scanner_fail_deep_validation(self):
        # Header present, but value is wrong (ABC instead of number)
        content = "# Required Header\nValue: ABC"
        results = self.scanner._audit(content, ".md", strict=True, base_dir=".", def_src="test.md", fmap={})
        checks = results["test_profile"]["checks"]
        
        self.assertFalse(checks[0]["passed"])
        self.assertIn("Must be number", checks[0]["remediation"])

    def test_red_flag_detection(self):
        content = "Some text with FORBIDDEN_TEXT inside."
        results = self.scanner._audit(content, ".md", strict=True, base_dir=".", def_src="test.md", fmap={})
        checks = results["test_profile"]["checks"]
        
        # Should have 2 checks: 1 Req (Fail) + 1 Red Flag (Fail)
        self.assertEqual(len(checks), 2)
        
        flag_check = next(c for c in checks if c["type"] == "red_flag")
        self.assertFalse(flag_check["passed"])
        self.assertEqual(flag_check["severity"], "CRITICAL")

    def test_ignore_logic(self):
        # Ignore the requirement
        self.scanner.ignored_rules = ["#+.*Required Header"]
        content = "# Wrong Header"
        results = self.scanner._audit(content, ".md", strict=True, base_dir=".", def_src="test.md", fmap={})
        checks = results["test_profile"]["checks"]
        
        self.assertTrue(checks[0]["passed"])
        self.assertEqual(checks[0]["status"], "EXCEPTION")

if __name__ == '__main__':
    unittest.main()
