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
                    ],
                    "reality_checks": [
                        {
                            "spec_pattern": "Database: (\\w+)",
                            "target_file": "requirements.txt",
                            "reality_pattern": "(?i)\\1",
                            "severity": "HIGH"
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

    def test_reality_check_pass(self):
        # Spec says Database: Postgres
        spec_content = "# Database\nDatabase: Postgres"
        # Requirements has postgres
        req_content = "psycopg2-binary\nPostgres==13.0"
        
        fmap = {"test.md": spec_content, "requirements.txt": req_content}
        
        results = self.scanner._audit(spec_content, ".md", strict=True, base_dir=".", def_src="test.md", fmap=fmap)
        checks = results["test_profile"]["checks"]
        
        # Find Reality Check
        rc = next(c for c in checks if c["id"].startswith("RealityCheck"))
        self.assertTrue(rc["passed"])
        self.assertEqual(rc["status"], "PASS")

    def test_reality_check_fail(self):
        # Spec says Database: Postgres
        spec_content = "# Database\nDatabase: Postgres"
        # Requirements has MySQL
        req_content = "mysql-connector"
        
        fmap = {"test.md": spec_content, "requirements.txt": req_content}
        
        results = self.scanner._audit(spec_content, ".md", strict=True, base_dir=".", def_src="test.md", fmap=fmap)
        checks = results["test_profile"]["checks"]
        
        # Find Reality Check
        rc = next(c for c in checks if c["id"].startswith("RealityCheck"))
        self.assertFalse(rc["passed"])
        self.assertEqual(rc["status"], "FAIL")
        self.assertEqual(rc["type"], "contradiction")

    def test_red_flag_detection(self):
        content = "Some text with FORBIDDEN_TEXT inside."
        results = self.scanner._audit(content, ".md", strict=True, base_dir=".", def_src="test.md", fmap={})
        checks = results["test_profile"]["checks"]
        
        flag_check = next(c for c in checks if c["type"] == "red_flag")
        self.assertFalse(flag_check["passed"])
        self.assertEqual(flag_check["severity"], "CRITICAL")

if __name__ == '__main__':
    unittest.main()
