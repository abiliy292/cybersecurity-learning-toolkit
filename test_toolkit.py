import tempfile
import unittest
from pathlib import Path

from toolkit import analyze_log, check_password_strength, sha256_file


class ToolkitTests(unittest.TestCase):
    def test_password_checker_returns_feedback(self):
        label, suggestions = check_password_strength("short")
        self.assertIn(label, {"Weak (basic estimate)", "Moderate (basic estimate)", "Strong (basic estimate)"})
        self.assertTrue(suggestions)

    def test_sha256_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.txt"
            path.write_text("hello", encoding="utf-8")
            self.assertEqual(
                sha256_file(str(path)),
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            )

    def test_analyze_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.log"
            path.write_text(
                "Failed password for user\nAccepted password for user\nAccount locked\n",
                encoding="utf-8",
            )
            self.assertEqual(analyze_log(str(path)), {"failed": 1, "successful": 1, "locked": 1})


if __name__ == "__main__":
    unittest.main()
