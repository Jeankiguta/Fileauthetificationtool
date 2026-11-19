import hashlib
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import file_integrity_checker as fic


def run_quietly(func, *args):
    """Run a function and return everything it printed."""
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        result = func(*args)
    return result, buffer.getvalue()


class TestFileIntegrityChecker(unittest.TestCase):

    def setUp(self):
        # Make a fresh temporary folder and test file for every test
        self.folder = tempfile.TemporaryDirectory()
        self.file = os.path.join(self.folder.name, "notes.txt")
        with open(self.file, "w") as f:
            f.write("Patient notes v1")

    def tearDown(self):
        self.folder.cleanup()

    # ---------- Calculate Hash ----------
    def test_01_hash_is_correct(self):
        expected = hashlib.sha256(b"Patient notes v1").hexdigest()
        result, _ = run_quietly(fic.calculate_file_hash, self.file)
        self.assertEqual(result, expected)

    def test_02_empty_file(self):
        open(self.file, "w").close()
        expected = hashlib.sha256(b"").hexdigest()
        result, _ = run_quietly(fic.calculate_file_hash, self.file)
        self.assertEqual(result, expected)

    def test_03_large_file_over_64kb(self):
        data = os.urandom(500_000)
        with open(self.file, "wb") as f:
            f.write(data)
        result, _ = run_quietly(fic.calculate_file_hash, self.file)
        self.assertEqual(result, hashlib.sha256(data).hexdigest())

    def test_04_hash_missing_file(self):
        result, output = run_quietly(fic.calculate_file_hash, "no_such_file.txt")
        self.assertIsNone(result)
        self.assertIn("could not be found", output)

    def test_05_hash_no_permission(self):
        with patch("builtins.open", side_effect=PermissionError):
            result, output = run_quietly(fic.calculate_file_hash, self.file)
        self.assertIsNone(result)
        self.assertIn("Not allowed", output)

    # ---------- Create Baseline ----------
    def test_06_baseline_creates_hash_file(self):
        _, output = run_quietly(fic.generate_integrity_signature, self.file)
        self.assertTrue(os.path.exists(self.file + ".hash"))
        self.assertIn("Baseline saved", output)

    def test_07_baseline_missing_file(self):
        _, output = run_quietly(fic.generate_integrity_signature, "no_such_file.txt")
        self.assertIn("File not found", output)
        self.assertFalse(os.path.exists("no_such_file.txt.hash"))

    # ---------- Check File ----------
    def test_08_check_unchanged_file(self):
        run_quietly(fic.generate_integrity_signature, self.file)
        _, output = run_quietly(fic.verify_file_integrity, self.file)
        self.assertIn("SUCCESS", output)

    def test_09_check_changed_file(self):
        run_quietly(fic.generate_integrity_signature, self.file)
        with open(self.file, "a") as f:
            f.write(" tampered")
        _, output = run_quietly(fic.verify_file_integrity, self.file)
        self.assertIn("WARNING", output)

    def test_10_check_one_byte_change(self):
        run_quietly(fic.generate_integrity_signature, self.file)
        with open(self.file, "w") as f:
            f.write("Patient notes v2")
        _, output = run_quietly(fic.verify_file_integrity, self.file)
        self.assertIn("WARNING", output)

    def test_11_check_missing_hash_file(self):
        _, output = run_quietly(fic.verify_file_integrity, self.file)
        self.assertIn("missing", output)

    def test_12_check_missing_file(self):
        _, output = run_quietly(fic.verify_file_integrity, "no_such_file.txt")
        self.assertIn("File not found", output)

    def test_13_check_unreadable_file_is_not_false_alarm(self):
        run_quietly(fic.generate_integrity_signature, self.file)
        with patch.object(fic, "calculate_file_hash", return_value=None):
            _, output = run_quietly(fic.verify_file_integrity, self.file)
        self.assertIn("Could not read", output)
        self.assertNotIn("WARNING", output)

    # ---------- Main Menu ----------
    def test_14_menu_exit(self):
        with patch("builtins.input", side_effect=["3"]):
            _, output = run_quietly(fic.main)
        self.assertIn("Goodbye", output)

    def test_15_menu_invalid_choice(self):
        with patch("builtins.input", side_effect=["9", "3"]):
            _, output = run_quietly(fic.main)
        self.assertIn("Invalid choice", output)

    def test_16_menu_full_run(self):
        answers = ["1", self.file, "2", self.file, "3"]
        with patch("builtins.input", side_effect=answers):
            _, output = run_quietly(fic.main)
        self.assertIn("Baseline saved", output)
        self.assertIn("SUCCESS", output)

    def test_17_menu_path_with_quotes(self):
        answers = ["1", f'"{self.file}"', "3"]
        with patch("builtins.input", side_effect=answers):
            _, output = run_quietly(fic.main)
        self.assertIn("Baseline saved", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
