"""
FILE INTEGRITY CHECKER - AUTOMATED TEST (all-in-one file)
Just run this file. It tests the File Integrity Checker automatically.
No other files are needed.
"""

# =====================================================
# PART 1: THE FILE INTEGRITY CHECKER CODE
# =====================================================
import hashlib
import os
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file, 64 KB at a time."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as target_file:
            for byte_block in iter(lambda: target_file.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"[-] Error: The file '{file_path}' could not be found.")
        return None
    except PermissionError:
        print(f"[-] Error: Not allowed to open '{file_path}'.")
        return None


def generate_integrity_signature(file_path):
    """Create a baseline: save the file's hash to a .hash file."""
    if not os.path.exists(file_path):
        print("[-] File not found.")
        return

    file_checksum = calculate_file_hash(file_path)
    if file_checksum:
        signature_file_path = file_path + ".hash"
        with open(signature_file_path, "w") as signature_file:
            signature_file.write(file_checksum)
        print("[+] Baseline saved.")
        print(f"[+] Hash file: {signature_file_path}")
        print(f"[+] SHA-256: {file_checksum}")


def verify_file_integrity(file_path):
    """Check the file: compare its current hash with the saved hash."""
    signature_file_path = file_path + ".hash"

    if not os.path.exists(file_path):
        print("[-] File not found.")
        return
    if not os.path.exists(signature_file_path):
        print("[-] Saved hash (.hash file) missing. Run option 1 first.")
        return

    with open(signature_file_path, "r") as signature_file:
        expected_signature = signature_file.read().strip()
    current_signature = calculate_file_hash(file_path)

    if current_signature is None:
        print("[-] Could not read the file.")
        return

    print(f"Saved hash:   {expected_signature}")
    print(f"Current hash: {current_signature}")

    if current_signature == expected_signature:
        print("SUCCESS: File has not changed.")
    else:
        print("WARNING: File has been changed!")


def display_menu():
    print("\n" + "=" * 40)
    print("  CYBERSECURITY FILE INTEGRITY VAULT")
    print("=" * 40)
    print("1. Create baseline")
    print("2. Check file")
    print("3. Exit")


def main():
    while True:
        display_menu()
        user_choice = input("Choose 1-3: ").strip()

        if user_choice == "1":
            target_path = input("File path: ").strip().strip('"')
            generate_integrity_signature(target_path)
        elif user_choice == "2":
            target_path = input("File path: ").strip().strip('"')
            verify_file_integrity(target_path)
        elif user_choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Please pick 1, 2 or 3.")


# =====================================================
# PART 2: THE AUTOMATED TESTS
# =====================================================



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
        result, _ = run_quietly(calculate_file_hash, self.file)
        self.assertEqual(result, expected)

    def test_02_empty_file(self):
        open(self.file, "w").close()
        expected = hashlib.sha256(b"").hexdigest()
        result, _ = run_quietly(calculate_file_hash, self.file)
        self.assertEqual(result, expected)

    def test_03_large_file_over_64kb(self):
        data = os.urandom(500_000)
        with open(self.file, "wb") as f:
            f.write(data)
        result, _ = run_quietly(calculate_file_hash, self.file)
        self.assertEqual(result, hashlib.sha256(data).hexdigest())

    def test_04_hash_missing_file(self):
        result, output = run_quietly(calculate_file_hash, "no_such_file.txt")
        self.assertIsNone(result)
        self.assertIn("could not be found", output)

    def test_05_hash_no_permission(self):
        with patch("builtins.open", side_effect=PermissionError):
            result, output = run_quietly(calculate_file_hash, self.file)
        self.assertIsNone(result)
        self.assertIn("Not allowed", output)

    # ---------- Create Baseline ----------
    def test_06_baseline_creates_hash_file(self):
        _, output = run_quietly(generate_integrity_signature, self.file)
        self.assertTrue(os.path.exists(self.file + ".hash"))
        self.assertIn("Baseline saved", output)

    def test_07_baseline_missing_file(self):
        _, output = run_quietly(generate_integrity_signature, "no_such_file.txt")
        self.assertIn("File not found", output)
        self.assertFalse(os.path.exists("no_such_file.txt.hash"))

    # ---------- Check File ----------
    def test_08_check_unchanged_file(self):
        run_quietly(generate_integrity_signature, self.file)
        _, output = run_quietly(verify_file_integrity, self.file)
        self.assertIn("SUCCESS", output)

    def test_09_check_changed_file(self):
        run_quietly(generate_integrity_signature, self.file)
        with open(self.file, "a") as f:
            f.write(" tampered")
        _, output = run_quietly(verify_file_integrity, self.file)
        self.assertIn("WARNING", output)

    def test_10_check_one_byte_change(self):
        run_quietly(generate_integrity_signature, self.file)
        with open(self.file, "w") as f:
            f.write("Patient notes v2")
        _, output = run_quietly(verify_file_integrity, self.file)
        self.assertIn("WARNING", output)

    def test_11_check_missing_hash_file(self):
        _, output = run_quietly(verify_file_integrity, self.file)
        self.assertIn("missing", output)

    def test_12_check_missing_file(self):
        _, output = run_quietly(verify_file_integrity, "no_such_file.txt")
        self.assertIn("File not found", output)

    def test_13_check_unreadable_file_is_not_false_alarm(self):
        run_quietly(generate_integrity_signature, self.file)
        with patch(__name__ + ".calculate_file_hash", return_value=None):
            _, output = run_quietly(verify_file_integrity, self.file)
        self.assertIn("Could not read", output)
        self.assertNotIn("WARNING", output)

    # ---------- Main Menu ----------
    def test_14_menu_exit(self):
        with patch("builtins.input", side_effect=["3"]):
            _, output = run_quietly(main)
        self.assertIn("Goodbye", output)

    def test_15_menu_invalid_choice(self):
        with patch("builtins.input", side_effect=["9", "3"]):
            _, output = run_quietly(main)
        self.assertIn("Invalid choice", output)

    def test_16_menu_full_run(self):
        answers = ["1", self.file, "2", self.file, "3"]
        with patch("builtins.input", side_effect=answers):
            _, output = run_quietly(main)
        self.assertIn("Baseline saved", output)
        self.assertIn("SUCCESS", output)

    def test_17_menu_path_with_quotes(self):
        answers = ["1", f'"{self.file}"', "3"]
        with patch("builtins.input", side_effect=answers):
            _, output = run_quietly(main)
        self.assertIn("Baseline saved", output)


if __name__ == "__main__":
    unittest.main(verbosity=2, exit=False)
