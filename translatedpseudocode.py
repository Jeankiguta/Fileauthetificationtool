import hashlib
import os


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


if __name__ == "__main__":
    main()
