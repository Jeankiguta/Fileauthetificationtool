# Fileauthetificationtool
def calculate_file_hash(file_path):
    """
    Reads a file in binary mode and calculates its SHA-256 cryptographic hash.
    Ensures memory efficiency by reading large files in small blocks.
    """
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as target_file:
            # Read block by block (64KB chunks) to support files of any size safely
            for byte_block in iter(lambda: target_file.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"[-] Error: The file '{file_path}' could not be found.")
        return None
    except PermissionError:
        print(f"[-] Error: Insufficient permissions to access '{file_path}'.")
        return None

def generate_integrity_signature(file_path):
    """
    Calculates the hash of a file and saves it into a reference file 
    for future security verification.
    """
    if not os.path.exists(file_path):
        print("[-] Operation failed: Target file does not exist.")
        return

    print(f"[*] Calculating security baseline for: {os.path.basename(file_path)}")
    file_checksum = calculate_file_hash(file_path)
    
    if file_checksum:
        signature_file_path = file_path + ".hash"
        with open(signature_file_path, "w") as signature_file:
            signature_file.write(file_checksum)
        print(f"[+] Baseline successfully secured!")
        print(f"[+] Saved signature path: {signature_file_path}")
        print(f"[+] Cryptographic Checksum (SHA-256): {file_checksum}")

def verify_file_integrity(file_path):
    """
    Recalculates a file's hash and compares it directly against the 
    stored reference signature to detect tampering.
    """
    signature_file_path = file_path + ".hash"
    
    if not os.path.exists(file_path):
        print("[-] Verification halted: Target file missing.")
        return
    if not os.path.exists(signature_file_path):
        print("[-] Verification halted: Reference signature (.hash file) is missing.")
        print("[*] Hint: Run option 1 on the file first to create a baseline.")
        return

    print(f"[*] Analyzing file integrity structure for: {os.path.basename(file_path)}")
    
    # Extract the original expected signature
    with open(signature_file_path, "r") as signature_file:
        expected_signature = signature_file.read().strip()
        
    # Recalculate current status
    current_signature = calculate_file_hash(file_path)
    
    print("-" * 50)
    print(f"Expected Hash: {expected_signature}")
    print(f"Current Hash: {current_signature}")
    print("-" * 50)
    
    # Security Comparison Check
    if current_signature == expected_signature:
        print("🟢 SUCCESS: File integrity verified. No unauthorized changes detected.")
    else:
        print("🔴 WARNING: CRITICAL ALTERATION DETECTED!")
        print("⚠️ The file contents have been modified, compromised, or corrupted since creation.")

def display_menu():
    """Renders the command-line interface terminal controls."""
    print("\n" + "="*45)
    print(" CYBERSECURITY FILE INTEGRITY VAULT ")
    print("="*45)
    print("1. Generate File Hash Signature (Baseline)")
    print("2. Verify File Integrity (Check Tampering)")
    print("3. Exit System")
    print("="*45)

def main():
    while True:
        display_menu()
        user_choice = input("Select an administrative operation (1-3): ").strip()
        
        if user_choice == "1":
            target_path = input("Enter the file path to establish baseline: ").strip()
            generate_integrity_signature(target_path)
        elif user_choice == "2":
            target_path = input("Enter the file path to verify: ").strip()
            verify_file_integrity(target_path)
        elif user_choice == "3":
            print("[*] Shutting down security system. Goodbye.")
            break
        else:
            print("[-] Invalid selection. Please specify options 1, 2, or 3.")

if __name__ == "__main__":
    main()
