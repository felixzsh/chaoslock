#!/usr/bin/env python3
import sys
import os
import hashlib
import random
from cryptography.fernet import Fernet
import base64
import datetime

PASSWORD_FILE = ".password_hash"
VAULT_DIR = "vault"


def get_password(prompt="Password: "):
    """Get password with asterisks display"""
    import termios
    import tty

    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    sys.stdout.write(prompt)
    sys.stdout.flush()
    password = []

    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch == "\n" or ch == "\r":
                sys.stdout.write("\r\n")
                break
            elif ch == "\x03":  # Ctrl-C
                raise KeyboardInterrupt
            elif ch == "\x7f":  # Backspace
                if password:
                    password.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            else:
                password.append(ch)
                sys.stdout.write("*")
                sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    return "".join(password)


def hash_password(password):
    """Create SHA-256 hash of password"""
    return hashlib.sha256(password.encode()).hexdigest()


def setup():
    """Setup password for first use"""
    if os.path.exists(PASSWORD_FILE):
        print(
            "System already configured, rm .password_hash to setup the password again."
        )
        return False

    password = get_password("Enter password: ")
    confirm = get_password("Confirm password: ")

    if password != confirm:
        print("Error: Passwords don't match.")
        return False

    if len(password) < 8:
        print("Warning: Password is too short (minimum 8 characters recommended).")

    with open(PASSWORD_FILE, "w") as f:
        f.write(hash_password(password))

    print(f"Password configured successfully. Hash file created: {PASSWORD_FILE}")
    return True


def validate_password(password):
    """Validate password against stored hash"""
    if not os.path.exists(PASSWORD_FILE):
        print("Error: System not configured. Run 'setup' first.")
        return False

    with open(PASSWORD_FILE, "r") as f:
        stored_hash = f.read().strip()

    return hash_password(password) == stored_hash


def generate_key(password):
    """Generate encryption key from password"""
    salt = b"fixed_salt_for_simplicity"
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, 32)
    return base64.urlsafe_b64encode(key)


def get_existing_filenames():
    """Get set of existing 4-digit encrypted filenames"""
    if not os.path.exists(VAULT_DIR):
        return set()

    existing = set()
    for filename in os.listdir(VAULT_DIR):
        if filename.endswith(".enc") and len(filename) == 8:
            try:
                num = int(filename[:4])
                if 0 <= num <= 9999:
                    existing.add(num)
            except ValueError:
                continue
    return existing


def generate_unique_filename():
    """Generate unique 4-digit filename"""
    existing = get_existing_filenames()

    if len(existing) >= 10000:
        raise Exception("No available filenames (all 0000-9999 used)")

    while True:
        num = random.randint(0, 9999)
        if num not in existing:
            return f"{num:04d}.enc"


def encrypt(file_path):
    """Encrypt a file"""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' doesn't exist.")
        return False

    password = get_password("Enter password: ")
    if not validate_password(password):
        print("Error: Invalid password.")
        return False

    try:
        with open(file_path, "rb") as f:
            content = f.read()

        key = generate_key(password)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(content)

        filename = generate_unique_filename()
        encrypted_path = os.path.join(VAULT_DIR, filename)

        os.makedirs(VAULT_DIR, exist_ok=True)
        with open(encrypted_path, "wb") as f:
            f.write(encrypted)

        with open(file_path, "wb") as f:
            f.write(b"")

        print(f"File '{file_path}' encrypted as '{filename}' (original file cleared)")
        return True
    except Exception as e:
        print(f"Error encrypting file: {e}")
        return False


def decrypt(file_path):
    """Decrypt a file"""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' doesn't exist.")
        return False

    password = get_password("Enter password: ")
    if not validate_password(password):
        print("Error: Invalid password.")
        return False

    try:
        with open(file_path, "rb") as f:
            encrypted = f.read()

        key = generate_key(password)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)

        print(decrypted.decode())

        return True
    except Exception as e:
        print(f"Error decrypting file: {e}")
        return False


def list_files():
    """List encrypted files"""
    if not os.path.exists(VAULT_DIR):
        print(f"No encrypted files in '{VAULT_DIR}'")
        return

    files = []
    for filename in sorted(os.listdir(VAULT_DIR)):
        if filename.endswith(".enc") and len(filename) == 8:
            try:
                num = int(filename[:4])
                if 0 <= num <= 9999:
                    files.append(filename)
            except ValueError:
                continue

    if files:
        print("Encrypted files:")
        for f in files:
            print(f"  {f}")
    else:
        print(f"No encrypted files in '{VAULT_DIR}'")


def rand(exclude_last_days=None):
    """Return a random number from encrypted files, shuffling vault and optionally filtering by date

    Args:
        exclude_last_days (int, optional): Exclude files modified within the last N days
    """
    if not os.path.exists(VAULT_DIR):
        print(f"No encrypted files in '{VAULT_DIR}'")
        return False

    files = []
    now = datetime.datetime.now()

    for filename in os.listdir(VAULT_DIR):
        if filename.endswith(".enc") and len(filename) == 8:
            try:
                num = int(filename[:4])
                if 0 <= num <= 9999:
                    file_path = os.path.join(VAULT_DIR, filename)
                    mod_time = datetime.datetime.fromtimestamp(
                        os.path.getmtime(file_path)
                    )

                    if exclude_last_days is not None:
                        cutoff_time = now - datetime.timedelta(days=exclude_last_days)
                        if mod_time < cutoff_time:
                            files.append(num)
                    else:
                        files.append(num)
            except (ValueError, OSError):
                print(f"Error: Invalid file name. Skipping: {filename}")
                continue

    if not files:
        if exclude_last_days is not None:
            print(
                f"No encrypted files older than {exclude_last_days} days in '{VAULT_DIR}'"
            )
        else:
            print(f"No encrypted files in '{VAULT_DIR}'")
        return False

    random.shuffle(files)
    random_number = random.choice(files)
    print(random_number)
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python textlock.py <command> [arguments]")
        print("Commands:")
        print("  setup                    - Setup password")
        print("  encrypt <file>           - Encrypt file")
        print("  decrypt <encrypted_file> - Decrypt file")
        print("  list                     - List encrypted files")
        print(
            "  rand [--exclude-last-days=<days>] - Get random number from encrypted files"
        )
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "setup":
        setup()

    elif command == "encrypt":
        if len(sys.argv) < 3:
            print("Usage: python crypter.py crypt <file>")
            sys.exit(1)
        encrypt(sys.argv[2])

    elif command == "decrypt":
        if len(sys.argv) < 3:
            print("Usage: python crypter.py decrypt <encrypted_file>")
            sys.exit(1)
        decrypt(sys.argv[2])

    elif command == "list":
        list_files()

    elif command == "rand":
        exclude_days = None
        if len(sys.argv) > 2:
            for i in range(2, len(sys.argv)):
                if sys.argv[i].startswith("--exclude-last-days="):
                    try:
                        exclude_days = int(sys.argv[i].split("=")[1])
                        if exclude_days < 0:
                            print(
                                "Error: exclude-last-days must be a non-negative integer"
                            )
                            sys.exit(1)
                    except ValueError:
                        print("Error: exclude-last-days must be an integer")
                        sys.exit(1)
                else:
                    print(f"Error: Unknown argument '{sys.argv[i]}'")
                    print("Usage: python textlock.py rand [--exclude-last-days=<days>]")
                    sys.exit(1)
        rand(exclude_days)

    else:
        print(f"Error: Unknown command '{command}'")
        print("Valid commands: setup, encrypt, decrypt, list, rand")
        sys.exit(1)


if __name__ == "__main__":
    main()
