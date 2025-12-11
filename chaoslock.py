#!/usr/bin/env python3
"""TextLock - CLI for secure file encryption and management"""
import sys
import hashlib
import random
from pathlib import Path
from cryptography.fernet import Fernet
import base64
import datetime
import typer
from typing_extensions import Annotated

app = typer.Typer(help="Password-based file encryption system")

PASSWORD_FILE = ".password_hash"
VAULT_DIR = "vault"


def get_password(prompt: str = "Password: ") -> str:
    """Get password with asterisks display"""
    import termios
    import tty

    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    typer.echo(prompt, nl=False)
    password = []

    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\n", "\r"):
                typer.echo()
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


def hash_password(password: str) -> str:
    """Create SHA-256 hash of password"""
    return hashlib.sha256(password.encode()).hexdigest()


def validate_password(password: str) -> bool:
    """Validate password against stored hash"""
    if not Path(PASSWORD_FILE).exists():
        typer.secho("Error: System not configured. Run 'setup' first.", fg=typer.colors.RED)
        raise typer.Exit(1)

    stored_hash = Path(PASSWORD_FILE).read_text().strip()
    return hash_password(password) == stored_hash


def generate_key(password: str) -> bytes:
    """Generate encryption key from password"""
    salt = b"fixed_salt_for_simplicity"
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, 32)
    return base64.urlsafe_b64encode(key)


def get_existing_filenames() -> set:
    """Get set of existing 4-digit encrypted filenames"""
    vault_path = Path(VAULT_DIR)
    if not vault_path.exists():
        return set()

    existing = set()
    for file_path in vault_path.glob("*.enc"):
        if len(file_path.stem) == 4:
            try:
                num = int(file_path.stem)
                if 0 <= num <= 9999:
                    existing.add(num)
            except ValueError:
                continue
    return existing


def generate_unique_filename() -> str:
    """Generate unique 4-digit filename"""
    existing = get_existing_filenames()

    if len(existing) >= 10000:
        raise Exception("No available filenames (all 0000-9999 are in use)")

    while True:
        num = random.randint(0, 9999)
        if num not in existing:
            return f"{num:04d}.enc"


@app.command()
def setup():
    """Setup system password"""
    if Path(PASSWORD_FILE).exists():
        typer.secho(
            f"System already configured. Delete '{PASSWORD_FILE}' to reconfigure.",
            fg=typer.colors.YELLOW
        )
        raise typer.Exit(0)

    password = get_password("Enter password: ")
    confirm = get_password("Confirm password: ")

    if password != confirm:
        typer.secho("Error: Passwords don't match.", fg=typer.colors.RED)
        raise typer.Exit(1)

    if len(password) < 8:
        typer.secho("Warning: Password too short (minimum 8 characters recommended).", fg=typer.colors.YELLOW)

    Path(PASSWORD_FILE).write_text(hash_password(password))
    typer.secho(f"✓ Password configured successfully. Hash file created: {PASSWORD_FILE}", fg=typer.colors.GREEN)


@app.command()
def encrypt(file_path: Annotated[Path, typer.Argument(help="File to encrypt", exists=True, readable=True)]):
    """Encrypt a file"""
    password = get_password("Enter password: ")
    if not validate_password(password):
        typer.secho("Error: Invalid password.", fg=typer.colors.RED)
        raise typer.Exit(1)

    try:
        content = file_path.read_bytes()

        key = generate_key(password)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(content)

        filename = generate_unique_filename()
        vault_path = Path(VAULT_DIR)
        vault_path.mkdir(exist_ok=True)
        
        encrypted_path = vault_path / filename
        encrypted_path.write_bytes(encrypted)

        # Clear original file
        file_path.write_bytes(b"")

        typer.secho(f"✓ File '{file_path}' encrypted as '{filename}' (original file cleared)", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"Error encrypting file: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)


@app.command()
def decrypt(file_path: Annotated[Path, typer.Argument(help="Encrypted file to decrypt", exists=True, readable=True)]):
    """Decrypt and display file contents"""
    password = get_password("Enter password: ")
    if not validate_password(password):
        typer.secho("Error: Invalid password.", fg=typer.colors.RED)
        raise typer.Exit(1)

    try:
        encrypted = file_path.read_bytes()

        key = generate_key(password)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)

        typer.echo(decrypted.decode())
    except Exception as e:
        typer.secho(f"Error decrypting file: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)


@app.command(name="list")
def list_files():
    """List encrypted files"""
    vault_path = Path(VAULT_DIR)
    
    if not vault_path.exists():
        typer.secho(f"No encrypted files in '{VAULT_DIR}'", fg=typer.colors.YELLOW)
        return

    files = []
    for file_path in sorted(vault_path.glob("*.enc")):
        if len(file_path.stem) == 4:
            try:
                num = int(file_path.stem)
                if 0 <= num <= 9999:
                    files.append(file_path.name)
            except ValueError:
                continue

    if files:
        typer.secho("Encrypted files:", fg=typer.colors.CYAN, bold=True)
        for f in files:
            typer.echo(f"  {f}")
    else:
        typer.secho(f"No encrypted files in '{VAULT_DIR}'", fg=typer.colors.YELLOW)


@app.command()
def rand(
    exclude_last_days: Annotated[int | None, typer.Option(help="Exclude files modified in the last N days")] = None
):
    """Get a random number from encrypted files"""
    vault_path = Path(VAULT_DIR)
    
    if not vault_path.exists():
        typer.secho(f"No encrypted files in '{VAULT_DIR}'", fg=typer.colors.YELLOW)
        raise typer.Exit(1)

    files = []
    now = datetime.datetime.now()

    for file_path in vault_path.glob("*.enc"):
        if len(file_path.stem) == 4:
            try:
                num = int(file_path.stem)
                if 0 <= num <= 9999:
                    mod_time = datetime.datetime.fromtimestamp(file_path.stat().st_mtime)

                    if exclude_last_days is not None:
                        cutoff_time = now - datetime.timedelta(days=exclude_last_days)
                        if mod_time < cutoff_time:
                            files.append(num)
                    else:
                        files.append(num)
            except (ValueError, OSError) as e:
                typer.secho(f"Invalid file name. Skipping: {file_path.name}. Error: {e}", fg=typer.colors.YELLOW)
                continue

    if not files:
        msg = f"No encrypted files"
        if exclude_last_days is not None:
            msg += f" older than {exclude_last_days} days"
        msg += f" in '{VAULT_DIR}'"
        typer.secho(msg, fg=typer.colors.YELLOW)
        raise typer.Exit(1)

    random.shuffle(files)
    random_number = random.choice(files)
    typer.echo(random_number)


if __name__ == "__main__":
    app()
