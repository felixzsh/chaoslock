import sys
import hashlib
import random
from pathlib import Path
from cryptography.fernet import Fernet
import base64
import datetime
import typer
from typing import Annotated
from . import vault

app = typer.Typer(help="Password-based file encryption system")

PASSWORD_FILE = ".password_hash"


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
                typer.echo("\r")
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
        typer.secho(
            "Error: System not configured. Run 'setup' first.", fg=typer.colors.RED
        )
        raise typer.Exit(1)

    stored_hash = Path(PASSWORD_FILE).read_text().strip()
    return hash_password(password) == stored_hash


def generate_key(password: str) -> bytes:
    """Generate encryption key from password"""
    salt = b"fixed_salt_for_simplicity"
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000, 32)
    return base64.urlsafe_b64encode(key)


@app.command()
def setup():
    """Setup system password"""
    if Path(PASSWORD_FILE).exists():
        typer.secho(
            f"System already configured. Delete '{PASSWORD_FILE}' to reconfigure.",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(0)

    password = get_password("Enter password: ")
    confirm = get_password("Confirm password: ")

    if password != confirm:
        typer.secho("Error: Passwords don't match.", fg=typer.colors.RED)
        raise typer.Exit(1)

    if len(password) < 8:
        typer.secho(
            "Warning: Password too short (minimum 8 characters recommended).",
            fg=typer.colors.YELLOW,
        )

    Path(PASSWORD_FILE).write_text(hash_password(password))
    typer.secho(
        f"✓ Password configured successfully. Hash file created: {PASSWORD_FILE}",
        fg=typer.colors.GREEN,
    )


@app.command()
def encrypt(
    file_path: Annotated[
        Path, typer.Argument(help="File to encrypt", exists=True, readable=True)
    ],
):
    """Encrypt a file"""
    password = get_password("Enter password: ")
    if not validate_password(password):
        typer.secho("Error: Invalid password.", fg=typer.colors.RED)
        raise typer.Exit(1)

    try:
        content = file_path.read_bytes()

        key = generate_key(password)
        fernet = Fernet(key)
        encrypted_content = fernet.encrypt(content)
        vault_id = vault.store(encrypted_content)
        file_path.write_bytes(b"")

        typer.secho(
            f"✓ File '{file_path}' encrypted as '{vault_id:04d}.enc' (original file cleared)",
            fg=typer.colors.GREEN,
        )
    except Exception as e:
        typer.secho(f"Error encrypting file: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)


@app.command()
def decrypt(
    file_path: Annotated[
        Path,
        typer.Argument(help="Encrypted file to decrypt", exists=True, readable=True),
    ],
):
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

    files = vault.get_file_ids()

    if files:
        typer.secho("Encrypted files:", fg=typer.colors.CYAN, bold=True)
        for f in sorted(files):
            typer.echo(f"  {f:04d}.enc")
    else:
        typer.secho(
            f"No encrypted files in '{vault.VAULT_DIR}'", fg=typer.colors.YELLOW
        )


@app.command()
def use(
    file_id: Annotated[str, typer.Argument(help="4-digit file ID to mark as used")],
):
    if len(file_id) != 4 or not file_id.isdigit():
        typer.secho(
            "Error: ID must be a 4-digit number (0000-9999)", fg=typer.colors.RED
        )
        raise typer.Exit(1)

    file_id_int = int(file_id)

    if not vault.file_exists(file_id_int):
        typer.secho(
            f"Error: File '{file_id_int:04d}.enc' does not exist in vault",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    if vault.mark_as_used(file_id_int):
        typer.secho(
            f"✓ ID '{file_id_int:04d}' marked as used at {datetime.datetime.now().isoformat()}",
            fg=typer.colors.GREEN,
        )
    else:
        typer.secho(
            f"Error: Failed to mark ID '{file_id_int:04d}' as used", fg=typer.colors.RED
        )
        raise typer.Exit(1)


@app.command()
def rand(
    exclude_last_days: Annotated[
        int | None, typer.Option(help="Exclude files modified in the last N days")
    ] = None,
    exclude_used_days: Annotated[
        int | None, typer.Option(help="Exclude files used in the last N days")
    ] = None,
):
    """Get a random number from encrypted files"""
    metadata = vault.get_metadata()

    if not metadata:
        typer.secho(
            f"No encrypted files in '{vault.VAULT_DIR}'", fg=typer.colors.YELLOW
        )
        raise typer.Exit(1)

    now = datetime.datetime.now()
    eligible_ids = []

    for file_id, file_metadata in metadata.items():
        try:
            if exclude_last_days is not None:
                created_at_str = file_metadata.get("created_at")
                if created_at_str:
                    created_at = datetime.datetime.fromisoformat(created_at_str)
                    cutoff_time = now - datetime.timedelta(days=exclude_last_days)
                    if created_at >= cutoff_time:
                        continue

            if exclude_used_days is not None:
                last_used_at_str = file_metadata.get("last_used_at")
                if last_used_at_str:
                    last_used_at = datetime.datetime.fromisoformat(last_used_at_str)
                    cutoff_time = now - datetime.timedelta(days=exclude_used_days)
                    if last_used_at >= cutoff_time:
                        continue

            eligible_ids.append(file_id)

        except (ValueError, KeyError) as e:
            typer.secho(
                f"Invalid metadata for ID '{file_id}'. Skipping. Error: {e}",
                fg=typer.colors.YELLOW,
            )
            continue

    if not eligible_ids:
        msg = "No encrypted files"
        if exclude_last_days is not None:
            msg += f" older than {exclude_last_days} days"
        if exclude_used_days is not None:
            if exclude_last_days is not None:
                msg += " and"
            msg += f" not used in the last {exclude_used_days} days"
        msg += f" in '{vault.VAULT_DIR}'"
        typer.secho(msg, fg=typer.colors.YELLOW)
        raise typer.Exit(1)

    random.shuffle(eligible_ids)
    random_number = random.choice(eligible_ids)
    typer.echo(random_number)


if __name__ == "__main__":
    app()
