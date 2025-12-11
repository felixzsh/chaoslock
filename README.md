# ChaosLock

CLI tool for securely encrypting files and random selection.

## Installation

```bash
git clone https://github.com/felix/chaoslock
cd chaoslock
pip install -r requirements.txt
```

## Usage

```bash
# Setup password (first time only)
python chaoslock.py setup

# Encrypt a file
python chaoslock.py encrypt my_diary.txt

# Decrypt a file
python chaoslock.py decrypt vault/1234.enc

# List encrypted files
python chaoslock.py list

# Get random number from encrypted files
python chaoslock.py rand

# Get random number excluding recent files
python chaoslock.py rand --exclude-last-days=7
```

## Commands

- `setup` - Configure system password
- `encrypt <file>` - Encrypt a file (stores in `vault/` with 4-digit name)
- `decrypt <file>` - Decrypt and display file contents
- `list` - List all encrypted files in vault
- `rand [--exclude-last-days=<days>]` - Get random number from encrypted files, optionally excluding recent files

## Notes

- Encrypted files are stored in the `vault/` directory
- Files are named with 4-digit numbers (0000-9999.enc)
- Original files are cleared after encryption
- Use `--help` flag for command-specific help

