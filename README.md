# Textlock

Simple tool to encrypt and decrypt text files.

## Usage

```bash
git clone https://github.com/felix/textlock
cd textlock

# Setup password (first time only)
./textlock setup

# Encrypt a file
./textlock encrypt my_diary.txt

# Decrypt a file
./textlock decrypt vault/1234.enc

# List encrypted files
./textlock list
```

# Notes

Encrypted files are stored in the relative `vault` directory.

