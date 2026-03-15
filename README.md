# nmmm-extractor

Decrypt and extract Samsung Memo backups (`.nmmm` files) created by Samsung Kies or Smart Switch.

If you've ever found an old `.nmmm` file on your computer and had no way to open it — this tool recovers your memos, recipes, notes, photos, and everything else inside.

## What it does

Takes a `.nmmm` backup file and extracts:

- **All memo text** — titles, content, timestamps, categories
- **Photo attachments** — images embedded in memos, saved as JPEGs/PNGs
- **SQLite database** — the original `memo.db` for advanced queries
- **Multiple output formats** — text and   JSON

## Quick start

```bash
# Install the only dependency
pip install cryptography

# Extract a backup
python nmmm_extractor.py your_backup.nmmm

# Output goes to your_backup_extracted/
```

That's it. No password needed for standard Kies/Smart Switch backups.

## Usage

```
python nmmm_extractor.py <input.nmmm> [output_directory] [options]
```

### Arguments

| Argument | Description |
|---|---|
| `input` | Path to the `.nmmm` backup file |
| `output` | Output directory (default: `<input_stem>_extracted`) |

### Options

| Option | Description |
|---|---|
| `--session-key KEY` | Session key for memo.bk decryption (auto-detected by default) |
| `--format {text,json,all}` | Output format (default: `all`) |
| `-v, --verbose` | Enable verbose logging |

### Examples

```bash
# Basic extraction
python nmmm_extractor.py srini_memos.nmmm

# Specify output directory
python nmmm_extractor.py srini_memos.nmmm ./my_memos

# JSON only
python nmmm_extractor.py srini_memos.nmmm --format json

# Verbose output for debugging
python nmmm_extractor.py srini_memos.nmmm -v
 
```

## Output structure

```
output_directory/
├── memos.txt       # Human-readable text file with all memos
├── memos.json      # Structured JSON for programmatic use
├── memo.db         # Original SQLite database
└── images/         # Extracted photo attachments
    ├── photo1.jpg
    └── photo2.jpg
```

## How it works

Samsung Memo `.nmmm` files use a two-layer encryption scheme:

### Layer 1: Kies container (AES-256-CBC)

The outer container is a Samsung Kies/Smart Switch backup format. The file is divided into 272-byte blocks:

- Each block = 256 bytes of AES-256-CBC encrypted data + 16 bytes of PKCS5 padding (`0x10` × 16)
- The first 2 blocks (544 bytes) form an XML header with metadata (version, compression type, etc.)
- The remaining blocks contain ZLib-compressed data
- Each block is encrypted independently with the same key and IV
- The AES key and IV are hardcoded in Samsung's Kies3.exe and SmartSwitchPC.exe binaries

After decryption and decompression, you get a ZIP archive containing `filelist.xml`, `Manifest.xml`, and `memo.bk`.

### Layer 2: Memo app encryption (AES-128-CBC)

The `memo.bk` file is encrypted by the Samsung Memo app itself:

- AES key = `SHA-256(session_key)[:16]` (first 16 bytes of the SHA-256 hash)
- IV = first 16 bytes of the `memo.bk` file
- The session key is passed from Kies/Smart Switch to the Memo app via an Android Intent
- For standard backups (no user password), the session key is `"RANDOM"`

After decryption, `memo.bk` yields a ZIP containing `memo.db` (SQLite database with all memo text) and an `app_attach/` directory with image attachments stored as `.blob` files (actually JPEGs/PNGs).

### Encryption key source

The AES-256 key and IV for Layer 1 were extracted from Samsung's own software:

- **Kies3.exe** — key found at file offset `0x47d79c`
- **SmartSwitchPC.exe** — same key found at file offset `0x782164`

The Layer 2 session key `"RANDOM"` was identified by analyzing the decompiled Samsung Memo APK (`BackupMemoTask.java`) and brute-forcing candidate strings from the Samsung binaries.

## Tested with

- Samsung Galaxy S5 (SM-G900A), Android 5.0
- Kies4-era backups (2015–2017)
- Samsung Smart Switch PC

The encryption keys are consistent across Kies3 and Smart Switch. Other Samsung devices and Android versions from the same era should work. If you encounter a backup that doesn't decrypt, please open an issue.

## Requirements

- Python 3.8+
- [`cryptography`](https://pypi.org/project/cryptography/) package

```bash
pip install cryptography
```

No other dependencies. The script uses only the Python standard library plus `cryptography` for AES decryption.

## Troubleshooting

**"Could not decrypt memo.bk with any known session key"**
The backup may use a user-set password. Try `--session-key` with the password you used when creating the backup in Kies/Smart Switch.

**"Could not find XML header in decrypted data"**
The file may not be a valid `.nmmm` Samsung Memo backup, or it may use a different encryption key (e.g., from a significantly newer version of Smart Switch). Open an issue with the file size and first 64 bytes (hex) of your file.

**"Decompression failed"**
The container decrypted but the payload isn't valid compressed data. This could indicate a different Kies version or a corrupted file.

## Related formats

Samsung Kies/Smart Switch uses the same outer encryption container for other backup types:

| Extension | Content |
|---|---|
| `.nmmm` | Samsung Memo |
| `.spb` | Contacts |
| `.ssm` | SMS messages |
| `.ssc` | Call log |
| `.sme` | MMS messages |
| `.scl` | Calendar |
| `.sal` | Alarm |

This tool handles `.nmmm` files specifically. The Kies container decryption (Layer 1) is the same across all formats — only the inner content structure differs.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- [Smartphone-Backup-Data-Extractor](https://github.com/JaehyeokHan/Smartphone-Backup-Data-Extractor) by Jaehyeok Han — documented the Kies block structure (256-byte blocks + 16-byte padding, 2-block XML header). Note: the published source has zeroed-out keys and does not support `.nmmm` files. The actual AES keys, IV, and session key in this tool were independently extracted from Samsung's Kies3.exe and SmartSwitchPC.exe binaries. 
