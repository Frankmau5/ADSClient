# ADSClient (v1.0.0)

A cross-platform command-line utility, Flet desktop GUI, and Python library for inspecting, adding, extracting, copying, backing up, restoring, and clearing **NTFS Alternate Data Streams (ADS)** and extended attributes on files and directories.

## Overview

Alternate Data Streams (ADS) are a feature of the NTFS file system that allows additional data streams or metadata to be attached to a file without affecting its primary content or reported size in File Explorer. For example, Windows uses the `Zone.Identifier` stream to mark files downloaded from the internet (`ZoneId=3`).

`ADSClient` works on both **Windows** and **Linux**:
- **Windows:** Uses `kernel32.dll` (`FindFirstStreamW` / `FindNextStreamW`) and the `filename:streamname` syntax.
- **Linux (Mounted NTFS & Native Filesystems):** When an NTFS drive is mounted on Linux via `ntfs-3g` or the Linux kernel `ntfs3` driver (with the default `streams_interface=xattr`), NTFS Alternate Data Streams are mapped directly to POSIX Extended Attributes in the `user.` namespace (`user.<stream_name>`). `ADSClient` automatically uses `os.listxattr`, `os.getxattr`, `os.setxattr`, and `os.removexattr` on Linux (with a fallback to `filename:streamname` if mounted with `streams_interface=windows`), so it works on mounted NTFS drives as well as `ext4`, `btrfs`, and `xfs`.

## Features

- **Forensic Stream Inspection (`scan`):**
  - Calculates **SHA-256 hashes** for every discovered stream.
  - Performs **magic-byte file type detection** (detects hidden Windows PE `MZ` executables, Linux `ELF` binaries, `#!` scripts, ZIP/Office/RAR/7z/GZIP archives, PDFs, PNG/JPEG/GIF images, and UTF-8 text) and flags suspicious executable/script streams (`[SUSPICIOUS EXECUTABLE]`).
  - Automatically parses **`Zone.Identifier`** streams (`ZoneId`, human-readable Zone name, `HostUrl`, and `ReferrerUrl`).
  - Filter results with `--suspicious-only`, `--zone <0..4>`, `--pattern "<glob>"`, and `--no-recursive`.
  - Outputs in human-readable **Tree Text**, **JSON**, or **CSV** formats.
- **Safe Stream Clearing (`clear`):**
  - Supports `--dry-run` to preview exactly which streams and byte sizes would be removed before deleting anything.
  - Supports deleting default metadata streams (`Zone.Identifier`, `OECustomProperty`, `encryptable`), a specific stream (`--name`), or all streams (`--overwrite`).
- **Stream Creation, Extraction, Cloning & Backup (`add-str`, `add-file`, `extract`, `copy`, `export-all`, `restore`):**
  - Attach UTF-8 strings (`add-str`) or binary files (`add-file`, raw bytes by default or Base64 with `--base64`).
  - Extract individual streams (`extract`) or copy streams between files (`copy`).
  - Bulk-export all discovered streams across a directory tree into a backup folder with a `manifest.json` index (`export-all`), and restore them in one command (`restore`).
- **Flet Graphical User Interface (`--gui` / `gui`):**
  - Launch an interactive desktop GUI with native file/folder pickers, Zone & Suspicious filters, dry-run toggle, one-click stream extraction/deletion, backup/restore, and stream creation/cloning.

## Installation

```bash
pip install -r requirements.txt
# Or install as a package (provides the `adsclient` CLI command):
pip install -e ".[gui]"
```

## Usage

### Launch the Flet GUI

```bash
python main.py --gui
# Or using the subcommand with an initial path:
python main.py gui --path "C:\path\to\folder"
```

### CLI Commands

| Subcommand | Description |
| :--- | :--- |
| `scan <path>` | Scan a file or directory for ADS streams (with SHA-256, magic type, and `Zone.Identifier` parsing) |
| `clear <path>` | Clear metadata streams, a named stream (`--name`), or all streams (`--overwrite`), with `--dry-run` support |
| `add-str <path>` | Attach UTF-8 text data (`--data`) to a named stream (`--name`) |
| `add-file <path>` | Embed a binary file (`--data`) into a named stream (`--name`), optionally Base64-encoded (`--base64`) |
| `extract <path>` | Extract a named stream (`--name`) to a file (`--output`) or `stdout` |
| `export-all <path>` | Bulk-export all discovered streams into a backup directory (`--output`) with `manifest.json` |
| `restore <backup_dir>` | Restore backed-up streams from `<backup_dir>/manifest.json` to their original files |
| `copy <src> <dst>` | Copy one (`--name`) or all streams from `<src>` to `<dst>` |
| `gui` | Launch the Flet desktop GUI |

#### 1. Scan for ADS Streams (`scan`)

```bash
# Recursive scan with tree output (includes SHA-256, Type, and Zone.Identifier details)
python main.py scan "C:\path\to\folder_or_file"

# Non-recursive scan filtered to *.exe files, exported as JSON or CSV
python main.py scan "C:\path\to\folder" --no-recursive --pattern "*.exe" --format json
python main.py scan "C:\path\to\folder" --format csv

# Filter to ONLY suspicious executable/script streams or Internet-downloaded files (ZoneId=3)
python main.py scan "C:\path\to\folder" --suspicious-only
python main.py scan "C:\path\to\folder" --zone 3

# Scan and automatically back up all discovered streams to a directory
python main.py scan "C:\path\to\folder" --export-dir "./ads_backup"
```

Example `scan` output:
```text
File: C:\Downloads\installer.exe
  ├─ Stream: Zone.Identifier (72 B) | Type: UTF-8 Text
  │  SHA-256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  │  Zone.Identifier: Zone 3 (Internet) | HostUrl=https://example.com/installer.exe
  └─ Preview: [ZoneTransfer]\nZoneId=3\nHostUrl=https://example.com/installer.exe
  ├─ Stream: payload.bin (4.2 KB) | Type: Windows PE Executable (MZ) [SUSPICIOUS EXECUTABLE]
  │  SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  └─ Preview: <binary: 4d 5a 90 00 03 00 00 00...>
```

#### 2. Clear Metadata or Specific Streams (`clear`)

```bash
# Preview what would be deleted without removing anything (--dry-run)
python main.py clear "C:\path\to\folder" --dry-run

# Clear default metadata streams (Zone.Identifier, OECustomProperty, encryptable)
python main.py clear "C:\path\to\folder"

# Delete a single named stream
python main.py clear "C:\path\to\file.txt" --name "secret_note"

# Delete ALL ADS streams on matching files
python main.py clear "C:\path\to\folder" --overwrite --pattern "*.docx"
```

#### 3. Add Text Data (`add-str`)

```bash
python main.py add-str "C:\path\to\file.txt" --name "secret_note" --data "Hidden UTF-8 text" --overwrite
```

#### 4. Add Binary File Data (`add-file`)

```bash
# Store raw binary file in an ADS stream
python main.py add-file "C:\path\to\file.txt" --name "hidden_payload" --data "C:\path\to\binary.bin"

# Store as Base64-encoded data
python main.py add-file "C:\path\to\file.txt" --name "hidden_payload" --data "C:\path\to\binary.bin" --base64
```

#### 5. Extract a Single Stream (`extract`)

```bash
# Extract stream to a file on disk
python main.py extract "C:\path\to\file.txt" --name "hidden_payload" --output "C:\path\to\recovered.bin"

# Extract a Base64-encoded stream
python main.py extract "C:\path\to\file.txt" --name "hidden_payload" --output "C:\path\to\recovered.bin" --base64
```

#### 6. Bulk Backup & Restore All Streams (`export-all` / `restore`)

```bash
# Export all streams across a folder tree into a backup directory with manifest.json
python main.py export-all "C:\path\to\folder" --output "./ads_backup"

# Restore exported streams back to their original files using manifest.json
python main.py restore "./ads_backup" --overwrite
```

#### 7. Copy Streams Between Files (`copy`)

```bash
# Copy all streams from source file to destination file
python main.py copy "C:\path\to\source.txt" "C:\path\to\dest.txt" --overwrite

# Copy only a specific stream
python main.py copy "C:\path\to\source.txt" "C:\path\to\dest.txt" --name "secret_note"
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## Project Structure

- `main.py` — CLI entry point (`click`), forensic analyzers (`detect_stream_type`, `parse_zone_identifier`), core `App` API, and multi-format `Displayer`.
- `gui.py` — Flet desktop GUI (`--gui` / `gui`).
- `pyADS.py` — Cross-platform `ADS` handler supporting both Windows `kernel32.dll` (`FindFirstStreamW` / `FindNextStreamW`) and Linux `xattr` (`ntfs-3g` / `ntfs3` / POSIX extended attributes).
- `tests/test_adsclient.py` — Automated unit test suite.
- `.github/workflows/ci.yml` — GitHub Actions CI pipeline testing on both Windows and Ubuntu Linux.
- `pyproject.toml` & `requirements.txt` — Package configuration and dependencies.
