# ADSClient

A Windows command-line utility and Python wrapper for inspecting, adding, and clearing **NTFS Alternate Data Streams (ADS)** on files and directories.

## Overview

Alternate Data Streams (ADS) are a feature of the Windows NTFS file system that allows additional data streams or metadata to be attached to a file using the `filename:streamname` syntax without affecting the file's primary content or reported size in File Explorer. For example, Windows uses the `Zone.Identifier` stream to mark files downloaded from the internet.

`ADSClient` provides a CLI built with `click` and a low-level `ctypes` wrapper around `kernel32.dll` (`FindFirstStreamW` / `FindNextStreamW`) to enumerate and manipulate these streams.

## Requirements

- **OS:** Windows (requires NTFS file system and `windll.kernel32`)
- **Python:** Python 3.x
- **Dependencies:**
  ```bash
  pip install click
  ```

## Usage

Run `main.py` with the `--command` option:

```bash
python main.py --command <COMMAND> [OPTIONS]
```

### Commands

#### 1. Scan for ADS Streams (`scan`)
Recursively scans a directory for files containing Alternate Data Streams and prints their paths, stream names, and contents.

```bash
python main.py --command scan --path "C:\path\to\folder"
```

#### 2. Clear Metadata / Streams (`clear`)
Recursively scans a directory and removes common metadata streams (`Zone.Identifier`, `OECustomProperty`, `encryptable`). Pass `--overwrite True` to delete **all** ADS streams found.

```bash
# Clear default metadata streams
python main.py --command clear --path "C:\path\to\folder"

# Clear all ADS streams
python main.py --command clear --path "C:\path\to\folder" --overwrite True
```

#### 3. Add Text Data to a Stream (`add_str`)
Attaches a string to a target file under a custom stream name.

```bash
python main.py --command add_str --path "C:\path\to\file.txt" --name "secret_note" --data "Hidden text inside ADS"
```

#### 4. Add Binary File Data to a Stream (`add_file`)
Reads a binary file, Base64-encodes its contents, and writes it to a named ADS stream on the target file.

```bash
python main.py --command add_file --path "C:\path\to\file.txt" --name "hidden_payload" --data "C:\path\to\binary.bin"
```

## Project Structure

- `main.py` — CLI entry point (`click`), high-level `App` API (`scan_files`, `delete_metadata`, `add_str_data`, `add_bin_data`), and output formatting (`Displayer`).
- `pyADS.py` — Low-level `ADS` handler using Windows `kernel32.dll` (`FindFirstStreamW`, `FindNextStreamW`, `FindClose`) to enumerate, read, write, and delete NTFS Alternate Data Streams (derived from Robin David's MIT-licensed `pyADS`).
