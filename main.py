import binascii
import configparser
import csv
import fnmatch
import hashlib
import json
import re
import sys
from base64 import b64decode, b64encode
from io import StringIO
from pathlib import Path
import click
from pyADS import ADS

__version__ = "1.0.0"


ZONE_NAMES = {
    "0": "Local Machine",
    "1": "Local Intranet",
    "2": "Trusted Sites",
    "3": "Internet",
    "4": "Restricted Sites",
}

MAGIC_SIGNATURES = [
    (b"MZ", "Windows PE Executable (MZ)", True),
    (b"\x7fELF", "ELF Executable", True),
    (b"#!", "Shebang Script", True),
    (b"PK\x03\x04", "ZIP / Office Archive", False),
    (b"Rar!\x1a\x07", "RAR Archive", False),
    (b"7z\xbc\xaf'\x1c", "7-Zip Archive", False),
    (b"%PDF-", "PDF Document", False),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", False),
    (b"\xff\xd8\xff", "JPEG Image", False),
    (b"GIF87a", "GIF Image", False),
    (b"GIF89a", "GIF Image", False),
    (b"\x1f\x8b\x08", "GZIP Archive", False),
]


def detect_stream_type(raw_bytes):
    """Detect payload file type from magic bytes or UTF-8 text heuristics.
    Returns (type_description, is_suspicious_executable).
    """
    if not raw_bytes:
        return ("Empty", False)

    for magic, label, is_suspicious in MAGIC_SIGNATURES:
        if raw_bytes.startswith(magic):
            return (label, is_suspicious)

    try:
        text = raw_bytes.decode("utf-8")
        lower_head = text[:256].lower().lstrip()
        if lower_head.startswith(("powershell", "cmd.exe", "wscript", "cscript", "<script", "import ")):
            return ("Script / Code (UTF-8)", True)
        return ("UTF-8 Text", False)
    except UnicodeDecodeError:
        return ("Binary Data", False)


def parse_zone_identifier(raw_bytes):
    """Parse Windows Zone.Identifier INI-style stream into structured dictionary."""
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None

    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return None

    if not parser.has_section("ZoneTransfer"):
        return None

    sec = parser["ZoneTransfer"]
    zone_id = sec.get("ZoneId", "").strip()
    zone_name = ZONE_NAMES.get(zone_id, f"Unknown ({zone_id})")
    host_url = sec.get("HostUrl", "").strip()
    referrer_url = sec.get("ReferrerUrl", "").strip()

    summary_parts = [f"Zone {zone_id} ({zone_name})"]
    if host_url:
        summary_parts.append(f"HostUrl={host_url}")
    if referrer_url:
        summary_parts.append(f"ReferrerUrl={referrer_url}")

    return {
        "ZoneId": zone_id,
        "ZoneName": zone_name,
        "HostUrl": host_url,
        "ReferrerUrl": referrer_url,
        "Summary": " | ".join(summary_parts),
    }


class DataObj:
    """Dataclass for ADS data"""

    def __init__(self, path, data):
        self.Path = path
        self.Data = data


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="ADSClient")
@click.option(
    '--gui',
    is_flag=True,
    default=False,
    help='Launch the graphical user interface (Flet GUI)',
)
@click.option(
    '--command',
    type=click.Choice(
        ['scan', 'clear', 'add_str', 'add_file', 'extract', 'export_all', 'restore', 'copy'],
        case_sensitive=False,
    ),
    help='Legacy command mode (prefer subcommands: scan, clear, add-str, add-file, extract, export-all, restore, copy, gui)',
)
@click.option('--path', help='Path to file or folder')
@click.option('--dst', help='Destination file path for copy command')
@click.option('--name', help='Name for stream')
@click.option('--data', help='The data you want to add to stream (text or filepath)')
@click.option('--output', help='Output file or directory path for extract / export_all')
@click.option('--export-dir', help='Directory to export all discovered streams during scan')
@click.option('--overwrite', is_flag=True, default=False, help='Overwrite existing stream or delete all ADS streams')
@click.option('--dry-run', is_flag=True, default=False, help='Preview streams that would be deleted without removing them')
@click.option('--no-recursive', is_flag=True, default=False, help='Do not recurse into subdirectories')
@click.option('--pattern', default='*', show_default=True, help='Glob file filter pattern (e.g. *.exe, *.docx)')
@click.option('--suspicious-only', is_flag=True, default=False, help='Only show suspicious executable/script streams')
@click.option('--zone', 'zone_filter', help='Filter scan results by Zone.Identifier ZoneId (0, 1, 2, 3, 4)')
@click.option('--base64', 'use_base64', is_flag=True, default=False, help='Encode/decode binary stream data as Base64')
@click.option(
    '--format',
    'output_format',
    type=click.Choice(['text', 'json', 'csv'], case_sensitive=False),
    default='text',
    help='Output format for scan results',
)
@click.pass_context
def cli(
    ctx,
    gui,
    command,
    path,
    dst,
    name,
    data,
    output,
    export_dir,
    overwrite,
    dry_run,
    no_recursive,
    pattern,
    suspicious_only,
    zone_filter,
    use_base64,
    output_format,
):
    """ADSClient - Inspect, add, extract, copy, backup, restore, and clear NTFS Alternate Data Streams (ADS)."""
    if gui:
        from gui import launch_gui
        launch_gui(initial_path=path or "")
        return

    if ctx.invoked_subcommand is not None:
        return

    if not command:
        click.echo(ctx.get_help())
        return

    if not path:
        raise click.UsageError("--path is required")

    app = App()
    recursive = not no_recursive
    cmd = command.lower()
    if cmd == "scan":
        data_list = scan_files(
            path,
            recursive=recursive,
            pattern=pattern,
            suspicious_only=suspicious_only,
            zone_filter=zone_filter,
            app=app,
        )
        app.Displayer.display(data_list, output_format=output_format)
        if export_dir:
            export_all_streams(path, export_dir, recursive=recursive, pattern=pattern, app=app)
    elif cmd == "clear":
        delete_metadata(
            path,
            overwrite=overwrite,
            stream_name=name,
            recursive=recursive,
            pattern=pattern,
            dry_run=dry_run,
            app=app,
        )
    elif cmd == "add_str":
        if not name or data is None:
            raise click.UsageError("--name and --data are required for 'add_str'")
        add_str_data(path, name, data, overwrite=overwrite, app=app)
    elif cmd == "add_file":
        if not name or not data:
            raise click.UsageError("--name and --data are required for 'add_file'")
        add_bin_data(path, name, data, use_base64=use_base64, overwrite=overwrite, app=app)
    elif cmd == "extract":
        if not name:
            raise click.UsageError("--name is required for 'extract'")
        extract_stream_data(path, name, output_path=output, use_base64=use_base64, app=app)
    elif cmd == "export_all":
        target_export = output or export_dir
        if not target_export:
            raise click.UsageError("--output or --export-dir is required for 'export_all'")
        export_all_streams(path, target_export, recursive=recursive, pattern=pattern, app=app)
    elif cmd == "restore":
        restore_streams(path, overwrite=overwrite, app=app)
    elif cmd == "copy":
        target_dst = dst or output
        if not target_dst:
            raise click.UsageError("--dst (or --output) is required for 'copy'")
        copy_streams(path, target_dst, stream_name=name, overwrite=overwrite, app=app)


@cli.command("gui")
@click.option("--path", default="", help="Initial file or folder path to populate in the GUI")
def gui_cmd(path):
    """Launch the Flet Graphical User Interface."""
    from gui import launch_gui
    launch_gui(initial_path=path)


@cli.command("scan")
@click.argument("path")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "csv"], case_sensitive=False),
    default="text",
    help="Output format (text, json, csv)",
)
@click.option("--no-recursive", is_flag=True, default=False, help="Do not recurse into subdirectories")
@click.option("--pattern", default="*", show_default=True, help="Glob pattern to filter files (e.g. *.exe)")
@click.option("--suspicious-only", is_flag=True, default=False, help="Only display suspicious executable/script streams")
@click.option("--zone", "zone_filter", help="Filter by Zone.Identifier ZoneId (0=Local, 1=Intranet, 2=Trusted, 3=Internet, 4=Restricted)")
@click.option("--export-dir", help="Optional folder to back up all discovered streams")
def scan_cmd(path, output_format, no_recursive, pattern, suspicious_only, zone_filter, export_dir):
    """Scan a file or directory for ADS streams (with SHA-256, magic type, and Zone.Identifier parsing)."""
    app = App()
    recursive = not no_recursive
    results = scan_files(
        path,
        recursive=recursive,
        pattern=pattern,
        suspicious_only=suspicious_only,
        zone_filter=zone_filter,
        app=app,
    )
    app.Displayer.display(results, output_format=output_format)
    if export_dir:
        export_all_streams(path, export_dir, recursive=recursive, pattern=pattern, app=app)


@cli.command("clear")
@click.argument("path")
@click.option("--name", help="Delete only a specific stream by name")
@click.option("--overwrite", is_flag=True, default=False, help="Delete ALL ADS streams on target file(s)")
@click.option("--dry-run", is_flag=True, default=False, help="Preview streams that would be deleted without removing them")
@click.option("--no-recursive", is_flag=True, default=False, help="Do not recurse into subdirectories")
@click.option("--pattern", default="*", show_default=True, help="Glob pattern to filter files")
def clear_cmd(path, name, overwrite, dry_run, no_recursive, pattern):
    """Clear ADS streams (supports --dry-run, --name, --overwrite, --no-recursive, --pattern)."""
    app = App()
    delete_metadata(
        path,
        overwrite=overwrite,
        stream_name=name,
        recursive=not no_recursive,
        pattern=pattern,
        dry_run=dry_run,
        app=app,
    )


@cli.command("add-str")
@click.argument("path")
@click.option("--name", required=True, help="Name for the ADS stream")
@click.option("--data", required=True, help="Text string to write to the stream")
@click.option("--overwrite", is_flag=True, default=False, help="Overwrite stream if it already exists")
def add_str_cmd(path, name, data, overwrite):
    """Attach UTF-8 text data to a file's ADS stream."""
    app = App()
    add_str_data(path, name, data, overwrite=overwrite, app=app)


@cli.command("add-file")
@click.argument("path")
@click.option("--name", required=True, help="Name for the ADS stream")
@click.option("--data", required=True, help="Path to source file to embed in the stream")
@click.option("--base64", "use_base64", is_flag=True, default=False, help="Base64-encode file content before storing")
@click.option("--overwrite", is_flag=True, default=False, help="Overwrite stream if it already exists")
def add_file_cmd(path, name, data, use_base64, overwrite):
    """Attach binary file contents to a file's ADS stream."""
    app = App()
    add_bin_data(path, name, data, use_base64=use_base64, overwrite=overwrite, app=app)


@cli.command("extract")
@click.argument("path")
@click.option("--name", required=True, help="Name of the ADS stream to extract")
@click.option("--output", help="Destination file path to save extracted data (prints to stdout if omitted)")
@click.option("--base64", "use_base64", is_flag=True, default=False, help="Base64-decode stream content before saving")
def extract_cmd(path, name, output, use_base64):
    """Extract data from an ADS stream to a file or stdout."""
    app = App()
    extract_stream_data(path, name, output_path=output, use_base64=use_base64, app=app)


@cli.command("export-all")
@click.argument("path")
@click.option("--output", "--export-dir", "export_dir", required=True, help="Destination directory for exported streams and manifest.json")
@click.option("--no-recursive", is_flag=True, default=False, help="Do not recurse into subdirectories")
@click.option("--pattern", default="*", show_default=True, help="Glob pattern to filter files")
def export_all_cmd(path, export_dir, no_recursive, pattern):
    """Bulk-export all discovered ADS streams into a backup directory with a JSON manifest."""
    app = App()
    export_all_streams(path, export_dir, recursive=not no_recursive, pattern=pattern, app=app)


@cli.command("restore")
@click.argument("backup_dir")
@click.option("--overwrite", is_flag=True, default=False, help="Overwrite existing streams on target files")
def restore_cmd(backup_dir, overwrite):
    """Restore exported ADS streams from a backup directory using its manifest.json."""
    app = App()
    restore_streams(backup_dir, overwrite=overwrite, app=app)


@cli.command("copy")
@click.argument("src_path")
@click.argument("dst_path")
@click.option("--name", help="Copy only a specific stream by name (copies all streams if omitted)")
@click.option("--overwrite", is_flag=True, default=False, help="Overwrite existing streams on destination file")
def copy_cmd(src_path, dst_path, name, overwrite):
    """Copy one or all ADS streams from SRC_PATH to DST_PATH."""
    app = App()
    copy_streams(src_path, dst_path, stream_name=name, overwrite=overwrite, app=app)


def _iter_target_paths(path, recursive=True, pattern="*"):
    """Yield target file(s) from either a single file path or directory path, filtered by glob pattern."""
    target = Path(path)
    if not target.exists():
        print(f"Error: Path '{path}' does not exist.")
        return
    if target.is_file():
        if fnmatch.fnmatch(target.name, pattern):
            yield target
    else:
        iterator = target.rglob("*") if recursive else target.glob("*")
        for p in iterator:
            if fnmatch.fnmatch(p.name, pattern):
                yield p


# scan
def scan_files(path, recursive=True, pattern="*", suspicious_only=False, zone_filter=None, app=None):
    """Scan files for ADS streams and return list of DataObj instances."""
    if app is None:
        app = App()
    output = list()
    zone_str = str(zone_filter).strip() if zone_filter is not None and str(zone_filter).strip() != "" else None

    for p in _iter_target_paths(path, recursive=recursive, pattern=pattern):
        streams = app.get_data(p)
        if not streams:
            continue

        if zone_str is not None:
            has_matching_zone = any(
                (s.get("ZoneInfo") or {}).get("ZoneId") == zone_str for s in streams
            )
            if not has_matching_zone:
                continue

        if suspicious_only:
            streams = [s for s in streams if s.get("Suspicious")]
            if not streams:
                continue

        output.append(DataObj(p, streams))
    return output


# clear
def delete_metadata(path, overwrite=False, stream_name=None, recursive=True, pattern="*", dry_run=False, app=None):
    """Delete metadata streams, a specific named stream, or all streams if overwrite=True."""
    if app is None:
        app = App()
    deleted_all = []
    for p in _iter_target_paths(path, recursive=recursive, pattern=pattern):
        deleted_all.extend(
            app.del_data(p, overwrite=overwrite, stream_name=stream_name, dry_run=dry_run)
        )
    return deleted_all


# add_str_data
def add_str_data(path, name, data_str, overwrite=False, app=None):
    """Add string data to a file ADS stream"""
    if app is None:
        app = App()
    r = app.add_str_data(path, name, data_str, overwrite=overwrite)
    if r:
        print("data was added.")
    else:
        print("data was not added.")
    return r


# add_bin_data
def add_bin_data(path, name, data_str, use_base64=False, overwrite=False, app=None):
    """Add bin data to a file ADS stream"""
    if app is None:
        app = App()
    r = app.add_bin_data(path, name, data_str, use_base64=use_base64, overwrite=overwrite)
    if r:
        print("data was added.")
    else:
        print("data was not added.")
    return r


# extract_stream_data
def extract_stream_data(path, name, output_path=None, use_base64=False, app=None):
    """Extract a named stream from a file and write it to output_path or stdout."""
    if app is None:
        app = App()
    content = app.extract_data(path, name, use_base64=use_base64)
    if content is None:
        return False

    if output_path:
        try:
            with open(output_path, "wb") as f:
                f.write(content)
            print(f"Extracted stream '{name}' ({len(content)} bytes) to '{output_path}'.")
            return True
        except OSError as e:
            print(f"Failed to write output file '{output_path}': {e}")
            return False
    else:
        try:
            print(content.decode("utf-8"))
        except UnicodeDecodeError:
            sys.stdout.buffer.write(content)
        return True


def _sanitize_filename(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(name))


# export_all_streams
def export_all_streams(path, export_dir, recursive=True, pattern="*", app=None):
    """Export all discovered ADS streams under path into export_dir with a manifest.json."""
    if app is None:
        app = App()

    out_dir = Path(export_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results = scan_files(path, recursive=recursive, pattern=pattern, app=app)
    manifest = []

    for idx, d in enumerate(results):
        for s in d.Data:
            sname = s.get("Name", "stream")
            raw = s.get("data", b"")
            safe_file = f"{idx:04d}_{_sanitize_filename(Path(d.Path).name)}__{_sanitize_filename(sname)}.bin"
            dest_path = out_dir / safe_file
            with open(dest_path, "wb") as f:
                f.write(raw)

            entry = {
                "source_file": str(d.Path),
                "stream_name": sname,
                "exported_file": str(dest_path),
                "size": s.get("Size", len(raw)),
                "sha256": s.get("SHA256"),
                "type": s.get("Type"),
                "suspicious": s.get("Suspicious", False),
                "zone_info": s.get("ZoneInfo"),
            }
            manifest.append(entry)

    manifest_path = out_dir / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as mf:
        json.dump(manifest, mf, indent=2)

    print(f"Exported {len(manifest)} stream(s) to '{out_dir}' (manifest: '{manifest_path}').")
    return manifest


# restore_streams
def restore_streams(backup_dir, overwrite=False, app=None):
    """Restore ADS streams from a backup directory containing manifest.json."""
    if app is None:
        app = App()

    bdir = Path(backup_dir)
    manifest_path = bdir / "manifest.json"
    if not manifest_path.exists():
        print(f"Error: Manifest not found at '{manifest_path}'.")
        return 0

    try:
        entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"Error reading manifest '{manifest_path}': {e}")
        return 0

    restored_count = 0
    for entry in entries:
        src_file = entry.get("source_file")
        sname = entry.get("stream_name")
        exp_file = entry.get("exported_file")
        if not src_file or not sname or not exp_file:
            continue

        exp_path = Path(exp_file)
        if not exp_path.exists():
            exp_path = bdir / exp_path.name
        if not exp_path.exists():
            print(f"Warning: Exported payload '{exp_file}' missing, skipping.")
            continue

        if not Path(src_file).exists():
            print(f"Warning: Target file '{src_file}' does not exist, skipping.")
            continue

        raw_bytes = exp_path.read_bytes()
        handler = ADS(str(src_file))
        if handler.add_stream_from_string(sname, raw_bytes, overwrite=overwrite):
            print(f"Restored stream '{sname}' ({len(raw_bytes)} bytes) to '{src_file}'.")
            restored_count += 1

    print(f"Restored {restored_count}/{len(entries)} stream(s).")
    return restored_count


# copy_streams
def copy_streams(src_path, dst_path, stream_name=None, overwrite=False, app=None):
    """Copy one or all ADS streams from src_path to dst_path."""
    if app is None:
        app = App()
    return app.copy_data(src_path, dst_path, stream_name=stream_name, overwrite=overwrite)


class App:
    """Core ADS Api"""

    METADATA_STREAMS = {"Zone.Identifier", "OECustomProperty", "encryptable"}

    def __init__(self):
        self.Displayer = Displayer()

    def is_data_in_file(self, filepath):
        """Searches for ADS steams and return bool"""
        handler = ADS(str(filepath))
        return handler.has_streams()

    def get_data(self, filepath):
        """Get name, size, SHA-256, detected type, Zone.Identifier info, and raw data from ADS stream."""
        output = list()
        handler = ADS(str(filepath))
        if handler.has_streams():
            for stream in handler:
                raw_data = handler.get_stream_content(stream)
                stream_type, is_suspicious = detect_stream_type(raw_data)
                sha256_hex = hashlib.sha256(raw_data).hexdigest()
                zone_info = parse_zone_identifier(raw_data) if stream == "Zone.Identifier" else None
                d = {
                    'Name': stream,
                    'Size': handler.get_stream_size(stream) or len(raw_data),
                    'SHA256': sha256_hex,
                    'Type': stream_type,
                    'Suspicious': is_suspicious,
                    'ZoneInfo': zone_info,
                    'data': raw_data,
                }
                output.append(d)
        return output

    def del_data(self, filepath, overwrite=False, stream_name=None, dry_run=False):
        """Deletes name and data from ADS stream (or previews deletion if dry_run=True)."""
        handler = ADS(str(filepath))
        deleted = []
        if handler.has_streams():
            for stream in list(handler):
                should_delete = (
                    (stream_name is not None and stream == stream_name)
                    or (stream_name is None and (overwrite or stream in self.METADATA_STREAMS))
                )
                if should_delete:
                    size = handler.get_stream_size(stream)
                    if dry_run:
                        print(f"[DRY-RUN] Would clear ADS '{stream}' ({size} bytes) in {filepath}")
                        deleted.append((str(filepath), stream, size))
                    else:
                        if handler.delete_stream(stream):
                            print(f"Cleared ADS '{stream}' in {filepath}")
                            deleted.append((str(filepath), stream, size))
                        else:
                            print(f"Failed to clear ADS '{stream}' in {filepath}")
        return deleted

    def add_str_data(self, filepath, stream_name, str_data, overwrite=False):
        """Add string data to ADS stream"""
        handler = ADS(str(filepath))
        b = str_data.encode("utf-8")
        return handler.add_stream_from_string(stream_name, b, overwrite=overwrite)

    def add_bin_data(self, filepath, stream_name, file_data, use_base64=False, overwrite=False):
        """Add binary data to ADS stream (raw bytes by default, or Base64 if use_base64=True)"""
        handler = ADS(str(filepath))
        try:
            with open(file_data, mode='rb') as f_open:
                data = f_open.read()
        except (FileNotFoundError, IsADirectoryError, PermissionError, OSError):
            print("Error. are you sure this file exist?")
            return False

        payload = b64encode(data) if use_base64 else data
        return handler.add_stream_from_string(stream_name, payload, overwrite=overwrite)

    def extract_data(self, filepath, stream_name, use_base64=False):
        """Read and optionally Base64-decode a specific ADS stream from a file."""
        handler = ADS(str(filepath))
        if stream_name not in handler.streams:
            print(f"Stream '{stream_name}' not found on '{filepath}'.")
            return None

        raw_data = handler.get_stream_content(stream_name)
        if use_base64:
            try:
                return b64decode(raw_data, validate=False)
            except binascii.Error as e:
                print(f"Error decoding Base64 content from stream '{stream_name}': {e}")
                return None
        return raw_data

    def copy_data(self, src_filepath, dst_filepath, stream_name=None, overwrite=False):
        """Copy one or all ADS streams from src_filepath to dst_filepath."""
        if not Path(src_filepath).exists():
            print(f"Error: Source file '{src_filepath}' does not exist.")
            return 0
        if not Path(dst_filepath).exists():
            print(f"Error: Destination file '{dst_filepath}' does not exist.")
            return 0

        src_handler = ADS(str(src_filepath))
        dst_handler = ADS(str(dst_filepath))
        copied = 0

        streams_to_copy = [stream_name] if stream_name else list(src_handler.streams)
        for sname in streams_to_copy:
            if sname not in src_handler.streams:
                print(f"Stream '{sname}' not found on '{src_filepath}'.")
                continue
            raw_data = src_handler.get_stream_content(sname)
            if dst_handler.add_stream_from_string(sname, raw_data, overwrite=overwrite):
                print(f"Copied stream '{sname}' ({len(raw_data)} bytes) from '{src_filepath}' to '{dst_filepath}'.")
                copied += 1

        return copied


class Displayer:
    """Command line interface to display ADS scan data"""

    MAX_PREVIEW_LEN = 120

    def __init__(self):
        pass

    @staticmethod
    def _format_size(num_bytes):
        if num_bytes < 1024:
            return f"{num_bytes} B"
        elif num_bytes < 1024 * 1024:
            return f"{num_bytes / 1024:.1f} KB"
        return f"{num_bytes / (1024 * 1024):.2f} MB"

    @classmethod
    def _format_preview(cls, raw_bytes):
        if not isinstance(raw_bytes, (bytes, bytearray)):
            return str(raw_bytes)
        try:
            text = raw_bytes.decode("utf-8")
            printable = text.replace("\r\n", "\\n").replace("\n", "\\n")
            if len(printable) > cls.MAX_PREVIEW_LEN:
                return printable[: cls.MAX_PREVIEW_LEN] + "..."
            return printable
        except UnicodeDecodeError:
            hex_preview = raw_bytes[:32].hex(" ")
            suffix = "..." if len(raw_bytes) > 32 else ""
            return f"<binary: {hex_preview}{suffix}>"

    def display(self, data, output_format="text"):
        fmt = (output_format or "text").lower()
        if fmt == "json":
            self.print_json(data)
        elif fmt == "csv":
            self.print_csv(data)
        else:
            self.basic_print(data)

    def basic_print(self, data):
        """Human-readable formatted output for DataObj list."""
        if not isinstance(data, list):
            print("Error with printing")
            return

        if not data:
            print("No Alternate Data Streams found.")
            return

        for d in data:
            print(f"File: {d.Path}")
            for stream in d.Data:
                name = stream.get("Name", "")
                raw = stream.get("data", b"")
                size = stream.get("Size", len(raw))
                sha256_hex = stream.get("SHA256", "")
                stream_type = stream.get("Type", "Unknown")
                suspicious = stream.get("Suspicious", False)
                zone_info = stream.get("ZoneInfo")
                preview = self._format_preview(raw)
                flag = " [SUSPICIOUS EXECUTABLE]" if suspicious else ""

                print(f"  ├─ Stream: {name} ({self._format_size(size)}) | Type: {stream_type}{flag}")
                if sha256_hex:
                    print(f"  │  SHA-256: {sha256_hex}")
                if zone_info:
                    print(f"  │  Zone.Identifier: {zone_info['Summary']}")
                print(f"  └─ Preview: {preview}")
            print()

    def print_json(self, data):
        """JSON output for scripting and auditing."""
        serializable = []
        for d in data:
            streams_out = []
            for s in d.Data:
                raw = s.get("data", b"")
                try:
                    content_str = raw.decode("utf-8")
                    encoding = "utf-8"
                except UnicodeDecodeError:
                    content_str = b64encode(raw).decode("ascii")
                    encoding = "base64"
                streams_out.append({
                    "name": s.get("Name"),
                    "size": s.get("Size", len(raw)),
                    "sha256": s.get("SHA256"),
                    "type": s.get("Type"),
                    "suspicious": s.get("Suspicious", False),
                    "zone_info": s.get("ZoneInfo"),
                    "encoding": encoding,
                    "content": content_str,
                })
            serializable.append({
                "path": str(d.Path),
                "streams": streams_out,
            })
        print(json.dumps(serializable, indent=2))

    def print_csv(self, data):
        """CSV output for spreadsheets and log ingestion."""
        buf = StringIO()
        writer = csv.writer(buf)
        writer.writerow(["path", "stream_name", "size_bytes", "type", "suspicious", "sha256", "zone_summary", "preview"])
        for d in data:
            for s in d.Data:
                raw = s.get("data", b"")
                zinfo = s.get("ZoneInfo") or {}
                writer.writerow([
                    str(d.Path),
                    s.get("Name", ""),
                    s.get("Size", len(raw)),
                    s.get("Type", ""),
                    s.get("Suspicious", False),
                    s.get("SHA256", ""),
                    zinfo.get("Summary", ""),
                    self._format_preview(raw),
                ])
        print(buf.getvalue(), end="")


main = cli

if __name__ == "__main__":
    main()
