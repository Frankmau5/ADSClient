import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

# Provide a lightweight click shim if click is not installed in the test environment
try:
    import click  # noqa: F401
except ImportError:
    click_mock = types.ModuleType("click")

    def _decorator(*_a, **_kw):
        def _wrap(f):
            f.command = lambda *_a2, **_kw2: _decorator()
            return f
        return _wrap

    click_mock.group = _decorator
    click_mock.version_option = _decorator
    click_mock.command = _decorator
    click_mock.option = _decorator
    click_mock.argument = _decorator
    click_mock.pass_context = lambda f: f
    click_mock.Choice = lambda *a, **kw: None
    click_mock.UsageError = RuntimeError
    sys.modules["click"] = click_mock

from main import (
    __version__,
    App,
    copy_streams,
    detect_stream_type,
    delete_metadata,
    export_all_streams,
    extract_stream_data,
    parse_zone_identifier,
    restore_streams,
    scan_files,
)


class TestADSClient(unittest.TestCase):
    def test_version(self):
        self.assertEqual(__version__, "1.0.0")
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(dir=str(Path.cwd()))
        self.root = Path(self.tmp_dir.name)
        self.app = App()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_magic_detection_and_zone_parser(self):
        t, susp = detect_stream_type(b"MZ\x90\x00\x03\x00")
        self.assertEqual(t, "Windows PE Executable (MZ)")
        self.assertTrue(susp)

        t2, susp2 = detect_stream_type(b"Hello UTF-8 World")
        self.assertEqual(t2, "UTF-8 Text")
        self.assertFalse(susp2)

        zone_raw = (
            b"[ZoneTransfer]\r\n"
            b"ZoneId=3\r\n"
            b"ReferrerUrl=https://example.com/downloads\r\n"
            b"HostUrl=https://example.com/downloads/payload.exe\r\n"
        )
        zinfo = parse_zone_identifier(zone_raw)
        self.assertIsNotNone(zinfo)
        self.assertEqual(zinfo["ZoneId"], "3")
        self.assertEqual(zinfo["ZoneName"], "Internet")
        self.assertIn("HostUrl=https://example.com/downloads/payload.exe", zinfo["Summary"])

    def test_end_to_end_streams_scan_extract_export_restore_copy_and_filters(self):
        sample_file = self.root / "sample.txt"
        sample_file.write_text("Primary file content", encoding="utf-8")

        sub_dir = self.root / "sub"
        sub_dir.mkdir()
        sub_file = sub_dir / "other.doc"
        sub_file.write_text("Subfile content", encoding="utf-8")

        # 1. Add text stream and Zone.Identifier stream
        self.assertTrue(self.app.add_str_data(sample_file, "secret_note", "Top secret UTF-8 🚀"))
        self.assertTrue(
            self.app.add_str_data(
                sample_file,
                "Zone.Identifier",
                "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://malicious.example/file.exe\r\n",
            )
        )

        # 2. Add raw binary stream (PE header) on sub_file
        bin_src = self.root / "dummy.exe"
        bin_src.write_bytes(b"MZ\x90\x00\x01\x02\x03")
        self.assertTrue(self.app.add_bin_data(sub_file, "hidden_pe", str(bin_src), use_base64=False))

        # 3. Scan with non-recursive, recursive, pattern, suspicious_only, and zone_filter
        non_rec = scan_files(self.root, recursive=False, app=self.app)
        self.assertEqual(len(non_rec), 1)

        rec_all = scan_files(self.root, recursive=True, app=self.app)
        self.assertEqual(len(rec_all), 2)

        rec_doc = scan_files(self.root, recursive=True, pattern="*.doc", app=self.app)
        self.assertEqual(len(rec_doc), 1)
        self.assertEqual(Path(rec_doc[0].Path).name, "other.doc")

        susp_only = scan_files(self.root, recursive=True, suspicious_only=True, app=self.app)
        self.assertEqual(len(susp_only), 1)
        self.assertEqual(susp_only[0].Data[0]["Name"], "hidden_pe")

        zone3_only = scan_files(self.root, recursive=True, zone_filter="3", app=self.app)
        self.assertEqual(len(zone3_only), 1)
        self.assertEqual(Path(zone3_only[0].Path).name, "sample.txt")

        # 4. Extract binary stream and verify contents match
        extracted_path = self.root / "recovered.exe"
        self.assertTrue(
            extract_stream_data(
                sub_file, "hidden_pe", output_path=str(extracted_path), use_base64=False, app=self.app
            )
        )
        self.assertEqual(extracted_path.read_bytes(), b"MZ\x90\x00\x01\x02\x03")

        # 5. Copy streams to a new target file
        copy_target = self.root / "cloned.txt"
        copy_target.write_text("Clone target", encoding="utf-8")
        copied_count = copy_streams(sample_file, copy_target, app=self.app)
        self.assertEqual(copied_count, 2)
        self.assertEqual(len(self.app.get_data(copy_target)), 2)
        delete_metadata(copy_target, overwrite=True, app=self.app)

        # 6. Export all streams and verify manifest.json
        backup_dir = self.root / "backup"
        manifest = export_all_streams(self.root, backup_dir, recursive=True, app=self.app)
        self.assertEqual(len(manifest), 3)
        self.assertTrue((backup_dir / "manifest.json").exists())
        saved_manifest = json.loads((backup_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(len(saved_manifest), 3)

        # 7. Dry-run clear should NOT remove the stream
        would_del = delete_metadata(sample_file, dry_run=True, app=self.app)
        self.assertEqual(len(would_del), 1)
        self.assertEqual(would_del[0][1], "Zone.Identifier")
        self.assertEqual(len(self.app.get_data(sample_file)), 2)

        # 8. Clear ALL streams across root, then restore them from backup!
        delete_metadata(self.root, overwrite=True, recursive=True, app=self.app)
        self.assertEqual(len(scan_files(self.root, recursive=True, app=self.app)), 0)

        restored = restore_streams(backup_dir, overwrite=True, app=self.app)
        self.assertEqual(restored, 3)
        self.assertEqual(len(scan_files(self.root, recursive=True, app=self.app)), 2)


if __name__ == "__main__":
    unittest.main()
