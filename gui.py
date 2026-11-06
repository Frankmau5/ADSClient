"""Flet GUI for ADSClient (launched via `python main.py --gui` or `python main.py gui`)."""

from pathlib import Path


def launch_gui(initial_path=""):
    try:
        import flet as ft
    except ImportError:
        print(
            "Error: 'flet' is required to launch the GUI.\n"
            "Install it with: pip install flet"
        )
        return False

    from main import (
        __version__,
        App,
        Displayer,
        copy_streams,
        delete_metadata,
        export_all_streams,
        extract_stream_data,
        restore_streams,
        scan_files,
        _sanitize_filename,
    )

    def main_view(page: ft.Page):
        page.title = f"ADSClient v{__version__} — NTFS Alternate Data Stream Inspector & Manager"
        page.window_width = 1150
        page.window_height = 860
        page.padding = 20
        page.scroll = ft.ScrollMode.AUTO

        app = App()
        status_text = ft.Text("Ready.", color=ft.colors.BLUE_GREY_400)

        def set_status(msg, is_error=False):
            status_text.value = msg
            status_text.color = ft.colors.RED_400 if is_error else ft.colors.GREEN_400
            page.update()

        # --- FilePickers ---
        path_field = ft.TextField(
            label="Target File or Folder Path",
            value=initial_path or str(Path.cwd()),
            expand=True,
        )
        export_dir_field = ft.TextField(
            label="Export / Backup Directory",
            value=str(Path.cwd() / "ads_backup"),
            expand=True,
        )
        add_stream_data = ft.TextField(
            label="Text Data or Source File Path", expand=True
        )

        pending_extract = {"file": None, "stream": None}

        def on_target_file_picked(e: ft.FilePickerResultEvent):
            if e.files:
                path_field.value = e.files[0].path
                page.update()

        def on_target_dir_picked(e: ft.FilePickerResultEvent):
            if e.path:
                path_field.value = e.path
                page.update()

        def on_export_dir_picked(e: ft.FilePickerResultEvent):
            if e.path:
                export_dir_field.value = e.path
                page.update()

        def on_embed_file_picked(e: ft.FilePickerResultEvent):
            if e.files:
                add_stream_data.value = e.files[0].path
                page.update()

        def on_save_stream_picked(e: ft.FilePickerResultEvent):
            if e.path and pending_extract["file"] and pending_extract["stream"]:
                ok = extract_stream_data(
                    pending_extract["file"],
                    pending_extract["stream"],
                    output_path=e.path,
                    app=app,
                )
                if ok:
                    set_status(
                        f"Extracted '{pending_extract['stream']}' to '{e.path}'."
                    )
                else:
                    set_status(
                        f"Failed to extract '{pending_extract['stream']}'.",
                        is_error=True,
                    )

        target_file_picker = ft.FilePicker(on_result=on_target_file_picked)
        target_dir_picker = ft.FilePicker(on_result=on_target_dir_picked)
        export_dir_picker = ft.FilePicker(on_result=on_export_dir_picked)
        embed_file_picker = ft.FilePicker(on_result=on_embed_file_picked)
        save_stream_picker = ft.FilePicker(on_result=on_save_stream_picked)
        page.overlay.extend(
            [
                target_file_picker,
                target_dir_picker,
                export_dir_picker,
                embed_file_picker,
                save_stream_picker,
            ]
        )

        # --- Scan / Filter Controls ---
        pattern_field = ft.TextField(
            label="Glob Pattern",
            value="*",
            width=130,
            tooltip="Filter files by glob pattern (e.g. *.exe, *.docx, *)",
        )
        zone_dropdown = ft.Dropdown(
            label="Zone Filter",
            width=160,
            value="",
            options=[
                ft.dropdown.Option("", "All Zones"),
                ft.dropdown.Option("0", "0 - Local"),
                ft.dropdown.Option("1", "1 - Intranet"),
                ft.dropdown.Option("2", "2 - Trusted"),
                ft.dropdown.Option("3", "3 - Internet"),
                ft.dropdown.Option("4", "4 - Restricted"),
            ],
        )
        recursive_switch = ft.Switch(label="Recursive", value=True)
        suspicious_switch = ft.Switch(label="Suspicious Only", value=False)
        dry_run_switch = ft.Switch(label="Dry Run (Preview Clear)", value=False)

        results_column = ft.Column(spacing=10, expand=True)

        def refresh_scan(_=None):
            target = path_field.value.strip()
            if not target:
                set_status("Please enter a target file or folder path.", is_error=True)
                return

            results_column.controls.clear()
            z_val = zone_dropdown.value if zone_dropdown.value else None
            data_objs = scan_files(
                target,
                recursive=recursive_switch.value,
                pattern=pattern_field.value.strip() or "*",
                suspicious_only=suspicious_switch.value,
                zone_filter=z_val,
                app=app,
            )

            if not data_objs:
                results_column.controls.append(
                    ft.Text("No matching Alternate Data Streams found.", italic=True)
                )
                set_status(f"Scan complete: 0 matching files with streams in '{target}'.")
                page.update()
                return

            total_streams = sum(len(d.Data) for d in data_objs)
            for d in data_objs:
                stream_cards = []
                for s in d.Data:
                    sname = s.get("Name", "")
                    ssize = Displayer._format_size(s.get("Size", 0))
                    stype = s.get("Type", "Unknown")
                    ssha = s.get("SHA256", "")
                    suspicious = s.get("Suspicious", False)
                    zone_info = s.get("ZoneInfo")
                    preview = Displayer._format_preview(s.get("data", b""))

                    def make_extract_handler(fpath, stream_to_ext):
                        def _on_ext(_):
                            pending_extract["file"] = fpath
                            pending_extract["stream"] = stream_to_ext
                            default_name = f"{_sanitize_filename(Path(fpath).name)}__{_sanitize_filename(stream_to_ext)}.bin"
                            try:
                                save_stream_picker.save_file(file_name=default_name)
                            except Exception:
                                out_dir = Path(export_dir_field.value.strip() or "ads_backup")
                                out_dir.mkdir(parents=True, exist_ok=True)
                                dest = out_dir / default_name
                                extract_stream_data(fpath, stream_to_ext, output_path=str(dest), app=app)
                                set_status(f"Extracted '{stream_to_ext}' to '{dest}'.")
                        return _on_ext

                    def make_delete_handler(fpath, stream_to_del):
                        def _on_del(_):
                            deleted = app.del_data(
                                fpath,
                                stream_name=stream_to_del,
                                dry_run=dry_run_switch.value,
                            )
                            prefix = "[DRY-RUN] Would delete" if dry_run_switch.value else "Deleted"
                            set_status(f"{prefix} stream '{stream_to_del}' from {fpath} ({len(deleted)} affected)")
                            refresh_scan()
                        return _on_del

                    details = [
                        ft.Text(
                            f"Stream: {sname}  |  Size: {ssize}  |  Type: {stype}"
                            + ("  [SUSPICIOUS EXECUTABLE]" if suspicious else ""),
                            weight=ft.FontWeight.BOLD,
                            color=ft.colors.RED_400 if suspicious else None,
                        ),
                        ft.Text(f"SHA-256: {ssha}", size=12, selectable=True),
                        ft.Text(f"Preview: {preview}", size=12, selectable=True),
                    ]
                    if zone_info:
                        details.append(
                            ft.Text(
                                f"Zone.Identifier: {zone_info.get('Summary', '')}",
                                size=12,
                                color=ft.colors.AMBER_400,
                                selectable=True,
                            )
                        )

                    stream_cards.append(
                        ft.Container(
                            content=ft.Row(
                                [
                                    ft.Column(details, expand=True, spacing=2),
                                    ft.Row(
                                        [
                                            ft.OutlinedButton(
                                                "Extract",
                                                on_click=make_extract_handler(d.Path, sname),
                                            ),
                                            ft.ElevatedButton(
                                                "Delete",
                                                on_click=make_delete_handler(d.Path, sname),
                                                color=ft.colors.RED_300,
                                            ),
                                        ],
                                        spacing=6,
                                    ),
                                ],
                                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                            ),
                            padding=10,
                            border=ft.border.all(1, ft.colors.OUTLINE_VARIANT),
                            border_radius=6,
                        )
                    )

                results_column.controls.append(
                    ft.Card(
                        content=ft.Container(
                            content=ft.Column(
                                [
                                    ft.Text(
                                        f"File: {d.Path}",
                                        weight=ft.FontWeight.BOLD,
                                        size=15,
                                        selectable=True,
                                    ),
                                    *stream_cards,
                                ],
                                spacing=8,
                            ),
                            padding=12,
                        )
                    )
                )

            set_status(
                f"Scan complete: found {total_streams} stream(s) across {len(data_objs)} file(s)."
            )
            page.update()

        def on_clear_metadata(_):
            target = path_field.value.strip()
            deleted = delete_metadata(
                target,
                overwrite=False,
                recursive=recursive_switch.value,
                pattern=pattern_field.value.strip() or "*",
                dry_run=dry_run_switch.value,
                app=app,
            )
            mode = "[DRY-RUN] Would clear" if dry_run_switch.value else "Cleared"
            set_status(f"{mode} {len(deleted)} metadata stream(s).")
            refresh_scan()

        def on_clear_all(_):
            target = path_field.value.strip()
            deleted = delete_metadata(
                target,
                overwrite=True,
                recursive=recursive_switch.value,
                pattern=pattern_field.value.strip() or "*",
                dry_run=dry_run_switch.value,
                app=app,
            )
            mode = "[DRY-RUN] Would clear" if dry_run_switch.value else "Cleared"
            set_status(f"{mode} {len(deleted)} total stream(s).")
            refresh_scan()

        def on_export_all(_):
            target = path_field.value.strip()
            out_dir = export_dir_field.value.strip()
            if not target or not out_dir:
                set_status("Specify both target path and export directory.", is_error=True)
                return
            manifest = export_all_streams(
                target,
                out_dir,
                recursive=recursive_switch.value,
                pattern=pattern_field.value.strip() or "*",
                app=app,
            )
            set_status(f"Exported {len(manifest)} stream(s) to '{out_dir}'.")

        def on_restore_backup(_):
            out_dir = export_dir_field.value.strip()
            if not out_dir:
                set_status("Specify the backup directory to restore from.", is_error=True)
                return
            count = restore_streams(out_dir, overwrite=True, app=app)
            set_status(f"Restored {count} stream(s) from '{out_dir}'.")
            refresh_scan()

        # --- Add / Copy Stream Controls ---
        add_stream_name = ft.TextField(label="Stream Name", width=200)
        add_base64_switch = ft.Switch(label="Base64 Encode (File)", value=False)
        add_overwrite_switch = ft.Switch(label="Overwrite Existing", value=False)
        copy_dst_field = ft.TextField(
            label="Destination File Path (for Copy Streams)", expand=True
        )

        def on_add_text(_):
            target = path_field.value.strip()
            sname = add_stream_name.value.strip()
            sdata = add_stream_data.value
            if not target or not sname:
                set_status("Target file path and stream name are required.", is_error=True)
                return
            ok = app.add_str_data(
                target, sname, sdata, overwrite=add_overwrite_switch.value
            )
            if ok:
                set_status(f"Added text stream '{sname}' to '{target}'.")
                refresh_scan()
            else:
                set_status(f"Failed to add stream '{sname}'.", is_error=True)

        def on_add_file(_):
            target = path_field.value.strip()
            sname = add_stream_name.value.strip()
            sfile = add_stream_data.value.strip()
            if not target or not sname or not sfile:
                set_status(
                    "Target file path, stream name, and source file path are required.",
                    is_error=True,
                )
                return
            ok = app.add_bin_data(
                target,
                sname,
                sfile,
                use_base64=add_base64_switch.value,
                overwrite=add_overwrite_switch.value,
            )
            if ok:
                set_status(f"Embedded file '{sfile}' into stream '{sname}'.")
                refresh_scan()
            else:
                set_status(f"Failed to embed file into stream '{sname}'.", is_error=True)

        def on_copy_streams(_):
            src = path_field.value.strip()
            dst = copy_dst_field.value.strip()
            sname = add_stream_name.value.strip() or None
            if not src or not dst:
                set_status("Specify both target (source) file and destination file.", is_error=True)
                return
            copied = copy_streams(
                src, dst, stream_name=sname, overwrite=add_overwrite_switch.value, app=app
            )
            set_status(f"Copied {copied} stream(s) from '{src}' to '{dst}'.")

        page.add(
            ft.Text(
                f"ADSClient v{__version__} — NTFS Alternate Data Stream Manager",
                size=22,
                weight=ft.FontWeight.BOLD,
            ),
            status_text,
            ft.Divider(),
            ft.Row(
                [
                    path_field,
                    ft.OutlinedButton(
                        "Browse File",
                        on_click=lambda _: target_file_picker.pick_files(),
                    ),
                    ft.OutlinedButton(
                        "Browse Folder",
                        on_click=lambda _: target_dir_picker.get_directory_path(),
                    ),
                ]
            ),
            ft.Row(
                [
                    pattern_field,
                    zone_dropdown,
                    recursive_switch,
                    suspicious_switch,
                    dry_run_switch,
                ]
            ),
            ft.Row(
                [
                    ft.ElevatedButton("Scan Streams", on_click=refresh_scan),
                    ft.OutlinedButton("Clear Metadata Streams", on_click=on_clear_metadata),
                    ft.OutlinedButton("Clear ALL Streams", on_click=on_clear_all),
                ],
                spacing=10,
            ),
            ft.Row(
                [
                    export_dir_field,
                    ft.OutlinedButton(
                        "Browse Backup Dir",
                        on_click=lambda _: export_dir_picker.get_directory_path(),
                    ),
                    ft.ElevatedButton("Export All Streams", on_click=on_export_all),
                    ft.OutlinedButton("Restore Backup", on_click=on_restore_backup),
                ]
            ),
            ft.Divider(),
            ft.Text("Add or Copy Streams", weight=ft.FontWeight.BOLD, size=16),
            ft.Row(
                [
                    add_stream_name,
                    add_stream_data,
                    ft.OutlinedButton(
                        "Pick File",
                        on_click=lambda _: embed_file_picker.pick_files(),
                    ),
                ]
            ),
            ft.Row(
                [
                    add_base64_switch,
                    add_overwrite_switch,
                    ft.ElevatedButton("Add Text Stream", on_click=on_add_text),
                    ft.ElevatedButton("Add File Stream", on_click=on_add_file),
                ]
            ),
            ft.Row(
                [
                    copy_dst_field,
                    ft.OutlinedButton("Copy Stream(s) to Destination", on_click=on_copy_streams),
                ]
            ),
            ft.Divider(),
            ft.Text("Discovered Streams", weight=ft.FontWeight.BOLD, size=16),
            results_column,
        )

    ft.app(target=main_view)
    return True
