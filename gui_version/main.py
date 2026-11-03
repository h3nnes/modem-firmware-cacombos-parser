from __future__ import annotations

import argparse
import re
import sys
import threading
import traceback
from pathlib import Path
from typing import Any, Sequence

import qualcomm_rf_combo_analyzer as analyzer

VERSION = analyzer.VERSION
TABLE_DISPLAY = analyzer.TABLE_DISPLAY
ModuleRecord = analyzer.ModuleRecord
ToolError = analyzer.ToolError
scan_source = analyzer.scan_source
export_many = analyzer.export_many
write_comparison_reports = analyzer.write_comparison_reports


class ExtractorGUI:
    @staticmethod
    def _detect_scale(root: Any) -> float:
        """Detect the display's scaling factor (100% = 1.0, 200% = 2.0, ...).

        Queries the display server via Tk itself (works through XWayland on
        Wayland/GNOME, and natively on X11/Windows/macOS), so it reflects
        whatever scaling the *user* has configured rather than any value
        hardcoded here.
        """
        try:
            dpi = root.winfo_fpixels("1i")  # pixels per inch, per the display server
            scale = dpi / 96.0  # 96 DPI is the Tk/X11 "100%" baseline
            if not (0.5 <= scale <= 4.0):  # reject bogus/unreported values
                raise ValueError(f"implausible DPI-derived scale: {scale}")
            return scale
        except Exception:
            return 1.0  # safe fallback: behave like today, unscaled

    def s(self, px: int) -> int:
        """Scale a raw pixel value by the detected display scaling factor."""
        return round(px * self.scale)

    def __init__(self) -> None:
        import tkinter as tk
        import tkinter.font as tkfont
        from tkinter import ttk

        self.tk = tk
        self.ttk = ttk
        self.root = tk.Tk()

        # Detect the user's display scaling and make Tk's own point->pixel
        # conversion match it, so fonts and anything sized in points (the
        # ttk default) come out the right physical size automatically.
        self.scale = self._detect_scale(self.root)
        self.root.tk.call("tk", "scaling", self.scale * 1.333333)

        # Everything below is sized in raw pixels (geometry, padx/pady,
        # Treeview column widths), which `tk scaling` does NOT touch, so we
        # scale those numbers ourselves via self.s(). If you add more
        # pixel-based sizes later, always wrap them in self.s(...) too.

        self.root.title(f"qcom-rfcard-mbn-parser GUI {VERSION}")

        # Bump the row height of the Treeview to match the scaled font,
        # since ttk doesn't do this automatically.
        style = ttk.Style()
        row_font = tkfont.nametofont("TkDefaultFont")
        style.configure("Treeview", rowheight=int(row_font.metrics("linespace") * 1.5))

        self.source: Path | None = None  # most recently imported source
        self.imported_sources: list[Path] = []
        self.records: list[ModuleRecord] = []
        self.visible_by_iid: dict[str, ModuleRecord] = {}
        self.checked_keys: set[str] = set()
        self.busy = False

        self.source_var = tk.StringVar(value="No imports")
        self.status_var = tk.StringVar(
            value="Import a modem image, UBI, RF MBN, or iPhone .ipsw/.bbfw to begin."
        )
        self.format_vars = {
            "mbn": tk.BooleanVar(value=False),
            "json": tk.BooleanVar(value=False),
            "csv": tk.BooleanVar(value=False),
            "b0cd": tk.BooleanVar(value=True),
            "b826": tk.BooleanVar(value=True),
        }

        outer = ttk.Frame(self.root, padding=self.s(12))
        outer.pack(fill="both", expand=True)

        top = ttk.Frame(outer)
        top.pack(fill="x", pady=(0, self.s(10)))
        self.import_button = ttk.Button(
            top,
            text="Import image / UBI / MBN / IPSW",
            command=self.choose_source,
        )
        self.import_button.pack(side="left")
        ttk.Label(top, textvariable=self.source_var).pack(
            side="left", fill="x", expand=True, padx=(self.s(12), self.s(12))
        )
        self.clear_imports_button = ttk.Button(
            top,
            text="Clear imports",
            command=self.clear_imports,
            state="disabled",
        )
        self.clear_imports_button.pack(side="right")

        tree_frame = ttk.Frame(outer)
        tree_frame.pack(fill="both", expand=True)
        columns = ("extract", "generation", "identity", "size", "lte", "nr", "path")
        self.tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "generation": "Format",
            "identity": "HWID_FSID_BID",
            "size": "Size",
            "lte": "LTE combos",
            "nr": "NR combos",
            "path": "Path inside image",
            "extract": "Extract",
        }
        widths = {
            "extract": self.s(70),
            "generation": self.s(120),
            "identity": self.s(145),
            "size": self.s(95),
            "lte": self.s(90),
            "nr": self.s(140),
            "path": self.s(620),
        }
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(
                column,
                width=widths[column],
                minwidth=widths[column] // 2,
                anchor="center" if column in {"extract", "generation", "identity", "size", "lte", "nr"} else "w",
                stretch=False,
            )
        y_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        x_scroll = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.tree.bind("<Button-1>", self.toggle_checkbox)
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Return>", lambda _: self.open_selected_viewer())
        self.tree.bind("<space>", self.toggle_selected_row)
        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        export_row = ttk.LabelFrame(outer, text="Export formats", padding=self.s(10))
        export_row.pack(fill="x", pady=(self.s(10), self.s(8)))
        labels = {
            "mbn": "MBN dump",
            "json": "JSON",
            "csv": "CSV",
            "b0cd": "0xB0CD (LTE)",
            "b826": "0xB826 (NR)",
        }
        for key in ("mbn", "json", "csv", "b0cd", "b826"):
            ttk.Checkbutton(
                export_row,
                text=labels[key],
                variable=self.format_vars[key],
            ).pack(side="left", padx=(0, self.s(16)))

        # Selection buttons
        selection_frame = ttk.Frame(export_row)
        selection_frame.pack(side="right", padx=(self.s(12), 0))

        BUTTON_WIDTH = 12

        ttk.Button(
            selection_frame,
            text="Deselect all",
            width=BUTTON_WIDTH,
            command=self.clear_selection,
        ).pack(side="left")

        ttk.Button(
            selection_frame,
            text="Select all",
            width=BUTTON_WIDTH,
            command=self.select_all,
        ).pack(side="left", padx=(self.s(8), 0))

        self.compare_button = ttk.Button(
            selection_frame,
            text="Compare",
            command=self.choose_compare,
        )
        self.compare_button.pack(side="right", padx=(self.s(20), 0))

        self.export_button = ttk.Button(
            selection_frame,
            text="Export",
            command=self.choose_export,
        )
        self.export_button.pack(side="right", padx=(self.s(8), 0))

        self.view_button = ttk.Button(
            selection_frame,
            text="View combos",
            command=self.open_selected_viewer,
        )
        self.view_button.pack(side="right", padx=(self.s(8), 0))

        ttk.Label(outer, textvariable=self.status_var).pack(fill="x")
        self.log = tk.Text(outer, height=7, wrap="word", state="disabled")
        self.log.pack(fill="x", pady=(self.s(5), 0))

        # Now that the UI is built, measure the "Export formats" row (five
        # checkbuttons plus the selection buttons, the widest row that
        # cannot scroll horizontally) and use its required width, including the outer frame's
        # left/right padding, for the default window width and the minsize.
        # A fixed 900px basis lets Tk's packer clip the last-packed
        # selection buttons ("View combos", "Export") when space runs out.
        self.root.update_idletasks()
        min_width = max(self.s(900), export_row.winfo_reqwidth() + 2 * self.s(12))
        self.root.geometry(f"{min_width}x{self.s(720)}")
        self.root.minsize(min_width, self.s(400))

    def append_log(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", message.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def set_busy(self, value: bool, message: str | None = None) -> None:
        self.busy = value
        state = "disabled" if value else "normal"
        self.import_button.configure(state=state)
        self.view_button.configure(state=state)
        self.export_button.configure(state=state)
        self.compare_button.configure(state=state)
        self.clear_imports_button.configure(
            state="disabled" if value or not self.records else "normal"
        )
        if message:
            self.status_var.set(message)
        self.root.configure(cursor="watch" if value else "")

    @staticmethod
    def _record_key(record: ModuleRecord) -> str:
        # Deduplicate by file name and SHA-256 hash so the same content is not
        # shown again when it is extracted from different scratch directories or
        # imported more than once in the same session.
        digest = record.sha256 or ""
        return f"{record.name}\0{digest}"

    def _update_source_label(self) -> None:
        count = len(self.imported_sources)
        if count == 0:
            self.source_var.set("No imports")
        elif count == 1:
            self.source_var.set(str(self.imported_sources[0]))
        else:
            self.source_var.set(
                f"{self.imported_sources[-1]}"
            )

    def choose_source(self) -> None:
        from tkinter import filedialog

        if self.busy:
            return

        filenames = filedialog.askopenfilenames(
            title="Choose Qualcomm modem images or RF MBNs",
            filetypes=(
                (
                    "Modem images, archives, and MBNs",
                    "*.img *.bin *.ubi *.mbn *.gz *.xz *.zst *.zip *.tar *.tar.md5 *.tgz *.lz4 *.7z"
                    " *.bbfw *.ipsw",
                ),
                ("MBN files", "*.mbn"),
                ("UBI images", "*.ubi"),
                ("iPhone baseband firmware", "*.bbfw *.ipsw"),
                (
                    "Modem images and archives",
                    "*.img *.bin *.ubi *.gz *.xz *.zst *.zip *.tar *.tar.md5 *.tgz *.lz4 *.7z",
                ),
                ("All files", "*.*"),
            ),
        )
        if not filenames:
            return

        # Deduplicate by resolved path so the same file selected more than
        # once (or returned twice by the platform dialog) is only scanned once.
        sources = list(dict.fromkeys(
            Path(filename).resolve() for filename in filenames
        ))

        if not sources:
            return

        self.set_busy(
            True,
            f"Scanning {len(sources)} selected source(s)…",
        )

        for source in sources:
            self.append_log(f"Scanning {source}")

        def work() -> None:
            results: list[tuple[Path, list[ModuleRecord]]] = []
            failures: list[tuple[Path, str]] = []

            for source in sources:
                try:
                    records = scan_source(source)
                    results.append((source, records))
                except Exception:
                    failures.append((source, traceback.format_exc()))

            self.root.after(
                0,
                lambda: self.multi_scan_finished(results, failures),
            )

        threading.Thread(target=work, daemon=True).start()

    def multi_scan_finished(
        self,
        results: list[tuple[Path, list[ModuleRecord]]],
        failures: list[tuple[Path, str]],
    ) -> None:
        from tkinter import messagebox

        existing_keys = {
            self._record_key(record)
            for record in self.records
        }

        total_found = 0
        total_added = 0
        total_duplicates = 0
        total_discarded_zero = 0

        for source, records in results:
            total_found += len(records)
            added_from_source = 0
            discarded_zero_from_source = 0

            for record in records:
                if not record.has_combos:
                    discarded_zero_from_source += 1
                    total_discarded_zero += 1
                    continue

                key = self._record_key(record)

                if key in existing_keys:
                    total_duplicates += 1
                    continue

                existing_keys.add(key)
                self.records.append(record)
                self.checked_keys.add(key)
                total_added += 1
                added_from_source += 1

            if source not in self.imported_sources:
                self.imported_sources.append(source)

            if discarded_zero_from_source:
                self.append_log(
                    f"Added {added_from_source} candidate RF MBN(s) "
                    f"from {source.name} (discarded {discarded_zero_from_source} zero/blank combo MBN(s))."
                )
            else:
                self.append_log(
                    f"Added {added_from_source} candidate RF MBN(s) "
                    f"from {source.name}."
                )

        for source, error in failures:
            final_line = error.strip().splitlines()[-1]
            self.append_log(f"Failed to scan {source}: {final_line}")

        self._update_source_label()
        self.refresh_tree()

        self.set_busy(
            False,
            f"Added {total_added} MBN(s) from {len(results)} source(s); "
            f"{len(self.records)} total imported.",
        )

        if total_duplicates:
            self.append_log(
                f"Skipped {total_duplicates} duplicate MBN row(s)."
            )

        if failures:
            messagebox.showwarning(
                "Some imports failed",
                f"Successfully scanned {len(results)} source(s).\n"
                f"Failed to scan {len(failures)} source(s).\n\n"
                "See the log for details.",
            )

    def scan_failed(self, error: str) -> None:
        from tkinter import messagebox

        self.set_busy(False, "Scan failed.")
        self.append_log(error)
        messagebox.showerror("Scan failed", error.splitlines()[-1])

    def scan_finished(self, source: Path, records: list[ModuleRecord]) -> None:
        existing_keys = {self._record_key(record) for record in self.records}
        added: list[ModuleRecord] = []
        discarded_zero = 0
        for record in records:
            if not record.has_combos:
                discarded_zero += 1
                continue
            key = self._record_key(record)
            if key in existing_keys:
                continue
            existing_keys.add(key)
            self.records.append(record)
            self.checked_keys.add(key)
            added.append(record)

        if source not in self.imported_sources:
            self.imported_sources.append(source)
        self._update_source_label()
        self.refresh_tree()
        self.set_busy(
            False,
            f"Added {len(added)} MBN(s); {len(self.records)} total imported.",
        )
        if discarded_zero:
            self.append_log(
                f"Added {len(added)} candidate RF MBN(s) from {source.name} "
                f"(discarded {discarded_zero} zero/blank combo MBN(s))."
            )
        elif len(added) == len(records):
            self.append_log(
                f"Added {len(added)} candidate RF MBN(s) from {source.name}."
            )
        else:
            skipped = len(records) - len(added)
            self.append_log(
                f"Added {len(added)} candidate RF MBN(s) from {source.name}; "
                f"skipped {skipped} duplicate(s)."
            )

    def clear_imports(self) -> None:
        if self.busy:
            return
        self.source = None
        self.imported_sources.clear()
        self.records.clear()
        self.visible_by_iid.clear()
        self.checked_keys.clear()
        self.refresh_tree()
        self._update_source_label()
        self.status_var.set(
            "Imports cleared. Import a modem image, UBI, RF MBN, or "
            "iPhone .ipsw/.bbfw to begin."
        )
        self.clear_imports_button.configure(state="disabled")
        self.append_log("Cleared all imported sources and MBN rows.")

    def refresh_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.visible_by_iid.clear()
        for index, record in enumerate(self.records):
            iid = f"module-{index}"
            self.visible_by_iid[iid] = record
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    "☑" if self._record_key(record) in self.checked_keys else "☐",
                    {"DAT/protobuf": "XML DAT"}.get(record.generation, record.generation),
                    record.identity,
                    f"{record.size / 1024:,.1f} KB",
                    str(record.lte_combos) if record.lte_combos >= 0 else "—",
                    record.nr_combos,
                    f"{record.inner_path}"
                    if record.source_path else record.inner_path,
                ),
            )

    def _toggle_iid(self, iid: str) -> None:
        record = self.visible_by_iid.get(iid)
        if record is None:
            return
        key = self._record_key(record)
        if key in self.checked_keys:
            self.checked_keys.remove(key)
        else:
            self.checked_keys.add(key)
        values = list(self.tree.item(iid, "values"))
        values[0] = "☑" if key in self.checked_keys else "☐"
        self.tree.item(iid, values=values)

    def toggle_checkbox(self, event: Any) -> None:
        region = self.tree.identify_region(event.x, event.y)
        column = self.tree.identify_column(event.x)
        iid = self.tree.identify_row(event.y)
        if region == "cell" and column == "#1" and iid:
            self._toggle_iid(iid)
            return "break"
        return None

    def toggle_selected_row(self, _event: Any = None) -> str:
        selection = self.tree.selection()
        if selection:
            self._toggle_iid(selection[0])
        return "break"

    def on_double_click(self, event: Any) -> str | None:
        region = self.tree.identify_region(event.x, event.y)
        column = self.tree.identify_column(event.x)
        if region not in ("cell", "tree") or column == "#1":
            return None
        iid = self.tree.identify_row(event.y)
        if not iid:
            return None
        record = self.visible_by_iid.get(iid)
        if record is None:
            return None
        self.open_viewer_for_record(record)
        return "break"

    def open_selected_viewer(self) -> None:
        from tkinter import messagebox

        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("View Combos", "Please select an RF card to view.")
            return
        record = self.visible_by_iid.get(selection[0])
        if record is None:
            return
        self.open_viewer_for_record(record)

    def open_viewer_for_record(self, record: ModuleRecord) -> None:
        import viewer

        viewer.open_viewer(
            self.root,
            record=record,
            source=self.source,
            scale=self.scale,
        )

    def select_all(self) -> None:
        self.checked_keys = {self._record_key(record) for record in self.records}
        self.refresh_tree()

    def clear_selection(self) -> None:
        self.checked_keys.clear()
        self.refresh_tree()

    def choose_compare(self) -> None:
        from tkinter import filedialog, messagebox

        if not self.records:
            messagebox.showwarning("No imports", "Import a modem image or RF MBN first.")
            return
        selected = [
            record for record in self.records
            if self._record_key(record) in self.checked_keys
        ]
        if len(selected) < 2:
            messagebox.showwarning(
                "Not enough MBNs",
                "Check at least two MBNs in the Extract column.",
            )
            return
        directory = filedialog.askdirectory(
            title="Choose comparison report directory"
        )
        if not directory:
            return
        output = Path(directory)
        reference = selected[0]
        self.set_busy(
            True,
            f"Comparing {len(selected)} MBN(s); reference: {reference.name}…",
        )
        self.append_log(
            f"Comparing {len(selected)} MBN(s); reference is {reference.name}"
        )

        def progress(message: str) -> None:
            self.root.after(0, lambda: self.append_log(message))

        def work() -> None:
            try:
                reports = write_comparison_reports(
                    Path(selected[0].source_path),
                    selected,
                    output,
                    progress,
                )
            except Exception:
                error = traceback.format_exc()
                self.root.after(0, lambda: self.compare_failed(error))
                return
            self.root.after(
                0,
                lambda: self.compare_finished(output, reports, len(selected)),
            )

        threading.Thread(target=work, daemon=True).start()

    def compare_failed(self, error: str) -> None:
        from tkinter import messagebox

        self.set_busy(False, "Comparison failed.")
        self.append_log(error)
        messagebox.showerror("Comparison failed", error.splitlines()[-1])

    def compare_finished(
        self,
        output: Path,
        reports: Sequence[Path],
        count: int,
    ) -> None:
        from tkinter import messagebox

        report_dir = reports[0].parent if reports else output
        self.set_busy(False, f"Compared {count} MBN(s); reports written to {report_dir}")
        report_list = "\n".join(f"• {r.name}" for r in reports)
        messagebox.showinfo(
            "Comparison complete",
            f"Compared {count} MBN(s).\n\n"
            f"Created folder: {report_dir.name}\n\n"
            f"Generated reports:\n{report_list}\n\n"
            f"{report_dir}",
        )

    def choose_export(self) -> None:
        from tkinter import filedialog, messagebox

        if not self.records:
            messagebox.showwarning("No imports", "Import a modem image or RF MBN first.")
            return
        selected = [
            record for record in self.records
            if self._record_key(record) in self.checked_keys
        ]
        if not selected:
            messagebox.showwarning("No MBN selected", "Check at least one MBN in the Extract column.")
            return
        formats = {key for key, variable in self.format_vars.items() if variable.get()}
        if not formats:
            messagebox.showwarning("No format", "Tick at least one export format.")
            return
        directory = filedialog.askdirectory(title="Choose export directory")
        if not directory:
            return
        output = Path(directory)
        self.set_busy(True, f"Exporting {len(selected)} MBN(s)…")
        self.append_log(f"Exporting to {output}")

        def progress(message: str) -> None:
            self.root.after(0, lambda: self.append_log(message))

        def work() -> None:
            try:
                summaries = export_many(
                    Path(selected[0].source_path), selected, output, formats, progress
                )
            except Exception:
                error = traceback.format_exc()
                self.root.after(0, lambda: self.export_failed(error))
                return
            self.root.after(0, lambda: self.export_finished(output, summaries))

        threading.Thread(target=work, daemon=True).start()

    def export_failed(self, error: str) -> None:
        from tkinter import messagebox

        self.set_busy(False, "Export failed.")
        self.append_log(error)
        messagebox.showerror("Export failed", error.splitlines()[-1])

    def export_finished(self, output: Path, summaries: list[dict[str, Any]]) -> None:
        from tkinter import messagebox

        self.set_busy(False, f"Exported {len(summaries)} MBN(s) to {output}")
        messagebox.showinfo(
            "Export complete",
            f"Exported {len(summaries)} MBN(s).\n\n{output}",
        )

    def run(self) -> None:
        self.root.mainloop()


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan and export Qualcomm legacy and DAT/protobuf RF combinations."
    )
    parser.add_argument(
        "source",
        nargs="?",
        type=Path,
        help="modem image/UBI container or a directly named RF MBN",
    )
    parser.add_argument("--list", action="store_true", help="list candidate MBNs")
    parser.add_argument("-o", "--output", type=Path, help="export directory")
    parser.add_argument(
        "--match",
        default=".*",
        help="regular expression matched against MBN name and inner path",
    )
    parser.add_argument(
        "--formats",
        nargs="+",
        choices=("mbn", "json", "csv", "b0cd", "b826"),
        default=("json", "csv", "b0cd", "b826"),
    )
    parser.add_argument("--version", action="version", version=VERSION)
    return parser


def cli_main(argv: Sequence[str] | None = None) -> int:
    args = build_cli().parse_args(argv)
    if args.source is None:
        ExtractorGUI().run()
        return 0
    try:
        records = [record for record in scan_source(args.source) if record.has_combos]
        matcher = re.compile(args.match, re.IGNORECASE)
        records = [
            record
            for record in records
            if matcher.search(f"{record.name} {record.inner_path}")
        ]
        if args.list or args.output is None:
            for record in records:
                print(
                    f"{record.generation:12} {record.identity:14} "
                    f"{record.size:10}  {record.inner_path}"
                )
            if args.output is None:
                return 0
        if not records:
            raise ToolError("No candidate RF MBN matched the selection")
        export_many(
            args.source,
            records,
            args.output,
            set(args.formats),
            print,
        )
        return 0
    except (OSError, ToolError, ValueError, analyzer.ParseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli_main())
