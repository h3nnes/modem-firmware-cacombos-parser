#!/usr/bin/env python3
"""Core Qualcomm RF-combination analysis and export routines.

This module contains all non-GUI work used by ``qualcomm_rf_combo_gui.py``:

* scanning a FAT16 modem image or a directly supplied RF MBN;
* parsing legacy ELF and modern DAT/protobuf RF cards;
* normalizing LTE CA, NR-CA, EN-DC, and NR-DC records;
* writing MBN, JSON, CSV, 0xB0CD, and 0xB826 exports; and
* comparing multiple RF-card MBNs.

This revision adds Magnus inline-150 legacy tables, UBI/UBIFS container input,
and dynamically selected native-aligned/later-generated band-group fields.

Keep this file beside ``legacy_rf_parser.py`` and
``modern_rfcard_parser.py``.
"""

from __future__ import annotations

import csv
import datetime
import hashlib
import itertools
import json
import logging
import re
import struct
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterable, Sequence

import image_extractor
import legacy_rf_parser as legacy
import new_rfcard_parser as modern

# Exposed so the GUI/CLI front end can handle parser failures without importing
# the legacy implementation directly.
ParseError = legacy.ParseError

VERSION = "1.9.0"
MODERN_RE = re.compile(
    r"^rf_config_(?P<hwid>\d+)_(?P<fsid>\d+)_(?P<bid>\d+)"
    r"(?:_(?P<rev>\d+))?\.mbn$",
    re.IGNORECASE,
)
LEGACY_RE = re.compile(
    r"^(?P<hwid>[0-9A-F]+)_(?P<fsid>[0-9A-F]+)"
    r"(?:_(?P<bid>[0-9A-F]+))?\.mbn$",
    re.IGNORECASE,
)
TABLE_DISPLAY = {
    "lte_ca": "LTE CA",
    "nr_ca": "NR-CA",
    "endc": "EN-DC",
    "nrdc": "NR-DC",
    "nr_unknown": "NR-only (unclassified)",
}
B826_SOURCE = {"endc": 3, "nr_ca": 4, "nrdc": 5}


@dataclass(frozen=True)
class ModuleRecord:
    inner_path: str
    name: str
    generation: str
    size: int
    hwid: int
    fsid: int
    bid: int
    external: bool = False
    source_path: str = ""
    sidecars: dict[str, str] = field(default_factory=dict)
    sha256: str = ""
    lte_combos: int = -1
    nr_combos: str = ""

    @property
    def identity(self) -> str:
        # Preserve the firmware's literal identity spelling (for example
        # Samsung ``847_a_0``) instead of rewriting hexadecimal tokens.
        stem = Path(self.name).stem
        if stem.lower().startswith("rf_config_"):
            stem = stem[len("rf_config_"):]
        return stem

    @property
    def total_combos(self) -> int:
        lte = max(0, self.lte_combos)
        nr = 0
        if self.nr_combos and self.nr_combos != "—":
            if "=" in self.nr_combos:
                try:
                    nr = int(self.nr_combos.split("=")[-1].strip())
                except ValueError:
                    nr = 0
            else:
                try:
                    nr = sum(int(p.strip()) for p in self.nr_combos.split("+") if p.strip().isdigit())
                except ValueError:
                    nr = 0
        return lte + nr

    @property
    def has_combos(self) -> bool:
        return self.total_combos > 0


class ToolError(RuntimeError):
    pass


def _parse_identity_token(token: str) -> int:
    """Parse decimal IDs while accepting hexadecimal alphabetic tokens.

    Qualcomm/Samsung legacy filenames can use tokens such as ``a`` for 0xA.
    Purely numeric tokens retain the historical decimal interpretation.
    """
    base = 16 if any(character.isalpha() for character in token) else 10
    return int(token, base)


def _identity_value(match: re.Match[str], field: str) -> int:
    token = match.groupdict().get(field)
    return _parse_identity_token(token) if token is not None else 0


def _matches_candidate(name: str) -> tuple[str, re.Match[str]] | None:
    match = MODERN_RE.fullmatch(name)
    if match:
        return "DAT/protobuf", match
    match = LEGACY_RE.fullmatch(name)
    if match:
        return "Legacy ELF", match
    return None


def _is_so_path(path: str) -> bool:
    """Return whether a firmware path contains an ``so`` directory.

    FAT paths use forward slashes while files extracted on Windows use
    backslashes, so normalize both before applying the legacy RF-card filter.
    """
    normalized = path.replace("\\", "/").casefold()
    return "/so/" in f"/{normalized.strip('/')}"


def _walk_fat(
    fat: legacy.Fat16Image,
    directory_cluster: int | None = None,
    parent: str = "",
    seen: set[int] | None = None,
) -> Iterable[tuple[str, legacy.FatDirectoryEntry]]:
    """Walk a FAT16 image without materializing unrelated file contents."""
    seen = seen if seen is not None else set()
    if directory_cluster is not None:
        if directory_cluster in seen:
            return
        seen.add(directory_cluster)
    for entry in fat.list_directory(directory_cluster):
        if entry.name in (".", ".."):
            continue
        path = f"{parent}/{entry.name}"
        if entry.is_directory:
            yield from _walk_fat(fat, entry.first_cluster, path, seen)
        else:
            yield path, entry


def scan_source(path: Path) -> list[ModuleRecord]:
    if not path.is_file():
        raise ToolError(f"File not found: {path}")

    direct = _matches_candidate(path.name)
    if direct:
        generation, match = direct
        blob = path.read_bytes()
        digest = hashlib.sha256(blob).hexdigest()
        temp_record = ModuleRecord(
            inner_path=str(path),
            name=path.name,
            generation=generation,
            size=path.stat().st_size,
            hwid=_identity_value(match, "hwid"),
            fsid=_identity_value(match, "fsid"),
            bid=_identity_value(match, "bid"),
            external=True,
            source_path=str(path.resolve()),
            sha256=digest,
        )
        lte, nr = _combo_counts(temp_record, blob)
        return _deduplicate_records(
            [
                ModuleRecord(
                    inner_path=str(path),
                    name=path.name,
                    generation=generation,
                    size=path.stat().st_size,
                    hwid=_identity_value(match, "hwid"),
                    fsid=_identity_value(match, "fsid"),
                    bid=_identity_value(match, "bid"),
                    external=True,
                    source_path=str(path.resolve()),
                    sha256=digest,
                    lte_combos=lte,
                    nr_combos=nr,
                )
            ],
            path,
        )

    try:
        fat = legacy.Fat16Image(path)
    except Exception as exc:
        # Not a FAT16 image: try the universal container extractor.
        try:
            result = image_extractor.scan_container(path)
        except Exception as extract_exc:
            raise ToolError(
                "Input is neither a named RF MBN nor a supported FAT16 modem image; "
                f"container extraction also failed: {extract_exc}"
            ) from extract_exc
        return _deduplicate_records(_records_from_extraction(result), path)

    records: list[ModuleRecord] = []
    for inner_path, entry in _walk_fat(fat):
        match_info = _matches_candidate(entry.name)
        if not match_info:
            continue
        generation, match = match_info
        # Numeric legacy modules are meaningful under the modem's /so tree.
        # This prevents unrelated numeric MCFG files from appearing as RF cards.
        if generation == "Legacy ELF" and not _is_so_path(inner_path):
            continue
        raw = fat._read_clusters(entry.first_cluster)[: entry.size]
        digest = hashlib.sha256(raw).hexdigest()
        temp_record = ModuleRecord(
            inner_path=inner_path,
            name=entry.name,
            generation=generation,
            size=entry.size,
            hwid=_identity_value(match, "hwid"),
            fsid=_identity_value(match, "fsid"),
            bid=_identity_value(match, "bid"),
            source_path=str(path.resolve()),
            sha256=digest,
        )
        lte, nr = _combo_counts(temp_record, raw)
        records.append(
            ModuleRecord(
                inner_path=inner_path,
                name=entry.name,
                generation=generation,
                size=entry.size,
                hwid=_identity_value(match, "hwid"),
                fsid=_identity_value(match, "fsid"),
                bid=_identity_value(match, "bid"),
                source_path=str(path.resolve()),
                sha256=digest,
                lte_combos=lte,
                nr_combos=nr,
            )
        )
    return _deduplicate_records(_sort_records(records), path)


def _records_from_extraction(result: image_extractor.ScanResult) -> list[ModuleRecord]:
    """Convert extracted MBN paths into ``ModuleRecord`` objects.

    Sidecars discovered in the same directory as an MBN are attached to that
    record so the GUI can optionally surface them.
    """
    records: list[ModuleRecord] = []
    scratch = result.scratch_dir
    for mbn_path in result.mbns:
        match_info = _matches_candidate(mbn_path.name)
        if not match_info:
            continue
        generation, match = match_info
        inner_rel = (
            str(mbn_path.relative_to(scratch))
            if scratch in mbn_path.parents
            else mbn_path.name
        )
        # Numeric MBNs are normally accepted only from Qualcomm's /so tree so
        # unrelated numeric MCFG files do not become RF-card candidates.
        # Apple BBCFG extraction places positively identified legacy ELFs in a
        # dedicated rfcards directory instead.  Normalize separators because
        # inner_rel is platform-native (notably backslashes on Windows).
        inner_parts = {
            part for part in inner_rel.replace("\\", "/").casefold().split("/")
            if part
        }
        if (
            generation == "Legacy ELF"
            and "so" not in inner_parts
            and "rfcards" not in inner_parts
        ):
            continue
        sidecars = image_extractor.sidecars_in_directory(mbn_path.parent, result.sidecars)
        if sidecars:
            logging.getLogger(__name__).info(
                "Discovered sidecars for %s: %s",
                mbn_path.name,
                ", ".join(sorted(sidecars)),
            )
        blob = mbn_path.read_bytes()
        digest = hashlib.sha256(blob).hexdigest()
        temp_record = ModuleRecord(
            inner_path=inner_rel,
            name=mbn_path.name,
            generation=generation,
            size=mbn_path.stat().st_size,
            hwid=_identity_value(match, "hwid"),
            fsid=_identity_value(match, "fsid"),
            bid=_identity_value(match, "bid"),
            external=True,
            source_path=str(mbn_path.resolve()),
            sidecars=sidecars,
            sha256=digest,
        )
        lte, nr = _combo_counts(temp_record, blob)
        records.append(
            ModuleRecord(
                inner_path=inner_rel,
                name=mbn_path.name,
                generation=generation,
                size=mbn_path.stat().st_size,
                hwid=_identity_value(match, "hwid"),
                fsid=_identity_value(match, "fsid"),
                bid=_identity_value(match, "bid"),
                external=True,
                source_path=str(mbn_path.resolve()),
                sidecars=sidecars,
                sha256=digest,
                lte_combos=lte,
                nr_combos=nr,
            )
        )
    return _sort_records(records)


def _sort_records(records: list[ModuleRecord]) -> list[ModuleRecord]:
    return sorted(
        records,
        key=lambda item: (
            0 if item.generation == "DAT/protobuf" else 1,
            item.hwid,
            item.fsid,
            item.bid,
            item.inner_path.casefold(),
        ),
    )


def _deduplicate_records(
    records: list[ModuleRecord], source: Path | None = None
) -> list[ModuleRecord]:
    """Drop duplicate records that share the same filename and SHA-256 hash.

    Some firmware packages contain the same MBN in several extraction paths
    (e.g. wrapped sparse images that surface identical files under different
    scratch directory names).  Keeping only the first occurrence prevents the
    GUI from exporting the same content multiple times.
    """
    seen: set[tuple[str, str]] = set()
    unique: list[ModuleRecord] = []
    for record in records:
        digest = record.sha256
        if not digest:
            try:
                blob = (
                    read_module(source, record)
                    if source
                    else Path(record.source_path).read_bytes()
                )
            except OSError as exc:
                logging.getLogger(__name__).warning(
                    "Cannot hash %s for deduplication: %s", record.name, exc
                )
                unique.append(record)
                continue
            digest = hashlib.sha256(blob).hexdigest()
        key = (record.name, digest)
        if key in seen:
            logging.getLogger(__name__).info(
                "Skipping duplicate MBN: %s (SHA256 %s)", record.name, digest[:16]
            )
            continue
        seen.add(key)
        unique.append(record)
    return unique


def record_source(record: ModuleRecord, fallback: Path | None = None) -> Path:
    """Return the real source file for a record.

    ``source_path`` allows one GUI session to contain records imported from
    several modem images or standalone MBN files. ``fallback`` preserves
    compatibility with records created by older callers.
    """
    if record.source_path:
        return Path(record.source_path)
    if fallback is not None:
        return fallback
    raise ToolError(f"No source file is associated with {record.name}")


def read_module(source: Path, record: ModuleRecord) -> bytes:
    actual_source = record_source(record, source)
    if record.external:
        return actual_source.read_bytes()
    return legacy.Fat16Image(actual_source).read_file(record.inner_path)


def _safe_class(value: int) -> str:
    return chr(64 + value) if 1 <= value <= 26 else ("-" if value == 0 else f"X{value}")


def _modern_lte_rows(rrc: Any, suffix: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    field = f"lte_info_per_band_sub_cap_{suffix}"
    raw_records = modern.chunks(bytes(getattr(rrc, field)), 50)[
        : int(getattr(rrc, f"{field}_num"))
    ]
    antenna_names = modern.reverse_enum(modern.enum_assignments(), "ANTENNA_")
    combos: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    for combo_index, raw in enumerate(raw_records):
        expression = modern.decode_lte_combo(raw)
        combo_components = []
        for position in range(6):
            offset = 2 + position * 8
            band, dl_class, dl_ant, ul_class, ul_ant, ul_qam = struct.unpack_from(
                "<HBBBBB", raw, offset
            )
            if not band:
                continue
            component = {
                "table": "lte_ca",
                "sub_capability": suffix,
                "combo_index": combo_index,
                "position": len(combo_components),
                "technology": "LTE",
                "band": band,
                "dl_bw_class_code": dl_class,
                "dl_bw_class": _safe_class(dl_class),
                "dl_bw_code": None,
                "dl_bandwidth": None,
                "dl_antenna_index": dl_ant,
                "dl_antenna": antenna_names.get(dl_ant, f"INDEX_{dl_ant}"),
                "ul_bw_class_code": ul_class,
                "ul_bw_class": _safe_class(ul_class),
                "ul_bw_code": None,
                "ul_bandwidth": None,
                "ul_antenna_index": ul_ant,
                "ul_antenna": antenna_names.get(ul_ant, f"INDEX_{ul_ant}"),
                "ul_qam_cap_index": ul_qam,
            }
            combo_components.append(component)
            components.append(component)
        combos.append(
            {
                "table": "lte_ca",
                "table_name": TABLE_DISPLAY["lte_ca"],
                "sub_capability": suffix,
                "combo_index": combo_index,
                "expression": expression,
                "component_count": len(combo_components),
                "power_class": None,
                "bcs_num": None,
                "ul_tx_switch_type": None,
                "higher_power_limit": None,
                "raw_hex": raw.hex(),
            }
        )
    return combos, components


def _modern_nr_rows(
    rrc: Any,
    suffix: str,
    prefix: str,
    table: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[tuple[Any, Any]]]:
    records = modern.nr_section_records(rrc, prefix, suffix)
    enum_map = modern.enum_assignments()
    bw_names = modern.reverse_enum(enum_map, "BW_")
    antenna_names = modern.reverse_enum(enum_map, "ANTENNA_")
    combos: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    for combo_index, (groups, prop) in enumerate(records):
        expression = "+".join(
            modern.decode_nr_band_group(group, bw_names, antenna_names)
            for group in groups
        )
        for position, group in enumerate(groups):
            component = {
                "table": table,
                "sub_capability": suffix,
                "combo_index": combo_index,
                "position": position,
                "technology": "LTE" if group.tech == 1 else "NR" if group.tech == 2 else f"TECH_{group.tech}",
                "band": int(group.band),
                "dl_bw_class_code": int(group.dl_bw_class),
                "dl_bw_class": _safe_class(int(group.dl_bw_class)),
                "dl_bw_code": int(group.dl_bw_per_cc),
                "dl_bandwidth": bw_names.get(int(group.dl_bw_per_cc)),
                "dl_antenna_index": int(group.dl_max_antennas_index),
                "dl_antenna": antenna_names.get(
                    int(group.dl_max_antennas_index),
                    f"INDEX_{int(group.dl_max_antennas_index)}",
                ),
                "ul_bw_class_code": int(group.ul_bw_class),
                "ul_bw_class": _safe_class(int(group.ul_bw_class)),
                "ul_bw_code": int(group.ul_bw_per_cc),
                "ul_bandwidth": bw_names.get(int(group.ul_bw_per_cc)),
                "ul_antenna_index": int(group.ul_max_antennas_index),
                "ul_antenna": antenna_names.get(
                    int(group.ul_max_antennas_index),
                    f"INDEX_{int(group.ul_max_antennas_index)}",
                ),
                "ul_qam_cap_index": int(group.ul_qam_cap_index),
                "max_scs": int(group.max_scs),
                "srs_tx_switch_type": int(group.srs_tx_switch_type),
                "tx_switch_impact_to_rx": int(group.tx_switch_impact_to_rx),
                "tx_switch_with_another_band": int(group.tx_switch_with_another_band),
                "srs_carrier_hop": int(group.srs_carrier_hop),
                "srs_carrier_hop_src": int(group.srs_carrier_hop_src),
                "rx_limit": int(group.rx_limit),
                "link_id": int(group.link_id),
            }
            components.append(component)
        combos.append(
            {
                "table": table,
                "table_name": TABLE_DISPLAY[table],
                "sub_capability": suffix,
                "combo_index": combo_index,
                "expression": expression,
                "component_count": len(groups),
                "power_class": int(prop.power_class),
                "bcs_num": int(prop.bcs_num),
                "ul_tx_switch_type": int(prop.ul_tx_switch_type),
                "higher_power_limit": bool(prop.higher_power_limit),
                "tdd_ant_swt_fdd_disruption": bool(prop.tdd_ant_swt_fdd_disruption),
                "simultaneous_rx_tx_endc": bool(prop.simultaneousRxTxInterBandENDC),
                "simultaneous_rx_tx_ca": bool(prop.simultaneousRxTxInterBandCA),
                "simultaneous_rx_tx_sul": bool(prop.simultaneousRxTxInterBandSUL),
                "intra_contig_type": int(prop.intra_contig_type),
                "srs_cs_type": int(prop.srs_cs_type),
                "intra_ulca_dual_pa": bool(prop.intra_ulca_dual_pa),
                "has_bcs5_counterpart": bool(prop.has_bcs5_counterpart),
                "env_mode_mask_idx": int(prop.env_mode_mask_idx),
                "env_mode_subset_mask_idx": int(prop.env_mode_subset_mask_idx),
                "simul_rxtx_bmap_idx": int(prop.simul_rxtx_bmap_idx),
                "simul_sul_rxtx_bmap_idx": int(prop.simul_sul_rxtx_bmap_idx),
            }
        )
    return combos, components, records


def parse_modern(record: ModuleRecord, blob: bytes) -> dict[str, Any]:
    dats = modern.extract_rfc_dats(blob)
    res_items = [
        (name, data)
        for name, data in dats.items()
        if name.casefold().endswith("_res.dat")
    ]
    if not res_items:
        raise ToolError("No embedded /rfc/*_res.dat was found")
    if len(res_items) > 1:
        raise ToolError(
            "More than one *_res.dat was found: "
            + ", ".join(name for name, _ in res_items)
        )
    dat_name, res_dat = res_items[0]
    encoding, protobuf_payload, message = modern.parse_res_dat(res_dat)
    card_info = modern.read_rfcard_info(dat_name, record.name, message.rrc)

    combinations: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    b0cd_packets: list[tuple[str, bytes]] = []
    b826_packets: list[tuple[str, bytes]] = []

    section_specs = (
        ("nr5g", "nr_ca", 4),
        ("lte_nr5g", "endc", 3),
        ("nr5g_nr5g", "nrdc", 5),
    )
    for suffix in ("high", "low"):
        lte_combos, lte_components = _modern_lte_rows(message.rrc, suffix)
        combinations.extend(lte_combos)
        components.extend(lte_components)
        packets = modern.b0cd_v41_packets(message.rrc, suffix)
        b0cd_packets.extend(
            (f"{suffix} LTE CA packet {index + 1}/{len(packets)}", payload)
            for index, payload in enumerate(packets)
        )

        for prefix, table, source in section_specs:
            combo_rows, component_rows, raw_records = _modern_nr_rows(
                message.rrc, suffix, prefix, table
            )
            combinations.extend(combo_rows)
            components.extend(component_rows)
            packets = (
                modern.b826_v22_packets(raw_records, source)
                if raw_records
                else []
            )
            b826_packets.extend(
                (
                    f"{suffix} {TABLE_DISPLAY[table]} source={source} "
                    f"packet {index + 1}/{len(packets)}",
                    payload,
                )
                for index, payload in enumerate(packets)
            )

    return {
        "metadata": {
            "tool": "Qualcomm RF Combination Extractor",
            "version": VERSION,
            "generation": record.generation,
            "module": asdict(record),
            "module_sha256": hashlib.sha256(blob).hexdigest(),
            "res_dat_path": dat_name,
            "res_dat_sha256": hashlib.sha256(res_dat).hexdigest(),
            "dat_encoding": encoding,
            "protobuf_size": len(protobuf_payload),
            "rfcard": card_info,
            "diag_note": "Headerless synthetic DIAG payloads reconstructed from static RFCard tables.",
        },
        "combinations": combinations,
        "components": components,
        "diag": {"b0cd": b0cd_packets, "b826": b826_packets},
    }


def _legacy_table_labels(
    blob: bytes,
    descriptors: Sequence[legacy.Descriptor],
) -> list[tuple[str, legacy.Descriptor, str | None]]:
    classified = [(legacy.classify_descriptor(blob, item), item) for item in descriptors]
    nr_only = sorted(
        [item for kind, item in classified if kind == "nrca"],
        key=lambda item: item.file_offset,
    )
    nr_labels: dict[int, tuple[str, str | None]] = {}
    if len(nr_only) == 1:
        # A lone NR-only descriptor on the validated X70/X75 cards is normally
        # RF_NRCA.  Retain the fact that this is an inference in the JSON.
        label = "nrdc" if b"RF_NRDC" in blob and b"RF_NRCA" not in blob else "nr_ca"
        nr_labels[id(nr_only[0])] = (
            label,
            "single NR-only descriptor inferred from available table/name evidence",
        )
    elif nr_only:
        nr_labels[id(nr_only[0])] = (
            "nr_ca",
            "first NR-only descriptor inferred as RF_NRCA by legacy descriptor order",
        )
        nr_labels[id(nr_only[1])] = (
            "nrdc",
            "second NR-only descriptor inferred as RF_NRDC by legacy descriptor order",
        )
        for item in nr_only[2:]:
            nr_labels[id(item)] = (
                "nr_unknown",
                "additional NR-only descriptor cannot be classified safely",
            )

    result = []
    for kind, descriptor in classified:
        if kind == "endc":
            result.append(("endc", descriptor, None))
        elif kind == "lteca":
            result.append(("lte_ca", descriptor, None))
        elif kind == "nrca":
            table, note = nr_labels[id(descriptor)]
            result.append((table, descriptor, note))
    return sorted(
        result,
        key=lambda item: (
            {"lte_ca": 0, "nr_ca": 1, "endc": 2, "nrdc": 3}.get(item[0], 9),
            item[1].file_offset,
        ),
    )


def _legacy_b0cd_packets(
    table_results: Sequence[tuple[str, dict[str, Any]]],
    packet_combos: int = 100,
) -> list[tuple[str, bytes]]:
    encoded = []
    for table, result in table_results:
        if table != "lte_ca":
            continue
        for combo in result["combinations"]:
            groups = []
            for entry in combo["entries"]:
                groups.append(
                    struct.pack(
                        "<HBBBBB",
                        int(entry["band"]),
                        int(entry["dl_bw_class_code"]),
                        int(
                            entry.get(
                                "ul_bw_class_code",
                                1 if entry["ul_present"] else 0,
                            )
                        ),
                        int(entry["dl_antenna_index"]),
                        int(entry["ul_antenna_index"]),
                        int(entry.get("ul_qam_cap_index") or 0),
                    )
                )
            if groups:
                encoded.append(bytes([len(groups)]) + b"".join(groups))
    packets = []
    for start in range(0, len(encoded), packet_combos):
        current = encoded[start : start + packet_combos]
        packets.append(bytes([41, len(current)]) + b"".join(current))
    return [
        (f"LTE CA packet {index + 1}/{len(packets)}", payload)
        for index, payload in enumerate(packets)
    ]


def _legacy_b826_packets(
    table_results: Sequence[tuple[str, dict[str, Any]]],
) -> list[tuple[str, bytes]]:
    output: list[tuple[str, bytes]] = []
    for table, result in table_results:
        source = B826_SOURCE.get(table)
        if source is None:
            continue
        records = []
        for combo in result["combinations"]:
            groups = []
            for entry in combo["entries"]:
                groups.append(
                    SimpleNamespace(
                        tech=1 if entry["rat"] == "LTE" else 2,
                        band=int(entry["band"]),
                        dl_bw_class=int(entry["dl_bw_class_code"]),
                        dl_bw_per_cc=int(entry["dl_bw_code"]),
                        ul_bw_class=int(
                            entry.get(
                                "ul_bw_class_code",
                                1 if entry["ul_present"] else 0,
                            )
                        ),
                        ul_bw_per_cc=int(entry["ul_bw_code"]),
                        dl_max_antennas_index=int(entry["dl_antenna_index"]),
                        ul_max_antennas_index=int(entry["ul_antenna_index"]),
                        ul_qam_cap_index=0,
                    )
                )
            prop = SimpleNamespace(
                ul_tx_switch_type=int(combo.get("ul_tx_switch_type_raw") or 0)
            )
            records.append((groups, prop))
        packets = modern.b826_v22_packets(records, source) if records else []
        output.extend(
            (
                f"{TABLE_DISPLAY[table]} source={source} "
                f"packet {index + 1}/{len(packets)}",
                payload,
            )
            for index, payload in enumerate(packets)
        )
    return output


def _find_legacy_lte_array(
    blob: bytes,
    image: legacy.Elf32Image,
) -> tuple[int, int, int] | None:
    """Find the older 50-byte LTE info-per-band array and its descriptor.

    Older RF cards keep LTE CA outside the shared NR/EN-DC descriptor layout.
    The descriptor begins with ``uint16 count``, padding, and ``uint32 VA``;
    each referenced record is a two-byte prefix followed by six packed
    eight-byte LTE components.
    """

    def validate_array(count: int, offset: int) -> bool:
        if not 1 <= count <= 100_000:
            return False
        if offset < 0 or offset + count * 50 > len(blob):
            return False
        for combo_index in range(count):
            raw = blob[offset + combo_index * 50 : offset + (combo_index + 1) * 50]
            if len(raw) != 50:
                return False
            populated = 0
            seen_empty = False
            for component_index in range(6):
                pos = 2 + component_index * 8
                component = raw[pos : pos + 8]
                band, dl_class, dl_ant, ul_class, ul_ant, ul_qam = (
                    struct.unpack_from("<HBBBBB", component)
                )
                reserved = component[7]
                if band == 0:
                    if any(component):
                        return False
                    seen_empty = True
                    continue
                if seen_empty:
                    return False
                if (
                    not 1 <= band <= 511
                    or not 1 <= dl_class <= 26
                    or dl_ant > 127
                    or ul_class > 26
                    or ul_ant > 31
                    or ul_qam > 15
                    or reserved != 0
                ):
                    return False
                populated += 1
            if not 1 <= populated <= 6:
                return False
        return True

    # Generated public symbols are authoritative.  Structural scanning can
    # otherwise mistake a smaller integer elsewhere in a large card (notably
    # HWID 700) for a second count that points at the same LTE array.
    named_candidates: dict[tuple[int, int], tuple[int, int, int]] = {}
    suffix = "_lte_combos_info_table_sub_cap_high"
    for symbol in image.dynamic_symbols():
        name = symbol.name.lower()
        if (
            symbol.file_offset is None
            or "internal" in name
            or not name.endswith(suffix)
        ):
            continue
        count = struct.unpack_from("<H", blob, symbol.file_offset)[0]
        records_va = struct.unpack_from("<I", blob, symbol.file_offset + 4)[0]
        records_offset = image.va_to_offset(records_va, count * 50)
        if records_offset is None or not validate_array(count, records_offset):
            continue
        named_candidates.setdefault(
            (records_offset, count),
            (symbol.file_offset, records_offset, count),
        )
    if len(named_candidates) == 1:
        return next(iter(named_candidates.values()))
    if len(named_candidates) > 1:
        details = ", ".join(
            f"0x{item[0]:X}->{item[2]} records at 0x{item[1]:X}"
            for item in named_candidates.values()
        )
        raise ToolError(f"Ambiguous named legacy LTE CA arrays: {details}")

    candidates: list[tuple[int, int, int]] = []
    for range_start, range_end in image.mapped_file_ranges():
        aligned_start = (range_start + 3) & ~3
        for descriptor_offset in range(aligned_start, range_end - 7, 4):
            count, records_va = struct.unpack_from("<II", blob, descriptor_offset)
            if not 1 <= count <= 100_000:
                continue
            records_offset = image.va_to_offset(records_va, count * 50)
            if records_offset is None or not validate_array(count, records_offset):
                continue
            candidates.append((descriptor_offset, records_offset, count))

    # The same count/pointer can occur in aliases or references.  Collapse
    # those before deciding whether discovery is unambiguous.
    unique: dict[tuple[int, int], tuple[int, int, int]] = {}
    for item in candidates:
        unique.setdefault((item[1], item[2]), item)
    if not unique:
        return None

    if len(unique) > 1:
        # A few generated ELFs contain a valid one-record helper/internal
        # LTE array in addition to the public LTE CA table. It is not the
        # advertised capability inventory. Ignore it only when at least one
        # larger candidate exists.
        nontrivial = {
            key: item for key, item in unique.items() if item[2] > 1
        }
        if nontrivial:
            unique = nontrivial

    if len(unique) > 1:
        details = ", ".join(
            f"0x{item[0]:X}->{item[2]} records at 0x{item[1]:X}"
            for item in unique.values()
        )
        raise ToolError(f"Ambiguous legacy LTE CA arrays: {details}")

    return next(iter(unique.values()))


def _parse_legacy_lte_array(
    record: ModuleRecord,
    blob: bytes,
    image: legacy.Elf32Image,
) -> dict[str, Any] | None:
    found = _find_legacy_lte_array(blob, image)
    if found is None:
        return None
    descriptor_offset, records_offset, count = found
    combinations = []
    for combo_index in range(count):
        offset = records_offset + combo_index * 50
        raw = blob[offset : offset + 50]
        entries = []
        for component_index in range(6):
            pos = 2 + component_index * 8
            component = raw[pos : pos + 8]
            band, dl_class, dl_ant, ul_class, ul_ant, ul_qam = (
                struct.unpack_from("<HBBBBB", component)
            )
            if band == 0:
                break
            dl_pattern, dl_antenna = legacy.antenna_info(dl_ant)
            ul_pattern, ul_antenna = legacy.antenna_info(ul_ant)
            entries.append(
                {
                    "position": component_index,
                    "rat": "LTE",
                    "band": band,
                    "band_label": f"B{band}",
                    "band_class_label": (
                        f"B{band}{legacy.bandwidth_class_label(dl_class)}"
                    ),
                    "dl_bw_class_code": dl_class,
                    "dl_bw_class": legacy.bandwidth_class_label(dl_class),
                    "dl_bw_code": 0,
                    "dl_bandwidth": "not stored",
                    "dl_antenna_index": dl_ant,
                    "dl_antenna": dl_antenna,
                    "dl_antenna_pattern": dl_pattern,
                    "ul_present": bool(ul_class),
                    "ul_bw_class_code": ul_class,
                    "ul_bw_class": legacy.bandwidth_class_label(ul_class),
                    "ul_bw_code": 0,
                    "ul_bandwidth": "not stored",
                    "ul_antenna_index": ul_ant,
                    "ul_antenna": ul_antenna,
                    "ul_antenna_pattern": ul_pattern,
                    "ul_qam_cap_index": ul_qam,
                    "group_index": None,
                    "feature_word_3_hex": None,
                    "feature_word_4_hex": None,
                    "feature_word_5_hex": None,
                    "raw_hex": component.hex(" "),
                }
            )
        combinations.append(
            {
                "combo_index": combo_index,
                "file_offset": offset,
                "file_offset_hex": f"0x{offset:X}",
                "raw_hex": raw.hex(" "),
                "combo_flags": int.from_bytes(raw[:2], "little"),
                "envelope_mask": 0,
                "subset_mask": 0,
                "num_band_entries": len(entries),
                "entries": entries,
                "combination": legacy.canonical_combination(entries),
                "combination_with_classes": legacy.canonical_combination(
                    entries, include_classes=True
                ),
            }
        )
    return {
        "metadata": {
            "input_file": record.name,
            "table_kind": "lteca",
            "descriptor_discovery": "automatic legacy 50-byte LTE array",
            "record_size": 50,
            "component_size": 8,
        },
        "descriptor": {
            "file_offset": descriptor_offset,
            "file_offset_hex": f"0x{descriptor_offset:X}",
            "combo_count": count,
            "combos_file_offset": records_offset,
            "combos_file_offset_hex": f"0x{records_offset:X}",
        },
        "combinations": combinations,
    }


def parse_legacy(record: ModuleRecord, blob: bytes) -> dict[str, Any]:
    image = legacy.Elf32Image(blob)
    card_name = legacy.rfcard_name_from_symbols(image)
    lte_result = _parse_legacy_lte_array(record, blob, image)
    try:
        descriptors = legacy.find_descriptors(blob, image)
    except legacy.ParseError:
        if card_name is None:
            raise
        descriptors = []
    labeled = _legacy_table_labels(blob, descriptors)
    if not labeled and lte_result is None and card_name is None:
        raise ToolError("No LTE/NR RF-combination descriptors were classified")

    parsed: list[tuple[str, dict[str, Any]]] = []
    combinations: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    inference_notes: list[str] = []

    # _find_legacy_lte_array already prefers the authoritative generated
    # dynamic symbol and falls back to structural scanning for stripped ELFs.
    if lte_result is not None:
        parsed.append(("lte_ca", lte_result))

    for table, descriptor, inference in labeled:
        result = legacy.parse_descriptor(
            Path(record.name),
            blob,
            descriptor,
            discovery="automatic",
            table_kind={
                "lte_ca": "lteca",
                "nr_ca": "nrca",
                "endc": "endc",
                "nrdc": "nrdc",
                "nr_unknown": "unknown",
            }[table],
            detected_table_count=len(descriptors),
            embedded_path=record.inner_path,
        )
        result["metadata"]["resolved_table"] = table
        result["metadata"]["classification_inference"] = inference
        parsed.append((table, result))
        if inference:
            inference_notes.append(
                f"{TABLE_DISPLAY.get(table, table)} at "
                f"{result['descriptor']['file_offset_hex']}: {inference}"
            )
        for combo in result["combinations"]:
            combinations.append(
                {
                    "table": table,
                    "table_name": TABLE_DISPLAY.get(table, table),
                    "sub_capability": None,
                    "combo_index": combo["combo_index"],
                    "expression": combo["combination_with_classes"],
                    "component_count": combo["num_band_entries"],
                    "power_class": combo.get("power_class_raw"),
                    "bcs_num": combo.get("bcs_num"),
                    "ul_tx_switch_type": combo.get("ul_tx_switch_type_raw", 0),
                    "higher_power_limit": combo.get("higher_power_limit"),
                    "descriptor_offset": result["descriptor"]["file_offset_hex"],
                    "combo_flags": combo.get("combo_flags", combo.get("lte_combo_flag_raw", 0)),
                    "envelope_mask": combo["envelope_mask"],
                    "subset_mask": combo["subset_mask"],
                    "raw_hex": combo["raw_hex"],
                }
            )
            for entry in combo["entries"]:
                components.append(
                    {
                        "table": table,
                        "sub_capability": None,
                        "combo_index": combo["combo_index"],
                        "position": entry["position"],
                        "technology": entry["rat"],
                        "band": entry["band"],
                        "dl_bw_class_code": entry["dl_bw_class_code"],
                        "dl_bw_class": entry["dl_bw_class"],
                        "dl_bw_code": entry["dl_bw_code"],
                        "dl_bandwidth": entry["dl_bandwidth"],
                        "dl_antenna_index": entry["dl_antenna_index"],
                        "dl_antenna": entry["dl_antenna"],
                        "ul_bw_class_code": entry.get(
                            "ul_bw_class_code",
                            1 if entry["ul_present"] else 0,
                        ),
                        "ul_bw_class": entry.get(
                            "ul_bw_class",
                            "A" if entry["ul_present"] else "-",
                        ),
                        "ul_bw_code": entry["ul_bw_code"],
                        "ul_bandwidth": entry["ul_bandwidth"],
                        "ul_antenna_index": entry["ul_antenna_index"],
                        "ul_antenna": entry["ul_antenna"],
                        "ul_qam_cap_index": None,
                        "group_index": entry["group_index"],
                        "feature_word_3": entry["feature_word_3_hex"],
                        "feature_word_4": entry["feature_word_4_hex"],
                        "feature_word_5": entry["feature_word_5_hex"],
                        "raw_hex": entry["raw_hex"],
                    }
                )

    # Normalize the separately stored legacy LTE table into the common
    # combination/component exports after the shared descriptor loop.
    if lte_result is not None:
        for combo in lte_result["combinations"]:
            combinations.append(
                {
                    "table": "lte_ca",
                    "table_name": TABLE_DISPLAY["lte_ca"],
                    "sub_capability": None,
                    "combo_index": combo["combo_index"],
                    "expression": combo["combination_with_classes"],
                    "component_count": combo["num_band_entries"],
                    "power_class": None,
                    "bcs_num": None,
                    "ul_tx_switch_type": None,
                    "higher_power_limit": None,
                    "descriptor_offset": lte_result["descriptor"]["file_offset_hex"],
                    "combo_flags": combo.get("combo_flags", combo.get("lte_combo_flag_raw", 0)),
                    "envelope_mask": None,
                    "subset_mask": None,
                    "raw_hex": combo["raw_hex"],
                }
            )
            for entry in combo["entries"]:
                components.append(
                    {
                        "table": "lte_ca",
                        "sub_capability": None,
                        "combo_index": combo["combo_index"],
                        "position": entry["position"],
                        "technology": "LTE",
                        "band": entry["band"],
                        "dl_bw_class_code": entry["dl_bw_class_code"],
                        "dl_bw_class": entry["dl_bw_class"],
                        "dl_bw_code": None,
                        "dl_bandwidth": "not stored",
                        "dl_antenna_index": entry["dl_antenna_index"],
                        "dl_antenna": entry["dl_antenna"],
                        "ul_bw_class_code": entry["ul_bw_class_code"],
                        "ul_bw_class": entry["ul_bw_class"],
                        "ul_bw_code": None,
                        "ul_bandwidth": "not stored",
                        "ul_antenna_index": entry["ul_antenna_index"],
                        "ul_antenna": entry["ul_antenna"],
                        "ul_qam_cap_index": entry["ul_qam_cap_index"],
                        "group_index": None,
                        "feature_word_3": None,
                        "feature_word_4": None,
                        "feature_word_5": None,
                        "raw_hex": entry["raw_hex"],
                    }
                )

    return {
        "metadata": {
            "tool": "Qualcomm RF Combination Extractor",
            "version": VERSION,
            "generation": record.generation,
            "module": asdict(record),
            "module_sha256": hashlib.sha256(blob).hexdigest(),
            "rfcard": {
                "name": card_name,
                "name_source": (
                    "ELF dynamic symbol" if card_name is not None else None
                ),
                "canonical_xml_variant_name": None,
                "canonical_xml_variant_name_embedded": False,
                "hwid": record.hwid,
                "fsid": record.fsid,
                "bid": record.bid,
                "key": record.identity,
                "res_dat_path": None,
                "environment_name_high": None,
                "environment_name_low": None,
            },
            "descriptor_count": len(descriptors),
            "classification_notes": inference_notes,
            "diag_note": (
                "Headerless synthetic DIAG payloads reconstructed from legacy "
                "RF tables. Fields absent from the static record use conservative defaults."
            ),
        },
        "legacy_tables": [result for _, result in parsed],
        "combinations": combinations,
        "components": components,
        "diag": {
            "b0cd": _legacy_b0cd_packets(parsed),
            "b826": _legacy_b826_packets(parsed),
        },
    }


def parse_module(record: ModuleRecord, blob: bytes) -> dict[str, Any]:
    if record.generation in {"DAT/protobuf", "XML DAT", "modern"}:
        return parse_modern(record, blob)
    if record.generation in {"Legacy ELF", "legacy"}:
        return parse_legacy(record, blob)
    raise ToolError(f"Unknown RF-card format: {record.generation}")


def _json_safe(parsed: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in parsed.items() if key != "diag"}


def _cell(value: Any) -> Any:
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return value


def _write_csv(path: Path, rows: Sequence[dict[str, Any]]) -> Path:
    if not rows:
        return path
    fields: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                fields.append(key)
    try:
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({key: _cell(value) for key, value in row.items()})
        return path
    except PermissionError:
        fallback = path.with_name(f"{path.stem}_new{path.suffix}")
        with fallback.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                writer.writerow({key: _cell(value) for key, value in row.items()})
        return fallback


def _format_scs_val(scs_code: Any) -> str:
    try:
        c = int(scs_code)
        if c > 0:
            return str((1 << (c - 1)) * 15)
    except Exception:
        pass
    return "15"


def _format_qam_val(qam_code: Any) -> str:
    try:
        return "256" if int(qam_code) == 2 else "64"
    except Exception:
        return "256"


def _format_bcs(bcs_num: Any) -> str:
    s = str(bcs_num).strip()
    return "All" if s in ("", "None", "-1") else s


def _format_ul_tx_switch(switch_type: Any) -> str:
    try:
        t = int(switch_type)
        if t == 1:
            return "option 1"
        elif t == 2:
            return "option 2"
        elif t == 3:
            return "option 1,2"
    except Exception:
        pass
    return "-"


def _format_mimo(ant_str: str) -> str:
    if not ant_str or ant_str.startswith("INDEX_"):
        return "1"
    return ant_str.replace("_", " + ")


def _format_bw(bw_str: str) -> str:
    if not bw_str:
        return ""
    out = bw_str.replace("_", " + ")
    return out[:-4] if out.endswith(" MHz") else out


def _format_scs_for_comp(comp: dict[str, Any], is_ul: bool = False) -> str:
    base_scs = _format_scs_val(comp.get("max_scs"))
    bw = comp.get("ul_bandwidth" if is_ul else "dl_bandwidth", "")
    bw_class = comp.get("ul_bw_class" if is_ul else "dl_bw_class", "A")
    if "_" in bw:
        ccs = len(bw.split("_"))
    elif bw_class in ("B", "C"):
        ccs = 2
    elif bw_class == "D":
        ccs = 3
    elif bw_class == "E":
        ccs = 4
    elif bw_class == "F":
        ccs = 5
    else:
        ccs = 1
    return " + ".join([base_scs] * ccs)


def _component_sort_key(comp: dict[str, Any], is_ul: bool = False) -> tuple[int, str]:
    try:
        band = int(comp.get("band", 0))
    except (ValueError, TypeError):
        band = 0
    bw_class = str(comp.get("ul_bw_class" if is_ul else "dl_bw_class", "") or "")
    return (band, bw_class)


def _has_real_bcs(combos: Sequence[dict[str, Any]]) -> bool:
    for c in combos:
        val = c.get("bcs_num")
        if val is not None and str(val).strip() not in ("", "0", "None", "-1"):
            return True
    return False


def _normalize_legacy_component(comp: dict[str, Any]) -> dict[str, Any]:
    """Map legacy parser sentinel values onto the modern component schema."""
    out = dict(comp)
    for key in ("dl_bw_class", "ul_bw_class"):
        if out.get(key) == "NONE":
            out[key] = "-"
    for key in ("dl_antenna", "ul_antenna"):
        ant = out.get(key)
        if isinstance(ant, str):
            if ant == "NONE":
                out[key] = "INDEX_0"
            elif ant.startswith("ANTENNA_"):
                out[key] = ant[len("ANTENNA_"):]
    return out


def generate_web_tables(
    combinations: Sequence[dict[str, Any]],
    components: Sequence[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    components = [_normalize_legacy_component(c) for c in components]
    comps_by_tbl_idx: dict[str, dict[int, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for comp in components:
        tbl = comp["table"]
        idx = int(comp["combo_index"])
        comps_by_tbl_idx[tbl][idx].append(comp)

    has_endc_bcs = _has_real_bcs([c for c in combinations if c.get("table") == "endc"])
    has_nrca_bcs = _has_real_bcs([c for c in combinations if c.get("table") == "nr_ca"])
    has_lteca_bcs = _has_real_bcs([c for c in combinations if c.get("table") == "lte_ca"])
    has_nrdc_bcs = _has_real_bcs([c for c in combinations if c.get("table") == "nrdc"])

    endc_rows: list[dict[str, Any]] = []
    nrca_rows: list[dict[str, Any]] = []
    lteca_rows: list[dict[str, Any]] = []
    nrdc_rows: list[dict[str, Any]] = []

    for c in combinations:
        tbl = c["table"]
        idx = int(c["combo_index"])
        comp_list = comps_by_tbl_idx[tbl].get(idx, [])
        bcs = _format_bcs(c.get("bcs_num", "0"))

        if tbl == "endc":
            lte_comps = sorted(
                [x for x in comp_list if x.get("technology") == "LTE" and x.get("dl_bw_class") not in ("-", "0", "", "None", None)],
                key=lambda x: _component_sort_key(x, is_ul=False),
                reverse=True,
            )
            nr_comps = sorted(
                [x for x in comp_list if x.get("technology") == "NR" and x.get("dl_bw_class") not in ("-", "0", "", "None", None)],
                key=lambda x: _component_sort_key(x, is_ul=False),
                reverse=True,
            )
            lte_ul = sorted(
                [x for x in comp_list if x.get("technology") == "LTE" and x.get("ul_bw_class") not in ("-", "0", "", "None", None)],
                key=lambda x: _component_sort_key(x, is_ul=True),
                reverse=True,
            )
            nr_ul = sorted(
                [x for x in comp_list if x.get("technology") == "NR" and x.get("ul_bw_class") not in ("-", "0", "", "None", None)],
                key=lambda x: _component_sort_key(x, is_ul=True),
                reverse=True,
            )

            row: dict[str, Any] = {
                "LTE DL": " + ".join(f"{x['band']}{x['dl_bw_class']}" for x in lte_comps),
                "LTE MIMO DL": " + ".join(_format_mimo(x["dl_antenna"]) for x in lte_comps),
                "LTE DL (QAM)": "256",
                "NR DL": " + ".join(f"{x['band']}{x['dl_bw_class']}" for x in nr_comps),
                "NR MIMO DL": " + ".join(_format_mimo(x["dl_antenna"]) for x in nr_comps),
                "NR DL (QAM)": "256",
                "NR SCS DL (kHz)": " + ".join(_format_scs_for_comp(x, is_ul=False) for x in nr_comps),
                "NR BW DL (MHz)": " + ".join(_format_bw(x.get("dl_bandwidth", "")) for x in nr_comps),
                "LTE UL": " + ".join(f"{x['band']}{x['ul_bw_class']}" for x in lte_ul),
                "LTE MIMO UL": " + ".join(_format_mimo(x["ul_antenna"]) for x in lte_ul),
                "LTE UL (QAM)": "256" if all(_format_qam_val(x.get("ul_qam_cap_index")) == "256" for x in lte_ul) else (" + ".join(_format_qam_val(x.get("ul_qam_cap_index")) for x in lte_ul) if lte_ul else ""),
                "NR UL": " + ".join(f"{x['band']}{x['ul_bw_class']}" for x in nr_ul),
                "NR MIMO UL": " + ".join(_format_mimo(x["ul_antenna"]) for x in nr_ul),
                "NR UL (QAM)": "256" if all(_format_qam_val(x.get("ul_qam_cap_index")) == "256" for x in nr_ul) else (" + ".join(_format_qam_val(x.get("ul_qam_cap_index")) for x in nr_ul) if nr_ul else ""),
                "NR SCS UL (kHz)": " + ".join(_format_scs_for_comp(x, is_ul=True) for x in nr_ul),
                "NR BW UL (MHz)": " + ".join(_format_bw(x.get("ul_bandwidth", "")) for x in nr_ul),
            }
            if has_endc_bcs:
                row["BCS LTE"] = bcs
                row["BCS NR"] = bcs
                row["BCS INTRA ENDC"] = ""
            endc_rows.append(row)

        elif tbl == "nr_ca":
            nr_dl = sorted(
                [x for x in comp_list if x.get("dl_bw_class") not in ("-", "0", "", "None", None)],
                key=lambda x: _component_sort_key(x, is_ul=False),
                reverse=True,
            )
            nr_ul = sorted(
                [x for x in comp_list if x.get("ul_bw_class") not in ("-", "0", "", "None", None)],
                key=lambda x: _component_sort_key(x, is_ul=True),
                reverse=True,
            )
            row = {
                "NR DL": " + ".join(f"{x['band']}{x['dl_bw_class']}" for x in nr_dl),
                "MIMO DL": " + ".join(_format_mimo(x["dl_antenna"]) for x in nr_dl),
                "DL (QAM)": "256",
                "SCS DL (kHz)": " + ".join(_format_scs_for_comp(x, is_ul=False) for x in nr_dl),
                "BW DL (MHz)": " + ".join(_format_bw(x.get("dl_bandwidth", "")) for x in nr_dl),
                "NR UL": " + ".join(f"{x['band']}{x['ul_bw_class']}" for x in nr_ul),
                "MIMO UL": " + ".join(_format_mimo(x["ul_antenna"]) for x in nr_ul),
                "UL (QAM)": "256" if all(_format_qam_val(x.get("ul_qam_cap_index")) == "256" for x in nr_ul) else (" + ".join(_format_qam_val(x.get("ul_qam_cap_index")) for x in nr_ul) if nr_ul else ""),
                "SCS UL (kHz)": " + ".join(_format_scs_for_comp(x, is_ul=True) for x in nr_ul),
                "BW UL (MHz)": " + ".join(_format_bw(x.get("ul_bandwidth", "")) for x in nr_ul),
                "UL TX Switch": _format_ul_tx_switch(c.get("ul_tx_switch_type")),
            }
            if has_nrca_bcs:
                row["BCS"] = bcs
            nrca_rows.append(row)

        elif tbl == "lte_ca":
            lte_dl = sorted(
                [x for x in comp_list if x.get("dl_bw_class") not in ("-", "0", "", "None", None)],
                key=lambda x: _component_sort_key(x, is_ul=False),
                reverse=True,
            )
            lte_ul = sorted(
                [x for x in comp_list if x.get("ul_bw_class") not in ("-", "0", "", "None", None)],
                key=lambda x: _component_sort_key(x, is_ul=True),
                reverse=True,
            )
            row = {
                "LTE DL": " + ".join(f"{x['band']}{x['dl_bw_class']}" for x in lte_dl),
                "MIMO DL": " + ".join(_format_mimo(x["dl_antenna"]) for x in lte_dl),
                "DL (QAM)": "256",
                "LTE UL": " + ".join(f"{x['band']}{x['ul_bw_class']}" for x in lte_ul),
                "MIMO UL": " + ".join(_format_mimo(x["ul_antenna"]) for x in lte_ul),
                "UL (QAM)": "256" if all(_format_qam_val(x.get("ul_qam_cap_index")) == "256" for x in lte_ul) else (" + ".join(_format_qam_val(x.get("ul_qam_cap_index")) for x in lte_ul) if lte_ul else ""),
            }
            if has_lteca_bcs:
                row["BCS"] = bcs
            lteca_rows.append(row)

        elif tbl == "nrdc":
            fr1_dl = sorted(
                [x for x in comp_list if int(x.get("band", 0)) < 257 and x.get("dl_bw_class") not in ("-", "0", "", "None", None)],
                key=lambda x: _component_sort_key(x, is_ul=False),
                reverse=True,
            )
            fr2_dl = sorted(
                [x for x in comp_list if int(x.get("band", 0)) >= 257 and x.get("dl_bw_class") not in ("-", "0", "", "None", None)],
                key=lambda x: _component_sort_key(x, is_ul=False),
                reverse=True,
            )
            fr1_ul = sorted(
                [x for x in comp_list if int(x.get("band", 0)) < 257 and x.get("ul_bw_class") not in ("-", "0", "", "None", None)],
                key=lambda x: _component_sort_key(x, is_ul=True),
                reverse=True,
            )
            fr2_ul = sorted(
                [x for x in comp_list if int(x.get("band", 0)) >= 257 and x.get("ul_bw_class") not in ("-", "0", "", "None", None)],
                key=lambda x: _component_sort_key(x, is_ul=True),
                reverse=True,
            )
            row = {
                "FR1 DL": " + ".join(f"{x['band']}{x['dl_bw_class']}" for x in fr1_dl),
                "FR1 MIMO DL": " + ".join(_format_mimo(x["dl_antenna"]) for x in fr1_dl),
                "FR1 DL (QAM)": "256" if fr1_dl else "",
                "FR1 SCS DL (kHz)": " + ".join(_format_scs_for_comp(x, is_ul=False) for x in fr1_dl),
                "FR1 BW DL (MHz)": " + ".join(_format_bw(x.get("dl_bandwidth", "")) for x in fr1_dl),
                "FR2 DL": " + ".join(f"{x['band']}{x['dl_bw_class']}" for x in fr2_dl),
                "FR2 MIMO DL": " + ".join(_format_mimo(x["dl_antenna"]) for x in fr2_dl),
                "FR2 DL (QAM)": "256" if fr2_dl else "",
                "FR2 SCS DL (kHz)": " + ".join(_format_scs_for_comp(x, is_ul=False) for x in fr2_dl),
                "FR2 BW DL (MHz)": " + ".join(_format_bw(x.get("dl_bandwidth", "")) for x in fr2_dl),
                "FR1 UL": " + ".join(f"{x['band']}{x['ul_bw_class']}" for x in fr1_ul),
                "FR1 MIMO UL": " + ".join(_format_mimo(x["ul_antenna"]) for x in fr1_ul),
                "FR1 UL (QAM)": "256" if all(_format_qam_val(x.get("ul_qam_cap_index")) == "256" for x in fr1_ul) else (" + ".join(_format_qam_val(x.get("ul_qam_cap_index")) for x in fr1_ul) if fr1_ul else ""),
                "FR1 SCS UL (kHz)": " + ".join(_format_scs_for_comp(x, is_ul=True) for x in fr1_ul),
                "FR1 BW UL (MHz)": " + ".join(_format_bw(x.get("ul_bandwidth", "")) for x in fr1_ul),
                "FR2 UL": " + ".join(f"{x['band']}{x['ul_bw_class']}" for x in fr2_ul),
                "FR2 MIMO UL": " + ".join(_format_mimo(x["ul_antenna"]) for x in fr2_ul),
                "FR2 UL (QAM)": "256" if all(_format_qam_val(x.get("ul_qam_cap_index")) == "256" for x in fr2_ul) else (" + ".join(_format_qam_val(x.get("ul_qam_cap_index")) for x in fr2_ul) if fr2_ul else ""),
                "FR2 SCS UL (kHz)": " + ".join(_format_scs_for_comp(x, is_ul=True) for x in fr2_ul),
                "FR2 BW UL (MHz)": " + ".join(_format_bw(x.get("ul_bandwidth", "")) for x in fr2_ul),
            }
            if has_nrdc_bcs:
                row["BCS"] = bcs
            nrdc_rows.append(row)

    return {
        "lte_ca": lteca_rows,
        "nr_ca": nrca_rows,
        "endc": endc_rows,
        "nrdc": nrdc_rows,
    }


def _write_web_csvs(
    destination: Path,
    stem: str,
    combinations: Sequence[dict[str, Any]],
    components: Sequence[dict[str, Any]],
) -> list[Path]:
    written: list[Path] = []
    tables = generate_web_tables(combinations, components)
    if tables.get("lte_ca"):
        p = destination / f"{stem}_lteca.csv"
        written.append(_write_csv(p, tables["lte_ca"]))
    if tables.get("nr_ca"):
        p = destination / f"{stem}_nrca.csv"
        written.append(_write_csv(p, tables["nr_ca"]))
    if tables.get("endc"):
        p = destination / f"{stem}_endc.csv"
        written.append(_write_csv(p, tables["endc"]))
    if tables.get("nrdc"):
        p = destination / f"{stem}_nrdc.csv"
        written.append(_write_csv(p, tables["nrdc"]))

    return written


def _write_diag(
    destination: Path,
    log_code: str,
    version: int,
    packets: Sequence[tuple[str, bytes]],
) -> None:
    lines = [
        "# Headerless Qualcomm DIAG payloads reconstructed from static RF tables.",
        f"# Log {log_code}, payload version {version}; one Payload block per packet.",
        "",
    ]
    for label, payload in packets:
        lines.extend((f"# {label}", f"Payload: {payload.hex()}", ""))
    destination.write_text("\n".join(lines), encoding="ascii")


def _counts(parsed: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for combo in parsed["combinations"]:
        table = combo["table"]
        counts[table] = counts.get(table, 0) + 1
    return counts


def _combo_counts(
    record: ModuleRecord, blob: bytes
) -> tuple[int, str]:
    """Return (lte_ca_count, nr_breakdown_string) for an MBN.

    NR format: ``endc+nr_ca+nrdc=total``.

    Legacy ELF files are counted from validated descriptors and the separate
    50-byte LTE array, without fully decoding every combination.
    """
    logger = logging.getLogger(__name__)

    try:
        if record.generation in {"Legacy ELF", "legacy"}:
            image = legacy.Elf32Image(blob)
            card_name = legacy.rfcard_name_from_symbols(image)

            # LTE CA is stored separately from the NR/EN-DC descriptor tables
            # on these generated legacy RF-card modules.
            lte_found = _find_legacy_lte_array(blob, image)
            lte = lte_found[2] if lte_found is not None else 0

            try:
                descriptors = legacy.find_descriptors(blob, image)
            except legacy.ParseError:
                if card_name is not None:
                    return lte, "0+0+0=0"
                raise
            labeled = _legacy_table_labels(blob, descriptors)

            lte += sum(
                descriptor.combo_count
                for table, descriptor, _note in labeled
                if table == "lte_ca"
            )

            endc = sum(
                descriptor.combo_count
                for table, descriptor, _note in labeled
                if table == "endc"
            )
            nr_ca = sum(
                descriptor.combo_count
                for table, descriptor, _note in labeled
                if table == "nr_ca"
            )
            nrdc = sum(
                descriptor.combo_count
                for table, descriptor, _note in labeled
                if table == "nrdc"
            )

            total = endc + nr_ca + nrdc
            return lte, f"{endc}+{nr_ca}+{nrdc}={total}"

        # DAT/protobuf and other supported formats use the normal parser.
        parsed = parse_module(record, blob)
        counts = _counts(parsed)

    except Exception as exc:
        logger.debug(
            "Failed to count combos for %s: %s",
            record.name,
            exc,
            exc_info=True,
        )
        return -1, "—"

    lte = counts.get("lte_ca", 0)
    endc = counts.get("endc", 0)
    nr_ca = counts.get("nr_ca", 0)
    nrdc = counts.get("nrdc", 0)
    total = endc + nr_ca + nrdc
    return lte, f"{endc}+{nr_ca}+{nrdc}={total}"


def export_module(
    source: Path,
    record: ModuleRecord,
    output_root: Path,
    formats: set[str],
) -> dict[str, Any]:
    blob = read_module(source, record)
    stem = Path(record.name).stem
    written: list[str] = []

    # Dump the untouched original MBN directly at the export root.
    if "mbn" in formats:
        mbn_path = output_root / record.name
        actual_source = record_source(record, source)
        source_is_destination = (
            record.external and actual_source.resolve() == mbn_path.resolve()
        )
        if not source_is_destination:
            mbn_path.write_bytes(blob)
        written.append(str(mbn_path))

    analysis_formats = formats & {"json", "csv", "b0cd", "b826"}

    # A pure MBN dump is a byte-for-byte extraction and must not invoke either
    # the legacy or modern parser.
    if not analysis_formats:
        return {
            "module": record.name,
            "inner_path": record.inner_path,
            "source_path": str(record_source(record, source)),
            "generation": record.generation,
            "counts": {},
            "diag_packets": {"0xB0CD": 0, "0xB826": 0},
            "written": written,
            "classification_notes": [],
        }

    parsed = parse_module(record, blob)
    destination = output_root / stem
    destination.mkdir(parents=True, exist_ok=True)

    if "json" in formats:
        path = destination / f"{stem}_all_combos.json"
        path.write_text(
            json.dumps(_json_safe(parsed), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        written.append(str(path))
    if "csv" in formats:
        combo_path = destination / f"{stem}_combinations.csv"
        component_path = destination / f"{stem}_components.csv"
        _write_csv(combo_path, parsed["combinations"])
        _write_csv(component_path, parsed["components"])
        written.extend((str(combo_path), str(component_path)))
        web_paths = _write_web_csvs(
            destination, stem, parsed["combinations"], parsed["components"]
        )
        written.extend(str(p) for p in web_paths)
    if "b0cd" in formats:
        path = destination / f"{stem}_0xB0CD_v41.txt"
        _write_diag(path, "0xB0CD", 41, parsed["diag"]["b0cd"])
        written.append(str(path))
    if "b826" in formats:
        path = destination / f"{stem}_0xB826_v22.txt"
        _write_diag(path, "0xB826", 22, parsed["diag"]["b826"])
        written.append(str(path))

    return {
        "module": record.name,
        "inner_path": record.inner_path,
        "source_path": str(record_source(record, source)),
        "generation": record.generation,
        "counts": _counts(parsed),
        "diag_packets": {
            "0xB0CD": len(parsed["diag"]["b0cd"]),
            "0xB826": len(parsed["diag"]["b826"]),
        },
        "written": written,
        "classification_notes": parsed["metadata"].get("classification_notes", []),
    }


def export_many(
    source: Path,
    records: Sequence[ModuleRecord],
    output_root: Path,
    formats: set[str],
    progress: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    if not formats:
        raise ToolError("Select at least one export format")
    output_root.mkdir(parents=True, exist_ok=True)
    summaries = []
    for index, record in enumerate(records, 1):
        if progress:
            progress(f"[{index}/{len(records)}] Parsing {record.name}...")
        summary = export_module(source, record, output_root, formats)
        summaries.append(summary)
        if progress:
            counts = ", ".join(
                f"{TABLE_DISPLAY.get(key, key)}={value}"
                for key, value in summary["counts"].items()
            )
            progress(f"    Done: {counts or 'no populated combo tables'}")
    summary_path = output_root / "extraction_summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "tool": "Qualcomm RF Combination Extractor",
                "version": VERSION,
                "source": str(source),
                "formats": sorted(formats),
                "modules": summaries,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    if progress:
        progress(f"Wrote {summary_path}")
    return summaries

####################
_COMPARE_PROPERTY_FIELDS = (
    "power_class",
    "bcs_num",
    "ul_tx_switch_type",
    "higher_power_limit",
)


def _combo_signature(combo: dict[str, Any]) -> tuple[Any, ...]:
    """Stable semantic key used by the GUI MBN comparison reports."""
    return (
        combo.get("table"),
        combo.get("sub_capability"),
        combo.get("expression"),
        *[combo.get(field) for field in _COMPARE_PROPERTY_FIELDS],
    )


def _format_component_band(prefix: str, band: str, dl_class: str) -> str:
    """Use QCAT-like case: LTE B1A, NR n78A."""
    rat = "n" if prefix.upper() == "N" else "B"
    suffix = "" if dl_class == "_" else dl_class
    return f"{rat}{band}{suffix}"


def _split_bw_mimo(side: str | None) -> tuple[list[str], list[str]]:
    """Convert '100x4,100x4' into (['100', '100'], ['4', '4'])."""
    bandwidths: list[str] = []
    mimo: list[str] = []

    if not side:
        return bandwidths, mimo

    for part in side.split(","):
        part = part.strip()
        if not part:
            continue

        if "x" in part:
            bandwidth, layers = part.rsplit("x", 1)
            bandwidths.append(bandwidth)
            mimo.append(layers)
        else:
            bandwidths.append(part)
            mimo.append("?")

    return bandwidths, mimo


_COMBO_TOKEN_RE = re.compile(
    r"^(?P<rat>[BN])(?P<band>\d+)"
    r"(?P<dl_class>_|[A-Z]|X\d+)"
    r"(?:\[(?P<dl_side>[^\]]*)\])?"
    r"(?:;(?P<ul_class>[A-Z]|X\d+)\[(?P<ul_side>[^\]]*)\])?$",
    re.IGNORECASE,
)


def _parse_combo_expression(
    expression: Any,
) -> tuple[dict[str, Any], ...] | None:
    """Parse a recovered combo expression into comparable components."""
    if not isinstance(expression, str) or not expression:
        return None

    components: list[dict[str, Any]] = []

    for raw_token in expression.split("+"):
        match = _COMBO_TOKEN_RE.fullmatch(raw_token.strip())
        if match is None:
            return None

        dl_bw, dl_mimo = _split_bw_mimo(match.group("dl_side"))
        ul_bw, ul_mimo = _split_bw_mimo(match.group("ul_side"))

        components.append(
            {
                "rat": match.group("rat").upper(),
                "band": int(match.group("band")),
                "dl_class": match.group("dl_class").upper(),
                "dl_bw": tuple(dl_bw),
                "dl_mimo": tuple(dl_mimo),
                "ul_class": (
                    match.group("ul_class").upper()
                    if match.group("ul_class")
                    else None
                ),
                "ul_bw": tuple(ul_bw),
                "ul_mimo": tuple(ul_mimo),
            }
        )

    return tuple(components)


def _compact_combo_expression(expression: Any) -> str:
    """Render a recovered RFCard expression as a compact QCAT-like row."""
    components = _parse_combo_expression(expression)
    if components is None:
        return str(expression)

    dl_bands: list[str] = []
    dl_mimo: list[str] = []
    dl_bw: list[str] = []
    ul_bands: list[str] = []

    for component in components:
        dl_bands.append(
            _format_component_band(
                component["rat"],
                str(component["band"]),
                component["dl_class"],
            )
        )

        dl_bw.extend(component["dl_bw"] or ("?",))
        dl_mimo.extend(component["dl_mimo"] or ("?",))

        if component["ul_class"]:
            rat_prefix = "n" if component["rat"] == "N" else "B"
            ul_bands.append(rat_prefix + str(component["band"]))

    return (
        f"DL: {'+'.join(dl_bands)}"
        f" | {'+'.join(dl_mimo)}"
        f" | {'+'.join(dl_bw)}"
        f" | UL: {'+'.join(ul_bands) if ul_bands else 'none'}"
    )


def _format_combo_signature(signature: tuple[Any, ...]) -> str:
    _table, _sub_capability, expression, *properties = signature

    property_labels = {
        "power_class": "pc",
        "bcs_num": "bcs",
        "ul_tx_switch_type": "swul",
        "higher_power_limit": "hpl",
    }

    attrs: list[str] = []

    for field, value in zip(_COMPARE_PROPERTY_FIELDS, properties):
        if value is None:
            continue

        if field == "higher_power_limit" and value is False:
            continue

        attrs.append(f"{property_labels[field]}={value}")

    base = _compact_combo_expression(expression)

    if attrs:
        return f"{base} | {', '.join(attrs)}"

    return base


def _signature_topology(
    signature: tuple[Any, ...],
) -> tuple[Any, ...] | None:
    """Return combo identity while ignoring BW, MIMO and properties.

    The table, RAT/band order, DL class and UL arrangement remain part of the
    identity. For example, n12A+n48A remains the same underlying combo when
    only its bandwidth or MIMO arrangement changes.
    """
    table, _sub_capability, expression, *_properties = signature
    components = _parse_combo_expression(expression)

    if components is None:
        return None

    return (
        table,
        tuple(
            (
                component["rat"],
                component["band"],
                component["dl_class"],
                component["ul_class"],
            )
            for component in components
        ),
    )


def _signature_bw(
    signature: tuple[Any, ...],
) -> tuple[Any, ...] | None:
    components = _parse_combo_expression(signature[2])

    if components is None:
        return None

    return tuple(
        (
            component["dl_bw"],
            component["ul_bw"],
        )
        for component in components
    )


def _signature_mimo(
    signature: tuple[Any, ...],
) -> tuple[Any, ...] | None:
    components = _parse_combo_expression(signature[2])

    if components is None:
        return None

    return tuple(
        (
            component["dl_mimo"],
            component["ul_mimo"],
        )
        for component in components
    )


def _signature_properties(
    signature: tuple[Any, ...],
) -> tuple[Any, ...]:
    """Return sub-capability and combo-level property values."""
    return (
        signature[1],
        *signature[3:],
    )


def _variant_note(
    removed: tuple[Any, ...],
    current_values: set[tuple[Any, ...]],
) -> str:
    removed_topology = _signature_topology(removed)

    if removed_topology is None:
        return "DELETED"

    candidates = [
        candidate
        for candidate in current_values
        if _signature_topology(candidate) == removed_topology
    ]

    if not candidates:
        return "DELETED"

    removed_bw = _signature_bw(removed)
    removed_mimo = _signature_mimo(removed)

    notes: list[tuple[int, str]] = []

    for candidate in candidates:
        bw_changed = _signature_bw(candidate) != removed_bw
        mimo_changed = _signature_mimo(candidate) != removed_mimo

        if bw_changed and mimo_changed:
            note = "BW and MIMO changed"
            score = 2
        elif bw_changed:
            note = "BW changed"
            score = 1
        elif mimo_changed:
            note = "MIMO changed"
            score = 1
        else:
            note = "Combo still exists"
            score = 0

        notes.append((score, note))

    notes.sort(key=lambda item: (item[0], item[1]))
    return notes[0][1]


def _band_set(
    parsed: dict[str, Any],
    *,
    technology: str,
    tables: set[str],
) -> set[int]:
    return {
        int(component["band"])
        for component in parsed["components"]
        if component.get("technology") == technology
        and component.get("table") in tables
    }


def _table_signatures(
    parsed: dict[str, Any],
    tables: set[str],
) -> set[tuple[Any, ...]]:
    return {
        _combo_signature(combo)
        for combo in parsed["combinations"]
        if combo.get("table") in tables
    }


def _raw_table_count(
    parsed: dict[str, Any],
    tables: set[str],
) -> int:
    return sum(
        1
        for combo in parsed["combinations"]
        if combo.get("table") in tables
    )


def _format_bands(bands: set[int], prefix: str) -> str:
    return (
        ", ".join(
            f"{prefix}{band}"
            for band in sorted(bands)
        )
        or "(none)"
    )


def _append_difference_list(
    lines: list[str],
    title: str,
    values: set[tuple[Any, ...]],
    *,
    current_values: set[tuple[Any, ...]] | None = None,
) -> None:
    lines.append(f"{title}: {len(values)}")

    if not values:
        lines.append("  (none)")
        return

    ordered_values = sorted(
        values,
        key=lambda item: _format_combo_signature(item).casefold(),
    )

    if current_values is not None:
        candidates_by_topo: dict[Any, list[tuple[Any, ...]]] = defaultdict(list)
        for candidate in current_values:
            topo = _signature_topology(candidate)
            if topo is not None:
                candidates_by_topo[topo].append(candidate)

        for value in ordered_values:
            text = _format_combo_signature(value)
            removed_topo = _signature_topology(value)
            candidates = candidates_by_topo.get(removed_topo, [])
            if not candidates:
                note = "DELETED"
            else:
                removed_bw = _signature_bw(value)
                removed_mimo = _signature_mimo(value)
                notes: list[tuple[int, str]] = []
                for cand in candidates:
                    bw_ch = _signature_bw(cand) != removed_bw
                    mimo_ch = _signature_mimo(cand) != removed_mimo
                    if bw_ch and mimo_ch:
                        notes.append((2, "BW and MIMO changed"))
                    elif bw_ch:
                        notes.append((1, "BW changed"))
                    elif mimo_ch:
                        notes.append((1, "MIMO changed"))
                    else:
                        notes.append((0, "Combo still exists"))
                notes.sort(key=lambda item: (item[0], item[1]))
                note = notes[0][1]
            lines.append(f"  {text} ({note})")
    else:
        for value in ordered_values:
            lines.append(f"  {_format_combo_signature(value)}")
#######################
def _identical_groups(
    analyses: Sequence[tuple[ModuleRecord, dict[str, Any]]],
    tables: set[str],
) -> list[list[str]]:
    groups: dict[frozenset[tuple[Any, ...]], list[str]] = {}
    for record, parsed in analyses:
        key = frozenset(_table_signatures(parsed, tables))
        groups.setdefault(key, []).append(record.name)
    return [
        names
        for names in groups.values()
        if len(names) > 1
    ]


def _comparison_inventory_line(
    record: ModuleRecord,
    parsed: dict[str, Any],
    tables: set[str],
) -> str:
    raw = _raw_table_count(parsed, tables)
    unique = len(_table_signatures(parsed, tables))
    table_counts = _counts(parsed)
    details = ", ".join(
        f"{TABLE_DISPLAY.get(table, table)}={table_counts.get(table, 0)}"
        for table in sorted(
            tables,
            key=lambda item: ("lte_ca", "nr_ca", "endc", "nrdc").index(item)
            if item in ("lte_ca", "nr_ca", "endc", "nrdc")
            else 99,
        )
    )
    return (
        f"{record.name}: raw={raw}, unique={unique}"
        + (f" ({details})" if details else "")
    )


def write_comparison_reports(
    source: Path,
    records: Sequence[ModuleRecord],
    output_root: Path,
    progress: Callable[[str], None] | None = None,
) -> list[Path]:
    """Compare checked GUI modules and write reports into a dedicated subfolder."""
    if len(records) < 2:
        raise ToolError("Select at least two MBNs to compare")

    timestamp = datetime.datetime.now().strftime("%y%m%d%H%M%S")
    target_dir = output_root / f"compare-{timestamp}"
    target_dir.mkdir(parents=True, exist_ok=True)
    analyses: list[tuple[ModuleRecord, dict[str, Any]]] = []
    failures: list[tuple[ModuleRecord, str]] = []

    for index, record in enumerate(records, 1):
        if progress:
            progress(f"[{index}/{len(records)}] Reading {record.name} for comparison…")
        try:
            blob = read_module(source, record)
            parsed = parse_module(record, blob)
            analyses.append((record, parsed))
        except Exception as exc:
            failures.append((record, f"{type(exc).__name__}: {exc}"))
            if progress:
                progress(f"    Failed: {failures[-1][1]}")

    if len(analyses) < 2:
        details = "; ".join(f"{record.name}: {error}" for record, error in failures)
        raise ToolError(
            "Fewer than two selected MBNs could be parsed"
            + (f": {details}" if details else "")
        )

    reference_record, reference_parsed = analyses[0]
    lte_tables = {"lte_ca"}
    nr_tables = {"nr_ca", "endc", "nrdc"}

    common_header = [
        "Qualcomm RF Combination Extractor — MBN Comparison",
        f"Tool version: {VERSION}",
        "Sources: " + ", ".join(
            sorted({str(record_source(record, source)) for record, _ in analyses})
        ),
        f"Reference: {reference_record.name}",
        "Reference selection: first checked MBN in table order",
        f"Successfully parsed: {len(analyses)} / {len(records)}",
        "",
    ]
    if failures:
        common_header.extend(
            [
                "PARSE FAILURES",
                *[f"- {record.name}: {error}" for record, error in failures],
                "",
            ]
        )

    lte_lines = common_header + [
        "LTE CA COMPARISON",
        "=" * 80,
        "",
        "INVENTORY",
    ]
    for record, parsed in analyses:
        lte_lines.append(_comparison_inventory_line(record, parsed, lte_tables))
        lte_lines.append(
            "  LTE bands: "
            + _format_bands(
                _band_set(parsed, technology="LTE", tables=lte_tables),
                "B",
            )
        )

    ref_lte_bands = _band_set(
        reference_parsed, technology="LTE", tables=lte_tables
    )
    ref_lte_combos = _table_signatures(reference_parsed, lte_tables)
    for record, parsed in analyses[1:]:
        bands = _band_set(parsed, technology="LTE", tables=lte_tables)
        combos = _table_signatures(parsed, lte_tables)
        lte_lines.extend(
            [
                "",
                "-" * 80,
                f"{record.name} compared with {reference_record.name}",
                f"Raw LTE CA total: {_raw_table_count(parsed, lte_tables)} "
                f"(reference {_raw_table_count(reference_parsed, lte_tables)})",
                f"Unique LTE CA total: {len(combos)} "
                f"(reference {len(ref_lte_combos)})",
                "LTE bands added: " + _format_bands(bands - ref_lte_bands, "B"),
                "LTE bands removed: " + _format_bands(ref_lte_bands - bands, "B"),
            ]
        )
        _append_difference_list(
            lte_lines,
            "LTE combos removed",
            ref_lte_combos - combos,
            current_values=combos,
        )

    lte_lines.extend(["", "=" * 80, "IDENTICAL LTE TABLE GROUPS"])
    lte_groups = _identical_groups(analyses, lte_tables)
    if lte_groups:
        for group in lte_groups:
            lte_lines.append("- " + ", ".join(group))
    else:
        lte_lines.append("(none)")

    nr_lines = common_header + [
        "NR COMPARISON (NR-CA / EN-DC / NR-DC)",
        "=" * 80,
        "",
        "INVENTORY",
    ]
    for record, parsed in analyses:
        nr_lines.append(_comparison_inventory_line(record, parsed, nr_tables))
        nr_lines.append(
            "  NR bands: "
            + _format_bands(
                _band_set(parsed, technology="NR", tables=nr_tables),
                "n",
            )
        )

    ref_nr_bands = _band_set(
        reference_parsed, technology="NR", tables=nr_tables
    )
    ref_by_table = {
        table: _table_signatures(reference_parsed, {table})
        for table in ("nr_ca", "endc", "nrdc")
    }
    for record, parsed in analyses[1:]:
        bands = _band_set(parsed, technology="NR", tables=nr_tables)
        nr_lines.extend(
            [
                "",
                "-" * 80,
                f"{record.name} compared with {reference_record.name}",
                f"Raw NR-related total: {_raw_table_count(parsed, nr_tables)} "
                f"(reference {_raw_table_count(reference_parsed, nr_tables)})",
                f"Unique NR-related total: {len(_table_signatures(parsed, nr_tables))} "
                f"(reference {len(_table_signatures(reference_parsed, nr_tables))})",
                "NR bands added: " + _format_bands(bands - ref_nr_bands, "n"),
                "NR bands removed: " + _format_bands(ref_nr_bands - bands, "n"),
            ]
        )
        for table in ("nr_ca", "endc", "nrdc"):
            current = _table_signatures(parsed, {table})
            reference = ref_by_table[table]
            nr_lines.append(
                f"{TABLE_DISPLAY[table]} total: "
                f"{_raw_table_count(parsed, {table})} raw / {len(current)} unique "
                f"(reference {_raw_table_count(reference_parsed, {table})} raw / "
                f"{len(reference)} unique)"
            )
            _append_difference_list(
                nr_lines,
                f"{TABLE_DISPLAY[table]} combos removed",
                reference - current,
                current_values=current,
            )

    nr_lines.extend(["", "=" * 80, "IDENTICAL NR TABLE GROUPS"])
    nr_groups = _identical_groups(analyses, nr_tables)
    if nr_groups:
        for group in nr_groups:
            nr_lines.append("- " + ", ".join(group))
    else:
        nr_lines.append("(none)")

    lte_path = target_dir / "rfcard_lte_compare.txt"
    nr_path = target_dir / "rfcard_nr_compare.txt"
    lte_path.write_text("\n".join(lte_lines) + "\n", encoding="utf-8")
    nr_path.write_text("\n".join(nr_lines) + "\n", encoding="utf-8")
    if progress:
        progress(f"Wrote {lte_path}")
        progress(f"Wrote {nr_path}")

    csv_paths = write_simplified_comparison_csvs(
        records,
        analyses,
        target_dir,
        progress,
    )
    return [*csv_paths, lte_path, nr_path]


_CC_CLASS_MAP = {
    "A": 1,
    "B": 2,
    "C": 2,
    "D": 3,
    "E": 4,
    "F": 5,
    "G": 6,
    "H": 7,
    "I": 8,
}


def format_simplified_component(comp: dict[str, Any]) -> tuple[str, int, int, int, str]:
    """Format a single component into simplified notation (omitting 'A' unless not class A).

    Returns:
        (comp_str, cc_count, is_nr, band, dl_class)
    """
    tech = comp.get("technology", "LTE")
    is_nr = 1 if tech == "NR" else 0
    prefix = "n" if is_nr else ""
    band = int(comp.get("band", 0))
    dl = comp.get("dl_bw_class", "-")
    dl_str = "" if dl in ("-", "", None, "X0", 0, "0") else str(dl).upper()
    class_str = "" if dl_str in ("A", "") else dl_str
    if dl_str or class_str:
        comp_str = f"{prefix}{band}{class_str}"
    else:
        comp_str = f"{prefix}{band}_"
    cc = _CC_CLASS_MAP.get(dl_str, 1)
    return comp_str, cc, is_nr, band, dl_str


def combo_simplified_key(
    table: str,
    components: Sequence[dict[str, Any]],
) -> tuple[int, tuple[tuple[int, int, str], ...], str]:
    """Calculate the sort key for a simplified combination.

    Sort order:
    1. Smallest CC count first (1CC, 2CC, 3CC, 4CC, 5CC...)
    2. Band numbers from low to high (by first band, then second band...)
    3. DL bandwidth classes
    4. Exact combo string tiebreaker
    """
    formatted = [format_simplified_component(c) for c in components]
    if table == "endc":
        lte_parts = [f[0] for f in formatted if f[2] == 0]
        nr_parts = [f[0] for f in formatted if f[2] == 1]
        combo_str = f"{'-'.join(lte_parts)}_{'-'.join(nr_parts)}"
    elif table == "nrdc":
        fr1_parts = [f[0] for f in formatted if f[3] < 100]
        fr2_parts = [f[0] for f in formatted if f[3] >= 100]
        if fr1_parts and fr2_parts:
            combo_str = f"{'-'.join(fr1_parts)}_{'-'.join(fr2_parts)}"
        else:
            combo_str = "-".join(f[0] for f in formatted)
    else:
        combo_str = "-".join(f[0] for f in formatted)

    total_cc = sum(f[1] for f in formatted)
    band_tuple = tuple((f[2], f[3], f[4]) for f in formatted)
    return total_cc, band_tuple, combo_str


NR_SDL_BANDS = {29, 67, 75, 76}
LTE_SDL_BANDS = {29, 32, 67, 75, 76}


def get_simplified_combos_dict(
    parsed: dict[str, Any],
) -> dict[str, dict[str, tuple[int, tuple[tuple[int, int, str], ...], str]]]:
    """Extract unique simplified combos per category including automatically filled subsets."""
    grouped: dict[str, dict[tuple[Any, int], list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for comp in parsed.get("components", []):
        table = comp["table"]
        key = (comp.get("sub_capability"), comp["combo_index"])
        grouped[table][key].append(comp)

    result: dict[str, dict[str, tuple[int, tuple[tuple[int, int, str], ...], str]]] = {}
    for table, combo_dict in grouped.items():
        unique: dict[str, tuple[int, tuple[tuple[int, int, str], ...], str]] = {}
        for _sub_cap_and_index, comps in combo_dict.items():
            comps.sort(key=lambda c: c.get("position", 0))
            if table == "endc":
                lte_comps = [c for c in comps if c.get("technology") == "LTE"]
                nr_comps = [c for c in comps if c.get("technology") == "NR"]
                for l_r in range(1, len(lte_comps) + 1):
                    for l_sub in itertools.combinations(lte_comps, l_r):
                        if all(int(c.get("band", 0)) in LTE_SDL_BANDS for c in l_sub):
                            continue
                        for n_r in range(1, len(nr_comps) + 1):
                            for n_sub in itertools.combinations(nr_comps, n_r):
                                if all(int(c.get("band", 0)) in NR_SDL_BANDS for c in n_sub):
                                    continue
                                sub = list(l_sub) + list(n_sub)
                                k = combo_simplified_key(table, sub)
                                unique[k[2]] = k
            elif table == "nr_ca":
                for r in range(1, len(comps) + 1):
                    for sub in itertools.combinations(comps, r):
                        if all(int(c.get("band", 0)) in NR_SDL_BANDS for c in sub):
                            continue
                        k = combo_simplified_key(table, list(sub))
                        unique[k[2]] = k
            elif table == "lte_ca":
                for r in range(1, len(comps) + 1):
                    for sub in itertools.combinations(comps, r):
                        if all(int(c.get("band", 0)) in LTE_SDL_BANDS for c in sub):
                            continue
                        k = combo_simplified_key(table, list(sub))
                        unique[k[2]] = k
            elif table == "nrdc":
                fr1_comps = [c for c in comps if int(c.get("band", 0)) < 100]
                fr2_comps = [c for c in comps if int(c.get("band", 0)) >= 100]
                if fr1_comps and fr2_comps:
                    for f1_r in range(1, len(fr1_comps) + 1):
                        for f1_sub in itertools.combinations(fr1_comps, f1_r):
                            if all(int(c.get("band", 0)) in NR_SDL_BANDS for c in f1_sub):
                                continue
                            for f2_r in range(1, len(fr2_comps) + 1):
                                for f2_sub in itertools.combinations(fr2_comps, f2_r):
                                    sub = list(f1_sub) + list(f2_sub)
                                    k = combo_simplified_key(table, sub)
                                    unique[k[2]] = k
                else:
                    for r in range(1, len(comps) + 1):
                        for sub in itertools.combinations(comps, r):
                            k = combo_simplified_key(table, list(sub))
                            unique[k[2]] = k
            else:
                k = combo_simplified_key(table, comps)
                unique[k[2]] = k
        result[table] = unique
    return result


def _make_column_headers(records: Sequence[ModuleRecord]) -> list[str]:
    names = [r.name for r in records]
    if len(set(names)) == len(names):
        return names
    headers = []
    seen: dict[str, int] = {}
    for r in records:
        count = seen.get(r.name, 0) + 1
        seen[r.name] = count
        if names.count(r.name) > 1:
            headers.append(f"{r.name} ({r.identity})")
        else:
            headers.append(r.name)
    return headers


def write_simplified_comparison_csvs(
    records: Sequence[ModuleRecord],
    analyses: Sequence[tuple[ModuleRecord, dict[str, Any]]],
    output_root: Path,
    progress: Callable[[str], None] | None = None,
) -> list[Path]:
    """Write column-sorted comparison CSVs with aligned rows and empty cells for missing combos."""
    output_root.mkdir(parents=True, exist_ok=True)
    headers = _make_column_headers(records)
    parsed_cards = [get_simplified_combos_dict(parsed) for _, parsed in analyses]

    table_specs = [
        ("lte_ca", "LTE CA", "rfcard_compare_lte.csv"),
        ("endc", "EN-DC", "rfcard_compare_endc.csv"),
        ("nr_ca", "NR-CA", "rfcard_compare_nrca.csv"),
        ("nrdc", "NR-DC", "rfcard_compare_nrdc.csv"),
    ]

    written_paths: list[Path] = []

    for table_key, table_label, filename in table_specs:
        all_combos: dict[str, tuple[int, tuple[tuple[int, int, str, str], ...], str]] = {}
        for card_data in parsed_cards:
            table_combos = card_data.get(table_key, {})
            for combo_str, sort_key in table_combos.items():
                if combo_str not in all_combos:
                    all_combos[combo_str] = sort_key

        if not all_combos:
            continue

        sorted_combos = [k[2] for k in sorted(all_combos.values())]
        target_path = output_root / filename
        with target_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(headers)
            for combo_str in sorted_combos:
                row = [
                    (f'="{combo_str}"' if table_key == "lte_ca" else combo_str)
                    if combo_str in card_data.get(table_key, {})
                    else ""
                    for card_data in parsed_cards
                ]
                writer.writerow(row)
        written_paths.append(target_path)
        if progress:
            progress(f"Wrote {target_path} ({len(sorted_combos)} rows)")

    # Master combined CSV with all categories
    all_path = output_root / "rfcard_compare_all.csv"
    with all_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        for table_key, table_label, _ in table_specs:
            all_combos = {}
            for card_data in parsed_cards:
                table_combos = card_data.get(table_key, {})
                for combo_str, sort_key in table_combos.items():
                    if combo_str not in all_combos:
                        all_combos[combo_str] = sort_key

            if not all_combos:
                continue

            sorted_combos = [k[2] for k in sorted(all_combos.values())]
            writer.writerow([f"=== {table_label} ==="] * len(headers))
            for combo_str in sorted_combos:
                row = [
                    (f'="{combo_str}"' if table_key == "lte_ca" else combo_str)
                    if combo_str in card_data.get(table_key, {})
                    else ""
                    for card_data in parsed_cards
                ]
                writer.writerow(row)
            writer.writerow([""] * len(headers))
    written_paths.append(all_path)
    if progress:
        progress(f"Wrote {all_path}")

    return written_paths


__all__ = [
    "VERSION",
    "TABLE_DISPLAY",
    "ModuleRecord",
    "ToolError",
    "ParseError",
    "scan_source",
    "read_module",
    "parse_module",
    "parse_modern",
    "parse_legacy",
    "export_module",
    "export_many",
    "write_comparison_reports",
    "write_simplified_comparison_csvs",
    "format_simplified_component",
    "combo_simplified_key",
    "get_simplified_combos_dict",
]
