#!/usr/bin/env python3
"""
Parse Qualcomm RF_ENDC and RF_NRCA combination tables from hardware-specific
modem .mbn files or extract the appropriate module directly from modem.img.

This parser uses only the Python standard library.  It was developed against the
AA515 hardware profiles 622_0_0.mbn through 625_0_0.mbn, but it discovers the
table descriptor from ELF virtual addresses instead of relying on one fixed file
offset.

Default output:
    <input_stem>_rf_endc.json
    <input_stem>_rf_endc_combos.csv
    <input_stem>_rf_endc_entries.csv
    <input_stem>_rf_endc_band_groups.csv

Example:
    python rf_endc_parser.py 622_0_0.mbn
    python rf_endc_parser.py modem.img --hwid 622 --table all
    python rf_endc_parser.py modem.img --list-hwids
    python rf_endc_parser.py modem.img --hwid 622 --extract-mbn --table all
    python rf_endc_parser.py 622_0_0.mbn --print-combo 100
    python rf_endc_parser.py 622_0_0.mbn --table nrca
    python rf_endc_parser.py 622_0_0.mbn --table all
    python rf_endc_parser.py 622_0_0.mbn --format csv --output-dir exports

Known AA515 layout, useful as a manual fallback:
    RF_NRCA descriptor file offset: 0x8EC28
    RF_ENDC descriptor file offset: 0xA7FF0
    combination record size: 40 bytes
    band-group record size: 12 bytes
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import struct
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Sequence


LEGACY_COMBO_RECORD_SIZE = 40
LEGACY_BAND_GROUP_RECORD_SIZE = 12
MODERN_COMBO_RECORD_SIZE = 44
MODERN_BAND_GROUP_RECORD_SIZE = 12
HI_INLINE_COMBO_RECORD_SIZE = 100
HI_INLINE_BAND_GROUP_RECORD_SIZE = 8
HI_INLINE_MAX_COMPONENTS = 12
HI_INLINE_PROPERTY_OFFSET = 96
HI_INLINE_COUNT_OFFSET = 98
MAGNUS_INLINE_COMBO_RECORD_SIZE = 150
MAGNUS_INLINE_BAND_GROUP_RECORD_SIZE = 12
MAGNUS_INLINE_MAX_COMPONENTS = 12
MAGNUS_INLINE_PROPERTY_OFFSET = 146
MAGNUS_INLINE_COUNT_OFFSET = 147
MAGNUS_INLINE_BCS_OFFSET = 148
MAX_GROUPS_PER_COMBO = 12
UNUSED_GROUP_INDEX = 0xFFFF

# B826 source enum values used by Qualcomm's diagnostic serialization.
TABLE_SOURCE_INFO = {
    "lteca": ("RF_LTE_CA", None),
    "endc": ("RF_ENDC", 3),
    "nrca": ("RF_NRCA", 4),
    "nrdc": ("RF_NRDC", 5),
}

# Qualcomm BW indexes independently correlated with B826 Versions 8-22.  The
# upstream Import0xB826 implementation notes that some rare values are inferred,
# so the raw index is always retained in our exports.
KNOWN_BANDWIDTH_PARTS_MHZ: dict[int, tuple[int, ...]] = {
    0: (),
    1: (5,),
    2: (10,),
    3: (15,),
    4: (20,),
    5: (20,),
    6: (20,),
    7: (20,),
    8: (20,),
    9: (25,),
    10: (30,),
    11: (40,),
    12: (50,),
    13: (50,),
    14: (50,),
    15: (50,),
    16: (50,),
    17: (60,),
    18: (70,),
    19: (80,),
    20: (90,),
    21: (100,),
    22: (100, 60),
    23: (100,),
    24: (100,),
    25: (100,),
    26: (100,),
    27: (100,),
    28: (100,),
    29: (100,),
    30: (40,),
    31: (60, 40),
    32: (100, 40),
    33: (200,),
    34: (200,),
    35: (200,),
    36: (200,),
    37: (10,),
    38: (25,),
    39: (40, 10),
    40: (40, 20),
    41: (35,),
    42: (30, 20),
    43: (60,),
    44: (30,),
    45: (45,),
    46: (50, 5),
    47: (50, 10),
    48: (50, 15),
    49: (50, 20),
    50: (40, 15),
    51: (15,),
    52: (30, 25),
    53: (20, 10),
    54: (20, 15),
    55: (5,),
    56: (80,),
    57: (80, 20),
    58: (40, 30),
    59: (100, 90),
    60: (30, 10),
    61: (100, 20),
    62: (80, 40),
    63: (50, 40),
    64: (100, 50),
    65: (100, 80),
}


class ParseError(RuntimeError):
    """Raised when the input does not contain a consistent RF table layout."""


@dataclass(frozen=True)
class FatDirectoryEntry:
    name: str
    attributes: int
    first_cluster: int
    size: int

    @property
    def is_directory(self) -> bool:
        return bool(self.attributes & 0x10)


class Fat16Image:
    """Small read-only FAT16 reader for Qualcomm modem.img files."""

    def __init__(self, path: Path) -> None:
        self.path = path
        with path.open("rb") as handle:
            boot = handle.read(512)
        if len(boot) < 64:
            raise ParseError("Input is too small to be a FAT filesystem.")

        self.bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
        self.sectors_per_cluster = boot[13]
        self.reserved_sectors = struct.unpack_from("<H", boot, 14)[0]
        self.fat_count = boot[16]
        self.root_entry_count = struct.unpack_from("<H", boot, 17)[0]
        total16 = struct.unpack_from("<H", boot, 19)[0]
        self.sectors_per_fat = struct.unpack_from("<H", boot, 22)[0]
        total32 = struct.unpack_from("<I", boot, 32)[0]
        self.total_sectors = total16 or total32

        if (
            self.bytes_per_sector not in (512, 1024, 2048, 4096)
            or self.sectors_per_cluster == 0
            or self.fat_count == 0
            or self.root_entry_count == 0
            or self.sectors_per_fat == 0
            or self.total_sectors == 0
        ):
            raise ParseError("Input is not a supported FAT16 filesystem.")

        root_bytes = self.root_entry_count * 32
        self.root_dir_sectors = (
            root_bytes + self.bytes_per_sector - 1
        ) // self.bytes_per_sector
        self.fat_offset = self.reserved_sectors * self.bytes_per_sector
        self.root_offset = (
            self.reserved_sectors + self.fat_count * self.sectors_per_fat
        ) * self.bytes_per_sector
        self.data_offset = (
            self.reserved_sectors
            + self.fat_count * self.sectors_per_fat
            + self.root_dir_sectors
        ) * self.bytes_per_sector
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

        data_sectors = (
            self.total_sectors
            - self.reserved_sectors
            - self.fat_count * self.sectors_per_fat
            - self.root_dir_sectors
        )
        cluster_count = data_sectors // self.sectors_per_cluster
        if not 4085 <= cluster_count < 65525:
            raise ParseError(
                f"Filesystem has {cluster_count} data clusters; FAT16 expected."
            )

        with path.open("rb") as handle:
            handle.seek(self.fat_offset)
            self.fat = handle.read(self.sectors_per_fat * self.bytes_per_sector)
        if len(self.fat) < (cluster_count + 2) * 2:
            raise ParseError("FAT table is shorter than the declared filesystem.")

    def _cluster_offset(self, cluster: int) -> int:
        if cluster < 2:
            raise ParseError(f"Invalid FAT16 cluster {cluster}.")
        return self.data_offset + (cluster - 2) * self.cluster_size

    def _cluster_chain(self, first_cluster: int) -> list[int]:
        chain: list[int] = []
        seen: set[int] = set()
        cluster = first_cluster
        while 2 <= cluster < 0xFFF8:
            if cluster in seen:
                raise ParseError(f"FAT16 cluster chain loops at {cluster}.")
            if cluster * 2 + 2 > len(self.fat):
                raise ParseError(f"FAT16 cluster {cluster} is outside the FAT.")
            seen.add(cluster)
            chain.append(cluster)
            cluster = struct.unpack_from("<H", self.fat, cluster * 2)[0]
            if cluster == 0xFFF7:
                raise ParseError("FAT16 cluster chain contains a bad cluster.")
            if cluster in (0, 1):
                raise ParseError("FAT16 cluster chain ended unexpectedly.")
        return chain

    def _read_clusters(self, first_cluster: int) -> bytes:
        chunks: list[bytes] = []
        with self.path.open("rb") as handle:
            for cluster in self._cluster_chain(first_cluster):
                handle.seek(self._cluster_offset(cluster))
                chunk = handle.read(self.cluster_size)
                if len(chunk) != self.cluster_size:
                    raise ParseError("FAT16 cluster extends beyond the image.")
                chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _short_name(entry: bytes) -> str:
        base = bytearray(entry[:8])
        extension = bytearray(entry[8:11])
        if base and base[0] == 0x05:
            base[0] = 0xE5
        base_text = bytes(base).decode("cp437", errors="replace").rstrip()
        extension_text = (
            bytes(extension).decode("cp437", errors="replace").rstrip()
        )
        return base_text + (f".{extension_text}" if extension_text else "")

    def _directory_bytes(self, first_cluster: int | None) -> bytes:
        if first_cluster is None:
            size = self.root_entry_count * 32
            with self.path.open("rb") as handle:
                handle.seek(self.root_offset)
                data = handle.read(size)
            if len(data) != size:
                raise ParseError("FAT16 root directory extends beyond the image.")
            return data
        return self._read_clusters(first_cluster)

    def list_directory(
        self, first_cluster: int | None
    ) -> list[FatDirectoryEntry]:
        data = self._directory_bytes(first_cluster)
        entries: list[FatDirectoryEntry] = []
        long_name_parts: dict[int, str] = {}
        for offset in range(0, len(data) - 31, 32):
            raw = data[offset : offset + 32]
            if raw[0] == 0x00:
                break
            if raw[0] == 0xE5:
                long_name_parts.clear()
                continue
            if raw[11] == 0x0F:
                ordinal = raw[0] & 0x1F
                if ordinal == 0:
                    long_name_parts.clear()
                    continue
                code_units = (
                    struct.unpack_from("<5H", raw, 1)
                    + struct.unpack_from("<6H", raw, 14)
                    + struct.unpack_from("<2H", raw, 28)
                )
                characters: list[str] = []
                for code_unit in code_units:
                    if code_unit in (0x0000, 0xFFFF):
                        break
                    characters.append(chr(code_unit))
                long_name_parts[ordinal] = "".join(characters)
                continue
            attributes = raw[11]
            if attributes & 0x08:  # volume label
                long_name_parts.clear()
                continue
            name = (
                "".join(
                    long_name_parts[index]
                    for index in sorted(long_name_parts)
                )
                if long_name_parts
                else self._short_name(raw)
            )
            long_name_parts.clear()
            first = struct.unpack_from("<H", raw, 26)[0]
            size = struct.unpack_from("<I", raw, 28)[0]
            entries.append(FatDirectoryEntry(name, attributes, first, size))
        return entries

    def find(self, inner_path: str) -> FatDirectoryEntry:
        components = [
            component
            for component in inner_path.replace("\\", "/").split("/")
            if component
        ]
        directory_cluster: int | None = None
        current: FatDirectoryEntry | None = None
        for index, component in enumerate(components):
            matches = [
                entry
                for entry in self.list_directory(directory_cluster)
                if entry.name.casefold() == component.casefold()
            ]
            if not matches:
                raise ParseError(
                    f"Path not found inside modem.img: /{'/'.join(components[:index + 1])}"
                )
            current = matches[0]
            if index < len(components) - 1:
                if not current.is_directory:
                    raise ParseError(
                        f"Not a directory inside modem.img: {current.name}"
                    )
                directory_cluster = current.first_cluster
        if current is None:
            raise ParseError("An empty path cannot be read from modem.img.")
        return current

    def read_file(self, inner_path: str) -> bytes:
        entry = self.find(inner_path)
        if entry.is_directory:
            raise ParseError(f"Path is a directory inside modem.img: {inner_path}")
        if entry.size == 0:
            return b""
        data = self._read_clusters(entry.first_cluster)
        if len(data) < entry.size:
            raise ParseError(f"FAT16 file is truncated: {inner_path}")
        return data[: entry.size]

    def hardware_mbns(self) -> list[str]:
        directory = self.find("/image/modem_pr/so")
        if not directory.is_directory:
            raise ParseError("/image/modem_pr/so is not a directory.")
        names = [
            entry.name
            for entry in self.list_directory(directory.first_cluster)
            if not entry.is_directory and entry.name.lower().endswith(".mbn")
        ]
        return sorted(names, key=str.casefold)


def normalize_hwid_name(hwid: str) -> str:
    text = hwid.strip()
    if not text:
        raise ParseError("HWID cannot be empty.")
    if text.lower().endswith(".mbn"):
        return text
    if text.lower().endswith("_0_0"):
        return text + ".mbn"
    return text + "_0_0.mbn"


@dataclass(frozen=True)
class LoadSegment:
    file_offset: int
    virtual_address: int
    file_size: int
    memory_size: int

    def contains_va_bytes(self, address: int, size: int = 1) -> bool:
        return (
            self.virtual_address <= address
            and address + size <= self.virtual_address + self.file_size
        )

    def contains_file_bytes(self, offset: int, size: int = 1) -> bool:
        return (
            self.file_offset <= offset
            and offset + size <= self.file_offset + self.file_size
        )


@dataclass(frozen=True)
class Descriptor:
    file_offset: int
    virtual_address: int | None
    combo_count: int
    combos_va: int
    combos_file_offset: int
    band_groups_va: int
    band_groups_file_offset: int
    antenna_table_count: int
    band_group_count: int
    count_byte_offset: int
    combo_record_size: int
    band_group_record_size: int
    descriptor_layout: str
    band_group_layout: str
    antenna_table_va: int | None


@dataclass(frozen=True)
class DynamicSymbol:
    name: str
    value: int
    size: int
    info: int
    file_offset: int | None

    @property
    def symbol_type(self) -> int:
        return self.info & 0x0F


class Elf32Image:
    """Minimal ELF32 little-endian reader; no external ELF package is required."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.load_segments = self._read_load_segments()

    def _read_load_segments(self) -> list[LoadSegment]:
        data = self.data
        if len(data) < 52 or data[:4] != b"\x7fELF":
            raise ParseError("Input is not an ELF file.")
        if data[4] != 1:
            raise ParseError("Only ELF32 files are supported.")
        if data[5] != 1:
            raise ParseError("Only little-endian ELF files are supported.")

        program_header_offset = struct.unpack_from("<I", data, 28)[0]
        program_header_size = struct.unpack_from("<H", data, 42)[0]
        program_header_count = struct.unpack_from("<H", data, 44)[0]
        if program_header_size < 32:
            raise ParseError("ELF program-header entry is unexpectedly small.")

        table_end = program_header_offset + program_header_size * program_header_count
        if table_end > len(data):
            raise ParseError("ELF program-header table extends beyond the file.")

        segments: list[LoadSegment] = []
        for index in range(program_header_count):
            offset = program_header_offset + index * program_header_size
            (
                segment_type,
                file_offset,
                virtual_address,
                _physical_address,
                file_size,
                memory_size,
                _flags,
                _alignment,
            ) = struct.unpack_from("<8I", data, offset)
            if segment_type != 1 or file_size == 0:  # PT_LOAD
                continue
            if file_offset + file_size > len(data):
                raise ParseError(
                    f"ELF load segment {index} extends beyond the input file."
                )
            segments.append(
                LoadSegment(
                    file_offset=file_offset,
                    virtual_address=virtual_address,
                    file_size=file_size,
                    memory_size=memory_size,
                )
            )

        if not segments:
            raise ParseError("ELF contains no file-backed PT_LOAD segments.")
        return segments

    def va_to_offset(self, address: int, size: int = 1) -> int | None:
        for segment in self.load_segments:
            if segment.contains_va_bytes(address, size):
                return segment.file_offset + address - segment.virtual_address
        return None

    def offset_to_va(self, offset: int, size: int = 1) -> int | None:
        for segment in self.load_segments:
            if segment.contains_file_bytes(offset, size):
                return segment.virtual_address + offset - segment.file_offset
        return None

    def mapped_file_ranges(self) -> Iterable[tuple[int, int]]:
        for segment in self.load_segments:
            yield segment.file_offset, segment.file_offset + segment.file_size

    def dynamic_symbols(self) -> list[DynamicSymbol]:
        """Read the SysV dynamic symbol table without section headers.

        Qualcomm RF-card ELFs commonly omit section headers but retain
        PT_DYNAMIC, DT_HASH, DT_SYMTAB and DT_STRTAB.  DT_HASH supplies the
        exact symbol count, so generated RF table symbols can be used as the
        primary discovery mechanism.
        """
        data = self.data
        phoff = struct.unpack_from("<I", data, 28)[0]
        phentsize = struct.unpack_from("<H", data, 42)[0]
        phnum = struct.unpack_from("<H", data, 44)[0]

        dynamic_file_offset: int | None = None
        dynamic_file_size = 0
        for index in range(phnum):
            offset = phoff + index * phentsize
            (
                segment_type,
                file_offset,
                _virtual_address,
                _physical_address,
                file_size,
                _memory_size,
                _flags,
                _alignment,
            ) = struct.unpack_from("<8I", data, offset)
            if segment_type == 2:  # PT_DYNAMIC
                dynamic_file_offset = file_offset
                dynamic_file_size = file_size
                break

        if dynamic_file_offset is None:
            return []

        tags: dict[int, int] = {}
        end = dynamic_file_offset + dynamic_file_size
        for offset in range(dynamic_file_offset, end, 8):
            tag, value = struct.unpack_from("<II", data, offset)
            if tag == 0:
                break
            tags[tag] = value

        # Required SysV dynamic entries.
        hash_va = tags.get(4)    # DT_HASH
        symtab_va = tags.get(6)  # DT_SYMTAB
        strtab_va = tags.get(5)  # DT_STRTAB
        syment = tags.get(11, 16)
        strsz = tags.get(10)
        if hash_va is None or symtab_va is None or strtab_va is None:
            return []
        if syment < 16:
            return []

        hash_offset = self.va_to_offset(hash_va, 8)
        symtab_offset = self.va_to_offset(symtab_va, 16)
        strtab_offset = self.va_to_offset(strtab_va, 1)
        if hash_offset is None or symtab_offset is None or strtab_offset is None:
            return []

        _bucket_count, symbol_count = struct.unpack_from("<II", data, hash_offset)
        if not 1 <= symbol_count <= 1_000_000:
            return []

        strtab_end = (
            strtab_offset + strsz
            if strsz is not None and strtab_offset + strsz <= len(data)
            else len(data)
        )

        symbols: list[DynamicSymbol] = []
        for index in range(symbol_count):
            offset = symtab_offset + index * syment
            if offset + 16 > len(data):
                break
            name_offset, value, size, info, _other, _section = struct.unpack_from(
                "<IIIBBH", data, offset
            )
            string_offset = strtab_offset + name_offset
            if not strtab_offset <= string_offset < strtab_end:
                name = ""
            else:
                nul = data.find(b"\0", string_offset, strtab_end)
                if nul < 0:
                    name = ""
                else:
                    name = data[string_offset:nul].decode(
                        "utf-8", errors="replace"
                    )
            mapped_size = size if size > 0 else 1
            symbols.append(
                DynamicSymbol(
                    name=name,
                    value=value,
                    size=size,
                    info=info,
                    file_offset=self.va_to_offset(value, mapped_size),
                )
            )
        return symbols


def make_antenna_table() -> list[list[int]]:
    """Recreate the shared 86-entry rf_endc antenna table."""
    table: list[list[int]] = [[0] * 8]
    for width in range(1, 9):
        table.append([1] * width + [0] * (8 - width))
        for count_2 in range(1, width + 1):
            values = [2] * count_2 + [1] * (width - count_2)
            table.append(values + [0] * (8 - width))
        for count_4 in range(1, width + 1):
            values = [4] * count_4 + [2] * (width - count_4)
            table.append(values + [0] * (8 - width))

    table.extend(
        [
            [8, 0, 0, 0, 0, 0, 0, 0],
            [8, 4, 0, 0, 0, 0, 0, 0],
            [8, 4, 4, 0, 0, 0, 0, 0],
            [8, 8, 0, 0, 0, 0, 0, 0],
            [4, 8, 0, 0, 0, 0, 0, 0],
        ]
    )
    if len(table) != 86:
        raise AssertionError(f"Internal antenna table has {len(table)} entries, not 86.")
    return table


ANTENNA_TABLE = make_antenna_table()


def antenna_info(index: int) -> tuple[list[int] | None, str]:
    if not 0 <= index < len(ANTENNA_TABLE):
        return None, f"ANTENNA_INDEX_{index}"
    pattern = ANTENNA_TABLE[index]
    populated = [value for value in pattern if value]
    name = "NONE" if not populated else "ANTENNA_" + "_".join(map(str, populated))
    return pattern, name


def bandwidth_parts(code: int) -> list[int] | None:
    parts = KNOWN_BANDWIDTH_PARTS_MHZ.get(code)
    return list(parts) if parts is not None else None


def bandwidth_label(code: int) -> str:
    parts = KNOWN_BANDWIDTH_PARTS_MHZ.get(code)
    if parts is None:
        return f"BW_CODE_{code}"
    if not parts:
        return "NONE"
    return "+".join(map(str, parts)) + " MHz"


def bandwidth_class_label(code: int) -> str:
    if code == 0:
        return "NONE"
    if 1 <= code <= 26:
        return chr(ord("A") + code - 1)
    return f"CLASS_{code}"


def read_combo_header(
    data: bytes,
    offset: int,
    count_byte_offset: int = 27,
) -> tuple[tuple[int, ...], int, int, int, int, int, int, int]:
    """Read either known X70/X75 40-byte combo-record revision."""
    group_indices = struct.unpack_from("<12H", data, offset)
    combo_flags = data[offset + 24]
    reserved_byte_1 = data[offset + 25]
    if count_byte_offset == 26:
        num_band_entries = data[offset + 26]
        reserved_byte_2 = data[offset + 27]
    elif count_byte_offset == 27:
        reserved_byte_2 = data[offset + 26]
        num_band_entries = data[offset + 27]
    else:
        raise ValueError(f"Unsupported component-count byte +{count_byte_offset}")
    reserved_word, envelope_mask, subset_mask = struct.unpack_from(
        "<3I", data, offset + 28
    )
    return (
        tuple(group_indices),
        combo_flags,
        reserved_byte_1,
        reserved_byte_2,
        num_band_entries,
        reserved_word,
        envelope_mask,
        subset_mask,
    )


def infer_band_group_layout(
    data: bytes,
    groups_offset: int,
    band_group_count: int,
    group_size: int,
    antenna_count: int,
    *,
    default_later: bool,
    count_byte_offset: int,
) -> str:
    """Infer band-group packing independently of combo-record layout.

    Three 12-byte layouts are currently known:

    ``x70_legacy_12``
        word1 bit 6 is a one-bit UL-present flag.

    ``later_generated_12``
        word1 bits 6..10 hold the full UL class; DL antenna starts at word2
        bit 6; UL antenna starts at word2 bit 13 and extends into word3.

    ``native_aligned_12``
        A related native layout places the full UL class at word1 bit 7,
        DL antenna at word2 bit 7, and UL antenna at word2 bit 14 with
        continuation in word3 bits 0..4. This layout occurs in Meizu X75 and
        several Sony/Xperia modules, so it must not be selected by OEM or by
        the combo-count byte alone.

    The strongest discriminator is semantic rather than OEM-specific:
    bandwidth class A represents one component carrier, therefore its antenna
    enum must resolve to a one-element antenna pattern. Decoding a native-
    aligned table with the later-generated shifts produces doubled enum
    indexes and multi-element patterns for essentially every class-A group.
    """
    if group_size != 12:
        return "compact_8"

    usable = 0
    native_all_valid = True
    native_nonzero_ul = 0

    class_a_groups = 0
    later_class_a_shape_errors = 0
    native_class_a_shape_errors = 0

    later_evidence = 0
    native_prefix_word1_set = 0
    native_prefix_word2_set = 0

    def antenna_component_count(index: int) -> int | None:
        if not 0 <= index < antenna_count:
            return None
        if not 0 <= index < len(ANTENNA_TABLE):
            return None
        return sum(1 for value in ANTENNA_TABLE[index] if value)

    for index in range(band_group_count):
        offset = groups_offset + index * group_size
        try:
            words = struct.unpack_from("<6H", data, offset)
        except struct.error:
            break

        rat_id = words[0] & 0x3
        band = (words[0] >> 2) & 0x1FF
        if rat_id not in (1, 2) or not 1 <= band <= 511:
            continue
        usable += 1

        dl_class = words[0] >> 11

        later_ul_class = (words[1] >> 6) & 0x1F
        later_dl_ant = (words[2] >> 6) & 0x7F
        later_ul_ant = (
            ((words[2] >> 13) & 0x07)
            | ((words[3] & 0x0F) << 3)
        )

        native_ul_class = (words[1] >> 7) & 0x1F
        native_dl_ant = (words[2] >> 7) & 0x7F
        native_ul_ant = (
            ((words[2] >> 14) & 0x03)
            | ((words[3] & 0x1F) << 2)
        )

        native_prefix_word1_set += (words[1] >> 6) & 1
        native_prefix_word2_set += (words[2] >> 6) & 1

        if native_ul_class:
            native_nonzero_ul += 1

        if (
            native_ul_class > 26
            or native_dl_ant >= antenna_count
            or native_ul_ant >= antenna_count
        ):
            native_all_valid = False

        # Class A is a one-CC class. The selected antenna enum must therefore
        # resolve to exactly one antenna-pattern element. This catches the
        # characteristic 2x enum-index error without relying on OEM names,
        # combo size, descriptor size, or count-byte location.
        if dl_class == 1:
            class_a_groups += 1
            later_count = antenna_component_count(later_dl_ant)
            native_count = antenna_component_count(native_dl_ant)
            if later_count != 1:
                later_class_a_shape_errors += 1
            if native_count != 1:
                native_class_a_shape_errors += 1

        # Positive evidence for the Sony/Samsung generated layout.
        if (
            2 <= later_ul_class <= 26
            and later_ul_class == dl_class
        ):
            later_evidence += 1
        if (
            (words[3] & 0x0F) != 0
            and later_ul_ant < antenna_count
            and later_ul_ant != ((words[2] >> 13) & 0x07)
        ):
            later_evidence += 1

    # Strong native-aligned fingerprint:
    # - the native fields remain in range;
    # - class-A groups decode as one-element antenna patterns;
    # - the later-generated shifts fail that same invariant for most groups.
    min_bad = max(4, (class_a_groups * 3) // 4)
    if (
        usable >= 8
        and native_all_valid
        and class_a_groups >= 4
        and native_class_a_shape_errors == 0
        and later_class_a_shape_errors >= min_bad
    ):
        return "native_aligned_12"

    # Compatibility fallback for a native table with too few class-A groups.
    # Count-at-+26 remains only a weak hint and is not required.
    if (
        usable >= 8
        and native_all_valid
        and native_nonzero_ul >= 4
        and native_prefix_word2_set == 0
        and native_prefix_word1_set <= max(4, usable // 20)
        and count_byte_offset == 26
    ):
        return "native_aligned_12"

    if later_evidence or default_later:
        return "later_generated_12"
    return "x70_legacy_12"

def validate_candidate(
    data: bytes,
    image: Elf32Image,
    descriptor_offset: int,
    *,
    exhaustive: bool,
) -> tuple[int, int, int, int, int, int, int, int, str, str, int | None] | None:
    """Validate a known RF combination descriptor layout."""
    if descriptor_offset < 0 or descriptor_offset + 20 > len(data):
        return None

    # Magnus-era MPSS.HI cards use a compact 24-byte descriptor containing a
    # 32-bit count and a pointer to 150-byte records.  Each record embeds up to
    # twelve native 12-byte components, followed by a six-byte trailer.  This
    # is distinct from both the earlier HI inline-100 representation and the
    # later shared-band-group descriptors.
    #
    # Native component byte layout (confirmed against generated RFCard data):
    #   +2 tech in the high bits (LTE=0x20, NR=0x40), +3 DL class,
    #   +4 DL BW, +5 DL antenna,
    #   +6 UL class, +7 UL BW, +8 UL antenna, +9 feature byte, +10 uint16 band.
    # Trailer: +146 combination property, +147 active count, +148 BCS.
    if descriptor_offset + 24 <= len(data):
        magnus_count, magnus_records_va = struct.unpack_from(
            "<II", data, descriptor_offset
        )
        magnus_reserved = data[descriptor_offset + 8:descriptor_offset + 24]
        magnus_records_offset = image.va_to_offset(
            magnus_records_va,
            magnus_count * MAGNUS_INLINE_COMBO_RECORD_SIZE,
        )
        if (
            1 <= magnus_count <= 100_000
            and not any(magnus_reserved)
            and magnus_records_offset is not None
        ):
            if exhaustive:
                magnus_indices: Sequence[int] = range(magnus_count)
            else:
                magnus_indices = sorted(
                    index
                    for index in {
                        0,
                        1,
                        magnus_count // 4,
                        magnus_count // 2,
                        magnus_count - 1,
                    }
                    if 0 <= index < magnus_count
                )

            magnus_valid = True
            highest_antenna_index = 0
            for combo_index in magnus_indices:
                record_offset = (
                    magnus_records_offset
                    + combo_index * MAGNUS_INLINE_COMBO_RECORD_SIZE
                )
                num_entries = data[
                    record_offset + MAGNUS_INLINE_COUNT_OFFSET
                ]
                if not 1 <= num_entries <= MAGNUS_INLINE_MAX_COMPONENTS:
                    magnus_valid = False
                    break
                for component_index in range(MAGNUS_INLINE_MAX_COMPONENTS):
                    component_offset = (
                        record_offset
                        + component_index
                        * MAGNUS_INLINE_BAND_GROUP_RECORD_SIZE
                    )
                    component = data[
                        component_offset:
                        component_offset + MAGNUS_INLINE_BAND_GROUP_RECORD_SIZE
                    ]
                    if component_index >= num_entries:
                        # Generated records use a two-byte 0x0002 sentinel in
                        # the first unused component; all later slots are zero.
                        expected = (
                            b"\x02\x00" + b"\0" * 10
                            if component_index == num_entries
                            else b"\0" * 12
                        )
                        if component != expected:
                            magnus_valid = False
                            break
                        continue
                    tech = component[2] >> 5
                    band = struct.unpack_from("<H", component, 10)[0]
                    dl_class = component[3]
                    ul_class = component[6]
                    if (
                        tech not in (1, 2)
                        or not 1 <= band <= 511
                        or not 1 <= dl_class <= 31
                        or ul_class > 31
                    ):
                        magnus_valid = False
                        break
                    highest_antenna_index = max(
                        highest_antenna_index,
                        component[5],
                        component[8],
                    )
                if not magnus_valid:
                    break

            if magnus_valid:
                return (
                    magnus_count,
                    magnus_records_offset,
                    0,
                    highest_antenna_index + 1,
                    -1,
                    MAGNUS_INLINE_COUNT_OFFSET,
                    MAGNUS_INLINE_COMBO_RECORD_SIZE,
                    MAGNUS_INLINE_BAND_GROUP_RECORD_SIZE,
                    "magnus_inline_150",
                    "magnus_native_12",
                    None,
                )

    # Earlier MPSS.HI cards store every NR/EN-DC band component directly in a
    # 100-byte combination record instead of referencing a shared band-group
    # table.  The 24-byte descriptor mirrors the legacy LTE descriptor:
    #
    #   uint16 count; pad; pointer records; uint16 antenna_count; ...
    #
    # Record bytes 0..95 are twelve packed eight-byte components; +96 is the
    # property byte, +98 is the active component count, and +99 is BCS.
    if descriptor_offset + 24 <= len(data):
        inline_count, inline_padding = struct.unpack_from(
            "<HH", data, descriptor_offset
        )
        inline_records_va = struct.unpack_from(
            "<I", data, descriptor_offset + 4
        )[0]
        inline_antenna_count = struct.unpack_from(
            "<H", data, descriptor_offset + 8
        )[0]
        inline_records_offset = image.va_to_offset(
            inline_records_va,
            inline_count * HI_INLINE_COMBO_RECORD_SIZE,
        )
        if (
            1 <= inline_count <= 100_000
            and inline_padding == 0
            and 1 <= inline_antenna_count <= 512
            and inline_records_offset is not None
        ):
            if exhaustive:
                inline_indices: Sequence[int] = range(inline_count)
            else:
                inline_indices = sorted(
                    index
                    for index in {
                        0,
                        1,
                        inline_count // 4,
                        inline_count // 2,
                        inline_count - 1,
                    }
                    if 0 <= index < inline_count
                )

            inline_valid = True
            for combo_index in inline_indices:
                record_offset = (
                    inline_records_offset
                    + combo_index * HI_INLINE_COMBO_RECORD_SIZE
                )
                num_entries = data[record_offset + HI_INLINE_COUNT_OFFSET]
                if not 1 <= num_entries <= HI_INLINE_MAX_COMPONENTS:
                    inline_valid = False
                    break
                for component_index in range(HI_INLINE_MAX_COMPONENTS):
                    component_offset = (
                        record_offset
                        + component_index * HI_INLINE_BAND_GROUP_RECORD_SIZE
                    )
                    component = data[
                        component_offset:
                        component_offset + HI_INLINE_BAND_GROUP_RECORD_SIZE
                    ]
                    if component_index >= num_entries:
                        if any(component):
                            inline_valid = False
                            break
                        continue
                    band_code = struct.unpack_from("<H", component)[0]
                    rat_id = band_code & 0x3
                    band = (band_code >> 2) & 0x1FF
                    dl_class = band_code >> 11
                    if (
                        not any(component)
                        or rat_id not in (1, 2)
                        or not 1 <= band <= 511
                        or not 1 <= dl_class <= 26
                    ):
                        inline_valid = False
                        break
                if not inline_valid:
                    break

            if inline_valid:
                antenna_table_va = struct.unpack_from(
                    "<I", data, descriptor_offset + 12
                )[0]
                if (
                    antenna_table_va == 0
                    or image.va_to_offset(antenna_table_va, 1) is None
                ):
                    antenna_table_va = None
                return (
                    inline_count,
                    inline_records_offset,
                    0,
                    inline_antenna_count,
                    -1,
                    HI_INLINE_COUNT_OFFSET,
                    HI_INLINE_COMBO_RECORD_SIZE,
                    HI_INLINE_BAND_GROUP_RECORD_SIZE,
                    "hi_inline_100",
                    "compact_8",
                    antenna_table_va,
                )

    words = struct.unpack_from("<5I", data, descriptor_offset)
    combo_count, combos_va, groups_va = words[:3]
    if not 1 <= combo_count <= 100_000:
        return None

    layouts: list[tuple[str, int, int, int, int | None]] = []
    # Legacy: count, combos_va, groups_va, antenna_count
    legacy_antenna_count = words[3]
    if 1 <= legacy_antenna_count <= 512:
        layouts.append(("legacy_40_12", LEGACY_COMBO_RECORD_SIZE,
                        LEGACY_BAND_GROUP_RECORD_SIZE, legacy_antenna_count, None))
    # Xperia/new generated layout: count, combos_va, groups_va,
    # antenna_table_va, antenna_count
    modern_antenna_va, modern_antenna_count = words[3], words[4]
    if 1 <= modern_antenna_count <= 512 and image.va_to_offset(modern_antenna_va, 1) is not None:
        layouts.append(("xperia_44_12", MODERN_COMBO_RECORD_SIZE,
                        MODERN_BAND_GROUP_RECORD_SIZE, modern_antenna_count,
                        modern_antenna_va))

    for layout_name, combo_size, group_size, antenna_count, antenna_va in layouts:
        combos_offset = image.va_to_offset(combos_va, combo_count * combo_size)
        groups_offset = image.va_to_offset(groups_va, group_size)
        if combos_offset is None or groups_offset is None:
            continue

        record_indices: Sequence[int]
        if exhaustive:
            record_indices = range(combo_count)
        else:
            record_indices = sorted({0, 1, combo_count // 4, combo_count // 2, combo_count - 1})

        selected_count_offset: int | None = None
        highest_group = -1
        for candidate_count_offset in (27, 26):
            candidate_highest = -1
            valid = True
            for combo_index in record_indices:
                record_offset = combos_offset + combo_index * combo_size
                try:
                    group_indices, _, _, _, num_entries, _, _, _ = read_combo_header(
                        data, record_offset, candidate_count_offset
                    )
                except (IndexError, struct.error):
                    valid = False
                    break
                if not 1 <= num_entries <= MAX_GROUPS_PER_COMBO:
                    valid = False
                    break
                active = group_indices[:num_entries]
                if any(index == UNUSED_GROUP_INDEX for index in active):
                    valid = False
                    break
                if num_entries < MAX_GROUPS_PER_COMBO and group_indices[num_entries] != UNUSED_GROUP_INDEX:
                    valid = False
                    break
                candidate_highest = max(candidate_highest, *active)
            if valid:
                selected_count_offset = candidate_count_offset
                highest_group = candidate_highest
                break

        if selected_count_offset is None:
            continue

        default_later = (
            layout_name == "xperia_44_12"
            or selected_count_offset == 26
        )
        if not exhaustive:
            provisional_group_layout = (
                "native_aligned_12"
                if selected_count_offset == 26
                else (
                    "later_generated_12"
                    if default_later
                    else "x70_legacy_12"
                )
            )
            return (combo_count, combos_offset, groups_offset, antenna_count,
                    highest_group, selected_count_offset, combo_size, group_size,
                    layout_name, provisional_group_layout, antenna_va)

        band_group_count = highest_group + 1
        if image.va_to_offset(groups_va, band_group_count * group_size) is None:
            continue

        band_group_layout = infer_band_group_layout(
            data,
            groups_offset,
            band_group_count,
            group_size,
            antenna_count,
            default_later=default_later,
            count_byte_offset=selected_count_offset,
        )

        valid_groups = True
        for group_index in range(band_group_count):
            group_offset = groups_offset + group_index * group_size
            try:
                words16 = struct.unpack_from("<4H" if group_size == 8 else "<6H", data, group_offset)
            except struct.error:
                valid_groups = False
                break
            rat_id = words16[0] & 0x3
            band = (words16[0] >> 2) & 0x1FF
            if rat_id not in (1, 2) or not 1 <= band <= 511:
                valid_groups = False
                break
            if band_group_layout == "native_aligned_12":
                dl_antenna_index = (words16[2] >> 7) & 0x7F
                ul_antenna_index = (
                    ((words16[2] >> 14) & 0x03)
                    | ((words16[3] & 0x1F) << 2)
                )
            else:
                dl_antenna_index = (words16[2] >> 6) & 0x7F
                if band_group_layout == "later_generated_12":
                    # Later generated packing continues the UL antenna enum
                    # into the low nibble of word 3.
                    ul_antenna_index = (
                        ((words16[2] >> 13) & 0x7)
                        | ((words16[3] & 0xF) << 3)
                    )
                else:
                    ul_antenna_index = (words16[2] >> 13) & 0x7
            if dl_antenna_index >= antenna_count or ul_antenna_index >= antenna_count:
                valid_groups = False
                break
        if valid_groups:
            return (combo_count, combos_offset, groups_offset, antenna_count,
                    highest_group, selected_count_offset, combo_size, group_size,
                    layout_name, band_group_layout, antenna_va)
    return None

NAMED_COMBO_TABLE_SUFFIXES = (
    ("nr5g_nr5g_combos_info_table_sub_cap_high", "nrdc"),
    ("lte_nr5g_combos_info_table_sub_cap_high", "endc"),
    ("nr5g_combos_info_table_sub_cap_high", "nrca"),
    ("lte_combos_info_table_sub_cap_high", "lteca"),
)


def rfcard_name_from_symbols(image: Elf32Image) -> str | None:
    """Recover the generated RFCard name from ELF dynamic symbols."""
    symbols = image.dynamic_symbols()
    public_suffixes = (
        "lte_combos_info_table_sub_cap_high",
        "nr5g_nr5g_combos_info_table_sub_cap_high",
        "lte_nr5g_combos_info_table_sub_cap_high",
        "nr5g_combos_info_table_sub_cap_high",
    )
    for suffix in public_suffixes:
        candidates = sorted(
            symbol.name
            for symbol in symbols
            if symbol.name.lower().endswith(suffix)
            and "internal" not in symbol.name.lower()
        )
        if candidates:
            return candidates[0][:-len(suffix)].rstrip("_")

    generated_names = sorted(
        symbol.name
        for symbol in symbols
        if symbol.name.lower().startswith("rfc_hwid")
    )
    if not generated_names:
        return None
    common_prefix = generated_names[0]
    for name in generated_names[1:]:
        limit = min(len(common_prefix), len(name))
        index = 0
        while index < limit and common_prefix[index] == name[index]:
            index += 1
        common_prefix = common_prefix[:index]
        if not common_prefix:
            return None
    return common_prefix.rstrip("_") or None


def find_named_descriptors(
    data: bytes,
    image: Elf32Image,
) -> list[tuple[str, Descriptor, str]]:
    """Locate public high RF tables from generated dynamic-symbol names.

    Symbol identity is authoritative for NR-CA versus NR-DC, which cannot be
    distinguished from RAT composition alone.
    """
    found: list[tuple[str, Descriptor, str]] = []
    seen_offsets: set[int] = set()
    for symbol in image.dynamic_symbols():
        name_lower = symbol.name.lower()
        table_kind: str | None = None
        for suffix, kind in NAMED_COMBO_TABLE_SUFFIXES:
            if name_lower.endswith(suffix):
                table_kind = kind
                break
        if table_kind is None or symbol.file_offset is None:
            continue
        if symbol.file_offset in seen_offsets:
            continue
        layout = validate_candidate(
            data,
            image,
            symbol.file_offset,
            exhaustive=True,
        )
        if layout is None:
            continue
        descriptor = make_descriptor(
            data,
            image,
            symbol.file_offset,
            layout,
        )
        found.append((table_kind, descriptor, symbol.name))
        seen_offsets.add(symbol.file_offset)

    # Band-group packing is a property of the shared group table, not of an
    # individual combo descriptor. Propagate the strongest proven layout to
    # every descriptor that references the same group-table VA.
    group_layout_by_va: dict[int, str] = {}
    layout_priority = {
        "x70_legacy_12": 0,
        "later_generated_12": 1,
        "native_aligned_12": 2,
    }
    for _kind, descriptor, _name in found:
        current = group_layout_by_va.get(descriptor.band_groups_va)
        if (
            current is None
            or layout_priority.get(descriptor.band_group_layout, 0)
            > layout_priority.get(current, 0)
        ):
            group_layout_by_va[descriptor.band_groups_va] = (
                descriptor.band_group_layout
            )

    found = [
        (
            kind,
            replace(
                descriptor,
                band_group_layout=group_layout_by_va.get(
                    descriptor.band_groups_va,
                    descriptor.band_group_layout,
                ),
            ),
            symbol_name,
        )
        for kind, descriptor, symbol_name in found
    ]

    order = {"lteca": 0, "endc": 1, "nrca": 2, "nrdc": 3}
    found.sort(
        key=lambda item: (
            order.get(item[0], 9),
            item[1].file_offset,
        )
    )
    return found


def find_descriptors(data: bytes, image: Elf32Image) -> list[Descriptor]:
    """Find public RF-combination table descriptors.

    Generated dynamic symbols are preferred. Structural scanning remains the
    compatibility fallback for stripped ELFs.
    """
    named = find_named_descriptors(data, image)
    if named:
        return [descriptor for _kind, descriptor, _name in named]

    candidates: list[tuple[int, tuple[int, ...]]] = []
    for range_start, range_end in image.mapped_file_ranges():
        aligned_start = (range_start + 3) & ~3
        for offset in range(aligned_start, range_end - 15, 4):
            quick = validate_candidate(
                data, image, offset, exhaustive=False
            )
            if quick is None:
                continue
            candidates.append((offset, quick))

    validated: list[Descriptor] = []
    for offset, _quick in candidates:
        full = validate_candidate(data, image, offset, exhaustive=True)
        if full is not None:
            validated.append(make_descriptor(data, image, offset, full))
    if not validated:
        raise ParseError(
            "No valid RF combination descriptor was found. "
            "Use --descriptor-offset if this firmware uses a different layout."
        )

    return sorted(validated, key=lambda descriptor: descriptor.file_offset)


def descriptor_rat_signatures(
    data: bytes,
    descriptor: Descriptor,
) -> set[frozenset[int]]:
    """Return the RAT set used by each kind of combination in a table."""
    signatures: set[frozenset[int]] = set()
    if descriptor.descriptor_layout in ("hi_inline_100", "magnus_inline_150"):
        for combo_index in range(descriptor.combo_count):
            offset = (
                descriptor.combos_file_offset
                + combo_index * descriptor.combo_record_size
            )
            num_entries = data[offset + descriptor.count_byte_offset]
            if descriptor.descriptor_layout == "magnus_inline_150":
                rats = {
                    data[
                        offset
                        + component_index * descriptor.band_group_record_size
                        + 2
                    ]
                    >> 5
                    for component_index in range(num_entries)
                }
            else:
                rats = {
                    struct.unpack_from(
                        "<H",
                        data,
                        offset
                        + component_index * descriptor.band_group_record_size,
                    )[0]
                    & 0x3
                    for component_index in range(num_entries)
                }
            signatures.add(frozenset(rats))
        return signatures

    for combo_index in range(descriptor.combo_count):
        offset = descriptor.combos_file_offset + combo_index * descriptor.combo_record_size
        group_indices, _, _, _, num_entries, _, _, _ = read_combo_header(
            data, offset, descriptor.count_byte_offset
        )
        rats: set[int] = set()
        for group_index in group_indices[:num_entries]:
            group_offset = (
                descriptor.band_groups_file_offset
                + group_index * descriptor.band_group_record_size
            )
            band_code = struct.unpack_from("<H", data, group_offset)[0]
            rats.add(band_code & 0x3)
        signatures.add(frozenset(rats))
    return signatures


def classify_descriptor(data: bytes, descriptor: Descriptor) -> str:
    """Classify a table using the RAT makeup of all its combination records."""
    signatures = descriptor_rat_signatures(data, descriptor)
    if signatures == {frozenset((1, 2))}:
        return "endc"
    if signatures == {frozenset((2,))}:
        return "nrca"
    if signatures == {frozenset((1,))}:
        return "lteca"
    return "unknown"


def find_descriptor(
    data: bytes,
    image: Elf32Image,
    table_kind: str = "endc",
) -> Descriptor:
    """Compatibility wrapper returning one requested table descriptor."""
    matches = [
        descriptor
        for descriptor in find_descriptors(data, image)
        if classify_descriptor(data, descriptor) == table_kind
    ]
    if not matches:
        raise ParseError(f"No {table_kind.upper()} RF table was found.")
    if len(matches) > 1:
        offsets = ", ".join(
            f"0x{descriptor.file_offset:X}" for descriptor in matches
        )
        raise ParseError(
            f"{table_kind.upper()} table detection is ambiguous ({offsets}); "
            "select one with --descriptor-offset."
        )
    return matches[0]


def make_descriptor(
    data: bytes,
    image: Elf32Image,
    descriptor_offset: int,
    validated_layout: tuple[int, int, int, int, int, int, int, int, str, str, int | None] | None = None,
) -> Descriptor:
    layout = validated_layout or validate_candidate(
        data, image, descriptor_offset, exhaustive=True
    )
    if layout is None:
        raise ParseError(
            f"0x{descriptor_offset:X} is not a valid RF table descriptor."
        )
    (
        combo_count,
        combos_offset,
        groups_offset,
        antenna_count,
        highest_group,
        count_byte_offset,
        combo_record_size,
        band_group_record_size,
        descriptor_layout,
        band_group_layout,
        antenna_table_va,
    ) = layout
    if descriptor_layout in ("hi_inline_100", "magnus_inline_150"):
        combo_count = struct.unpack_from(
            "<I" if descriptor_layout == "magnus_inline_150" else "<H",
            data,
            descriptor_offset,
        )[0]
        combos_va = struct.unpack_from("<I", data, descriptor_offset + 4)[0]
        groups_va = 0
        groups_offset = 0
        band_group_count = 0
        descriptor_size = 24
    else:
        _, combos_va, groups_va = struct.unpack_from(
            "<3I", data, descriptor_offset
        )
        band_group_count = highest_group + 1
        descriptor_size = 20
    return Descriptor(
        file_offset=descriptor_offset,
        virtual_address=image.offset_to_va(descriptor_offset, descriptor_size),
        combo_count=combo_count,
        combos_va=combos_va,
        combos_file_offset=combos_offset,
        band_groups_va=groups_va,
        band_groups_file_offset=groups_offset,
        antenna_table_count=antenna_count,
        band_group_count=band_group_count,
        count_byte_offset=count_byte_offset,
        combo_record_size=combo_record_size,
        band_group_record_size=band_group_record_size,
        descriptor_layout=descriptor_layout,
        band_group_layout=band_group_layout,
        antenna_table_va=antenna_table_va,
    )

def parse_band_group(data: bytes, descriptor: Descriptor, index: int) -> dict[str, Any]:
    offset = descriptor.band_groups_file_offset + index * descriptor.band_group_record_size
    if descriptor.band_group_layout == "magnus_native_12":
        raw = data[offset:offset + MAGNUS_INLINE_BAND_GROUP_RECORD_SIZE]
        native_word_0 = struct.unpack_from("<H", raw, 0)[0]
        tech_field = raw[2]
        rat_id = tech_field >> 5
        rat = {1: "LTE", 2: "NR"}.get(rat_id, f"RAT_{rat_id}")
        dl_bw_class_code = raw[3]
        dl_bw_code = raw[4]
        dl_antenna_index = raw[5]
        ul_bw_class_code = raw[6]
        ul_bw_code = raw[7]
        ul_antenna_index = raw[8]
        feature_byte = raw[9]
        band = struct.unpack_from("<H", raw, 10)[0]
        band_label = f"B{band}" if rat == "LTE" else f"n{band}"
        dl_bw_class = bandwidth_class_label(dl_bw_class_code)
        dl_pattern, dl_antenna_name = antenna_info(dl_antenna_index)
        ul_pattern, ul_antenna_name = antenna_info(ul_antenna_index)
        words = struct.unpack_from("<6H", raw)
        return {
            "group_index": index,
            "file_offset": offset,
            "file_offset_hex": f"0x{offset:X}",
            "raw_hex": raw.hex(" "),
            "raw_words": list(words),
            "native_word_0_raw": native_word_0,
            "tech_field_raw": tech_field,
            "tech_field_hex": f"0x{tech_field:02X}",
            "band_code_raw": band,
            "band_code_hex": f"0x{band:04X}",
            "band_code_high": 0,
            "dl_bw_class_code": dl_bw_class_code,
            "dl_bw_class": dl_bw_class,
            "rat_id": rat_id,
            "rat": rat,
            "band": band,
            "band_label": band_label,
            "band_class_label": f"{band_label}{dl_bw_class}",
            "dl_bw_code": dl_bw_code,
            "dl_bandwidth": bandwidth_label(dl_bw_code),
            "dl_bandwidth_parts_mhz": bandwidth_parts(dl_bw_code),
            "ul_present": ul_bw_class_code != 0,
            "ul_bw_class_code": ul_bw_class_code,
            "ul_bw_class": bandwidth_class_label(ul_bw_class_code),
            "band_group_layout": descriptor.band_group_layout,
            "field_2_unknown_high": 0,
            "native_word1_prefix_bit": None,
            "native_word2_prefix_bit": None,
            "x75_word1_alignment_bit": None,
            "x75_word2_alignment_bit": None,
            "ul_bw_code": ul_bw_code,
            "ul_bandwidth": bandwidth_label(ul_bw_code),
            "ul_bandwidth_parts_mhz": bandwidth_parts(ul_bw_code),
            "dl_antenna_index": dl_antenna_index,
            "dl_antenna": dl_antenna_name,
            "dl_antenna_pattern": dl_pattern,
            "ul_antenna_index": ul_antenna_index,
            "ul_antenna": ul_antenna_name,
            "ul_antenna_pattern": ul_pattern,
            "feature_byte_raw": feature_byte,
            "feature_byte_hex": f"0x{feature_byte:02X}",
            "feature_word_3_raw": words[3],
            "feature_word_3_hex": f"0x{words[3]:04X}",
            "feature_word_4_raw": words[4],
            "feature_word_4_hex": f"0x{words[4]:04X}",
            "feature_word_5_raw": words[5],
            "feature_word_5_hex": f"0x{words[5]:04X}",
        }
    if descriptor.band_group_record_size == 8:
        words = struct.unpack_from("<4H", data, offset) + (0, 0)
    else:
        words = struct.unpack_from("<6H", data, offset)
    band_code = words[0]
    rat_id = band_code & 0x3
    band = (band_code >> 2) & 0x1FF
    rat = {1: "LTE", 2: "NR"}.get(rat_id, f"RAT_{rat_id}")
    band_label = f"B{band}" if rat == "LTE" else f"n{band}"
    dl_bw_class_code = band_code >> 11
    dl_bw_class = bandwidth_class_label(dl_bw_class_code)

    dl_bw_code = words[1] & 0x3F

    # Qualcomm used at least three related 12-byte band-group packings.
    #
    # X70 legacy:
    #   word1 bit 6      = UL present
    #   word2 bits 6..12 = DL antenna enum
    #   word2 bits 13..15 = UL antenna enum
    #
    # Sony/Samsung later generated:
    #   word1 bits 6..10 = full UL bandwidth class
    #   word2 bits 6..12 = DL antenna enum
    #   word2 bits 13..15 + word3 bits 0..3 = UL antenna enum
    #
    # Native aligned:
    #   word1 bit 6      = alignment/reserved
    #   word1 bits 7..11 = full UL bandwidth class
    #   word2 bit 6      = alignment/reserved
    #   word2 bits 7..13 = DL antenna enum
    #   word2 bits 14..15 + word3 bits 0..4 = UL antenna enum
    layout = descriptor.band_group_layout
    if layout == "native_aligned_12":
        ul_bw_class_code = (words[1] >> 7) & 0x1F
        ul_present = ul_bw_class_code != 0
        field_2_unknown_high = words[1] >> 12
        dl_antenna_index = (words[2] >> 7) & 0x7F
        ul_antenna_index = (
            ((words[2] >> 14) & 0x03)
            | ((words[3] & 0x1F) << 2)
        )
    elif layout == "later_generated_12":
        ul_bw_class_code = (words[1] >> 6) & 0x1F
        ul_present = ul_bw_class_code != 0
        field_2_unknown_high = words[1] >> 11
        dl_antenna_index = (words[2] >> 6) & 0x7F
        ul_antenna_index = (
            ((words[2] >> 13) & 0x07)
            | ((words[3] & 0x0F) << 3)
        )
    else:
        ul_present = bool((words[1] >> 6) & 1)
        ul_bw_class_code = 1 if ul_present else 0
        field_2_unknown_high = words[1] >> 7
        dl_antenna_index = (words[2] >> 6) & 0x7F
        ul_antenna_index = (words[2] >> 13) & 0x07

    ul_bw_code = words[2] & 0x3F
    dl_pattern, dl_antenna_name = antenna_info(dl_antenna_index)
    ul_pattern, ul_antenna_name = antenna_info(ul_antenna_index)

    return {
        "group_index": index,
        "file_offset": offset,
        "file_offset_hex": f"0x{offset:X}",
        "raw_hex": data[offset : offset + descriptor.band_group_record_size].hex(" "),
        "raw_words": list(words),
        "band_code_raw": band_code,
        "band_code_hex": f"0x{band_code:04X}",
        "band_code_high": band_code >> 11,
        "dl_bw_class_code": dl_bw_class_code,
        "dl_bw_class": dl_bw_class,
        "rat_id": rat_id,
        "rat": rat,
        "band": band,
        "band_label": band_label,
        "band_class_label": f"{band_label}{dl_bw_class}",
        "dl_bw_code": dl_bw_code,
        "dl_bandwidth": bandwidth_label(dl_bw_code),
        "dl_bandwidth_parts_mhz": bandwidth_parts(dl_bw_code),
        "ul_present": ul_present,
        "ul_bw_class_code": ul_bw_class_code,
        "ul_bw_class": bandwidth_class_label(ul_bw_class_code),
        "band_group_layout": descriptor.band_group_layout,
        "field_2_unknown_high": field_2_unknown_high,
        "native_word1_prefix_bit": (
            (words[1] >> 6) & 1
            if layout == "native_aligned_12"
            else None
        ),
        "native_word2_prefix_bit": (
            (words[2] >> 6) & 1
            if layout == "native_aligned_12"
            else None
        ),
        # Backward-compatible aliases from parser v5.
        "x75_word1_alignment_bit": (
            (words[1] >> 6) & 1
            if layout == "native_aligned_12"
            else None
        ),
        "x75_word2_alignment_bit": (
            (words[2] >> 6) & 1
            if layout == "native_aligned_12"
            else None
        ),
        "ul_bw_code": ul_bw_code,
        "ul_bandwidth": bandwidth_label(ul_bw_code),
        "ul_bandwidth_parts_mhz": bandwidth_parts(ul_bw_code),
        "dl_antenna_index": dl_antenna_index,
        "dl_antenna": dl_antenna_name,
        "dl_antenna_pattern": dl_pattern,
        "ul_antenna_index": ul_antenna_index,
        "ul_antenna": ul_antenna_name,
        "ul_antenna_pattern": ul_pattern,
        "feature_word_3_raw": words[3],
        "feature_word_3_hex": f"0x{words[3]:04X}",
        "feature_word_4_raw": words[4],
        "feature_word_4_hex": f"0x{words[4]:04X}",
        "feature_word_5_raw": words[5],
        "feature_word_5_hex": f"0x{words[5]:04X}",
    }


def canonical_combination(
    entries: Sequence[dict[str, Any]],
    *,
    include_classes: bool = False,
) -> str:
    label_field = "band_class_label" if include_classes else "band_label"
    lte = sorted(
        (entry for entry in entries if entry["rat"] == "LTE"),
        key=lambda entry: entry["band"],
    )
    nr = sorted(
        (entry for entry in entries if entry["rat"] == "NR"),
        key=lambda entry: entry["band"],
    )
    lte_text = "+".join(entry[label_field] for entry in lte)
    nr_text = "+".join(entry[label_field] for entry in nr)
    if lte and nr:
        return f"DC_{lte_text}_{nr_text}"
    if nr:
        return f"NRCA_{nr_text}"
    return f"CA_{lte_text}"



UL_TX_SWITCH_LABELS = {
    0: "none",
    1: "switched_ul",
    2: "dual_ul",
    3: "both",
}


def decode_combo_property_byte(value: int) -> dict[str, Any]:
    """Decode the shared legacy RF combination-property byte.

    Confirmed layout:

        bits 0..2  power-class enum
        bit 3      TDD antenna-switch / FDD disruption
        bit 4      simultaneous Rx/Tx inter-band EN-DC
        bit 5      simultaneous Rx/Tx inter-band CA
        bits 6..7  UL TX-switch type

    Later bytes differ between X70, X75 and Sony/Xperia generated layouts, so
    those bytes remain raw unless separately validated.
    """
    value &= 0xFF
    power_class = value & 0x07
    ul_tx_switch = (value >> 6) & 0x03
    return {
        "property_byte_raw": value,
        "property_byte_hex": f"0x{value:02X}",
        "power_class_raw": power_class,
        "power_class": power_class,
        "power_class_label": (
            f"PC{power_class}" if power_class else "unspecified"
        ),
        "tdd_ant_swt_fdd_disruption": bool(value & 0x08),
        "simultaneous_rx_tx_endc": bool(value & 0x10),
        "simultaneous_rx_tx_ca": bool(value & 0x20),
        "ul_tx_switch_type_raw": ul_tx_switch,
        "ul_tx_switch_type": ul_tx_switch,
        "ul_tx_switch_label": UL_TX_SWITCH_LABELS[ul_tx_switch],
    }

def parse_combo(
    data: bytes,
    descriptor: Descriptor,
    band_groups: Sequence[dict[str, Any]],
    combo_index: int,
) -> dict[str, Any]:
    if descriptor.descriptor_layout in ("hi_inline_100", "magnus_inline_150"):
        offset = (
            descriptor.combos_file_offset
            + combo_index * descriptor.combo_record_size
        )
        if descriptor.descriptor_layout == "magnus_inline_150":
            property_offset = MAGNUS_INLINE_PROPERTY_OFFSET
            bcs_offset = MAGNUS_INLINE_BCS_OFFSET
            reserved_word = struct.unpack_from("<H", data, offset + 144)[0]
            reserved_byte = data[offset + 149]
        else:
            property_offset = HI_INLINE_PROPERTY_OFFSET
            bcs_offset = descriptor.count_byte_offset + 1
            reserved_word = 0
            reserved_byte = data[offset + HI_INLINE_PROPERTY_OFFSET + 1]
        combo_flags = data[offset + property_offset]
        num_band_entries = data[offset + descriptor.count_byte_offset]
        bcs_num = data[offset + bcs_offset]
        inline_descriptor = replace(
            descriptor,
            band_groups_file_offset=offset,
            band_group_count=num_band_entries,
        )
        entries: list[dict[str, Any]] = []
        for position in range(num_band_entries):
            entry = parse_band_group(data, inline_descriptor, position)
            entry["group_index"] = None
            entry["position"] = position
            entries.append(entry)

        rats = {entry["rat"] for entry in entries}
        if rats == {"LTE", "NR"}:
            rat_mix = "EN-DC"
        elif rats == {"NR"}:
            rat_mix = "NR-CA"
        elif rats == {"LTE"}:
            rat_mix = "LTE-CA"
        else:
            rat_mix = "+".join(sorted(rats))
        property_fields = decode_combo_property_byte(combo_flags)
        return {
            "combo_index": combo_index,
            "file_offset": offset,
            "file_offset_hex": f"0x{offset:X}",
            "raw_hex": data[
                offset:offset + descriptor.combo_record_size
            ].hex(" "),
            "rat_mix": rat_mix,
            "combination_source_order": "+".join(
                entry["band_label"] for entry in entries
            ),
            "combination_source_order_with_classes": "+".join(
                entry["band_class_label"] for entry in entries
            ),
            "combination": canonical_combination(entries),
            "combination_with_classes": canonical_combination(
                entries, include_classes=True
            ),
            "group_indices": [],
            "all_group_indices_raw": [],
            "combo_flags": combo_flags,
            "combo_flags_hex": f"0x{combo_flags:02X}",
            **property_fields,
            "bcs_num": bcs_num,
            "higher_power_limit": None,
            "reserved_byte_1": reserved_byte,
            "reserved_byte_2": 0,
            "num_band_entries": num_band_entries,
            "reserved_word": reserved_word,
            "envelope_mask": 0,
            "envelope_mask_hex": "0x00000000",
            "subset_mask": 0,
            "subset_mask_hex": "0x00000000",
            "extension_word": None,
            "extension_word_hex": None,
            "entries": entries,
        }

    offset = descriptor.combos_file_offset + combo_index * descriptor.combo_record_size
    (
        all_group_indices,
        combo_flags,
        reserved_byte_1,
        reserved_byte_2,
        num_band_entries,
        reserved_word,
        envelope_mask,
        subset_mask,
    ) = read_combo_header(data, offset, descriptor.count_byte_offset)
    group_indices = list(all_group_indices[:num_band_entries])
    entries: list[dict[str, Any]] = []
    for position, group_index in enumerate(group_indices):
        entry = dict(band_groups[group_index])
        entry["position"] = position
        entries.append(entry)

    rats = {entry["rat"] for entry in entries}
    property_fields = decode_combo_property_byte(combo_flags)
    combo_extension_word = (
        struct.unpack_from("<I", data, offset + 40)[0]
        if descriptor.combo_record_size >= 44
        else None
    )

    if rats == {"LTE", "NR"}:
        rat_mix = "EN-DC"
    elif rats == {"NR"}:
        rat_mix = "NR-CA"
    elif rats == {"LTE"}:
        rat_mix = "LTE-CA"
    else:
        rat_mix = "+".join(sorted(rats))

    return {
        "combo_index": combo_index,
        "file_offset": offset,
        "file_offset_hex": f"0x{offset:X}",
        "raw_hex": data[offset : offset + descriptor.combo_record_size].hex(" "),
        "rat_mix": rat_mix,
        "combination_source_order": "+".join(
            entry["band_label"] for entry in entries
        ),
        "combination_source_order_with_classes": "+".join(
            entry["band_class_label"] for entry in entries
        ),
        "combination": canonical_combination(entries),
        "combination_with_classes": canonical_combination(
            entries, include_classes=True
        ),
        "group_indices": group_indices,
        "all_group_indices_raw": list(all_group_indices),
        # combo_flags is retained for compatibility. It is the same source
        # byte exposed below as property_byte_raw.
        "combo_flags": combo_flags,
        "combo_flags_hex": f"0x{combo_flags:02X}",
        **property_fields,
        "bcs_num": None,
        "higher_power_limit": None,
        "reserved_byte_1": reserved_byte_1,
        "reserved_byte_2": reserved_byte_2,
        "num_band_entries": num_band_entries,
        "reserved_word": reserved_word,
        "envelope_mask": envelope_mask,
        "envelope_mask_hex": f"0x{envelope_mask:08X}",
        "subset_mask": subset_mask,
        "subset_mask_hex": f"0x{subset_mask:08X}",
        "extension_word": combo_extension_word,
        "extension_word_hex": (f"0x{combo_extension_word:08X}" if combo_extension_word is not None else None),
        "entries": entries,
    }


def parse_descriptor(
    path: Path,
    data: bytes,
    descriptor: Descriptor,
    *,
    discovery: str,
    table_kind: str,
    detected_table_count: int,
    embedded_path: str | None = None,
) -> dict[str, Any]:
    band_groups = (
        []
        if descriptor.descriptor_layout in ("hi_inline_100", "magnus_inline_150")
        else [
            parse_band_group(data, descriptor, index)
            for index in range(descriptor.band_group_count)
        ]
    )
    combinations = [
        parse_combo(data, descriptor, band_groups, index)
        for index in range(descriptor.combo_count)
    ]
    if table_kind == "nrdc":
        for combo in combinations:
            combo["rat_mix"] = "NR-DC"
            combo["combination"] = combo["combination"].replace("NRCA_", "NRDC_", 1)
            combo["combination_with_classes"] = combo["combination_with_classes"].replace("NRCA_", "NRDC_", 1)
    used_group_indices = sorted(
        {
            group_index
            for combo in combinations
            for group_index in combo["group_indices"]
        }
    )

    descriptor_va = descriptor.virtual_address
    source_name, source_index = TABLE_SOURCE_INFO.get(
        table_kind, (f"UNKNOWN_{table_kind.upper()}", None)
    )
    return {
        "metadata": {
            "parser": "rf_endc_parser.py",
            "input_file": str(path),
            "embedded_input_path": embedded_path,
            "input_size": len(data),
            "input_sha256": hashlib.sha256(data).hexdigest(),
            "table_kind": table_kind,
            "b826_source_name": source_name,
            "b826_source_index": source_index,
            "detected_table_count": detected_table_count,
            "descriptor_discovery": discovery,
            "combo_record_size": descriptor.combo_record_size,
            "component_count_byte_offset": descriptor.count_byte_offset,
            "band_group_record_size": descriptor.band_group_record_size,
            "known_bandwidth_parts_mhz": KNOWN_BANDWIDTH_PARTS_MHZ,
            "notes": [
                "Unknown bandwidth and feature codes are retained as raw values.",
                "Some rare Qualcomm bandwidth-index mappings are inferred.",
                "BC_ID is not stored in these hardware RF source records.",
                "Combination-property bits 0..2 are power class; bits 6..7 are UL TX switching.",
                "X75-native band groups use one-bit-aligned UL-class and antenna fields.",
                "Later generated band groups store UL class in word1 bits 6..10 and extend the UL antenna enum into word3 bits 0..3.",
                "DL bandwidth class uses the high five bits of band_code.",
                "B826 repacks these source records; it is not a byte-for-byte copy.",
            ],
        },
        "descriptor": {
            "file_offset": descriptor.file_offset,
            "file_offset_hex": f"0x{descriptor.file_offset:X}",
            "virtual_address": descriptor_va,
            "virtual_address_hex": (
                f"0x{descriptor_va:X}" if descriptor_va is not None else None
            ),
            "combo_count": descriptor.combo_count,
            "combos_va": descriptor.combos_va,
            "combos_va_hex": f"0x{descriptor.combos_va:X}",
            "combos_file_offset": descriptor.combos_file_offset,
            "combos_file_offset_hex": f"0x{descriptor.combos_file_offset:X}",
            "band_groups_va": descriptor.band_groups_va,
            "band_groups_va_hex": f"0x{descriptor.band_groups_va:X}",
            "band_groups_file_offset": descriptor.band_groups_file_offset,
            "band_groups_file_offset_hex": (
                f"0x{descriptor.band_groups_file_offset:X}"
            ),
            "band_group_count": descriptor.band_group_count,
            "used_band_group_count": len(used_group_indices),
            "used_band_group_indices": used_group_indices,
            "antenna_table_count": descriptor.antenna_table_count,
            "descriptor_layout": descriptor.descriptor_layout,
            "band_group_layout": descriptor.band_group_layout,
            "antenna_table_va": descriptor.antenna_table_va,
            "antenna_table_va_hex": (f"0x{descriptor.antenna_table_va:X}" if descriptor.antenna_table_va is not None else None),
        },
        "antenna_table": [
            {
                "index": index,
                "pattern": pattern,
                "name": antenna_info(index)[1],
            }
            for index, pattern in enumerate(ANTENNA_TABLE)
        ],
        "band_groups": band_groups,
        "combinations": combinations,
    }


def parse_tables(
    path: Path,
    descriptor_offset: int | None,
    table_kind: str = "endc",
    *,
    data: bytes | None = None,
    embedded_path: str | None = None,
) -> list[dict[str, Any]]:
    if data is None:
        data = path.read_bytes()
    image = Elf32Image(data)

    if descriptor_offset is not None:
        descriptor = make_descriptor(data, image, descriptor_offset)
        classified_kind = classify_descriptor(data, descriptor)
        return [
            parse_descriptor(
                path,
                data,
                descriptor,
                discovery="manual",
                table_kind=classified_kind,
                detected_table_count=1,
                embedded_path=embedded_path,
            )
        ]

    named = find_named_descriptors(data, image)
    if named:
        classified = [
            (kind, descriptor)
            for kind, descriptor, _symbol_name in named
        ]
        descriptors = [descriptor for _kind, descriptor in classified]
        discovery_mode = "dynamic-symbol"
    else:
        descriptors = find_descriptors(data, image)
        classified = [
            (classify_descriptor(data, descriptor), descriptor)
            for descriptor in descriptors
        ]
        discovery_mode = "structural"

        # NR-CA and NR-DC both contain only NR components, so RAT makeup alone
        # cannot distinguish them. This size rule is fallback-only for stripped
        # ELFs; named symbols are authoritative when available.
        nr_only_positions = [
            index for index, (kind, _descriptor) in enumerate(classified)
            if kind == "nrca"
        ]
        if len(nr_only_positions) > 1:
            primary = max(
                nr_only_positions,
                key=lambda index: classified[index][1].combo_count,
            )
            classified = [
                (("nrdc" if index in nr_only_positions and index != primary else kind), descriptor)
                for index, (kind, descriptor) in enumerate(classified)
            ]
    if table_kind == "all":
        selected = [
            item
            for item in classified
            if item[0] in ("lteca", "endc", "nrca", "nrdc")
        ]
    else:
        selected = [item for item in classified if item[0] == table_kind]

    if not selected:
        available = ", ".join(sorted({kind for kind, _ in classified}))
        raise ParseError(
            f"No {table_kind.upper()} RF table was found "
            f"(available: {available or 'none'})."
        )
    if table_kind != "all" and len(selected) > 1:
        offsets = ", ".join(
            f"0x{descriptor.file_offset:X}" for _, descriptor in selected
        )
        raise ParseError(
            f"{table_kind.upper()} table detection is ambiguous ({offsets}); "
            "select one with --descriptor-offset."
        )

    selected.sort(
        key=lambda item: (
            {"lteca": 0, "endc": 1, "nrca": 2, "nrdc": 3}.get(item[0], 9),
            item[1].file_offset,
        )
    )
    return [
        parse_descriptor(
            path,
            data,
            descriptor,
            discovery=discovery_mode,
            table_kind=kind,
            detected_table_count=len(descriptors),
            embedded_path=embedded_path,
        )
        for kind, descriptor in selected
    ]


def parse_file(
    path: Path,
    descriptor_offset: int | None,
    table_kind: str = "endc",
) -> dict[str, Any]:
    """Parse one RF table; retained as the API-compatible single-table helper."""
    results = parse_tables(path, descriptor_offset, table_kind)
    if len(results) != 1:
        raise ParseError(
            "parse_file() requires one table; use parse_tables(..., 'all')."
        )
    return results[0]


def write_json(result: dict[str, Any], path: Path, compact: bool) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        if compact:
            json.dump(result, handle, ensure_ascii=False, separators=(",", ":"))
        else:
            json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_csv_exports(result: dict[str, Any], base: Path) -> list[Path]:
    combo_path = base.with_name(base.name + "_combos.csv")
    entry_path = base.with_name(base.name + "_entries.csv")
    group_path = base.with_name(base.name + "_band_groups.csv")

    combo_fields = [
        "combo_index",
        "file_offset_hex",
        "rat_mix",
        "combination",
        "combination_with_classes",
        "combination_source_order",
        "combination_source_order_with_classes",
        "num_band_entries",
        "group_indices",
        "combo_flags_hex",
        "property_byte_hex",
        "power_class_raw",
        "power_class_label",
        "tdd_ant_swt_fdd_disruption",
        "simultaneous_rx_tx_endc",
        "simultaneous_rx_tx_ca",
        "ul_tx_switch_type_raw",
        "ul_tx_switch_label",
        "bcs_num",
        "higher_power_limit",
        "reserved_byte_1",
        "reserved_byte_2",
        "reserved_word",
        "envelope_mask_hex",
        "subset_mask_hex",
        "raw_hex",
    ]
    combo_rows = []
    for combo in result["combinations"]:
        row = dict(combo)
        row["group_indices"] = " ".join(map(str, combo["group_indices"]))
        combo_rows.append(row)
    write_csv(combo_path, combo_fields, combo_rows)

    entry_fields = [
        "combo_index",
        "position",
        "group_index",
        "rat",
        "band",
        "band_label",
        "band_class_label",
        "band_code_hex",
        "band_code_high",
        "dl_bw_class_code",
        "dl_bw_class",
        "dl_bw_code",
        "dl_bandwidth",
        "dl_bandwidth_parts_mhz",
        "ul_present",
        "ul_bw_class_code",
        "ul_bw_class",
        "band_group_layout",
        "ul_bw_code",
        "ul_bandwidth",
        "ul_bandwidth_parts_mhz",
        "dl_antenna_index",
        "dl_antenna",
        "dl_antenna_pattern",
        "ul_antenna_index",
        "ul_antenna",
        "ul_antenna_pattern",
        "field_2_unknown_high",
        "feature_word_3_hex",
        "feature_word_4_hex",
        "feature_word_5_hex",
        "file_offset_hex",
        "raw_hex",
    ]
    entry_rows = []
    for combo in result["combinations"]:
        for entry in combo["entries"]:
            row = dict(entry)
            row["combo_index"] = combo["combo_index"]
            row["dl_antenna_pattern"] = " ".join(
                map(str, entry["dl_antenna_pattern"] or [])
            )
            row["ul_antenna_pattern"] = " ".join(
                map(str, entry["ul_antenna_pattern"] or [])
            )
            row["dl_bandwidth_parts_mhz"] = "+".join(
                map(str, entry["dl_bandwidth_parts_mhz"] or [])
            )
            row["ul_bandwidth_parts_mhz"] = "+".join(
                map(str, entry["ul_bandwidth_parts_mhz"] or [])
            )
            entry_rows.append(row)
    write_csv(entry_path, entry_fields, entry_rows)

    group_fields = [
        "group_index",
        "file_offset_hex",
        "band_code_hex",
        "band_code_high",
        "rat",
        "band",
        "band_label",
        "band_class_label",
        "dl_bw_code",
        "dl_bw_class_code",
        "dl_bw_class",
        "dl_bandwidth",
        "dl_bandwidth_parts_mhz",
        "ul_present",
        "ul_bw_class_code",
        "ul_bw_class",
        "band_group_layout",
        "field_2_unknown_high",
        "ul_bw_code",
        "ul_bandwidth",
        "ul_bandwidth_parts_mhz",
        "dl_antenna_index",
        "dl_antenna",
        "dl_antenna_pattern",
        "ul_antenna_index",
        "ul_antenna",
        "ul_antenna_pattern",
        "feature_word_3_hex",
        "feature_word_4_hex",
        "feature_word_5_hex",
        "raw_hex",
    ]
    group_rows = []
    for group in result["band_groups"]:
        row = dict(group)
        row["dl_antenna_pattern"] = " ".join(
            map(str, group["dl_antenna_pattern"] or [])
        )
        row["ul_antenna_pattern"] = " ".join(
            map(str, group["ul_antenna_pattern"] or [])
        )
        row["dl_bandwidth_parts_mhz"] = "+".join(
            map(str, group["dl_bandwidth_parts_mhz"] or [])
        )
        row["ul_bandwidth_parts_mhz"] = "+".join(
            map(str, group["ul_bandwidth_parts_mhz"] or [])
        )
        group_rows.append(row)
    write_csv(group_path, group_fields, group_rows)
    return [combo_path, entry_path, group_path]


def parse_integer(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a decimal or 0x-prefixed integer"
        ) from error


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Extract Qualcomm RF_ENDC/RF_NRCA combinations from a hardware-specific "
            "ELF .mbn or directly from a FAT16 modem.img, using only Python's "
            "standard library."
        )
    )
    parser.add_argument(
        "input",
        type=Path,
        help="hardware-specific .mbn file or Qualcomm FAT16 modem.img",
    )
    parser.add_argument(
        "--hwid",
        default="622",
        help=(
            "hardware module selected from modem.img, e.g. 622, 622_0_0, "
            "or 622_0_0.mbn (default: 622)"
        ),
    )
    parser.add_argument(
        "--list-hwids",
        action="store_true",
        help="list hardware .mbn modules in modem.img and exit",
    )
    parser.add_argument(
        "--extract-mbn",
        action="store_true",
        help="also save the selected .mbn outside modem.img",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="output directory (default: beside the input file)",
    )
    parser.add_argument(
        "--prefix",
        help=(
            "output filename prefix (default: <input_stem>_<source>; "
            "source suffixes are appended when --table all is used)"
        ),
    )
    parser.add_argument(
        "--table",
        choices=("lteca", "endc", "nrca", "nrdc", "all"),
        default="endc",
        help="RF table to parse (default: endc)",
    )
    parser.add_argument(
        "--format",
        choices=("json", "csv", "both"),
        default="both",
        help="export format (default: both)",
    )
    parser.add_argument(
        "--descriptor-offset",
        type=parse_integer,
        help="manual descriptor file offset, e.g. 0xA7FF0",
    )
    parser.add_argument(
        "--compact-json",
        action="store_true",
        help="write JSON without indentation",
    )
    parser.add_argument(
        "--print-combo",
        type=int,
        metavar="INDEX",
        help="also print one decoded global combination to the console",
    )
    parser.add_argument(
        "--no-export",
        action="store_true",
        help="validate and optionally print a combination without writing files",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    input_path: Path = args.input
    if not input_path.is_file():
        print(f"error: file not found: {input_path}", file=sys.stderr)
        return 2

    try:
        with input_path.open("rb") as handle:
            signature = handle.read(4)

        embedded_data: bytes | None = None
        embedded_path: str | None = None
        selected_name = input_path.name
        if signature == b"\x7fELF":
            if args.list_hwids:
                raise ParseError("--list-hwids requires a FAT16 modem.img input.")
        else:
            fat = Fat16Image(input_path)
            available = fat.hardware_mbns()
            if args.list_hwids:
                print(f"Hardware modules in {input_path}:")
                for name in available:
                    print(name)
                return 0

            selected_name = normalize_hwid_name(args.hwid)
            actual = next(
                (
                    name
                    for name in available
                    if name.casefold() == selected_name.casefold()
                ),
                None,
            )
            if actual is None:
                raise ParseError(
                    f"{selected_name} was not found in /image/modem_pr/so. "
                    "Use --list-hwids to show available modules."
                )
            selected_name = actual
            embedded_path = f"/image/modem_pr/so/{selected_name}"
            embedded_data = fat.read_file(embedded_path)
            print(
                f"Selected {embedded_path} from {input_path} "
                f"({len(embedded_data)} bytes)"
            )

        results = parse_tables(
            input_path,
            args.descriptor_offset,
            args.table,
            data=embedded_data,
            embedded_path=embedded_path,
        )
    except (OSError, ParseError, struct.error) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    output_dir = args.output_dir or input_path.parent
    written: list[Path] = []

    for result in results:
        descriptor = result["descriptor"]
        source_name = result["metadata"]["b826_source_name"]
        source_index = result["metadata"]["b826_source_index"]
        source_suffix = (
            f" (B826 source {source_index})"
            if source_index is not None
            else ""
        )
        print(
            f"{source_name}{source_suffix}: "
            f"{descriptor['combo_count']} combinations, "
            f"{descriptor['band_group_count']} band groups "
            f"({descriptor['used_band_group_count']} referenced), "
            f"{descriptor['antenna_table_count']} antenna entries"
        )
        print(
            f"Descriptor {descriptor['file_offset_hex']}; "
            f"combos {descriptor['combos_file_offset_hex']}; "
            f"band groups {descriptor['band_groups_file_offset_hex']}"
        )

        if args.print_combo is not None:
            if not 0 <= args.print_combo < descriptor["combo_count"]:
                if len(results) == 1:
                    print(
                        f"error: combo index must be 0 through "
                        f"{descriptor['combo_count'] - 1}",
                        file=sys.stderr,
                    )
                    return 2
                print(
                    f"{source_name}: combo {args.print_combo} is outside "
                    f"0..{descriptor['combo_count'] - 1}; skipped",
                    file=sys.stderr,
                )
                continue
            print(json.dumps(result["combinations"][args.print_combo], indent=2))

    if args.extract_mbn:
        if embedded_data is None:
            print(
                "Input is already an ELF .mbn; --extract-mbn has no effect.",
                file=sys.stderr,
            )
        else:
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
                extracted_path = output_dir / selected_name
                extracted_path.write_bytes(embedded_data)
                written.append(extracted_path)
            except OSError as error:
                print(f"error writing extracted MBN: {error}", file=sys.stderr)
                return 1

    if args.no_export:
        for path in written:
            print(f"Wrote {path}")
        return 0

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        for result in results:
            source_slug = result["metadata"]["b826_source_name"].lower()
            if args.prefix:
                prefix = (
                    f"{args.prefix}_{source_slug}"
                    if len(results) > 1
                    else args.prefix
                )
            else:
                prefix = f"{Path(selected_name).stem}_{source_slug}"
            base = output_dir / prefix
            if args.format in ("json", "both"):
                json_path = base.with_suffix(".json")
                write_json(result, json_path, args.compact_json)
                written.append(json_path)
            if args.format in ("csv", "both"):
                written.extend(write_csv_exports(result, base))
    except OSError as error:
        print(f"error writing output: {error}", file=sys.stderr)
        return 1

    for path in written:
        print(f"Wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

