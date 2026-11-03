from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import legacy_rfcard_parser as legacy


class FlatImage:
    """Minimal VA mapper for descriptor unit tests."""

    records_va = 0x1000
    records_offset = 64

    def __init__(self, data: bytes) -> None:
        self.data = data

    def va_to_offset(self, address: int, size: int = 1) -> int | None:
        offset = self.records_offset + address - self.records_va
        if address >= self.records_va and 0 <= offset <= len(self.data) - size:
            return offset
        return None

    def offset_to_va(self, offset: int, size: int = 1) -> int | None:
        if 0 <= offset <= len(self.data) - size:
            return 0x2000 + offset
        return None


def component(rat: int, band: int, dl_class: int = 1) -> bytes:
    band_code = rat | (band << 2) | (dl_class << 11)
    return struct.pack("<H", band_code) + b"\0" * 6


def inline_fixture(combos: list[list[tuple[int, int]]]) -> bytes:
    data = bytearray(FlatImage.records_offset + len(combos) * 100)
    struct.pack_into(
        "<HHIHHIII",
        data,
        0,
        len(combos),
        0,
        FlatImage.records_va,
        81,
        0,
        0,
        0,
        0,
    )
    for combo_index, entries in enumerate(combos):
        offset = FlatImage.records_offset + combo_index * 100
        for position, (rat, band) in enumerate(entries):
            start = offset + position * 8
            data[start:start + 8] = component(rat, band)
        data[offset + 96] = 2
        data[offset + 98] = len(entries)
    return bytes(data)


def magnus_component(
    rat: int,
    band: int,
    dl_class: int = 1,
    *,
    word_0: int = 0,
    dl_bw: int = 14,
    dl_ant: int = 3,
    ul_class: int = 1,
    ul_bw: int = 14,
    ul_ant: int = 1,
    feature: int = 10,
) -> bytes:
    return struct.pack(
        "<HBBBBBBBBH",
        word_0,
        rat << 5,
        dl_class,
        dl_bw,
        dl_ant,
        ul_class,
        ul_bw,
        ul_ant,
        feature,
        band,
    )


def magnus_fixture(combos: list[list[tuple[int, int, int]]]) -> bytes:
    data = bytearray(FlatImage.records_offset + len(combos) * 150)
    struct.pack_into("<II4I", data, 0, len(combos), FlatImage.records_va, 0, 0, 0, 0)
    for combo_index, entries in enumerate(combos):
        offset = FlatImage.records_offset + combo_index * 150
        for position, (rat, band, dl_class) in enumerate(entries):
            start = offset + position * 12
            data[start:start + 12] = magnus_component(
                rat,
                band,
                dl_class,
                word_0=position + 3,
            )
        if len(entries) < 12:
            sentinel = offset + len(entries) * 12
            data[sentinel:sentinel + 12] = b"\x02\x00" + b"\0" * 10
        data[offset + 146] = 1
        data[offset + 147] = len(entries)
        data[offset + 148] = 5
    return bytes(data)


class HiInlineDescriptorTests(unittest.TestCase):
    def test_nr_ca_inline_descriptor_and_combos(self) -> None:
        data = inline_fixture([[(2, 79), (2, 41)], [(2, 78)]])
        image = FlatImage(data)

        layout = legacy.validate_candidate(data, image, 0, exhaustive=True)
        self.assertIsNotNone(layout)
        self.assertEqual(layout[8], "hi_inline_100")
        self.assertEqual(layout[0], 2)

        descriptor = legacy.make_descriptor(data, image, 0, layout)
        self.assertEqual(legacy.classify_descriptor(data, descriptor), "nrca")
        parsed = legacy.parse_descriptor(
            Path("660_0_0.mbn"),
            data,
            descriptor,
            discovery="unit test",
            table_kind="nrca",
            detected_table_count=1,
        )
        self.assertEqual(
            [combo["combination"] for combo in parsed["combinations"]],
            ["NRCA_n41+n79", "NRCA_n78"],
        )
        self.assertEqual(parsed["combinations"][0]["num_band_entries"], 2)
        self.assertEqual(parsed["descriptor"]["descriptor_layout"], "hi_inline_100")

    def test_endc_inline_descriptor(self) -> None:
        data = inline_fixture([[(1, 3), (2, 78)]])
        image = FlatImage(data)
        descriptor = legacy.make_descriptor(data, image, 0)

        self.assertEqual(legacy.classify_descriptor(data, descriptor), "endc")
        parsed = legacy.parse_descriptor(
            Path("660_0_0.mbn"),
            data,
            descriptor,
            discovery="unit test",
            table_kind="endc",
            detected_table_count=1,
        )
        combo = parsed["combinations"][0]
        self.assertEqual(combo["combination"], "DC_B3_n78")
        self.assertEqual(combo["bcs_num"], 0)

    def test_nonzero_unused_component_is_rejected(self) -> None:
        data = bytearray(inline_fixture([[(2, 78)]]))
        data[FlatImage.records_offset + 8] = 1
        self.assertIsNone(
            legacy.validate_candidate(
                bytes(data),
                FlatImage(bytes(data)),
                0,
                exhaustive=True,
            )
        )


class MagnusInlineDescriptorTests(unittest.TestCase):
    def test_native_150_endc_descriptor_and_band_location(self) -> None:
        data = magnus_fixture([[(1, 39, 1), (2, 79, 3)]])
        image = FlatImage(data)

        layout = legacy.validate_candidate(data, image, 0, exhaustive=True)
        self.assertIsNotNone(layout)
        self.assertEqual(layout[8], "magnus_inline_150")
        self.assertEqual(layout[9], "magnus_native_12")

        descriptor = legacy.make_descriptor(data, image, 0, layout)
        self.assertEqual(legacy.classify_descriptor(data, descriptor), "endc")
        parsed = legacy.parse_descriptor(
            Path("625_0_0.mbn"),
            data,
            descriptor,
            discovery="unit test",
            table_kind="endc",
            detected_table_count=1,
        )
        combo = parsed["combinations"][0]
        self.assertEqual(combo["combination"], "DC_B39_n79")
        self.assertEqual(combo["combination_with_classes"], "DC_B39A_n79C")
        self.assertEqual(combo["bcs_num"], 5)
        self.assertEqual(combo["power_class_raw"], 1)
        self.assertEqual(
            [(entry["rat"], entry["band"]) for entry in combo["entries"]],
            [("LTE", 39), ("NR", 79)],
        )

    def test_bad_native_150_sentinel_is_rejected(self) -> None:
        data = bytearray(magnus_fixture([[(2, 78, 1)]]))
        data[FlatImage.records_offset + 12] = 3
        self.assertIsNone(
            legacy.validate_candidate(
                bytes(data),
                FlatImage(bytes(data)),
                0,
                exhaustive=True,
            )
        )


class LegacyFilenameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "gui_version"))
        import qualcomm_rf_combo_analyzer

        cls.analyzer = qualcomm_rf_combo_analyzer

    def test_two_component_mmwave_name(self) -> None:
        matched = self.analyzer._matches_candidate("710_0.mbn")
        self.assertIsNotNone(matched)
        generation, match = matched
        self.assertEqual(generation, "Legacy ELF")
        self.assertEqual(self.analyzer._identity_value(match, "hwid"), 710)
        self.assertEqual(self.analyzer._identity_value(match, "fsid"), 0)
        self.assertEqual(self.analyzer._identity_value(match, "bid"), 0)


class ModuleRecordComboTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(ROOT / "gui_version"))
        import qualcomm_rf_combo_analyzer

        cls.analyzer = qualcomm_rf_combo_analyzer

    def test_zero_combos_is_discarded(self) -> None:
        record = self.analyzer.ModuleRecord(
            inner_path="test.mbn",
            name="rf_config_2901_0_0.mbn",
            generation="DAT/protobuf",
            size=1000,
            hwid=2901,
            fsid=0,
            bid=0,
            lte_combos=0,
            nr_combos="0+0+0=0",
        )
        self.assertEqual(record.total_combos, 0)
        self.assertFalse(record.has_combos)

    def test_blank_combos_is_discarded(self) -> None:
        record = self.analyzer.ModuleRecord(
            inner_path="test.mbn",
            name="rf_config_2901_0_0.mbn",
            generation="DAT/protobuf",
            size=1000,
            hwid=2901,
            fsid=0,
            bid=0,
            lte_combos=-1,
            nr_combos="—",
        )
        self.assertEqual(record.total_combos, 0)
        self.assertFalse(record.has_combos)

    def test_positive_combos_is_kept(self) -> None:
        record_lte = self.analyzer.ModuleRecord(
            inner_path="test.mbn",
            name="rf_config_2025_0_0.mbn",
            generation="DAT/protobuf",
            size=1000,
            hwid=2025,
            fsid=0,
            bid=0,
            lte_combos=500,
            nr_combos="0+0+0=0",
        )
        self.assertEqual(record_lte.total_combos, 500)
        self.assertTrue(record_lte.has_combos)

        record_nr = self.analyzer.ModuleRecord(
            inner_path="test.mbn",
            name="rf_config_2025_0_0.mbn",
            generation="DAT/protobuf",
            size=1000,
            hwid=2025,
            fsid=0,
            bid=0,
            lte_combos=0,
            nr_combos="3131+420+34=3585",
        )
        self.assertEqual(record_nr.total_combos, 3585)
        self.assertTrue(record_nr.has_combos)


if __name__ == "__main__":
    unittest.main()
