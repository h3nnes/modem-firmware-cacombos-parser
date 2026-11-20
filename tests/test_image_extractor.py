from __future__ import annotations

import os
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "gui_version"
if str(GUI) not in sys.path:
    sys.path.insert(0, str(GUI))

import image_extractor
import qualcomm_rf_combo_analyzer as analyzer


class ImageExtractorTests(unittest.TestCase):
    def test_detects_ubi_magic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "NON-HLOS.ubi"
            image.write_bytes(b"UBI#" + (b"\x00" * 508))
            self.assertEqual(image_extractor.detect(image), "ubi")

    def test_discovers_legacy_rfcard_only_under_so(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            so = root / "image" / "modem_pr" / "so"
            mcfg = root / "image" / "modem_pr" / "mcfg"
            so.mkdir(parents=True)
            mcfg.mkdir(parents=True)
            legacy = so / "549_0_1.mbn"
            unrelated = mcfg / "549_0_1.mbn"
            modern = mcfg / "rf_config_1324_0_0.mbn"
            for path in (legacy, unrelated, modern):
                path.write_bytes(b"test")

            mbns, _sidecars = image_extractor.discover_candidates(root)

            self.assertEqual({path.resolve() for path in mbns}, {legacy.resolve(), modern.resolve()})

    def test_rfcard_name_accepts_modern_and_legacy_names(self) -> None:
        self.assertTrue(image_extractor.is_rfcard_name("rf_config_1324_0_0.mbn"))
        self.assertTrue(image_extractor.is_rfcard_name("549_0_1.mbn"))
        self.assertFalse(image_extractor.is_rfcard_name("mcfg_sw.mbn"))

    def test_legacy_so_filter_accepts_windows_and_posix_paths(self) -> None:
        self.assertTrue(analyzer._is_so_path(r"image\modem_pr\so\549_0_1.mbn"))
        self.assertTrue(analyzer._is_so_path("image/modem_pr/so/549_0_1.mbn"))
        self.assertFalse(analyzer._is_so_path(r"image\mcfg\549_0_1.mbn"))

    def test_finds_embedded_fat_payload_behind_motorola_wrapper(self) -> None:
        boot = bytearray(512)
        boot[0:3] = b"\xeb\x3c\x90"
        boot[3:11] = b"MSWIN4.1"
        struct.pack_into("<H", boot, 11, 512)  # bytes per sector
        boot[13] = 4  # sectors per cluster
        struct.pack_into("<H", boot, 14, 1)  # reserved sectors
        boot[16] = 2  # FAT count
        struct.pack_into("<H", boot, 17, 512)  # root entries
        struct.pack_into("<H", boot, 19, 100)  # total sectors
        boot[21] = 0xF8  # media descriptor
        struct.pack_into("<H", boot, 22, 1)  # sectors per FAT
        boot[510:512] = b"\x55\xaa"
        payload = bytes(boot) + b"\x00" * (100 * 512 - 512)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "motosignature27radio.img"
            path.write_bytes(
                b"SINGLE_N_LONELY\x00" + b"\x00" * (0x3500 - 16) + payload
            )
            self.assertEqual(image_extractor._fat_headers(path, 1), [0x3500])

            # Without a known OEM the boot-sector signature alone is not enough.
            no_oem = bytearray(boot)
            no_oem[3:11] = b"\x00" * 8
            path.write_bytes(
                b"SINGLE_N_LONELY\x00"
                + b"\x00" * (0x3500 - 16)
                + bytes(no_oem)
                + b"\x00" * (100 * 512 - 512)
            )
            self.assertEqual(image_extractor._fat_headers(path, 1), [])

    def test_scan_container_parses_signature_27_fat_wrapper(self) -> None:
        corpus = Path(
            os.environ.get("CORPUS_DIR", "/home/henrik/apps/qualcomm-hwcombos-mbn-parser")
        )
        image = corpus / "motosignature27radio.img"
        if not image.exists() or shutil.which("7z") is None:
            self.skipTest("Signature 27 image or 7z not available")
        result = image_extractor.scan_container(image)
        self.assertEqual(
            sorted(path.name for path in result.mbns),
            [
                "rf_config_0500_0_0_0170.mbn",
                "rf_config_0501_0_0_0170.mbn",
                "rf_config_0502_0_0_0170.mbn",
                "rf_config_0503_0_0_0170.mbn",
                "rf_config_0510_0_0_0170.mbn",
                "rf_config_0511_0_0_0170.mbn",
                "rf_config_0512_0_0_0170.mbn",
                "rf_config_0513_0_0_0170.mbn",
                "rf_config_0520_0_0_0170.mbn",
            ],
        )


if __name__ == "__main__":
    unittest.main()
