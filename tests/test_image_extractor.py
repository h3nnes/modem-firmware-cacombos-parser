from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
