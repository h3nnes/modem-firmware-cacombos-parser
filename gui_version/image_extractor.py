#!/usr/bin/env python3
"""Container/filesystem extraction helpers for the upstream GUI analyzer.

This module re-implements the recursive detection and extraction logic from
``qcom-rfcard-mbn-parser-fork/extract_rfcards.py`` in a form suitable for the
upstream ``qualcomm_rf_combo_analyzer`` data model.  It discovers
``rf_config_<HWID>_<FSID>_<BID>.mbn`` files and legacy ``so/*.mbn`` RF cards
inside Android modem firmware containers (sparse, payload, super, ext4,
EROFS, squashfs, F2FS, UBI/UBIFS, FAT,
gzip/xz/zstd/zip/tar/7z, etc.) and returns the paths of any matching MBNs plus
co-located sidecar files.

Apple ships the same Qualcomm cards inside a ``.bbfw``/``.ipsw``, where they are
compressed and content-addressed.  ``extract_bbcfg`` delegates to
``iphone_rf_parser`` to recover both modern ``rf_config_*`` cards and numeric
legacy ELF cards, so everything downstream can select the matching parser.

All external helpers are optional; missing tools are logged once and skipped.
"""

from __future__ import annotations

import gzip
import logging
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)

RFCARD_PATTERN = re.compile(
    r"rf_config_[0-9A-Fa-f]{3,6}_[0-9A-Fa-f]{1,4}_[0-9A-Fa-f]{1,4}"
    r"(?:_(?P<rev>\d+))?"
    r"\.mbn$",
    re.IGNORECASE,
)
LEGACY_RFCARD_PATTERN = re.compile(
    r"^[0-9A-Fa-f]{1,6}_[0-9A-Fa-f]{1,4}(?:_[0-9A-Fa-f]{1,4})?\.mbn$"
)

# Files that add context around an rf_config MBN (kept when present in the same
# directory).  The fork also recognises ``rfcard_info_all.(csv|json)``.
SIDECAR_PATTERNS = (
    re.compile(r"^rf_config_.*_combos\.xml$"),
    re.compile(r"^rf_config_.*_combos_.*\.txt$"),
    re.compile(r"^mbn_ota\.md5sum$"),
    re.compile(r"^rfcard_info_all\.(csv|json)$"),
)

MAGIC_MAX = 4096
MAX_RECURSION_DEPTH = 8
MIN_CONTAINER_SIZE = 512


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


@dataclass
class ToolStatus:
    """Track which external helpers were checked and found missing."""

    missing: set[str] = field(default_factory=set)
    checked: set[str] = field(default_factory=set)

    def check(self, cmd: str) -> bool:
        """Return True if ``cmd`` is available; cache and log misses."""
        if cmd in self.checked:
            return cmd not in self.missing
        self.checked.add(cmd)
        if _have(cmd):
            return True
        self.missing.add(cmd)
        logger.warning("External helper %r not found; some containers may be skipped", cmd)
        return False

    def report(self) -> None:
        if self.missing:
            logger.warning(
                "Some external tools were not available; certain container types "
                "may have been skipped: %s",
                ", ".join(sorted(self.missing)),
            )


@dataclass
class ExtractContext:
    workdir: Path
    tools: ToolStatus
    outputs: list[Path] = field(default_factory=list)


class ExtractionError(RuntimeError):
    """Raised when a container cannot be processed."""


def _new_workdir(ctx: ExtractContext, tag: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=f"{tag}_", dir=ctx.workdir))


def _run(
    cmd: list[str],
    cwd: Path | None = None,
    check: bool = False,
) -> subprocess.CompletedProcess:
    logger.debug("$ %s", " ".join(str(x) for x in cmd))
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _read_magic(path: Path, n: int = MAGIC_MAX) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(n)
    except OSError:
        return b""


def _slice_file(src: Path, dst: Path, offset: int, chunk_size: int = 1 << 20) -> None:
    """Copy ``src`` from ``offset`` to end into ``dst``."""
    with src.open("rb") as handle:
        handle.seek(offset)
        with dst.open("wb") as out:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                out.write(chunk)


# Android sparse image magic and header validation.
_SPARSE_MAGIC = struct.unpack("<I", b"\x3a\xff\x26\xed")[0]


def _sparse_headers(path: Path, max_offsets: int = 8) -> list[int]:
    """Return up to ``max_offsets`` sparse-image start offsets in ``path``.

    Some OEM firmware images wrap a sparse/ext4 payload in a proprietary
    header (e.g. Motorola ``SINGLE_N_LONELY``).  Scanning for valid sparse
    headers lets us find and extract the real filesystem even when the first
    bytes of the file are not a known container.
    """
    offsets: list[int] = []
    size = path.stat().st_size
    if size < 28:
        return offsets
    # Read in chunks so we do not load huge firmware images into memory.
    chunk_size = 1 << 20
    overlap = 28
    with path.open("rb") as handle:
        pos = 0
        while pos < size and len(offsets) < max_offsets:
            read_size = min(chunk_size, size - pos)
            data = handle.read(read_size)
            if not data:
                break
            start = 0
            while True:
                idx = data.find(b"\x3a\xff\x26\xed", start)
                if idx < 0:
                    break
                offset = pos + idx
                if offset + 28 <= size:
                    try:
                        header = struct.unpack(
                            "<IHHHHIIII",
                            _read_at(handle, offset, 28),
                        )
                    except (struct.error, OSError):
                        header = ()
                    (
                        magic,
                        major,
                        minor,
                        file_hdr_sz,
                        chunk_hdr_sz,
                        block_size,
                        total_blocks,
                        total_chunks,
                        _image_checksum,
                    ) = header
                    if (
                        magic == _SPARSE_MAGIC
                        and major == 1
                        and minor == 0
                        and file_hdr_sz == 28
                        and chunk_hdr_sz == 12
                        and block_size in (512, 1024, 2048, 4096, 8192, 16384, 32768)
                        and total_blocks > 0
                        and total_chunks > 0
                    ):
                        offsets.append(offset)
                start = idx + 1
            pos += read_size - overlap if read_size == chunk_size else read_size
    return offsets


def _read_at(handle, offset: int, n: int) -> bytes:
    handle.seek(offset)
    return handle.read(n)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def detect(path: Path) -> str:
    """Return a short type tag for ``path`` based on magic bytes."""
    head = _read_magic(path)
    if not head:
        return "empty"

    if head.startswith(b"\x3a\xff\x26\xed"):
        return "sparse"
    if head.startswith(b"CrAU"):
        return "payload"
    if head.startswith(b"ANDROID!"):
        return "bootimg"
    # Android super.img: LP_METADATA_GEOMETRY_MAGIC at offset 0x1000.
    if len(head) >= 0x1000 + 4:
        if head[:4] == b"gsla" or head[0x1000:0x1004] == b"gsla":
            return "super"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if head.startswith(b"\x04\x22\x4d\x18"):
        return "lz4"
    # Apple baseband config container (the bbcfg.mbn member of a .bbfw).
    # Checked before the archive tags below because it is a bare container.
    if head.startswith(b"\x00GFC") or b"BBCFGMBN" in head[:64]:
        return "bbcfg"
    if head.startswith(b"PK\x03\x04") or path.suffix.lower() in (".bbfw", ".ipsw"):
        return "zip"
    if head[:4] == b"7z\xbc\xaf" and head[4:6] == b"\x27\x1c":
        return "7z"
    if head.startswith((b"hsqs", b"sqsh")):
        return "squashfs"
    # tar (ustar magic at offset 257).
    if len(head) >= 265 and head[257:262] == b"ustar":
        return "tar"
    # ext2/3/4 - superblock magic 0x53EF at offset 0x438.
    if len(head) >= 0x43A and head[0x438:0x43A] == b"\x53\xef":
        return "ext4"
    # EROFS - superblock magic 0xE0F5E1E2 at offset 0x400.
    if len(head) >= 0x404 and head[0x400:0x404] == b"\xe2\xe1\xf5\xe0":
        return "erofs"
    # F2FS - superblock magic 0xF2F52010 at offset 0x400 (LE).
    if len(head) >= 0x404 and head[0x400:0x404] == b"\x10\x20\xf5\xf2":
        return "f2fs"
    # UBI.
    if head.startswith(b"UBI#"):
        return "ubi"
    # FAT12/16/32: OEM name at offset 3.
    if len(head) >= 11 and head[3:11].rstrip(b"\x00 ") in (
        b"MSDOS5.0",
        b"MSWIN4.1",
        b"mkfs.fat",
        b"FAT     ",
        b"MSDOS",
    ):
        return "fat"
    if len(head) >= 0x1FE and head[0x1FE:0x200] == b"\x55\xaa":
        # Last-resort MBR-style boot signature; likely FAT or a partition table.
        return "fat_or_mbr"
    return "unknown"


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------


def extract_sparse(path: Path, ctx: ExtractContext) -> Path | None:
    """Convert a sparse image to a raw ext4 image, or extract it directly.

    ``simg2img`` is preferred because it yields a raw image we can chain into
    the ext4 extractor.  If it is missing or fails, fall back to ``7z`` which
    can read Android sparse images directly and extract the filesystem tree.
    """
    if _have("simg2img"):
        out = _new_workdir(ctx, "sparse") / (path.stem + ".raw")
        res = _run(["simg2img", str(path), str(out)])
        if res.returncode == 0 and out.exists() and out.stat().st_size > 0:
            return out
        logger.warning("simg2img failed on %s: %s", path, _stderr(res))

    if _have("7z"):
        # 7z understands sparse images and returns the extracted files.
        out = _new_workdir(ctx, "sparse")
        res = _run(["7z", "x", "-y", f"-o{out}", str(path)])
        if res.returncode == 0 or any(out.rglob("*")):
            return out
        logger.warning("7z sparse extraction failed on %s: %s", path, _stderr(res))

    # Trigger the standard missing-tool warning only when neither helper is
    # installed.  If a helper is installed but failed, that was already logged.
    if not _have("simg2img") and not _have("7z"):
        ctx.tools.check("simg2img")
        logger.warning("No sparse image extractor available for %s", path.name)
    return None


def extract_ext4(path: Path, ctx: ExtractContext) -> Path | None:
    if not ctx.tools.check("debugfs"):
        return None
    out = _new_workdir(ctx, "ext4")
    res = _run(["debugfs", "-R", f"rdump / {out}", str(path)])
    # ``debugfs`` returns 0 even when it warns about chown; treat any files as success.
    produced = any(out.rglob("*"))
    if not produced:
        logger.warning("debugfs produced nothing for %s: %s", path, _stderr(res))
        return None
    return out


def extract_erofs(path: Path, ctx: ExtractContext) -> Path | None:
    if not ctx.tools.check("fsck.erofs"):
        return None
    out = _new_workdir(ctx, "erofs")
    res = _run(["fsck.erofs", f"--extract={out}", "--no-preserve", str(path)])
    if res.returncode != 0:
        logger.warning("fsck.erofs failed on %s: %s", path, _stderr(res))
        return None
    return out


def extract_7z(path: Path, ctx: ExtractContext, tag: str) -> Path | None:
    if not ctx.tools.check("7z"):
        return None
    out = _new_workdir(ctx, tag)
    res = _run(["7z", "x", "-y", f"-o{out}", str(path)])
    if res.returncode != 0 and not any(out.rglob("*")):
        logger.warning("7z x failed on %s: %s", path, _stderr(res))
        return None
    return out


def extract_squashfs(path: Path, ctx: ExtractContext) -> Path | None:
    if _have("unsquashfs"):
        out = _new_workdir(ctx, "squashfs")
        res = _run(["unsquashfs", "-d", str(out / "root"), "-f", str(path)])
        if res.returncode == 0 and any(out.rglob("*")):
            return out
    return extract_7z(path, ctx, "squashfs")


def extract_gzip(path: Path, ctx: ExtractContext) -> Path | None:
    out = _new_workdir(ctx, "gzip") / (path.stem or "inner.bin")
    try:
        with gzip.open(path, "rb") as src, out.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
    except OSError as exc:
        logger.warning("gzip decompress failed for %s: %s", path, exc)
        return None
    return out


def extract_xz(path: Path, ctx: ExtractContext) -> Path | None:
    try:
        import lzma  # stdlib
    except ImportError:
        logger.warning("python lzma module unavailable")
        return None
    out = _new_workdir(ctx, "xz") / (path.stem or "inner.bin")
    try:
        with lzma.open(path, "rb") as src, out.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 20)
    except (OSError, lzma.LZMAError) as exc:
        logger.warning("xz decompress failed for %s: %s", path, exc)
        return None
    return out


def extract_zstd(path: Path, ctx: ExtractContext) -> Path | None:
    if _have("zstd"):
        out = _new_workdir(ctx, "zstd") / (path.stem or "inner.bin")
        res = _run(["zstd", "-d", "-f", "-o", str(out), str(path)])
        if res.returncode == 0 and out.exists():
            return out
    try:
        import zstandard  # optional
    except ImportError:
        logger.warning("zstd binary missing and python 'zstandard' not installed")
        return None
    out = _new_workdir(ctx, "zstd") / (path.stem or "inner.bin")
    try:
        with path.open("rb") as src, out.open("wb") as dst:
            zstandard.ZstdDecompressor().copy_stream(src, dst)
    except Exception as exc:  # noqa: BLE001
        logger.warning("zstd decompress failed for %s: %s", path, exc)
        return None
    return out


def extract_lz4(path: Path, ctx: ExtractContext) -> Path | None:
    out = _new_workdir(ctx, "lz4") / (path.stem or "inner.bin")
    if _have("lz4"):
        res = _run(["lz4", "-d", "-f", str(path), str(out)])
        if res.returncode == 0 and out.exists() and out.stat().st_size > 0:
            return out
        logger.warning("lz4 binary failed on %s: %s", path, _stderr(res))
    try:
        import lz4.frame  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("lz4 binary missing and python 'lz4' not installed")
        return None
    try:
        with path.open("rb") as src, out.open("wb") as dst:
            shutil.copyfileobj(lz4.frame.LZ4FrameFile(src), dst, length=1 << 20)
    except Exception as exc:  # noqa: BLE001
        logger.warning("lz4 decompress failed for %s: %s", path, exc)
        return None
    return out


def extract_tar(path: Path, ctx: ExtractContext) -> Path | None:
    out = _new_workdir(ctx, "tar")
    try:
        with tarfile.open(path, "r:*") as tar:
            try:
                tar.extractall(out, filter="data")  # type: ignore[call-arg]
            except TypeError:
                tar.extractall(out)  # pragma: no cover
    except (tarfile.TarError, OSError) as exc:
        logger.warning("tar extract failed for %s: %s", path, exc)
        return None
    return out


def extract_super(path: Path, ctx: ExtractContext) -> Path | None:
    if not ctx.tools.check("lpunpack"):
        return None
    out = _new_workdir(ctx, "super")
    res = _run(["lpunpack", str(path), str(out)])
    if res.returncode != 0:
        logger.warning("lpunpack failed on %s: %s", path, _stderr(res))
        return None
    return out


def extract_payload(path: Path, ctx: ExtractContext) -> Path | None:
    for cmd in ("payload-dumper-go", "payload_dumper"):
        if _have(cmd):
            out = _new_workdir(ctx, "payload")
            args = (
                [cmd, "-o", str(out), str(path)]
                if cmd == "payload-dumper-go"
                else [cmd, "--out", str(out), str(path)]
            )
            res = _run(args)
            if res.returncode == 0 and any(out.rglob("*")):
                return out
    logger.warning(
        "%s looks like an OTA payload; install payload-dumper-go or the "
        "'payload_dumper' Python package and rerun.",
        path.name,
    )
    return None


def extract_f2fs(path: Path, ctx: ExtractContext) -> Path | None:  # noqa: ARG001
    logger.warning(
        "%s looks like an F2FS image; F2FS extraction is not supported by this tool",
        path.name,
    )
    return None


def _safe_output_component(value: object, fallback: str) -> str:
    """Return one filesystem-safe component for UBI image/volume names."""
    component = Path(str(value)).name
    component = re.sub(r"[^0-9A-Za-z_.-]+", "_", component).strip("._")
    return component or fallback


def _extract_ubi_with_python(path: Path, out: Path) -> bool:
    """Extract UBI/UBIFS using the Python ``ubi-reader`` package.

    Imports stay local so every non-UBI workflow continues to be stdlib-only.
    Calling the library directly also works in a bundled GUI where its console
    entry-point executable is not present.
    """
    try:
        from ubireader.ubi import ubi
        from ubireader.ubi_io import leb_virtual_file, ubi_file
        from ubireader.ubifs import ubifs
        from ubireader.ubifs.output import extract_files
        from ubireader.utils import guess_peb_size
    except ImportError:
        return False

    ufile = None
    try:
        peb_size = guess_peb_size(str(path))
        if not peb_size:
            raise ExtractionError(f"Could not determine UBI PEB size for {path.name}")

        ufile = ubi_file(str(path), peb_size, 0, None)
        ubi_obj = ubi(ufile)
        extracted_volumes = 0
        for image_index, image in enumerate(ubi_obj.images):
            image_name = _safe_output_component(
                getattr(image, "image_seq", image_index),
                f"image_{image_index}",
            )
            for volume_index, volume_name in enumerate(image.volumes):
                volume = image.volumes[volume_name]
                volume_blocks = volume.get_blocks(ubi_obj.blocks)
                if not volume_blocks:
                    continue

                target = out / image_name / _safe_output_component(
                    volume_name,
                    f"volume_{volume_index}",
                )
                target.mkdir(parents=True, exist_ok=True)
                try:
                    leb_file = leb_virtual_file(ubi_obj, volume_blocks)
                    ubifs_obj = ubifs(leb_file)
                    extract_files(ubifs_obj, str(target), False)
                except (Exception, SystemExit) as exc:
                    # A UBI image may mix UBIFS and raw/static volumes.  Keep
                    # scanning other volumes when one is not a filesystem.
                    logger.warning(
                        "Skipping non-UBIFS or unreadable UBI volume %r: %s",
                        volume_name,
                        exc,
                    )
                    continue
                if any(target.rglob("*")):
                    extracted_volumes += 1

        if extracted_volumes:
            logger.info(
                "Extracted %d UBIFS volume(s) from %s",
                extracted_volumes,
                path.name,
            )
            return True
        logger.warning("ubi-reader found no extractable UBIFS volumes in %s", path)
    except (Exception, SystemExit) as exc:  # ubi-reader uses SystemExit for fatal parse errors
        logger.warning("Python ubi-reader failed on %s: %s", path, exc)
    finally:
        if ufile is not None:
            try:
                ufile.close()
            except Exception:  # noqa: BLE001
                pass
    return False


def _extract_ubi_with_command(path: Path, out: Path) -> bool:
    """Fallback to ubi-reader's console entry point when it is on PATH."""
    for command in ("ubireader_extract_files", "ubireader_extract_files.exe"):
        if not _have(command):
            continue
        res = _run([command, "-o", str(out), str(path)])
        if any(item.is_file() for item in out.rglob("*")):
            if res.returncode != 0:
                logger.warning(
                    "%s returned %d but produced files for %s: %s",
                    command,
                    res.returncode,
                    path.name,
                    _stderr(res),
                )
            return True
        logger.warning("%s failed on %s: %s", command, path, _stderr(res))
    return False


def extract_ubi(path: Path, ctx: ExtractContext) -> Path | None:
    """Extract UBI images whose volumes contain UBIFS filesystems."""
    out = _new_workdir(ctx, "ubi")
    if _extract_ubi_with_python(path, out):
        return out
    # Use a fresh empty directory: the Python backend may have left a partial
    # volume tree, while the console entry point rejects non-empty outputs.
    out = _new_workdir(ctx, "ubi")
    if _extract_ubi_with_command(path, out):
        return out
    raise ExtractionError(
        "UBI/UBIFS support requires the Python 'ubi-reader' package "
        "(install with: python -m pip install ubi-reader)"
    )


def _stderr(res: subprocess.CompletedProcess) -> str:
    return res.stderr.decode(errors="replace").strip()


# ---------------------------------------------------------------------------
# Apple baseband firmware
# ---------------------------------------------------------------------------


def _ber_length(blob: bytes, pos: int) -> tuple[int | None, int]:
    """Decode a BER/DER length at ``pos``; return ``(length, body_offset)``."""
    try:
        first = blob[pos]
    except IndexError:
        return None, pos
    if first < 0x80:
        return first, pos + 1
    count = first & 0x7F
    if not 1 <= count <= 4:
        return None, pos
    start = pos + 1
    chunk = blob[start:start + count]
    if len(chunk) != count:
        return None, pos
    return int.from_bytes(chunk, "big"), start + count


def extract_bbcfg(path: Path, ctx: ExtractContext) -> Path | None:
    """Extract an Apple Qualcomm baseband config container (``BBCFGMBN``).

    Apple stores the RF cards compressed and content-addressed in the tag-0xA9
    blob store, so scanning for EFS pathname tags alone finds ``device_lut``
    and ``device_settings`` but never a card.  ``iphone_rf_parser`` walks that
    store and writes modern cards under Android-style ``rf_config_*.mbn`` names
    and legacy ELFs under numeric legacy names.  This lets the analyzer route
    each generation to its corresponding parser.
    The EFS pathname scan below still runs afterwards so the EFS tree is
    preserved alongside the cards.
    """
    out = _new_workdir(ctx, "bbcfg")
    cards: list = []
    try:
        import iphone_rf_parser

        cards = iphone_rf_parser.extract_bbcfg_tree(path, out, with_efs=False)
        if cards:
            logger.info(
                "iphone_rf_parser recovered %d RF card(s) from %s",
                len(cards),
                path.name,
            )
    except Exception as exc:  # noqa: BLE001 - never let this abort a scan
        logger.warning("iPhone RF card recovery failed for %s: %s", path, exc)

    # Walk the EFS pathname/value records so the surrounding config tree is
    # available next to the recovered cards.
    written = 0
    try:
        data = path.read_bytes()
        tag_path = b"\x9f\x83\x74"
        tag_data = b"\x9f\x83\x76"
        pos = 0
        while True:
            idx = data.find(tag_path, pos)
            if idx == -1:
                break
            path_len, path_start = _ber_length(data, idx + 3)
            if path_len is None:
                pos = idx + 3
                continue
            try:
                name = data[path_start:path_start + path_len].decode("utf-8").strip("\x00")
            except UnicodeDecodeError:
                pos = idx + 3
                continue
            value_idx = data.find(
                tag_data, path_start + path_len, path_start + path_len + 64
            )
            if value_idx == -1:
                pos = path_start + path_len
                continue
            data_len, data_start = _ber_length(data, value_idx + 3)
            if data_len is None:
                pos = idx + 3
                continue
            target = (out / name.lstrip("/")).resolve()
            if out.resolve() not in target.parents:
                # An EFS pathname is attacker-controlled data; never let one
                # escape the scratch directory via "..".
                logger.warning("skipping out-of-tree EFS pathname %r", name)
                pos = data_start + data_len
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data[data_start:data_start + data_len])
            written += 1
            pos = data_start + data_len
    except Exception as exc:  # noqa: BLE001
        logger.warning("bbcfg EFS scan failed for %s: %s", path, exc)

    # Report success when either half produced something; the RF cards are the
    # point of this extractor, so they must not be discarded when a firmware
    # image happens to carry no EFS pathname records.
    if cards or written:
        return out
    return None


def extract_zip(path: Path, ctx: ExtractContext) -> Path | None:
    """Extract a standard ZIP archive, or a ``.bbfw``/``.ipsw`` (both are ZIPs).

    An IPSW is tens of gigabytes and holds exactly one thing of interest, so
    when the archive contains ``.bbfw`` members only those are unpacked; the
    recursive unwrap then opens each one normally.  Archives without ``.bbfw``
    members - every Android package - are extracted in full as before.
    """
    import zipfile

    out = _new_workdir(ctx, "zip")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            basebands = [
                name for name in archive.namelist() if name.lower().endswith(".bbfw")
            ]
            if basebands:
                logger.info(
                    "%s: extracting %d baseband member(s) only",
                    path.name,
                    len(basebands),
                )
                for member in basebands:
                    archive.extract(member, out)
            else:
                archive.extractall(out)
        return out
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "zipfile extraction failed for %s (%s); falling back to 7z", path, exc
        )
    return extract_7z(path, ctx, "zip")


# ---------------------------------------------------------------------------
# Recursion driver
# ---------------------------------------------------------------------------

EXTRACTORS: dict[str, Callable[[Path, ExtractContext], Path | None]] = {
    "bbcfg": extract_bbcfg,
    "sparse": extract_sparse,
    "ext4": extract_ext4,
    "erofs": extract_erofs,
    "fat": lambda p, c: extract_7z(p, c, "fat"),
    "fat_or_mbr": lambda p, c: extract_7z(p, c, "fat_or_mbr"),
    "squashfs": extract_squashfs,
    "gzip": extract_gzip,
    "xz": extract_xz,
    "zstd": extract_zstd,
    "lz4": extract_lz4,
    "zip": extract_zip,
    "7z": lambda p, c: extract_7z(p, c, "7z"),
    "tar": extract_tar,
    "super": extract_super,
    "payload": extract_payload,
    "f2fs": extract_f2fs,
    "ubi": extract_ubi,
}


def unwrap(path: Path, ctx: ExtractContext, depth: int = 0) -> None:
    """Recursively unwrap ``path`` and register extracted file-tree roots.

    Every produced directory is appended to ``ctx.outputs``; scanning happens
    afterwards so that the same logic can be used by the GUI without copying
    files to a destination directory.
    """
    if depth > MAX_RECURSION_DEPTH:
        logger.warning("Max recursion depth reached at %s", path)
        return
    if not path.exists() or path.stat().st_size < MIN_CONTAINER_SIZE:
        return

    tag = detect(path)
    logger.info("detect: %s -> %s", path, tag)

    if tag in ("empty", "unknown", "bootimg"):
        # For unrecognized top-level images, scan for known containers that are
        # hidden behind OEM wrappers (e.g. Motorola ``SINGLE_N_LONELY`` packages
        # where the real sparse image starts several KB into the file).
        if tag == "unknown" and depth == 0:
            _unwrap_embedded_containers(path, ctx, depth)
        return

    extractor = EXTRACTORS.get(tag)
    if extractor is None:
        logger.debug("No extractor for tag %s", tag)
        return

    produced = extractor(path, ctx)
    if produced is None:
        return

    if produced.is_dir():
        ctx.outputs.append(produced)
        for child in produced.rglob("*"):
            if child.is_file():
                _maybe_unwrap_child(child, ctx, depth + 1)
    else:
        unwrap(produced, ctx, depth + 1)


def _maybe_unwrap_child(path: Path, ctx: ExtractContext, depth: int) -> None:
    """Only recurse into children whose magic clearly identifies a container."""
    tag = detect(path)
    if tag in EXTRACTORS:
        unwrap(path, ctx, depth)


def _unwrap_embedded_containers(path: Path, ctx: ExtractContext, depth: int) -> None:
    """Look for known containers embedded at arbitrary offsets inside ``path``.

    OEM update packages sometimes prepend a header/table before the actual
    sparse, ext4, or archive payload.  We scan for a small set of reliable
    signatures and slice each match out into its own temporary file so the
    normal recursive pipeline can process it.
    """
    logger.info("scanning %s for embedded containers", path)

    # Android sparse images are the most common wrapped payload in Qualcomm
    # modem firmware (radio.img/non-hlos.bin style packages).
    for offset in _sparse_headers(path):
        logger.info("found sparse image at offset %d in %s", offset, path)
        sliced = _new_workdir(ctx, "sliced") / (path.stem + ".sparse")
        _slice_file(path, sliced, offset)
        unwrap(sliced, ctx, depth + 1)


# ---------------------------------------------------------------------------
# Public API for the analyzer
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Paths discovered inside an extracted container."""

    mbns: list[Path]
    sidecars: list[Path]
    scratch_dir: Path


def is_rfcard_name(name: str) -> bool:
    return bool(RFCARD_PATTERN.match(name) or LEGACY_RFCARD_PATTERN.match(name))


def is_rfcard_path(path: Path) -> bool:
    """Identify modern cards and legacy cards in known RF-card directories."""
    if RFCARD_PATTERN.match(path.name):
        return True
    if not LEGACY_RFCARD_PATTERN.match(path.name):
        return False
    return any(
        part.casefold() in {"so", "rfcards"}
        for part in path.parent.parts
    )


def is_sidecar_name(name: str) -> bool:
    return any(pattern.match(name) for pattern in SIDECAR_PATTERNS)


def discover_candidates(root: Path) -> tuple[list[Path], list[Path]]:
    """Walk ``root`` and return all MBN and sidecar paths."""
    mbns: list[Path] = []
    sidecars: list[Path] = []
    if root.is_file():
        candidates = [root]
    elif root.is_dir():
        candidates = list(root.rglob("*"))
    else:
        candidates = []
    for path in candidates:
        if not path.is_file():
            continue
        name = path.name
        if is_rfcard_path(path):
            mbns.append(path)
        elif is_sidecar_name(name):
            sidecars.append(path)
    return mbns, sidecars


def sidecars_in_directory(directory: Path, sidecars: list[Path]) -> dict[str, str]:
    return {path.name: str(path) for path in sidecars if path.parent == directory}


def scan_container(path: Path) -> ScanResult:
    """Recursively unwrap ``path`` and return discovered candidates.

    The returned ``ScanResult.scratch_dir`` contains all extracted content and
    must remain valid while the caller still needs to read the files.  Callers
    can safely leave cleanup to the operating system; this module does not
    delete scratch directories automatically so that GUI exports/comparisons
    continue to work after the scan finishes.
    """
    if not path.is_file():
        raise ExtractionError(f"Not a file: {path}")
    if path.stat().st_size < MIN_CONTAINER_SIZE:
        raise ExtractionError(f"File too small to be a container: {path}")

    scratch = Path(tempfile.mkdtemp(prefix="rfcards_gui_"))
    logger.info("Extraction scratch directory: %s", scratch)

    ctx = ExtractContext(workdir=scratch, tools=ToolStatus())
    unwrap(path, ctx)
    ctx.tools.report()

    all_mbns: list[Path] = []
    all_sidecars: list[Path] = []
    for output in ctx.outputs:
        mbns, sidecars = discover_candidates(output)
        all_mbns.extend(mbns)
        all_sidecars.extend(sidecars)

    return ScanResult(mbns=all_mbns, sidecars=all_sidecars, scratch_dir=scratch)


__all__ = [
    "ExtractionError",
    "ExtractContext",
    "ScanResult",
    "ToolStatus",
    "detect",
    "discover_candidates",
    "extract_7z",
    "extract_bbcfg",
    "extract_erofs",
    "extract_ext4",
    "extract_gzip",
    "extract_payload",
    "extract_squashfs",
    "extract_sparse",
    "extract_super",
    "extract_tar",
    "extract_ubi",
    "extract_xz",
    "extract_zip",
    "extract_zstd",
    "is_rfcard_name",
    "is_rfcard_path",
    "is_sidecar_name",
    "scan_container",
    "sidecars_in_directory",
    "unwrap",
]
