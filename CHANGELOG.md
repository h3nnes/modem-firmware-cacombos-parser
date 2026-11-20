# Changelog

## 1.9.2 - 2026-11-20

- Recognize embedded FAT16 payloads inside Motorola `SINGLE_N_LONELY` radio
  packages. Newer packages (e.g. Signature 27) wrap a raw FAT16
  `NON-HLOS.bin` instead of the sparse image older `radio.img` files use, so
  the embedded-container scan now falls back to validated FAT boot sectors.

### Desktop

- Scan for an embedded FAT boot sector after the sparse scan finds nothing,
  and slice it into the normal FAT extraction pipeline.

### Webapp

- Add `scanForFat16` to the in-house FAT reader and use it when a top-level
  image is not a recognized container and contains no sparse payload.
- Verified against `motosignature27radio.img`: nine DAT/protobuf
  `rf_config_*_0170.mbn` cards under
  `fat/image/modem_pr/mcfg/configs/mcfg_ddr/rf/`, no warnings.
- Bump the reported parser version to 1.9.2.

## 1.9.1 - 2026-11-13

### Webapp

- Add native FBPK v1 container unwrapping (`webapp/js/lib/fbpk.js`). Pixel 11
  (kodiak / MediaTek MT6986D) `radio-*.img` files start with an FBPK header
  whose `modem` entry is an ext4 filesystem containing
  `images/<release>/md/modem-bundle.img.gz`; the MediaTek scanner now walks that
  chain and reports the card profiles instead of treating the file as unknown.
- Detect FBPK in the generic container table and expose its entries as
  zero-copy files. An FBPK entry that is an ext4 filesystem is forced through
  the ext4 reader, because its boot block also carries a tar-style manifest.
- Bump the reported parser version to 1.9.1.

## 1.9.0 - 2026-11-03

- Add MPSS.HI Magnus/SM6350 support for 24-byte descriptors and 150-byte
  inline LTE, NR-CA, and EN-DC combination records.
- Decode native 12-byte components from their correct technology, bandwidth,
  antenna, and band fields.
- Include named legacy LTE tables in JSON, CSV, 0xB0CD, and batch combo counts.
- Add UBI/UBIFS extraction through `ubi-reader`, with command-line fallback.
- Discover numeric legacy RFCard MBNs under `so` directories on both Windows
  and POSIX-style paths.
- Expand regression coverage for HI inline layouts, UBI detection, and legacy
  RFCard discovery.

### Webapp

- Port the Magnus inline-150 descriptor and native 12-byte component decoder
  to `webapp/js/lib/legacy_parser.js` (byte-exact against the desktop parser,
  including field order).
- Add a native browser UBI/UBIFS reader (`webapp/js/lib/ubi.js`): EC/VID
  headers, volume tables, image/volume grouping, the UBIFS index tree, and
  none/LZO1X/zlib data-node decompression. No external tools, no dependencies.
  zstd nodes and encrypted volumes are skipped with a warning.
- Unpack UBI images under `ubi/<image_seq>/<volume>/...`, matching the desktop
  tool's `out/<image_seq>/<volume>/...` layout.
- Count named legacy LTE-CA tables in the card-list combo counts, so a Magnus
  card's LTE count includes its `lteca` descriptor.
- Accept numeric legacy MBNs below `so` (and Apple's `rfcards`) with both
  path separator styles normalized.
- Register `ubi` as a supported container and add `.ubi` to the file picker.
- Bump the reported parser version to 1.9.0.

Webapp/desktop differences: the browser has no `ubi-reader` dependency
(implemented natively), and UBIFS zstd/encrypted content cannot be decoded, so
those files are skipped with a warning instead of failing the whole image.

