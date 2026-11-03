# Changelog

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

