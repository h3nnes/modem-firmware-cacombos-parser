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
