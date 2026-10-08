// Detect-table invariants: fixed order, same magic
// offsets/bytes, same tag strings. Unsupported-container descriptors carry the
// tool the Python extractor would have invoked (or null for the hard-rejected
// F2FS/UBI branches).
import { test } from "node:test";
import assert from "node:assert/strict";
import { detect, UNSUPPORTED_TAGS, SUPPORTED_TAGS } from "../js/lib/formats.js";

test("magic detect table (plan verbatim cases)", () => {
  assert.equal(detect(new Uint8Array([0x3a, 0xff, 0x26, 0xed, 1, 0, 0, 0])), "sparse");
  assert.equal(detect(new Uint8Array([0, 0x47, 0x46, 0x43, 0, 0, 0, 0])), "bbcfg"); // \x00GFC
  assert.equal(detect(new Uint8Array(512).fill(0)), "unknown");
});

test("unknown magics fall through the whole table", () => {
  // CPRK is not a known container magic: the detect table has no branch for
  // it, so it must reach "unknown".
  assert.equal(detect(new Uint8Array([0x43, 0x50, 0x52, 0x4b])), "unknown");
  assert.equal(detect(new Uint8Array(0)), "empty");
});

test("name-based detection: .bbfw/.ipsw are zips before any magic check", () => {
  assert.equal(detect(new Uint8Array(64).fill(0x41), "baseband.bbfw"), "zip");
  assert.equal(detect(new Uint8Array(64).fill(0x41), "fw.ipsw"), "zip");
  assert.equal(detect(new Uint8Array(64).fill(0x41), "fw.bbfw.orig"), "unknown");
});

test("ordering pins: payload/bootimg/super precede gzip; bbcfg precedes zip", () => {
  assert.equal(detect(new Uint8Array([0x43, 0x72, 0x41, 0x55])), "payload"); // CrAU
  assert.equal(detect(new Uint8Array([0x41, 0x4e, 0x44, 0x52, 0x4f, 0x49, 0x44, 0x21])), "bootimg");
  const superHead = new Uint8Array(0x1010);
  superHead.set([0x67, 0x73, 0x6c, 0x61], 0x1000); // gsla at 0x1000
  assert.equal(detect(superHead), "super");
  assert.equal(detect(new Uint8Array([0x1f, 0x8b, 0, 0])), "gzip");
  assert.equal(detect(new Uint8Array([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])), "xz");
  assert.equal(detect(new Uint8Array([0x28, 0xb5, 0x2f, 0xfd])), "zstd");
  assert.equal(detect(new Uint8Array([0x04, 0x22, 0x4d, 0x18])), "lz4");
  const bbcfgHead = new Uint8Array(64);
  bbcfgHead.set([0x42, 0x42, 0x43, 0x46, 0x47, 0x4d, 0x42, 0x4e], 8); // BBCFGMBN in first 64
  assert.equal(detect(bbcfgHead), "bbcfg");
  assert.equal(detect(new Uint8Array([0x50, 0x4b, 0x03, 0x04])), "zip");
  assert.equal(detect(new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])), "7z");
  assert.equal(detect(new Uint8Array([0x68, 0x73, 0x71, 0x73])), "squashfs"); // hsqs
  assert.equal(detect(new Uint8Array([0x73, 0x71, 0x73, 0x68])), "squashfs"); // sqsh
  const tarHead = new Uint8Array(600);
  tarHead.set([0x75, 0x73, 0x74, 0x61, 0x72], 257); // ustar at 257
  assert.equal(detect(tarHead), "tar");
  const ext4Head = new Uint8Array(0x500);
  ext4Head[0x438] = 0x53;
  ext4Head[0x439] = 0xef;
  assert.equal(detect(ext4Head), "ext4");
  const erofsHead = new Uint8Array(0x500);
  erofsHead.set([0xe2, 0xe1, 0xf5, 0xe0], 0x400);
  assert.equal(detect(erofsHead), "erofs");
  const f2fsHead = new Uint8Array(0x500);
  f2fsHead.set([0x10, 0x20, 0xf5, 0xf2], 0x400);
  assert.equal(detect(f2fsHead), "f2fs");
  assert.equal(detect(new Uint8Array([0x55, 0x42, 0x49, 0x23])), "ubi"); // UBI#
  const fatHead = new Uint8Array(64);
  fatHead.set([0x4d, 0x53, 0x44, 0x4f, 0x53, 0x35, 0x2e, 0x30], 3); // MSDOS5.0
  assert.equal(detect(fatHead), "fat");
  const mbrHead = new Uint8Array(512);
  mbrHead[510] = 0x55;
  mbrHead[511] = 0xaa;
  assert.equal(detect(mbrHead), "fat_or_mbr");
});

test("FAT OEM names accepted (image_extractor.py:272-280)", () => {
  for (const oem of ["MSDOS5.0", "MSWIN4.1", "mkfs.fat", "MSDOS"]) {
    const head = new Uint8Array(64);
    for (let i = 0; i < 8; i++) head[3 + i] = oem.charCodeAt(i);
    assert.equal(detect(head), "fat", oem);
  }
  // rstrip(b"\x00 ") semantics: NUL/space padding is trimmed before comparing,
  // so the literal b"FAT     " set entry is unreachable in Python ("FAT" does
  // not equal "FAT     ") and must stay unreachable here.
  const fatPadded = new Uint8Array(64);
  fatPadded.set([0x46, 0x41, 0x54, 0x20, 0x20, 0x20, 0x20, 0x20], 3); // "FAT     "
  assert.equal(detect(fatPadded), "unknown");
  // rstrip(b"\x00 ") semantics: NUL/space padding is trimmed before comparing.
  const head = new Uint8Array(64);
  head.set([0x4d, 0x53, 0x44, 0x4f, 0x53, 0, 0, 0], 3); // "MSDOS\0\0\0"
  assert.equal(detect(head), "fat");
});

test("unsupported containers name the tool the Python extractor would call", () => {
  assert.equal(UNSUPPORTED_TAGS.payload.tool, "payload-dumper-go");
  assert.equal(UNSUPPORTED_TAGS.super.tool, "lpunpack");
  assert.equal(UNSUPPORTED_TAGS.erofs.tool, "fsck.erofs");
  assert.equal(UNSUPPORTED_TAGS.squashfs.tool, "unsquashfs");
  assert.equal(UNSUPPORTED_TAGS["7z"].tool, "7z");
  assert.equal(UNSUPPORTED_TAGS.xz.tool, "xz");
  assert.equal(UNSUPPORTED_TAGS.zstd.tool, "zstd");
  assert.equal(UNSUPPORTED_TAGS.f2fs.tool, null);
  assert.equal(UNSUPPORTED_TAGS.ubi.tool, null);
  // ext4 is handled in-house (radio.img's sparse payload is an ext4 filesystem).
  assert.equal(UNSUPPORTED_TAGS.ext4, undefined);
});

test("corpus-relevant containers are supported in-house", () => {
  for (const tag of ["sparse", "gzip", "lz4", "zip", "tar", "fat", "fat_or_mbr", "bbcfg", "ext4"]) {
    assert.ok(SUPPORTED_TAGS.has(tag), `${tag} must be supported`);
  }
  for (const tag of Object.keys(UNSUPPORTED_TAGS)) {
    assert.ok(!SUPPORTED_TAGS.has(tag), `${tag} must not claim support`);
  }
});
