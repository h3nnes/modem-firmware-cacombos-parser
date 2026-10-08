// Apple BBCFG/MAVZ layer. Synthetic fixtures only - the corpus contains
// no iPhone records (every corpus generation is 'Legacy ELF'/'DAT/protobuf'
// from Android containers). Differential-checked against CPython during
// development: iter_rfcards on the synthetic bbcfg reproduces the same card
// list CPython does, through the same MAVZ fallback path.
import { test } from "node:test";
import assert from "node:assert/strict";
import { zlibSync, strToU8 } from "../lib/vendor/fflate.js";
import {
  decompressMavz,
  iterRfcards,
  extractBbcfgTree,
  extractEfsPathnames,
  isBbcfg,
  containerInfo,
} from "../js/lib/iphone.js";
import { VDir, VFile } from "../js/lib/extractor.js";
import { sha256Hex } from "../js/lib/hash.js";

function u32(n) {
  return Uint8Array.of(n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255);
}

function mavz(payload) {
  const z = zlibSync(payload);
  const out = new Uint8Array(8 + z.length);
  out.set([0x4d, 0x41, 0x56, 0x5a]); // MAVZ
  out.set(u32(payload.length), 4);
  out.set(z, 8);
  return out;
}

function bbcfgContainer(body) {
  // +0x28 "BBCFGMBN0", BER records follow the marker (RECORDS_START=0x28 makes
  // the Python walker treat the marker itself as a leading garbage TLV).
  const out = new Uint8Array(0x31 + body.length);
  out.set([0x00, 0x47, 0x46, 0x43], 0); // \x00GFC
  new DataView(out.buffer).setUint32(4, 3, true); // version
  new DataView(out.buffer).setUint32(0x14, out.length - 40, true);
  out.set([0x42, 0x42, 0x43, 0x46, 0x47, 0x4d, 0x42, 0x4e, 0x30], 0x28); // BBCFGMBN0
  out.set(body, 0x31);
  return out;
}

// The addFile callback extractor.js hands to the iphone layer.
const addFile = (dir, path, data, size, kind) => {
  const name = path.split("/").pop();
  dir.addFile(path, kind === "text" ? VFile.text(name, data) : VFile.mem(name, data));
};

// BER records for the EFS scan: raw tag bytes 9f8374/9f8376 + short-form length.
function berRecord(tag, bytes) {
  const out = new Uint8Array(tag.length + 1 + bytes.length);
  out.set(tag);
  out[tag.length] = bytes.length;
  out.set(bytes, tag.length + 1);
  return out;
}
const EFS_PATH = [0x9f, 0x83, 0x74];
const EFS_VALUE = [0x9f, 0x83, 0x76];

test("MAVZ decompress: declared size enforced, compressed length accounting", () => {
  const payload = strToU8("/rfc/1426_7_res.dat");
  const blob = mavz(payload);
  const { raw, compressedLen } = decompressMavz(blob, 0);
  assert.deepEqual(raw, payload);
  // len(blob) - offset - 8 - unused(0): exactly the zlib stream length
  assert.equal(compressedLen, blob.length - 8);
  // trailing garbage lands in unused_data and is excluded
  const padded = new Uint8Array(blob.length + 7);
  padded.set(blob);
  padded.set([1, 2, 3, 4, 5, 6, 7], blob.length);
  assert.equal(decompressMavz(padded, 0).compressedLen, blob.length - 8);
  // declared-size mismatch raises like IPhoneRFError
  const bad = mavz(payload);
  new DataView(bad.buffer).setUint32(4, payload.length + 1, true);
  assert.throws(() => decompressMavz(bad, 0), /declared/);
});

test("iterRfcards classifies MAVZ payloads and skips non-cards", () => {
  const resBytes = strToU8("xx/res/placeholder\x00/rfc/1426_7_res.dat\x00/rfc/1426_7_cmn.dat\x00");
  const junk = strToU8("not a card at all");
  const name1 = strToU8("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); // 40 hex chars
  const name2 = strToU8("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  const card = mavz(resBytes);
  const junkMavz = mavz(junk);
  // body: [40-hex name][gap][MAVZ card][gap][non-MAVZ bytes][40-hex name][MAVZ junk]
  const body = new Uint8Array(name1.length + 8 + card.length + 4 + junk.length + name2.length + junkMavz.length);
  let off = 0;
  for (const part of [name1, new Uint8Array(8), card, new Uint8Array(4), junk, name2, junkMavz]) {
    body.set(part, off);
    off += part.length;
  }
  const blob = bbcfgContainer(body);
  assert.ok(isBbcfg(blob));
  const info = containerInfo(blob);
  assert.equal(info.version, 3);
  assert.equal(info.payload_size, blob.length - 40); // declared = size - 40 (as built)

  const cards = [...iterRfcards(blob)];
  assert.equal(cards.length, 1);
  const c = cards[0];
  assert.equal(c.ordinal, 0);
  assert.equal(c.hwid, 1426);
  assert.equal(c.fset, 7);
  assert.equal(c.filename, "rf_config_1426_7_0.mbn");
  assert.equal(c.generation, "DAT/protobuf");
  assert.equal(c.resDat, "/rfc/1426_7_res.dat");
  assert.equal(c.cmnDat, "/rfc/1426_7_cmn.dat");
  // leftmost 40-hex match in the window: "BBCFGMBN0"'s trailing 0 merges with
  // the name run - verified byte-identical against CPython re.findall.
  assert.equal(c.contentName, "0" + "a".repeat(39));
  assert.equal(c.rawSize, resBytes.length);
});

test("extractBbcfgTree writes cards and rfcard_info_all sidecars into rfcards/", async () => {
  const resBytes = strToU8("junk\x00/rfc/99_1_res.dat");
  const card = mavz(resBytes);
  const body = new Uint8Array(40 + 4 + card.length);
  body.set(strToU8("1".repeat(40)), 0);
  body.set(card, 44);
  const blob = bbcfgContainer(body);
  const dir = new VDir("bbcfg_0");
  const cards = await extractBbcfgTree(blob, dir, addFile);
  assert.equal(cards.length, 1);
  assert.deepEqual(cards[0].raw, resBytes);
  const rfcards = dir.dir("rfcards");
  assert.deepEqual([...rfcards.entries.keys()].sort(), ["rf_config_99_1_0.mbn", "rfcard_info_all.csv", "rfcard_info_all.json"]);
  assert.deepEqual(await rfcards.entries.get("rf_config_99_1_0.mbn").read(), resBytes);
  const json = JSON.parse(new TextDecoder().decode(await rfcards.entries.get("rfcard_info_all.json").read()));
  assert.equal(json.cards.length, 1);
  assert.equal(json.cards[0].filename, "rf_config_99_1_0.mbn");
  assert.ok(json.cards[0].bbcfg_offset.startsWith("0x"));
  // container_info hashes the whole blob
  assert.equal(json.container.sha256, sha256Hex(blob));
  const csv = new TextDecoder().decode(await rfcards.entries.get("rfcard_info_all.csv").read());
  assert.ok(csv.startsWith("ordinal,hwid,fset,synthetic_bid,"));
  assert.ok(csv.includes("rf_config_99_1_0.mbn"));
});

test("extractEfsPathnames writes EFS records and rejects traversal", async () => {
  const dir = new VDir("bbcfg_0");
  const path1 = berRecord(EFS_PATH, strToU8("/nv/edfp/config"));
  const value1 = berRecord(EFS_VALUE, Uint8Array.of(1, 2, 3));
  const evil = berRecord(EFS_PATH, strToU8("../../evil"));
  const value2 = berRecord(EFS_VALUE, Uint8Array.of(9));
  const blob = new Uint8Array(3 + path1.length + value1.length + evil.length + value2.length);
  let off = 0;
  for (const part of [strToU8("PAD"), path1, value1, evil, value2]) {
    blob.set(part, off);
    off += part.length;
  }
  const written = extractEfsPathnames(blob, dir, (target, path, data) => addFile(target, path, data));
  assert.equal(written, 1);
  const nv = dir.dir("nv");
  assert.ok(nv, "nv dir created");
  const target = nv.dir("edfp").entries.get("config");
  assert.ok(target, "config file written under nv/edfp");
  assert.deepEqual(await target.read(), Uint8Array.of(1, 2, 3));
  // the traversal attempt wrote nothing outside
  assert.deepEqual([...dir.entries.keys()], ["nv"]);
});
