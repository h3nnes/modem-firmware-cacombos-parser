// JS API shape:
//   readVarint(u8, pos) -> { value, pos }
//   protobufFields(data) -> Map<fieldNumber, [wire, value][]>
//   protoBytes/protoUint/protoRepeatedUint(fields, number)
//   makeRrcView(payload) -> rrc field object (SimpleNamespace shape)
//   extractRfcDats(blob) -> [{ name, offset, data }] with Python dict
//     semantics: deduped by name, last data wins, first-appearance order
//   datPayloadCandidates(dat) -> [[encoding, payload]]
//   parseResDat(dat) -> { encoding, payload, rrc }
//   decodeNrProperty(raw) / decodeBandGroup(raw) -> plain field objects
//   nrSectionRecords(rrc, prefix, suffix) -> [[groups, prop]]
//   decodeLteCombo(raw) / decodeNrBandGroup(group, bw, ant) -> strings
//   parseModernModule(record, blob) -> { metadata, combinations, components, diag }
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { hex, hexToBytes } from "../js/lib/bytes.js";
import { zlibSync } from "../lib/vendor/fflate.js";
import { Fat16Image } from "../js/lib/fat16.js";
import { sourceFor } from "../js/lib/source.js";
import { CORPUS_DIR, corpusAvailable, deepEqualOrdered, containerBlobs } from "./helpers.mjs";
import { truncateParse } from "./golden_transform.mjs";
import {
  readVarint,
  protobufFields,
  protoBytes,
  protoUint,
  protoRepeatedUint,
  makeRrcView,
  extractRfcDats,
  datPayloadCandidates,
  parseResDat,
  decodeNrProperty,
  decodeBandGroup,
  decodeLteCombo,
  decodeNrBandGroup,
  enumAssignments,
  reverseEnum,
  parseModernModule,
  readRfcardInfo,
  b0cdV41Packets,
  b826V22Packets,
  b826V22Component,
  pyCasefold,
  pyNdInt,
} from "../js/lib/modern_parser.js";
import { sha256Hex } from "../js/lib/hash.js";
import { ToolError } from "../js/lib/legacy_parser.js";

const enc = new TextEncoder();
const bytes = (s) => enc.encode(s);

function concatBytes(arrs) {
  let n = 0;
  for (const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

// Large-EFS item framing consumed by extract_rfc_dats: TLV type 0x0001 +
// uint16 path length (including NUL), the NUL-terminated path, then TLV type
// 0x0002 + uint32 length + payload.
function framedItem(path, data) {
  const p = bytes(path);
  const out = new Uint8Array(4 + p.length + 1 + 6 + data.length);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, 1, true);
  dv.setUint16(2, p.length + 1, true);
  out.set(p, 4);
  out[4 + p.length] = 0;
  dv.setUint16(4 + p.length + 1, 2, true);
  dv.setUint32(4 + p.length + 3, data.length, true);
  out.set(data, 4 + p.length + 1 + 6);
  return out;
}

function namesOf(blob) {
  return extractRfcDats(blob).map((d) => d.name);
}

// Packs 12 bytes using the pinned NRBandGroup bit layout (see the layout
// test below for the bit-by-bit derivation).
function packBandGroup(v) {
  const out = new Uint8Array(12);
  const dv = new DataView(out.buffer);
  const u0 = (v.tech & 3) | (v.band & 0x1ff) << 2 | (v.dl_bw_class & 0x1f) << 11
    | (v.dl_bw_per_cc & 0x7f) << 16 | (v.ul_bw_class & 0x1f) << 23;
  const u1 = (v.ul_bw_per_cc & 0x7f) | (v.dl_max_antennas_index & 0x7f) << 7
    | (v.ul_max_antennas_index & 0x7f) << 14 | (v.max_scs & 7) << 21
    | (v.ul_qam_cap_index & 3) << 24 | (v.srs_tx_switch_type & 0xf) << 26
    | (v.tx_switch_impact_to_rx & 3) << 30;
  const u2 = (v.tx_switch_with_another_band & 3) | (v.srs_carrier_hop & 1) << 2
    | (v.srs_carrier_hop_src & 3) << 3 | (v.rx_limit & 1) << 5
    | (v.num_tx_meeting_combo_pc & 3) << 6 | (v.link_id & 3) << 8;
  dv.setUint32(0, u0 >>> 0, true);
  dv.setUint32(4, u1 >>> 0, true);
  dv.setUint32(8, u2 >>> 0, true);
  return out;
}

test("varint uses multiplication (no 32-bit shift overflow)", () => {
  assert.deepEqual(readVarint(hexToBytes("ffffffff0f"), 0), { value: 4294967295, pos: 5 });
  // 1 << 32 would wrap to 0 with a JS shift; must come out as 2**32.
  assert.deepEqual(readVarint(hexToBytes("8080808010"), 0), { value: 4294967296, pos: 5 });
});

test("varint round-trips Python-encoded values", () => {
  // Byte sequences produced by the Python reference encoder for
  // 2**28-1, 2**28, 2**32, 2**35, 2**56 and 2**62. Values above 2**53 come
  // back as exact BigInts (Python arbitrary-precision parity).
  const cases = [
    ["ffffff7f", 268435455],
    ["8080808001", 268435456],
    ["8080808010", 4294967296],
    ["808080808001", 34359738368],
    ["808080808080808001", 72057594037927936n],
    ["808080808080808040", 4611686018427387904n],
  ];
  for (const [h, expected] of cases) {
    assert.equal(readVarint(hexToBytes(h), 0).value, expected);
  }
  assert.deepEqual(readVarint(hexToBytes("01ac02"), 1), { value: 300, pos: 3 });
});

test("varint raises the Python truncation error", () => {
  assert.throws(() => readVarint(new Uint8Array([0x80]), 0), /Truncated protobuf varint/);
  // shift reaches 70 without a terminator: same ValueError in Python
  assert.throws(() => readVarint(new Uint8Array(10).fill(0x80), 0), /Truncated protobuf varint/);
});

test("NRBandGroup 12-byte layout is pinned (Python ctypes derivation)", () => {
  // Derived from the ctypes struct (Python: NRBandGroup(tech=1, band=66,
  // dl_bw_class=0x0a, dl_bw_per_cc=2, ul_bw_per_cc=1) -> 09510200 01000000
  // 00000000): unit0 = tech@0-1, band@2-10, dl_bw_class@11-15,
  // dl_bw_per_cc@16-22, ul_bw_class@23-27; ul_bw_per_cc overflows unit0 and
  // starts unit1 at bit 32 (the 33rd bit).
  const g = decodeBandGroup(hexToBytes("095102000100000000000000"));
  assert.equal(g.tech, 1);
  assert.equal(g.band, 66);
  assert.equal(g.dl_bw_class, 0x0a);
  assert.equal(g.dl_bw_per_cc, 2);
  assert.equal(g.ul_bw_class, 0);
  assert.equal(g.ul_bw_per_cc, 1);
  assert.equal(g.dl_max_antennas_index, 0);
  assert.equal(g.ul_max_antennas_index, 0);

  // Full decode pinned against Python-built fixtures.
  // NRBandGroup(tech=2, band=41, dl_bw_class=3, dl_bw_per_cc=21,
  //   ul_bw_class=2, ul_bw_per_cc=4, dl_max_antennas_index=3,
  //   ul_max_antennas_index=2, max_scs=5, ul_qam_cap_index=2,
  //   srs_tx_switch_type=9, tx_switch_impact_to_rx=3,
  //   tx_switch_with_another_band=2, srs_carrier_hop=1, srs_carrier_hop_src=3,
  //   rx_limit=1, num_tx_meeting_combo_pc=2, link_id=1)
  assert.deepEqual(decodeBandGroup(hexToBytes("a61815018481a0e6be010000")), {
    tech: 2, band: 41, dl_bw_class: 3, dl_bw_per_cc: 21, ul_bw_class: 2,
    ul_bw_per_cc: 4, dl_max_antennas_index: 3, ul_max_antennas_index: 2,
    max_scs: 5, ul_qam_cap_index: 2, srs_tx_switch_type: 9,
    tx_switch_impact_to_rx: 3, tx_switch_with_another_band: 2,
    srs_carrier_hop: 1, srs_carrier_hop_src: 3, rx_limit: 1,
    num_tx_meeting_combo_pc: 2, link_id: 1,
  });
  // Every field maxed: unit boundaries must not bleed (Python:
  // all fields (1<<w)-1 -> ffffff0f ffffffff ff030000).
  assert.deepEqual(decodeBandGroup(hexToBytes("ffffff0fffffffffff030000")), {
    tech: 3, band: 0x1ff, dl_bw_class: 0x1f, dl_bw_per_cc: 0x7f, ul_bw_class: 0x1f,
    ul_bw_per_cc: 0x7f, dl_max_antennas_index: 0x7f, ul_max_antennas_index: 0x7f,
    max_scs: 7, ul_qam_cap_index: 3, srs_tx_switch_type: 0xf,
    tx_switch_impact_to_rx: 3, tx_switch_with_another_band: 3,
    srs_carrier_hop: 1, srs_carrier_hop_src: 3, rx_limit: 1,
    num_tx_meeting_combo_pc: 3, link_id: 3,
  });
  assert.throws(() => decodeBandGroup(new Uint8Array(11)), /Short NRBandGroup/);
});

test("NRComboProperty bit-slice decode matches Python", () => {
  // Python decode_nr_property(bytes([0x69, 0xb2, 0x1f, 5, 0x34, 0x12, 0x78,
  // 0x56, 0xbc, 0x9a, 0xde, 0xf0]))
  assert.deepEqual(decodeNrProperty(hexToBytes("69b21f0534127856bc9adef0")), {
    power_class: 1, tdd_ant_swt_fdd_disruption: 1, simultaneousRxTxInterBandENDC: 0,
    simultaneousRxTxInterBandCA: 1, ul_tx_switch_type: 1, intra_contig_type: 2,
    srs_cs_type: 6, intra_ulca_dual_pa: 0, simultaneousRxTxInterBandSUL: 1,
    num_bands: 31, has_bcs5_counterpart: 0, higher_power_limit: 0, bcs_num: 5,
    env_mode_mask_idx: 4660, env_mode_subset_mask_idx: 22136,
    simul_rxtx_bmap_idx: 39612, simul_sul_rxtx_bmap_idx: 61662,
  });
  assert.throws(() => decodeNrProperty(new Uint8Array(11)), /Short NRComboProperty/);
});

test("/rfc/ byte scanner matches the Python regex battery", () => {
  // Ground truth for every case below was produced with the Python
  // extract_rfc_dats implementation.
  assert.deepEqual(
    namesOf(framedItem("/rfc/modem_rfscen_xoo_res.dat", bytes("DATA"))),
    ["/rfc/modem_rfscen_xoo_res.dat"],
  );
  // Two .dat paths sharing a prefix: greedy backtracking keeps both.
  assert.deepEqual(
    namesOf(concatBytes([framedItem("/rfc/x.dat", bytes("D1")), framedItem("/rfc/x.dat.dat", bytes("D2"))])),
    ["/rfc/x.dat", "/rfc/x.dat.dat"],
  );
  // Greedy match extends over an inner .dat: one full name, not two.
  assert.deepEqual(namesOf(framedItem("/rfc/a.dat.dat", bytes("D"))), ["/rfc/a.dat.dat"]);
  // The regex requires NUL termination: CR/LF ends the allowed run but can
  // never complete a match.
  assert.deepEqual(namesOf(framedItem("/rfc/a.dat\rjunk", bytes("D"))), []);
  assert.deepEqual(namesOf(framedItem("/rfc/a.dat\nmore.dat", bytes("D"))), []);
  // Allowed-run length limit: [^\x00\r\n]{1,240} + ".dat" = at most 244.
  assert.deepEqual(namesOf(framedItem("/rfc/" + "a".repeat(240) + ".dat", bytes("D"))),
    ["/rfc/" + "a".repeat(240) + ".dat"]);
  assert.deepEqual(namesOf(framedItem("/rfc/" + "a".repeat(241) + ".dat", bytes("D"))), []);
  // At least one char before ".dat" ({1,240} lower bound).
  assert.deepEqual(namesOf(framedItem("/rfc/.dat", bytes("D"))), []);
  // Missing NUL at EOF.
  const truncated = framedItem("/rfc/x.dat", bytes("D"));
  assert.deepEqual(namesOf(truncated.subarray(0, 10 + 1 + 6 + 1 - 1 + 0)), []);
  // IGNORECASE.
  assert.deepEqual(namesOf(framedItem("/RFC/MODEM_RES.DAT", bytes("D"))), ["/RFC/MODEM_RES.DAT"]);
  // Bytes outside \x00/\r/\n are allowed inside the run.
  assert.deepEqual(namesOf(framedItem("/rfc/a.dat\x01.dat", bytes("D"))), ["/rfc/a.dat\x01.dat"]);
});

test("/rfc/ scanner validates the Large-EFS TLV framing", () => {
  // match.start() < 4: no room for the TLV header.
  assert.deepEqual(namesOf(framedItem("/rfc/x.dat", bytes("D")).subarray(2)), []);
  // Wrong TLV type.
  const wrongType = framedItem("/rfc/x.dat", bytes("D"));
  new DataView(wrongType.buffer).setUint16(0, 0, true);
  assert.deepEqual(namesOf(wrongType), []);
  // Wrong path length.
  const wrongLen = framedItem("/rfc/x.dat", bytes("D"));
  new DataView(wrongLen.buffer).setUint16(2, 10, true);
  assert.deepEqual(namesOf(wrongLen), []);
  // Wrong data TLV type / overflowing data length.
  const wrongData = framedItem("/rfc/x.dat", bytes("D"));
  new DataView(wrongData.buffer).setUint16(4 + 9 + 1, 3, true);
  assert.deepEqual(namesOf(wrongData), []);
  const overLong = framedItem("/rfc/x.dat", bytes("D"));
  new DataView(overLong.buffer).setUint32(4 + 9 + 3, 99, true);
  assert.deepEqual(namesOf(overLong), []);
  // Python dict semantics: duplicate path -> last data wins, one entry.
  const dup = extractRfcDats(concatBytes([framedItem("/rfc/x.dat", bytes("AAA")), framedItem("/rfc/x.dat", bytes("BB"))]));
  assert.deepEqual(dup.map((d) => d.name), ["/rfc/x.dat"]);
  assert.equal(new TextDecoder().decode(dup[0].data), "BB");
});

test("zlib candidate loop finds streams at metadata offsets", () => {
  // Fixture generated with Python: 15 junk bytes, uint32 LE payload size,
  // zlib.compress(b"protobuf-ish bytes" * 10). The stream starts at offset 19,
  // so the accepting candidate is base 14 -> "14-byte-metadata+hash+size+zlib".
  const dat = hexToBytes(
    "111111111111111111111111111111b4000000"
    + "789c2b28ca2fc94f2a4dd3cd2cce5048aa2c492d2e18f422005d39479b",
  );
  const payload = bytes("protobuf-ish bytes".repeat(10));
  const cands = datPayloadCandidates(dat);
  assert.deepEqual(cands.map(([encoding]) => encoding), ["14-byte-metadata+hash+size+zlib", "raw"]);
  assert.deepEqual(cands[0][1], payload);
  assert.deepEqual(cands[1][1], dat);

  // Trailing bytes after the zlib stream are ignored, exactly like
  // zlib.decompress (the adler trailer is still verified at stream end).
  const withJunk = hexToBytes(
    "111111111111111111111111111111b4000000"
    + "789c2b28ca2fc94f2a4dd3cd2cce5048aa2c492d2e18f422005d39479b545241494c494e47",
  );
  const cands2 = datPayloadCandidates(withJunk);
  assert.deepEqual(cands2.map(([encoding]) => encoding), ["14-byte-metadata+hash+size+zlib", "raw"]);
  assert.deepEqual(cands2[0][1], payload);

  // size+raw fallback and raw fallback.
  const rawDat = hexToBytes("020000004142");
  const cands3 = datPayloadCandidates(rawDat);
  assert.deepEqual(cands3.map(([encoding]) => encoding), ["size+raw", "raw"]);
  assert.deepEqual(cands3[0][1], bytes("AB"));
  assert.deepEqual(cands3[1][1], rawDat);
  assert.deepEqual(datPayloadCandidates(hexToBytes("deadbeef")).map(([e]) => e), ["raw"]);
});

test("parseResDat decodes the first viable candidate", () => {
  const payload = bytes("\x3a\x04\x0a\x02te");
  const stream = zlibSync(payload);
  const dat = new Uint8Array(5 + 4 + stream.length);
  dat.fill(0x22, 0, 5);
  new DataView(dat.buffer).setUint32(5, payload.length, true);
  dat.set(stream, 9);
  const { encoding, payload: protobuf, rrc } = parseResDat(dat);
  assert.equal(encoding, "4-byte-metadata+hash+size+zlib");
  assert.deepEqual(protobuf, payload);
  assert.deepEqual([...rrc.NR_band_group_table_high], [0x74, 0x65]);
  assert.equal(rrc.nr5g_info_per_band_sub_cap_high_num, 0);
  assert.equal(rrc.env_name_high, "");

  assert.throws(() => parseResDat(hexToBytes("deadbeef")), /Cannot parse res DAT protobuf: /);
});

test("protobuf field walker matches Python", () => {
  const data = hexToBytes(
    "3a03089601" + "40ac02" + "3a0101" + "4a0496 01ac02".replace(/ /g, "")
    + "2d01020304" + "291111111111111111",
  );
  const fields = protobufFields(data);
  assert.deepEqual(
    fields.get(7).map(([w, v]) => [w, hex(v)]),
    [[2, "089601"], [2, "01"]],
  );
  assert.deepEqual(fields.get(8), [[0, 300]]);
  assert.deepEqual(fields.get(9).map(([w, v]) => [w, hex(v)]), [[2, "9601ac02"]]);
  assert.deepEqual(fields.get(5).map(([w, v]) => [w, hex(v)]), [[5, "01020304"], [1, "1111111111111111"]]);

  assert.deepEqual([...protoBytes(fields, 7)], [0x08, 0x96, 0x01, 0x01]);
  assert.equal(protoUint(fields, 8), 300);
  assert.deepEqual(protoRepeatedUint(fields, 9), [150, 300]);
  assert.equal(protoUint(fields, 99), 0);
  assert.deepEqual(protoBytes(fields, 99), new Uint8Array(0));
  assert.deepEqual(protoRepeatedUint(fields, 99), []);
  // Single length-delimited field: no copy, the stored view is returned as-is
  // (multi-field still concatenates in order).
  const single = new Map([[7, [[2, new Uint8Array([1, 2, 3])]]]]);
  const view = protoBytes(single, 7);
  assert.equal(view, single.get(7)[0][1]);
  assert.deepEqual([...protoBytes(fields, 9)], [0x96, 0x01, 0xac, 0x02]);

  assert.throws(() => protobufFields(new Uint8Array([0x00])), /Invalid protobuf field zero/);
  assert.throws(() => protobufFields(new Uint8Array([0x36])), /Unsupported protobuf wire type 6/);
  assert.throws(() => protobufFields(new Uint8Array([0x0a])), /Truncated protobuf varint/);
  assert.throws(() => protobufFields(new Uint8Array([0x39, 0x01, 0x02])), /Truncated protobuf fixed64/);
  assert.throws(() => protobufFields(new Uint8Array([0x2a, 0x05, 0x61, 0x62])), /Truncated protobuf length-delimited field/);
  assert.throws(() => protobufFields(new Uint8Array([0x08, 0x80])), /Truncated protobuf varint/);
});

test("makeRrcView requires the rrc field #7", () => {
  assert.throws(() => makeRrcView(new Uint8Array(0)), /res protobuf has no rrc field #7/);
  assert.throws(() => makeRrcView(new Uint8Array([0x08, 0x01])), /res protobuf has no rrc field #7/);
});

test("enum assignments and reverse lookup match Python", () => {
  const e = enumAssignments();
  assert.equal(Object.keys(e).length, 156);
  assert.equal(e.BW_5, 1);
  assert.equal(e.BW_100_100, 23);
  assert.equal(e.BW_DEFAULT, 0);
  assert.equal(e.ANTENNA_INVALID, 0);
  assert.equal(e.ANTENNA_1, 1);
  assert.equal(e.ANTENNA_2_1, 5);
  assert.equal(e.ANTENNA_4_2, 7);
  assert.equal(e.ANTENNA_8, 81);
  assert.equal(e.ANTENNA_6_6, 89);
  assert.equal(Object.keys(e).filter((k) => k.startsWith("ANTENNA_")).length, 90);

  const bw = reverseEnum(e, "BW_");
  assert.equal(bw.get(0), undefined); // BW_DEFAULT blacklisted
  assert.equal(bw.get(1), "5");
  assert.equal(bw.get(22), "100_60");
  const ant = reverseEnum(e, "ANTENNA_");
  assert.equal(ant.get(0), undefined); // ANTENNA_INVALID blacklisted
  assert.equal(ant.get(5), "2_1");
});

test("LTE combo decode matches Python", () => {
  // Python: bytearray(50) with <HBBBBB>(66,1,3,1,1,2)@2 and <HBBBBB>(12,1,2,0,0,0)@10
  assert.equal(
    decodeLteCombo(hexToBytes(
      "000042000103010102000c000102000000000000000000000000000000000000000000000000000000000000000000000000",
    )),
    "B66A[3];A[1]+B12A[2]",
  );
});

test("NR band group text decode matches Python", () => {
  const bw = reverseEnum(enumAssignments(), "BW_");
  const ant = reverseEnum(enumAssignments(), "ANTENNA_");
  assert.equal(
    decodeNrBandGroup(decodeBandGroup(packBandGroup({ tech: 2, band: 78, dl_bw_class: 10, dl_bw_per_cc: 21, dl_max_antennas_index: 2 })), bw, ant),
    "N78J[100x2]",
  );
  assert.equal(
    decodeNrBandGroup(decodeBandGroup(packBandGroup({ tech: 1, band: 3, dl_bw_class: 1, dl_bw_per_cc: 4, dl_max_antennas_index: 2, ul_bw_class: 2, ul_bw_per_cc: 21, ul_max_antennas_index: 1 })), bw, ant),
    "B3A[20x2];B[100x1]",
  );
  // Supplementary uplink: dl_bw_class 0 renders the N<band>_ syntax.
  assert.equal(
    decodeNrBandGroup(decodeBandGroup(packBandGroup({ tech: 2, band: 78, dl_bw_class: 0, dl_bw_per_cc: 21, dl_max_antennas_index: 2, ul_bw_class: 3, ul_bw_per_cc: 4, ul_max_antennas_index: 1 })), bw, ant),
    "N78_;C[20x1]",
  );
  // Multi-CC bandwidths pad missing antenna layers with the last value.
  assert.equal(
    decodeNrBandGroup(decodeBandGroup(packBandGroup({ tech: 2, band: 41, dl_bw_class: 5, dl_bw_per_cc: 24, dl_max_antennas_index: 5 })), bw, ant),
    "N41E[100x2,100x1,100x1]",
  );
});

// --- golden (corpus-gated): differential parity for "DAT/protobuf" records ---

test("modern DAT/protobuf records match Python goldens", { skip: !corpusAvailable() }, async () => {
  const corpus = JSON.parse(await readFile(new URL("../goldens/corpus.json", import.meta.url)));
  let checked = 0;
  for (const [img, recs] of Object.entries(corpus)) {
    const resolvable = recs.filter((r) => r.generation === "DAT/protobuf");
    if (resolvable.length === 0) continue;
    const src = await sourceFor(join(CORPUS_DIR, img));
    try {
      // container images (sparse/... and fat/... inner paths) resolve through
      // the Task 9 extraction layer keyed by the normalized inner_path
      const byPath = recs.some((r) => !r.inner_path.startsWith("/"))
        ? await containerBlobs(src, img)
        : await (async () => {
            const fat = new Fat16Image(src);
            await fat.init();
            const map = new Map();
            for (const entry of await fat.walk()) {
              map.set(entry.path, { read: () => fat.readFile(entry) });
            }
            return map;
          })();
      const imgTag = img.replace(/\.[^.]+$/, "").slice(0, 40).replaceAll(" ", "_");
      for (const rec of resolvable) {
        const vfile = byPath.get(rec.inner_path);
        assert.ok(vfile, `${img}: missing ${rec.inner_path}`);
        const blob = await vfile.read();
        const parsed = parseModernModule({ name: rec.name, inner_path: rec.inner_path }, blob);
        const goldenPath = `../goldens/parse/${imgTag}__${rec.name.replaceAll("/", "_")}.json`;
        const expected = JSON.parse(await readFile(new URL(goldenPath, import.meta.url)));
        deepEqualOrdered(truncateParse(parsed), expected, `${img}/${rec.name}`);
        checked++;
      }
    } finally {
      await src.close();
    }
  }
  assert.equal(checked, 336);
});

// --- F1: exact varint arithmetic past 2**53 (Python arbitrary-precision int) ---

// Minimal protobuf varint encoder.
function encVarint(n) {
  n = BigInt(n);
  const out = [];
  for (;;) {
    const group = Number(n & 0x7fn);
    n >>= 7n;
    if (n) out.push(group | 0x80);
    else { out.push(group); break; }
  }
  return Uint8Array.of(...out);
}

test("readVarint is exact past 2**53 (Python arbitrary-precision parity)", () => {
  // Ground truth from Python read_varint: every value below decodes exactly.
  // 2**53+1 would round to 2**53 in a double accumulator.
  const twoPow53Plus1 = readVarint(hexToBytes("8180808080808010"), 0);
  assert.equal(typeof twoPow53Plus1.value, "bigint");
  assert.equal(twoPow53Plus1.value, 9007199254740993n);
  assert.equal(twoPow53Plus1.pos, 8);
  // 2**63-1 (Python 9223372036854775807; a double gives ...776000).
  assert.equal(readVarint(hexToBytes("ffffffffffffffff7f"), 0).value, 9223372036854775807n);
  // 127 * 2**56, the exact value of the reviewer's 80808080808080807f payload.
  assert.equal(readVarint(hexToBytes("80808080808080807f"), 0).value, 9151314442816847872n);
  // A full 10-byte varint: 2**70-1, exact.
  assert.equal(readVarint(hexToBytes("ffffffffffffffffff7f"), 0).value, 1180591620717411303423n);

  // Values within the safe range stay plain Numbers (2**49-1, the largest
  // value the double fast path can produce, and the 2**53 boundary itself).
  const maxFast = readVarint(hexToBytes("ffffffffffff7f"), 0);
  assert.equal(typeof maxFast.value, "number");
  assert.equal(maxFast.value, 562949953421311);
  assert.equal(readVarint(encVarint(9007199254740991n), 0).value, 9007199254740991);
  assert.equal(readVarint(encVarint(9007199254740992n), 0).value, 9007199254740992n);
});

test("protobufFields derives field number and wire type from the exact key", () => {
  // Key 2**53+7: exact key % 8 == 7 -> Python raises
  // "Unsupported protobuf wire type 7". A rounded key (2**53) has wire 0 and
  // would keep parsing (previously: a bogus truncation error instead).
  assert.throws(
    () => protobufFields(hexToBytes("8780808080808010")),
    /Unsupported protobuf wire type 7/,
  );
  // The reviewer's fuzz payload: 10-byte key with wire type 7.
  assert.throws(
    () => protobufFields(hexToBytes("87808080808080808002003a07ca04044556494c")),
    /Unsupported protobuf wire type 7/,
  );
  // Key 2**53+5 -> wire 5, field number (2**53+5)>>3 == 2**50 (exact Number).
  const fixed32 = protobufFields(concatBytes([encVarint((1n << 53n) + 5n), Uint8Array.of(1, 2, 3, 4)]));
  assert.deepEqual(fixed32.get(2 ** 50), [[5, Uint8Array.of(1, 2, 3, 4)]]);

  // Field numbers above 2**53 stay exact BigInt map keys:
  // key 2**56+2 -> wire 2, number (2**56+2)>>3 == 2**53.
  const big = protobufFields(concatBytes([hexToBytes("828080808080808001"), Uint8Array.of(0)]));
  assert.ok(big.has(9007199254740992n));
  assert.deepEqual([...big.get(9007199254740992n)].map(([w]) => w), [2]);
  // Small keys keep Number map keys, and field zero is still rejected.
  assert.throws(() => protobufFields(new Uint8Array([0x00])), /Invalid protobuf field zero/);
});

test("protoUint/protoRepeatedUint return exact values past 2**53", () => {
  const exact = protobufFields(concatBytes([encVarint(8), encVarint((1n << 53n) + 1n)]));
  assert.equal(protoUint(exact, 1), 9007199254740993n);
  const huge = protobufFields(concatBytes([encVarint(8), hexToBytes("ffffffffffffffff7f")]));
  assert.deepEqual(protoRepeatedUint(huge, 1), [9223372036854775807n]);
  // In-range values remain Numbers.
  const small = protobufFields(concatBytes([encVarint(8), encVarint(300n)]));
  assert.equal(typeof protoUint(small, 1), "number");
  assert.equal(protoUint(small, 1), 300);
});

// --- F2/F3/F4: Unicode parity helpers exercised through readRfcardInfo ---

const emptyRrc = { env_name_high: "", env_name_low: "" };

test("readRfcardInfo strips Python whitespace, keeping U+FEFF", () => {
  // Python str.strip() set: NBSP and C0 1C-1F / U+0085 are stripped...
  const nbsp = readRfcardInfo("/rfc/1_2_res.dat", "y.mbn", { env_name_high: "\u00a0NB\u00a0", env_name_low: "" });
  assert.equal(nbsp.environment_name_high, "NB");
  assert.equal(nbsp.name, "NB");
  // ...and a lone NBSP strips to "" which flips name_source to derived.
  const lone = readRfcardInfo("/rfc/1_2_res.dat", "y.mbn", { env_name_high: "\u00a0", env_name_low: "" });
  assert.equal(lone.environment_name_high, null);
  assert.equal(lone.name, "RFCARD_HWID1_FSID2");
  assert.equal(lone.name_source, "derived_from_hwid_fsid");
  const c0 = readRfcardInfo("/rfc/1_2_res.dat", "y.mbn", { env_name_high: "\x1cNB\x1d", env_name_low: "" });
  assert.equal(c0.environment_name_high, "NB");
  const nel = readRfcardInfo("/rfc/1_2_res.dat", "y.mbn", { env_name_high: "\u0085NB\u0085", env_name_low: "" });
  assert.equal(nel.environment_name_high, "NB");
  // Python keeps U+FEFF (JS \s would strip it).
  const bom = readRfcardInfo("/rfc/1_2_res.dat", "y.mbn", { env_name_high: "\ufeffX\ufeff", env_name_low: "" });
  assert.equal(bom.environment_name_high, "\ufeffX\ufeff");
  assert.equal(bom.name, "\ufeffX\ufeff");
  // ASCII whitespace still strips.
  const ascii = readRfcardInfo("/rfc/1_2_res.dat", "y.mbn", { env_name_high: "  NB\t", env_name_low: "" });
  assert.equal(ascii.environment_name_high, "NB");
});

test("readRfcardInfo matches Python \\d (Unicode Nd) and int() semantics", () => {
  // Python \d matches Nd and int() evaluates Arabic-Indic digits as 123/45.
  const ar = readRfcardInfo("/rfc/١٢٣_٤٥_res.dat", "x.mbn", emptyRrc);
  assert.equal(ar.hwid, 123);
  assert.equal(ar.fsid, 45);
  assert.equal(ar.key, "123_45");
  assert.equal(ar.name, "RFCARD_HWID123_FSID45");
  const mbn = readRfcardInfo("/rfc/x.dat", "rf_config_١٢٣_٤٥_٦٧٨.mbn", emptyRrc);
  assert.equal(mbn.hwid, 123);
  assert.equal(mbn.fsid, 45);
  assert.equal(mbn.bid, 678);
  const mixed = readRfcardInfo("/rfc/x.dat", "rf_config_1_٢_3.mbn", emptyRrc);
  assert.deepEqual([mixed.hwid, mixed.fsid, mixed.bid], [1, 2, 3]);
  // Superscript two is No, not Nd: Python \\d does not match it.
  const sup = readRfcardInfo("/rfc/²_3_res.dat", "x.mbn", emptyRrc);
  assert.equal(sup.hwid, null);
  assert.equal(sup.fsid, null);
});

test("readRfcardInfo replicates Python re.IGNORECASE folding", () => {
  // Python re.I simple-folds U+017F (long s) onto "s".
  const longS = readRfcardInfo("/rfc/1_2_reſ.dat", "x.mbn", emptyRrc);
  assert.equal(longS.hwid, 1);
  assert.equal(longS.fsid, 2);
  // U+0130/U+0131 fold onto "i" for the rf_config_ literal.
  for (const name of ["rf_confİg_1_2_3.mbn", "rf_confıg_1_2_3.mbn"]) {
    const m = readRfcardInfo("/rfc/x.dat", name, emptyRrc);
    assert.deepEqual([m.hwid, m.fsid, m.bid], [1, 2, 3], name);
  }
  // Negatives: ligatures do not fold under re.I, and long s is not "r".
  for (const name of ["rf_conﬁg_1_2_3.mbn", "rf_conﬂg_1_2_3.mbn"]) {
    assert.equal(readRfcardInfo("/rfc/x.dat", name, emptyRrc).bid, null, name);
  }
  assert.equal(readRfcardInfo("/rfc/1_2_ſes.dat", "x.mbn", emptyRrc).hwid, null);
  // ASCII case folding still works, and .mbn/.dat are case-insensitive.
  const upper = readRfcardInfo("/rfc/1_2_RES.DAT", "rf_config_1_2_3.MBN", emptyRrc);
  assert.equal(upper.bid, 3);
});

test("extractRfcDats compares the TLV path length in bytes", () => {
  // "/rfc/café.dat" is 13 UTF-16 units but 14 UTF-8 bytes (15 with the NUL).
  // Python validates len(path_with_nul) == 15, so the byte framing accepts...
  const found = extractRfcDats(framedItem("/rfc/café.dat", bytes("ZZ")));
  assert.deepEqual(found.map((d) => d.name), ["/rfc/café.dat"]);
  assert.deepEqual([...found[0].data], [0x5a, 0x5a]);
  // ...and a UTF-16-unit length (14) must be rejected. (A name.length + 1
  // comparison would wrongly accept this framing.)
  const p = bytes("/rfc/café.dat");
  const short = new Uint8Array(4 + p.length + 1 + 6 + 2);
  const dv = new DataView(short.buffer);
  dv.setUint16(0, 1, true);
  dv.setUint16(2, 14, true); // wrong: UTF-16 units + NUL, not byte length
  short.set(p, 4);
  short[4 + p.length] = 0;
  dv.setUint16(4 + p.length + 1, 2, true);
  dv.setUint32(4 + p.length + 3, 2, true);
  short.set(bytes("ZZ"), 4 + p.length + 1 + 6);
  assert.deepEqual(namesOf(short), []);
});

// --- F4d: Python casefold parity for the *_res.dat filter ---

test("pyCasefold matches Python str.casefold on probe chars", () => {
  // Python ground truth: "ſΣςﬁİẞß".casefold() == "sσσfii\u0307ssss".
  assert.equal(pyCasefold("\u017f\u03a3\u03c2\ufb01\u0130\u1e9e\u00df"), "s\u03c3\u03c3fii\u0307ssss");
  assert.equal(pyCasefold("X_RES.DAT"), "x_res.dat");
  assert.equal(pyCasefold("\u13a0"), "\u13a0"); // Cherokee upper keeps itself
  assert.ok(pyCasefold("x_reſ.dat").endsWith("_res.dat"));
  assert.ok(pyCasefold("x_ﬁ_res.dat").endsWith("_res.dat"));
  assert.ok(!pyCasefold("x_reẞ.dat").endsWith("_res.dat"));
});

test("pyCasefold/pyNdInt ASCII fast paths agree with the Unicode paths", () => {
  // ASCII: casefold == lower; the regex fast path must not skip the non-ASCII
  // cases above (they are covered by the test above).
  assert.equal(pyCasefold("ABC abc 123 !@#"), "abc abc 123 !@#");
  assert.equal(pyCasefold(""), "");
  // Nd digits: ASCII, a 15-digit exact double, a 16-digit value that must stay
  // a BigInt, and a non-ASCII Nd run through the table path.
  assert.equal(pyNdInt("42"), 42);
  assert.equal(pyNdInt("000015"), 15);
  assert.equal(pyNdInt("999999999999999"), 999999999999999);
  assert.equal(pyNdInt("9007199254740993"), 9007199254740993n);
  assert.equal(pyNdInt("\u0661\u0662\u0663"), 123); // Arabic-Indic ١٢٣
  assert.equal(pyNdInt("\u0660"), 0);
});

// Valid res DAT payload: field 7 (rrc) containing field 1 (two bytes "te").
function makeResDat() {
  const payload = bytes("\x3a\x04\x0a\x02te");
  const stream = zlibSync(payload);
  const dat = new Uint8Array(5 + 4 + stream.length);
  dat.fill(0x22, 0, 5);
  new DataView(dat.buffer).setUint32(5, payload.length, true);
  dat.set(stream, 9);
  return dat;
}

test("parseModernModule accepts res names only Python casefold() matches", () => {
  const record = { name: "rf_config_1_2_3.mbn", inner_path: "/rf_config_1_2_3.mbn" };
  // "ſ" casefolds to "s": Python name.casefold().endswith("_res.dat") accepts.
  const longS = parseModernModule(record, framedItem("/rfc/x_reſ.dat", makeResDat()));
  assert.equal(longS.metadata.res_dat_path, "/rfc/x_reſ.dat");
  // The "fi" ligature casefolds to "fi".
  const lig = parseModernModule(record, framedItem("/rfc/x_ﬁ_res.dat", makeResDat()));
  assert.equal(lig.metadata.res_dat_path, "/rfc/x_ﬁ_res.dat");
  // Without a casefold match the Python ToolError is raised.
  assert.throws(() => parseModernModule(record, framedItem("/rfc/x_reſ2.dat", makeResDat())), ToolError);
});

test("module_sha256 reuses record.sha256 when present, hashes only as fallback", () => {
  const blob = framedItem("/rfc/x_res.dat", makeResDat());
  const baseRecord = { name: "rf_config_1_2_3.mbn", inner_path: "/rf_config_1_2_3.mbn" };
  const withDigest = parseModernModule({ ...baseRecord, sha256: "aa".repeat(32) }, blob);
  assert.equal(withDigest.metadata.module_sha256, "aa".repeat(32));
  const without = parseModernModule({ ...baseRecord, sha256: undefined }, blob);
  assert.equal(without.metadata.module_sha256, sha256Hex(blob));
});

// --- F5: candidate-loop rejection on a corrupt adler32 trailer ---

test("datPayloadCandidates rejects zlib streams with a corrupt adler trailer", () => {
  const payload = bytes("protobuf-ish bytes".repeat(10));
  const stream = zlibSync(payload);
  const bad = stream.slice();
  bad[bad.length - 1] ^= 0xff; // Python: zlib.error "incorrect data check"
  const dat = concatBytes([new Uint8Array(15).fill(0x11), Uint8Array.of(...u32le(payload.length)), bad]);
  assert.deepEqual(datPayloadCandidates(dat).map(([e]) => e), ["raw"]);
  // Control: the intact stream is accepted at base 14.
  const good = concatBytes([new Uint8Array(15).fill(0x11), Uint8Array.of(...u32le(payload.length)), stream]);
  assert.deepEqual(datPayloadCandidates(good).map(([e]) => e), ["14-byte-metadata+hash+size+zlib", "raw"]);
});

function u32le(n) {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}

// --- F5: DIAG encoder fixtures pinned against Python ---

// 50-byte LTE record: <HBBBBB> components at offsets 2, 10, ... (1 pad byte).
function lteRecord(...comps) {
  const out = new Uint8Array(50);
  comps.forEach((c, i) => {
    const dv = new DataView(out.buffer);
    dv.setUint16(2 + i * 8, c[0], true);
    for (let k = 0; k < 5; k++) out[2 + i * 8 + 2 + k] = c[k + 1];
  });
  return out;
}

test("b0cdV41Packets match Python-generated fixtures", () => {
  // Python fixture: rrc with two high combos (B66A[3];A[1]+B12A[2] and
  // B41C[4];C[2]) and one low combo, encoded by new_rfcard_parser.
  const rrc = {
    lte_info_per_band_sub_cap_high: concatBytes([
      lteRecord([66, 1, 3, 1, 1, 2], [12, 1, 2, 0, 0, 0]),
      lteRecord([41, 3, 4, 2, 2, 1]),
    ]),
    lte_info_per_band_sub_cap_high_num: 2,
    lte_info_per_band_sub_cap_low: lteRecord([7, 2, 1, 1, 2, 1]),
    lte_info_per_band_sub_cap_low_num: 1,
  };
  const high = b0cdV41Packets(rrc, "high");
  assert.deepEqual(high.map((p) => hex(p)), ["290202420001010301020c0001000200000129000302040201"]);
  const low = b0cdV41Packets(rrc, "low");
  assert.deepEqual(low.map((p) => hex(p)), ["29010107000201010201"]);
  assert.equal(sha256Hex(concatBytes([...high, ...low])),
    "845d769a9b095fded0af042e6bbe87a314c6d19df43b443aa0de4a46027a87d9");
});

test("b826V22 encoder matches Python-generated fixtures", () => {
  // Python: NRBandGroup(tech=2, band=41, dl_bw_class=3, dl_bw_per_cc=21,
  // ul_bw_class=2, ul_bw_per_cc=4, dl_max_antennas_index=3,
  // ul_max_antennas_index=2, max_scs=5, ul_qam_cap_index=2,
  // srs_tx_switch_type=9, tx_switch_impact_to_rx=3, ...).
  const bg1 = {
    tech: 2, band: 41, dl_bw_class: 3, dl_bw_per_cc: 21, ul_bw_class: 2,
    ul_bw_per_cc: 4, dl_max_antennas_index: 3, ul_max_antennas_index: 2,
    ul_qam_cap_index: 2,
  };
  // NRBandGroup(tech=1, band=3, dl_bw_class=1, dl_bw_per_cc=4,
  // ul_bw_class=2, ul_bw_per_cc=21, dl_max_antennas_index=2,
  // ul_max_antennas_index=1, ul_qam_cap_index=1, ...).
  const bg2 = {
    tech: 1, band: 3, dl_bw_class: 1, dl_bw_per_cc: 4, ul_bw_class: 2,
    ul_bw_per_cc: 21, dl_max_antennas_index: 2, ul_max_antennas_index: 1,
    ul_qam_cap_index: 1,
  };
  assert.equal(hex(b826V22Component(bg1)), "298e8110820a01000000");
  assert.equal(hex(b826V22Component(bg2)), "03048108044205000000");

  // Three records packed into one packet by b826_v22_packets(records, 4).
  const prop = { ul_tx_switch_type: 1 };
  const packets = b826V22Packets([[[bg1, bg2], prop], [[bg2], prop], [[bg1, bg2, bg1], prop]], 4);
  assert.equal(packets.length, 1);
  assert.equal(hex(packets[0]),
    "1600000003000000030004802000000000000000000000000000298e8110820a010000000304810804420500000040200000000000000000000000000003048108044205000000c02000000000000000000000000000298e8110820a0100000003048108044205000000298e8110820a01000000");
  assert.equal(sha256Hex(packets[0]),
    "ef499d82c0f65124456103d059ff0998cf2ecc13bd5999ea22c3ba7b05d57287");

  // Python raises on out-of-range encodings.
  assert.throws(() => b826V22Packets([[Array.from({ length: 16 }, () => bg1), prop]], 4),
    /0xB826 v22 supports 1..15 components, got 16/);
  assert.throws(() => b826V22Component({ ...bg1, band: 0x200 }),
    /0xB826 v22 band exceeds 9 bits: 512/);
  assert.throws(() => b826V22Component({ ...bg1, dl_max_antennas_index: 0x80 }),
    /0xB826 v22 component field exceeds its bit width/);
});
