// 0xB0CD (v41) / 0xB826 (v22) DIAG exports: legacy diag builders + exportModule
// text output, with a Python differential on real corpus records.
//
// The modern encoders (b0cd_v41_packets/b826_v22_packets) already live in
// modern_parser.js and are pinned by modern_parser.test.mjs.
//
// JS API shape added here:
//   legacyB0cdPackets(tableResults, packetCombos=100) -> [[label, Uint8Array]]
//   legacyB826Packets(tableResults) -> [[label, Uint8Array]]
//     tableResults: [[table, result]] pairs (result.combinations[].entries
//     carry band/dl_bw_class_code/ul_present/
//     ul_bw_class_code/dl_bw_code/ul_bw_code/dl_antenna_index/ul_antenna_index/
//     rat; combos carry ul_tx_switch_type_raw).
//   parseLegacyModule(record, blob) -> { ..., diag: { b0cd, b826 } }
//   exportModule(record, parsed, "b0cd"|"b826") -> [{ filename, text }]
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { hex, hexToBytes } from "../js/lib/bytes.js";
import {
  legacyB0cdPackets,
  legacyB826Packets,
  parseLegacyModule,
  ToolError,
} from "../js/lib/legacy_parser.js";
import { parseModule, exportModule } from "../js/lib/analyzer.js";
import { Fat16Image } from "../js/lib/fat16.js";
import { sourceFor } from "../js/lib/source.js";
import { CORPUS_DIR, corpusAvailable, containerBlobs } from "./helpers.mjs";

// --- synthetic fixtures ---------------------------------------------------------

// Legacy band-group entry shape (mirrors parseBandGroup/parseLegacyLteArray).
function entry(rat, band, fields = {}) {
  return {
    rat,
    band,
    dl_bw_class_code: 1,
    dl_bw_code: 0,
    ul_present: false,
    ul_bw_class_code: 0,
    ul_bw_code: 0,
    dl_antenna_index: 0,
    ul_antenna_index: 0,
    ...fields,
  };
}

function result(combos) {
  return { combinations: combos };
}

test("legacyB0cdPackets: only lte_ca tables, skips empty groups, ul/qam defaults, labels", () => {
  const tableResults = [
    ["endc", result([
      { entries: [entry("LTE", 3, { ul_present: true, ul_bw_class_code: 1 })], ul_tx_switch_type_raw: 0 },
    ])],
    ["lte_ca", result([
      { entries: [
        entry("LTE", 3, { dl_bw_class_code: 2, ul_present: true, ul_bw_class_code: 1, dl_antenna_index: 4, ul_antenna_index: 2 }),
        entry("LTE", 7, { dl_bw_class_code: 1 }),
      ] },
      { entries: [] },
      { entries: [
        entry("LTE", 260, { dl_bw_class_code: 1, ul_present: true, ul_bw_class_code: 3, dl_antenna_index: 1, ul_antenna_index: 1, ul_qam_cap_index: 2 }),
      ] },
    ])],
    ["nr_ca", result([
      { entries: [entry("NR", 78, { ul_present: true, ul_bw_class_code: 1 })] },
    ])],
  ];

  const packets = legacyB0cdPackets(tableResults);
  assert.equal(packets.length, 1);
  const [label, payload] = packets[0];
  // One packet holding the two non-empty lte_ca combos: header bytes([41, 2]),
  // combo 1 with 2 groups, combo 2 with 1 group. struct.pack("<HBBBBB", ...)
  // group bytes: band(u16 LE), dl_class, ul_class, dl_ant, ul_ant, qam.
  assert.equal(label, "LTE CA packet 1/1");
  assert.equal(
    hex(payload),
    "2902"
      + "02" + "03000201040200" + "07000100000000"
      + "01" + "04010103010102",
  );
});

test("legacyB0cdPackets: chunking above 100 combos per packet (bytes([41, len]))", () => {
  const combos = [];
  for (let i = 0; i < 250; i++) {
    combos.push({ entries: [entry("LTE", 1, { dl_bw_class_code: 1, ul_present: true, ul_bw_class_code: 1, dl_antenna_index: 1, ul_antenna_index: 1 })] });
  }
  const packets = legacyB0cdPackets([["lte_ca", result(combos)]]);
  assert.equal(packets.length, 3);
  assert.deepEqual(packets.map(([label]) => label), [
    "LTE CA packet 1/3",
    "LTE CA packet 2/3",
    "LTE CA packet 3/3",
  ]);
  // Each encoded combo is count byte + 7-byte group = 8 bytes.
  assert.equal(packets[0][1].length, 2 + 100 * 8);
  assert.equal(packets[1][1].length, 2 + 100 * 8);
  assert.equal(packets[2][1].length, 2 + 50 * 8);
  assert.deepEqual([...packets[0][1].slice(0, 2)], [41, 100]);
  assert.deepEqual([...packets[1][1].slice(0, 2)], [41, 100]);
  assert.deepEqual([...packets[2][1].slice(0, 2)], [41, 50]);
  // Group payload shape inside the first packet.
  assert.equal(hex(packets[0][1].slice(2, 10)), "01" + "01000101010100");
  assert.equal(hex(packets[2][1].slice(2, 10)), "01" + "01000101010100");
});

test("legacyB826Packets: sources 3/4/5 per table, tech/rat + prop mapping, labels", () => {
  const tableResults = [
    ["lte_ca", result([
      { entries: [entry("LTE", 3, { ul_present: true, ul_bw_class_code: 1 })] },
    ])],
    ["endc", result([
      { entries: [
        // struct-derived expected component (Python b826_v22_component):
        entry("LTE", 3, { dl_bw_class_code: 2, dl_bw_code: 5, ul_present: true, ul_bw_class_code: 1, ul_bw_code: 7, dl_antenna_index: 4, ul_antenna_index: 2 }),
      ], ul_tx_switch_type_raw: 2 },
    ])],
    ["nr_ca", result([
      { entries: [
        entry("NR", 78, { dl_bw_class_code: 1, dl_bw_code: 20, ul_present: true, ul_bw_class_code: 1, ul_bw_code: 20, dl_antenna_index: 2, ul_antenna_index: 1 }),
        entry("NR", 79, { dl_bw_class_code: 1, dl_bw_code: 24, ul_bw_code: 0, dl_antenna_index: 1 }),
      ] },
    ])],
    ["nrdc", result([
      { entries: [
        entry("LTE", 3, { dl_bw_class_code: 2, dl_bw_code: 5, ul_present: true, ul_bw_class_code: 1, ul_bw_code: 7, dl_antenna_index: 4, ul_antenna_index: 2 }),
        entry("NR", 78, { dl_bw_class_code: 1, dl_bw_code: 20, ul_present: true, ul_bw_class_code: 1, ul_bw_code: 20, dl_antenna_index: 2, ul_antenna_index: 1 }),
      ], ul_tx_switch_type_raw: 1 },
    ])],
    ["nr_unknown", result([
      { entries: [entry("NR", 78, { ul_present: true, ul_bw_class_code: 1 })] },
    ])],
  ];

  const packets = legacyB826Packets(tableResults);
  assert.equal(packets.length, 3);
  assert.deepEqual(packets.map(([label]) => label), [
    "EN-DC source=3 packet 1/1",
    "NR-CA source=4 packet 1/1",
    "NR-DC source=5 packet 1/1",
  ]);
  // 15-byte packet header <HHHHHB>(22,0,total,start,count,source) + records.
  assert.equal(
    hex(packets[0][1]),
    "1600000001000000010003"
      + "404000000000000000000000000000"
      + "0308421080c201000000",
  );
  assert.equal(
    hex(packets[1][1]),
    "1600000001000000010004"
      + "800000000000000000000000000000"
      + "4e064108000a05000000"
      + "4f860000000c00000000",
  );
  assert.equal(
    hex(packets[2][1]),
    "1600000001000000010005"
      + "802000000000000000000000000000"
      + "0308421080c201000000"
      + "4e064108000a05000000",
  );
});

// --- parseLegacyModule diag (synthetic ELF, full parse path) --------------------

// hi_inline_100 band-group component (legacy_parser.test.mjs component()).
function bandGroupComponent(rat, band, dlClass = 1) {
  const bandCode = rat | (band << 2) | (dlClass << 11);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setUint16(0, bandCode, true);
  return out;
}

// Minimal ELF32 (one PT_LOAD, vaddr 0 => file offset == VA) wrapping an
// hi_inline_100 nr_ca descriptor at offset 256 with its combos at 1024.
function elfFixture(combos, { flags = 2 } = {}) {
  const total = 1024 + combos.length * 100;
  const data = new Uint8Array(total);
  const dv = new DataView(data.buffer);
  data.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1, 0], 0);
  dv.setUint16(16, 2, true); // e_type ET_EXEC
  dv.setUint16(18, 40, true); // e_machine EM_ARM
  dv.setUint32(20, 1, true); // e_version
  dv.setUint32(28, 52, true); // e_phoff
  dv.setUint16(40, 52, true); // e_ehsize
  dv.setUint16(42, 32, true); // e_phentsize
  dv.setUint16(44, 1, true); // e_phnum
  dv.setUint32(52, 1, true); // p_type PT_LOAD
  dv.setUint32(56, 0, true); // p_offset
  dv.setUint32(60, 0, true); // p_vaddr
  dv.setUint32(64, 0, true); // p_paddr
  dv.setUint32(68, total, true); // p_filesz
  dv.setUint32(72, total, true); // p_memsz
  dv.setUint32(76, 5, true); // p_flags
  dv.setUint32(80, 0x1000, true); // p_align
  dv.setUint16(256, combos.length, true); // descriptor combo count
  dv.setUint32(260, 1024, true); // combos VA
  dv.setUint16(264, 81, true); // antenna count
  combos.forEach((entries, comboIndex) => {
    const offset = 1024 + comboIndex * 100;
    entries.forEach(([rat, band], position) => {
      data.set(bandGroupComponent(rat, band), offset + position * 8);
    });
    data[offset + 96] = flags; // combo property byte
    data[offset + 98] = entries.length; // num_band_entries
  });
  return data;
}

test("parseLegacyModule returns diag: { b0cd, b826 } from the full parse path", () => {
  const blob = elfFixture([[[2, 79], [2, 41]], [[2, 78]]]);
  const record = { name: "660_0_0.mbn", inner_path: "/image/modem_pr/so/660_0_0.mbn", generation: "Legacy ELF" };
  const parsed = parseModule(record, blob);

  // Single NR-only descriptor with no RF_NRDC/RF_NRCA symbols -> nr_ca.
  assert.deepEqual(parsed.diag.b0cd, []);
  assert.equal(parsed.diag.b826.length, 1);
  const [label, payload] = parsed.diag.b826[0];
  assert.equal(label, "NR-CA source=4 packet 1/1");
  // Two hi_inline combos (2 + 1 NR entries, dl/ul fields zero in this fixture).
  assert.equal(
    hex(payload),
    "1600000002000000020004"
      + "800000000000000000000000000000"
      + "4f060000000000000000"
      + "29060000000000000000"
      + "400000000000000000000000000000"
      + "4e060000000000000000",
  );
});

// --- exportModule DIAG text ------------------------------------------------------

test("exportModule b0cd/b826 produce the exact _write_diag text and filenames", () => {
  const record = { name: "823_0_0.mbn", inner_path: "/x", generation: "Legacy ELF" };
  const parsed = {
    metadata: {},
    combinations: [],
    components: [],
    diag: {
      b0cd: [["LTE CA packet 1/1", hexToBytes("29020203000201040200070001000000000104010103010102")]],
      b826: [
        ["EN-DC source=3 packet 1/1", hexToBytes("16000000010000000100034040000000000000000000000000000308421080c201000000")],
        ["NR-CA source=4 packet 1/1", hexToBytes("16000000010000000100048000000000000000000000000000004e064108000a050000004f860000000c00000000")],
      ],
    },
  };

  const [b0cd] = exportModule(record, parsed, "b0cd");
  assert.deepEqual(b0cd, {
    filename: "823_0_0_0xB0CD_v41.txt",
    text:
      "# Headerless Qualcomm DIAG payloads reconstructed from static RF tables.\n"
      + "# Log 0xB0CD, payload version 41; one Payload block per packet.\n"
      + "\n"
      + "# LTE CA packet 1/1\n"
      + "Payload: 29020203000201040200070001000000000104010103010102\n",
  });

  const [b826] = exportModule(record, parsed, "b826");
  assert.equal(b826.filename, "823_0_0_0xB826_v22.txt");
  assert.equal(
    b826.text,
    "# Headerless Qualcomm DIAG payloads reconstructed from static RF tables.\n"
      + "# Log 0xB826, payload version 22; one Payload block per packet.\n"
      + "\n"
      + "# EN-DC source=3 packet 1/1\n"
      + "Payload: 16000000010000000100034040000000000000000000000000000308421080c201000000\n"
      + "\n"
      + "# NR-CA source=4 packet 1/1\n"
      + "Payload: 16000000010000000100048000000000000000000000000000004e064108000a050000004f860000000c00000000\n",
  );
});

test("exportModule DIAG: empty packet lists write header-only files; missing diag raises", () => {
  const record = { name: "881_0.mbn", inner_path: "/x", generation: "Legacy ELF" };
  const parsed = { metadata: {}, combinations: [], components: [], diag: { b0cd: [], b826: [] } };

  const [b0cd] = exportModule(record, parsed, "b0cd");
  assert.deepEqual(b0cd, {
    filename: "881_0_0xB0CD_v41.txt",
    text:
      "# Headerless Qualcomm DIAG payloads reconstructed from static RF tables.\n"
      + "# Log 0xB0CD, payload version 41; one Payload block per packet.\n",
  });
  const [b826] = exportModule(record, parsed, "b826");
  assert.equal(
    b826.text,
    "# Headerless Qualcomm DIAG payloads reconstructed from static RF tables.\n"
      + "# Log 0xB826, payload version 22; one Payload block per packet.\n",
  );

  // Python reads parsed["diag"][key] unconditionally; the JS port raises the
  // shared ToolError style when a caller hands over a diag-less parse result.
  assert.throws(() => exportModule(record, { metadata: {}, combinations: [], components: [] }, "b0cd"), ToolError);
  assert.throws(() => exportModule(record, { metadata: {}, combinations: [], components: [], diag: {} }, "b826"), ToolError);
});

// --- differential: corpus records vs the real Python parser + _write_diag --------

const UPSTREAM_REF = new URL("./diag_ref.py", import.meta.url).pathname;

function runProbe(blobPath, name, generation, outdir) {
  const res = spawnSync("python3", [UPSTREAM_REF, blobPath, name, generation, outdir], {
    encoding: "utf8",
    maxBuffer: 1 << 28,
  });
  if (res.error || res.status !== 0) return null;
  const line = res.stdout.split("\n").find((l) => l.startsWith("DIAGREF = "));
  if (!line) return null;
  return JSON.parse(line.slice("DIAGREF = ".length));
}

test("exportModule DIAG text is byte-identical to Python _write_diag on corpus records", { skip: !corpusAvailable() }, async (t) => {
  if (!existsSync(UPSTREAM_REF)) return t.skip("diag_ref.py unavailable");
  const cases = [
    {
      img: "pocof6pro_modem.img",
      name: "823_0_0.mbn",
      generation: "Legacy ELF",
      inner_path: "/image/modem_pr/so/823_0_0.mbn",
      kind: "fat",
    },
    {
      img: "pocof6pro_modem.img",
      name: "810_0_0.mbn",
      generation: "Legacy ELF",
      inner_path: "/image/modem_pr/so/810_0_0.mbn",
      kind: "fat",
    },
    {
      img: "ximi18max_modemfirmware_a.img",
      name: "rf_config_1426_0_0_0170.mbn",
      generation: "DAT/protobuf",
      inner_path: "/image/modem_pr/mcfg/configs/mcfg_ddr/rf/rf_config_1426_0_0_0170.mbn",
      kind: "fat",
    },
    {
      img: "radio.img",
      name: "rf_config_0610_0_0.mbn",
      generation: "DAT/protobuf",
      inner_path: "sparse/image/modem_pr/mcfg/configs/mcfg_ddr/rf/rf_config_0610_0_0.mbn",
      kind: "container",
    },
  ];

  const workdir = await mkdtemp(join(tmpdir(), "diagref-"));
  try {
    let checked = 0;
    for (const { img, name, generation, inner_path, kind } of cases) {
      const src = await sourceFor(join(CORPUS_DIR, img));
      try {
        let blob;
        if (kind === "fat") {
          const fat = new Fat16Image(src);
          await fat.init();
          const entry = (await fat.walk()).find((e) => e.path === inner_path);
          assert.ok(entry, `${img}: missing ${inner_path}`);
          blob = await fat.readFile(entry);
        } else {
          const blobs = await containerBlobs(src, img);
          const vfile = blobs.get(inner_path);
          assert.ok(vfile, `${img}: missing ${inner_path}`);
          blob = await vfile.read();
        }

        const record = { name, inner_path, generation };
        const parsed = parseModule(record, blob);

        const blobPath = join(workdir, `case${checked}.bin`);
        const { writeFile } = await import("node:fs/promises");
        await writeFile(blobPath, blob);
        const expected = runProbe(blobPath, name, generation, workdir);
        if (!expected) return t.skip("python3 diag_ref probe unavailable");

        for (const key of ["b0cd", "b826"]) {
          const [file] = exportModule(record, parsed, key);
          const pyText = await readFile(expected[key].file, "utf8");
          // Byte-exact: TextEncoder bytes must equal the Python file bytes.
          assert.deepEqual(
            [...new TextEncoder().encode(file.text)],
            [...await readFile(expected[key].file)],
            `${img}/${name} ${key}: text bytes`,
          );
          assert.equal(file.text, pyText, `${img}/${name} ${key}: text`);
          assert.equal(file.filename, `${name.replace(/\.mbn$/i, "")}_0xB${key === "b0cd" ? "0CD_v41" : "826_v22"}.txt`);
          // Per-packet payload hex equality (catches label/payload misalignment).
          assert.deepEqual(
            parsed.diag[key].map(([, payload]) => hex(payload)),
            expected[key].hex,
            `${img}/${name} ${key}: payload hex`,
          );
          assert.deepEqual(
            parsed.diag[key].map(([label]) => label),
            expected[key].labels,
            `${img}/${name} ${key}: labels`,
          );
        }
        checked++;
      } finally {
        await src.close();
      }
    }
    assert.equal(checked, 4);
  } finally {
    await rm(workdir, { recursive: true, force: true });
  }
});
