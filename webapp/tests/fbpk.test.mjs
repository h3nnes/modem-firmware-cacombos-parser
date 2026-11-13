// FBPK v1 header/entry-table tests. REAL_HEADER is the first 0x8C bytes of
// radio-kodiak-a900a-qpr_261007-261007-m-16537144.img (Pixel 11 / MT6986D), so
// the field offsets are pinned by a real container rather than only by the
// synthetic builder below.
import test from "node:test";
import assert from "node:assert/strict";
import { FbpkError, isFbpk, parseFbpk, parseFbpkHeader } from "../js/lib/fbpk.js";

const REAL_HEADER = Uint8Array.from(Buffer.from("4642504b0100000061393030612d5150525f3236313030372d3236313030372d4d2d313635333731343400000000000000000000000000000000000000000000000000000000000000000000010000008c30920b010000006d6f64656d000000000000000000000000000000000000000000000000000000000000000030920b000000009030920b85493e97", "hex"));

const u32le = (n) => Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);

// Synthetic v1 container: contiguous entry headers/payloads, next offsets set
// to the following header (the last one points past EOF like real images).
function build(entries, { name = "release", count = entries.length, total } = {}) {
  const headerSize = 0x54;
  const entrySize = 0x38;
  const offsets = [];
  let end = headerSize;
  for (const e of entries) { offsets.push(end); end += entrySize + e.data.length; }
  const buf = new Uint8Array(total ?? end);
  buf.set([0x46, 0x42, 0x50, 0x4b]);
  const dv = new DataView(buf.buffer);
  dv.setUint32(4, 1, true);
  for (let i = 0; i < name.length && i < 0x44; i++) buf[8 + i] = name.charCodeAt(i);
  dv.setUint32(0x4c, count, true);
  dv.setUint32(0x50, total ?? end, true);
  entries.forEach((e, i) => {
    const o = offsets[i];
    dv.setUint32(o, 1, true);
    for (let j = 0; j < e.name.length && j < 32; j++) buf[o + 4 + j] = e.name.charCodeAt(j);
    dv.setUint32(o + 0x28, e.data.length, true);
    dv.setUint32(o + 0x30, i + 1 < entries.length ? offsets[i + 1] : end + 4, true);
    buf.set(e.data, o + entrySize);
  });
  return buf;
}

test("fbpk v1: real Pixel 11 radio header (independent offset pin)", () => {
  assert.ok(isFbpk(REAL_HEADER));
  const h = parseFbpkHeader(REAL_HEADER, 0x0b92308c);
  assert.equal(h.version, 1);
  assert.equal(h.name, "a900a-QPR_261007-261007-M-16537144");
  assert.equal(h.totalSize, 0x0b92308c);
  assert.deepEqual(h.entries, [{ type: 1, name: "modem", offset: 0x8c, size: 0x0b923000 }]);
});

test("fbpk v1: multi-entry containers honor the next-entry offsets", () => {
  const buf = build([
    { name: "one", data: Uint8Array.of(1, 2, 3) },
    { name: "two", data: Uint8Array.of(4, 5) },
  ]);
  const h = parseFbpk(buf);
  assert.deepEqual(h.entries.map((e) => e.name), ["one", "two"]);
  assert.deepEqual([...h.entries[0].data], [1, 2, 3]);
  assert.deepEqual([...h.entries[1].data], [4, 5]);
});

test("fbpk v1: version, declared size, count and truncation are validated", () => {
  const good = build([{ name: "modem", data: Uint8Array.of(9, 9) }]);
  const v2 = good.slice();
  new DataView(v2.buffer).setUint32(4, 2, true);
  assert.throws(() => parseFbpkHeader(v2), (e) => e instanceof FbpkError && /version 2/.test(e.message));

  // Declared total is larger than the available container.
  assert.throws(() => parseFbpkHeader(good, good.length - 1), /declares .* bytes but only .* are available/);

  // More entries than the declared container can possibly hold.
  const tooMany = good.slice();
  new DataView(tooMany.buffer).setUint32(0x4c, 0x7fffffff, true);
  assert.throws(() => parseFbpkHeader(tooMany), /entry count .* exceeds/);

  // Truncated entry table.
  assert.throws(() => parseFbpkHeader(good.subarray(0, 0x60), good.length), /truncated FBPK entry table/);
});

test("fbpk v1: non-FBPK input is rejected", () => {
  assert.equal(isFbpk(Uint8Array.of(1, 2, 3, 4)), false);
  assert.throws(() => parseFbpkHeader(Uint8Array.of(1, 2, 3, 4)), /not an FBPK container/);
});
