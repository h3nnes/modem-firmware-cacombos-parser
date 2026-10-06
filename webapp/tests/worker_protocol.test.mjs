// Worker protocol: stable source identity (WEBAPP_PERFORMANCE_REVIEW.md step 2).
//
// A File posted to a worker is structured-cloned into a NEW wrapper per message,
// so the old WeakMaps keyed by the File object never hit across requests. main.js
// now assigns a monotonic, never-reused sourceId per imported File and registers
// {sourceId, file} once in the scan; every parseCard/export/importCards carries
// only the id. These tests drive worker.js through a fake `self` and assert the
// per-source memo actually survives across separate messages.
//
// worker.js is a module entry (it installs self.onmessage at import time), so the
// fake self must exist before the dynamic import. `parseModule` once is covered
// by the corpus-gated case at the bottom; the always-on cases use a synthetic tar
// container, because a parseable card requires corpus data.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { CORPUS_DIR, corpusAvailable } from "./helpers.mjs";
import { isValidTablesShape } from "../js/cardcache.js";

// --- synthetic tar (extractTar ignores the checksum field) ---------------------

const octal = (n, width) => n.toString(8).padStart(width - 1, "0") + "\0";

function tarHeader(name, size) {
  const h = new Uint8Array(512);
  const write = (off, s) => {
    for (let i = 0; i < s.length; i++) h[off + i] = s.charCodeAt(i);
  };
  write(0, name.slice(0, 100));
  write(100, "0000644\0");
  write(108, "0000000\0");
  write(116, "0000000\0");
  write(124, octal(size, 12));
  write(136, octal(0, 12));
  for (let i = 0; i < 8; i++) h[148 + i] = 0x20;
  h[156] = 0x30; // regular file
  write(257, "ustar\0");
  write(263, "00");
  return h;
}

const pad512 = (data) => {
  const out = new Uint8Array(Math.ceil(data.length / 512) * 512);
  out.set(data);
  return out;
};

function buildTar(members) {
  const blocks = [];
  for (const m of members) blocks.push(tarHeader(m.name, m.data.length), pad512(m.data));
  blocks.push(new Uint8Array(1024)); // end-of-archive marker
  const out = new Uint8Array(blocks.reduce((n, b) => n + b.length, 0));
  let off = 0;
  for (const b of blocks) {
    out.set(b, off);
    off += b.length;
  }
  return out;
}

const MBN_BYTES = new Uint8Array(600);
for (let i = 0; i < MBN_BYTES.length; i++) MBN_BYTES[i] = (i * 13 + 7) & 0xff;
const TAR = buildTar([{ name: "rf_config_1306_0_0.mbn", data: MBN_BYTES }]);

// --- fake worker host ----------------------------------------------------------

const posted = [];
const waiters = [];
globalThis.self = {
  postMessage(message) {
    posted.push(message);
    for (let i = waiters.length - 1; i >= 0; i--) {
      if (waiters[i].predicate(message)) waiters.splice(i, 1)[0].resolve(message);
    }
  },
};

const workerModule = await import(new URL("../js/worker.js", import.meta.url).href);

function waitFor(predicate, start = 0, timeout = 5000) {
  // Only consider messages posted at/after `start`: several tests post replies
  // with the same shape (e.g. records with fileIndex 0), and an unscoped scan
  // would match an earlier test's reply. The timeout is a parameter because an
  // MTK image scan legitimately takes longer than 5s (unwrap + full decode).
  for (let i = start; i < posted.length; i++) {
    if (predicate(posted[i])) return Promise.resolve(posted[i]);
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timed out waiting for a worker reply")), timeout);
    waiters.push({
      predicate,
      resolve: (message) => {
        clearTimeout(timer);
        resolve(message);
      },
    });
  });
}

async function request(message, predicate, timeout) {
  const start = posted.length;
  const pending = waitFor(predicate, start, timeout);
  globalThis.self.onmessage({ data: message });
  return pending;
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// --- tests ---------------------------------------------------------------------

test("worker: scan artifacts mean two exports of one sourceId never re-extract", async () => {
  const sourceId = 101;
  const scan = await request(
    { type: "scan", id: 1, files: [{ sourceId, file: new File([TAR], "payload.tar") }] },
    (m) => m.type === "records" && m.fileIndex === 0,
  );
  assert.equal(scan.records.length, 1, "the tar's candidate must be discovered");
  const record = scan.records[0];

  const parseBefore = workerModule.getDebugCounters().parseModule;
  // The scan seeds parseMemo with the exact candidate bytes (step 3), so neither
  // export may run extractContainer again or invoke the parser.
  const extractAfterScan = workerModule.getDebugCounters().extractContainer;

  const first = await request(
    { type: "export", id: 11, sourceId, fileIndex: 0, record, format: "mbn" },
    (m) => m.id === 11,
  );
  assert.deepEqual(new Uint8Array(first.files[0].bytes), MBN_BYTES);

  const second = await request(
    { type: "export", id: 12, sourceId, fileIndex: 0, record, format: "mbn" },
    (m) => m.id === 12,
  );
  assert.deepEqual(new Uint8Array(second.files[0].bytes), MBN_BYTES, "bytes must be identical");
  assert.equal(
    workerModule.getDebugCounters().extractContainer,
    extractAfterScan,
    "seeded scan bytes must make both exports extraction-free",
  );
  assert.equal(workerModule.getDebugCounters().parseModule, parseBefore, "a pure mbn export must never parse");
});

test("worker: an unknown sourceId errors with the request id instead of reading", async () => {
  const reply = await request(
    { type: "parseCard", id: 77, sourceId: 987654, fileIndex: 0, record: { name: "missing.mbn" } },
    (m) => m.type === "error" && m.id === 77,
  );
  assert.match(reply.message, /unknown sourceId/);
});

test("worker: a superseded open (cancel before dequeue) never parses or replies", async () => {
  const sourceId = 404;
  const scan = await request(
    { type: "scan", id: 24, files: [{ sourceId, file: new File([TAR], "superseded.tar") }] },
    (m) => m.type === "records" && m.fileIndex === 0,
  );
  const record = scan.records[0];
  const before = workerModule.getDebugCounters().parseModule;
  const mark = posted.length;
  // Post the open and its cancel back-to-back: cancel is handled immediately, so
  // the parse-lane handler sees the id in `cancelled` at dequeue time.
  globalThis.self.onmessage({ data: { type: "parseCard", id: 901, sourceId, fileIndex: 0, record } });
  globalThis.self.onmessage({ data: { type: "cancel", id: 901 } });
  await delay(50);
  const replies = posted.slice(mark).filter((m) => m.id === 901);
  assert.equal(replies.length, 0, "a cancelled open must not reply");
  assert.equal(workerModule.getDebugCounters().parseModule, before, "a cancelled open must not parse");
});

test("worker: release drops the registered sources so later ops fail loudly", async () => {
  const sourceId = 202;
  await request(
    { type: "scan", id: 2, files: [{ sourceId, file: new File([TAR], "payload2.tar") }] },
    (m) => m.type === "records" && m.fileIndex === 0,
  );
  globalThis.self.onmessage({ data: { type: "release" } });
  await delay(20); // release runs on the main chain; parseCard is now priority-lane
  const reply = await request(
    { type: "parseCard", id: 78, sourceId, fileIndex: 0, record: { name: "payload2.tar" } },
    (m) => m.type === "error" && m.id === 78,
  );
  assert.match(reply.message, /unknown sourceId/);
});

test("worker: reopening the same card parses once (corpus-gated)", { skip: !corpusAvailable() }, async () => {
  const { readFile } = await import("node:fs/promises");
  const { join } = await import("node:path");
  // radio.img is the container image corpusAvailable() guarantees; its scan
  // extracts once and step 3 seeds parseMemo, so reopen must not re-extract.
  const bytes = await readFile(join(CORPUS_DIR, "radio.img"));
  const file = new File([bytes], "radio.img");
  const sourceId = 303;
  const scan = await request(
    { type: "scan", id: 3, files: [{ sourceId, file }] },
    (m) => m.type === "records" && m.fileIndex === 0,
  );
  const record = scan.records[0];
  assert.ok(record, "the image must yield at least one card");
  const extractAfterScan = workerModule.getDebugCounters().extractContainer;

  await request({ type: "parseCard", id: 31, sourceId, fileIndex: 0, record }, (m) => m.id === 31);
  await delay(30); // let the fire-and-forget cache put settle
  const afterFirst = workerModule.getDebugCounters().parseModule;
  const tablesAfterFirst = workerModule.getDebugCounters().generateWebTables;
  await request({ type: "parseCard", id: 32, sourceId, fileIndex: 0, record }, (m) => m.id === 32);
  assert.equal(
    workerModule.getDebugCounters().parseModule,
    afterFirst,
    "reopening a card must hit the per-source parse memo",
  );
  assert.equal(
    workerModule.getDebugCounters().extractContainer,
    extractAfterScan,
    "seeded scan bytes must make card opens extraction-free",
  );

  // Worker-side table cache: a new sourceId for the same file (new scan) must
  // serve the open from the cache without re-formatting the tables.
  const sourceId2 = 304;
  await request(
    { type: "scan", id: 4, files: [{ sourceId: sourceId2, file }] },
    (m) => m.type === "records" && m.fileIndex === 0,
  );
  await request({ type: "parseCard", id: 33, sourceId: sourceId2, fileIndex: 0, record }, (m) => m.id === 33);
  assert.equal(
    workerModule.getDebugCounters().generateWebTables,
    tablesAfterFirst,
    "a cache hit must skip table formatting",
  );

  // Clear wipes the worker cache, so the next open regenerates the tables.
  globalThis.self.onmessage({ data: { type: "clearCache" } });
  await delay(30);
  await request({ type: "parseCard", id: 34, sourceId: sourceId2, fileIndex: 0, record }, (m) => m.id === 34);
  assert.equal(
    workerModule.getDebugCounters().generateWebTables,
    tablesAfterFirst + 1,
    "after clearCache the card is regenerated",
  );
});

test("worker: parse retention is bounded and evicted parses re-parse correctly (corpus-gated)", { skip: !corpusAvailable() }, async () => {
  const { readFile } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const file = new File([await readFile(join(CORPUS_DIR, "radio.img"))], "radio.img");
  const sourceId = 305;
  const scan = await request(
    { type: "scan", id: 5, files: [{ sourceId, file }] },
    (m) => m.type === "records" && m.fileIndex === 0,
  );
  const [a, b] = scan.records;
  assert.ok(a && b, "radio.img carries two cards");
  workerModule.setMaxRetainedParses(1);
  try {
    const exportJson = async (id, record) =>
      (await request({ type: "export", id, sourceId, fileIndex: 0, record, format: "json" }, (m) => m.id === id)).files;
    const start = workerModule.getDebugCounters().parseModule;
    const first = await exportJson(51, a);
    await exportJson(52, b); // evicts a's parse (cap = 1)
    assert.equal(workerModule.getDebugCounters().parseModule, start + 2);
    const again = await exportJson(53, a);
    assert.equal(workerModule.getDebugCounters().parseModule, start + 3, "an evicted parse is rebuilt on demand");
    assert.deepEqual(again, first, "the rebuilt parse must export identically");
    await exportJson(54, a);
    assert.equal(workerModule.getDebugCounters().parseModule, start + 3, "the retained parse is reused");
  } finally {
    workerModule.setMaxRetainedParses(2);
  }
});

// MTK DRDI card open (Stage C): the scan seeds the image memo through the
// onMtkImage hook, so the first parseCard never re-unwraps (a Tensor rebuild
// would re-verify 640 SHA-384 slot digests); reopen hits the per-card parse
// memo and the worker-side table cache; release drops everything.
const mtkWorkerImage = "mtk_pocox8pro_d8500u_modem.img";
const mtkWorkerAvailable = () => existsSync(join(CORPUS_DIR, mtkWorkerImage));

test("worker: MTK card open reuses the scan-seeded image memo (corpus-gated)", { skip: !mtkWorkerAvailable() }, async () => {
  const { readFile } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const file = new File([await readFile(join(CORPUS_DIR, mtkWorkerImage))], mtkWorkerImage);
  const sourceId = 401;
  const scan = await request(
    { type: "scan", id: 7, files: [{ sourceId, file }] },
    (m) => m.type === "records" && m.fileIndex === 0,
    60000,
  );
  const record = scan.records[0];
  assert.equal(record.generation, "MediaTek DRDI");
  const afterScan = workerModule.getDebugCounters();
  assert.equal(afterScan.unwrapMtk, 0, "the scan seeds the image memo — no card-open unwrap");

  const tablesReply = await request(
    { type: "parseCard", id: 61, sourceId, fileIndex: 0, record },
    (m) => m.type === "tables" && m.id === 61,
  );
  await delay(30); // let the fire-and-forget cache put settle
  const afterFirst = workerModule.getDebugCounters();
  assert.equal(afterFirst.unwrapMtk, afterScan.unwrapMtk, "card open must not re-unwrap");
  assert.equal(afterFirst.parseMtkProfile, afterScan.parseMtkProfile + 1, "one per-card parse");
  assert.equal(afterFirst.generateMtkTables, afterScan.generateMtkTables + 1, "one table build");
  const tables = tablesReply.tables;
  assert.deepEqual(Object.keys(tables), ["lte_ca", "nr_ca", "endc", "nrdc"]);
  assert.ok(isValidTablesShape(tables), "viewer envelope shape");
  assert.equal(tables.endc.length, record.mtk.counts.endc, "ENDC rows match the scan count");
  assert.equal(tables.nr_ca.length, record.mtk.counts.nrca, "NR-CA rows match the scan count");
  assert.equal(tables.lte_ca.length, record.mtk.counts.lte, "LTE rows match the scan count");

  await request({ type: "parseCard", id: 62, sourceId, fileIndex: 0, record }, (m) => m.type === "tables" && m.id === 62);
  const afterReopen = workerModule.getDebugCounters();
  assert.equal(afterReopen.parseMtkProfile, afterFirst.parseMtkProfile, "reopening hits the per-card parse memo");
  assert.equal(afterReopen.generateMtkTables, afterFirst.generateMtkTables, "reopening hits the table cache");
  assert.equal(afterReopen.unwrapMtk, afterFirst.unwrapMtk, "reopening keeps the image memo");

  globalThis.self.onmessage({ data: { type: "release" } });
  await delay(20);
  // release drops the registered sources (the table cache is clearCache's
  // job), so a card that was never parsed must fail loudly on its sourceId.
  const uncached = scan.records[1];
  assert.ok(uncached, "the image carries a second card");
  const reply = await request(
    { type: "parseCard", id: 63, sourceId, fileIndex: 0, record: uncached },
    (m) => m.type === "error" && m.id === 63,
    30000,
  );
  assert.match(reply.message, /unknown sourceId/, "release drops the registered source");
});
