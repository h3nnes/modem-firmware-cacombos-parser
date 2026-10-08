// Analyzer orchestration: record identity + candidate name matching,
// sort/dedup, per-record combo counts, FAT16 and container scanning,
// web-table formatting and CSV/JSON/DIAG exports. scanSource returns
// { records: [], warnings: [{ tool, message }] } for inputs that are neither
// a named MBN nor a FAT16 image. Output values, dict key insertion order,
// iteration order and message strings must stay identical; goldens compare
// key order.
import { sha256HexAsync } from "./hash.js";
import { hex } from "./bytes.js";
import { Fat16Image } from "./fat16.js";
import { Elf32Image, ParseError } from "./elf.js";
import { extractContainer, discoverCandidates, sidecarsInDirectory } from "./extractor.js";
import { isFtab, parseFtabEntriesFromSource, findFtabMemberInBbfw } from "./apple_ftab.js";
import { lzfseDecode } from "./lzfse.js";
import { inspectAppleBank } from "./apple_cr.js";
import {
  rfcardNameFromSymbols,
  findDescriptors,
  legacyTableLabels,
  findLegacyLteArray,
  parseLegacyModule,
  ToolError,
} from "./legacy_parser.js";
import { parseModernModule, countModernCombos, pyCasefold, pyNdInt, pyRegexFold } from "./modern_parser.js";
import { scanMtk } from "./mtk_scan.js";

export { ToolError };

// Cooperative cancellation for the worker's scan (Task 11): scanSource accepts
// an optional { shouldCancel } callback (default no-op, checked between files
// by the worker and per walk iteration here) and throws ScanCancelled so the
// worker can unwind silently. Purely additive: no golden path changes.
export class ScanCancelled extends Error {
  constructor() {
    super("scan cancelled");
    this.name = "ScanCancelled";
  }
}

// --- ModuleRecord -------------------------------------------------------------

// Literal firmware spelling of the file stem.
export function recordIdentity(name) {
  let stem = pyStem(name);
  if (stem.slice(0, 10).toLowerCase() === "rf_config_") stem = stem.slice(10);
  return stem;
}

// Strip the last suffix only ("a.b.c" -> "a.b").
function pyStem(name) {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(0, dot) : name;
}

// int()-style conversion over regex-captured tokens: decimal IDs while
// accepting hexadecimal alphabetic tokens. pyNdInt/pyRegexFold are shared
// with modern_parser.js: \p{Nd} matches Unicode Nd and int() evaluates Nd
// digits, so matching uses \p{Nd} with the ignore-case fold pre-normalized
// and value evaluation via the Nd block table.

function parseIdentityToken(token) {
  const base = /[a-z]/i.test(token) ? 16 : 10;
  return base === 16 ? parseInt(token, 16) : pyNdInt(token);
}

function identityValue(match, field) {
  const token = match.groups[field];
  return token !== undefined ? parseIdentityToken(token) : 0;
}

// --- int()-style conversions used by the web-table formatting -----------------

// Raises on null/undefined/non-integer strings exactly like int() does;
// callers rely on the exception (their catch or crash paths).
function pyInt(value) {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new TypeError(`int() argument must be an integer, not ${value}`);
    return value;
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (!/^[+-]?\d+$/.test(s)) throw new TypeError(`invalid literal for int(): ${value}`);
    return parseInt(s, 10);
  }
  throw new TypeError("int() argument must be a number or numeric string");
}

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

// dict.get(key, default) semantics: default applies only when the key is absent.
const dictGet = (obj, key, fallback) => (hasOwn(obj, key) ? obj[key] : fallback);

// --- name classification ------------------------------------------------------

const MODERN_NAME_RE = /^rf_config_(?<hwid>\p{Nd}+)_(?<fsid>\p{Nd}+)_(?<bid>\p{Nd}+)(?:_(?<rev>\p{Nd}+))?\.mbn$/iu;
const LEGACY_NAME_RE = /^(?<hwid>[0-9A-F]+)_(?<fsid>[0-9A-F]+)(?:_(?<bid>[0-9A-F]+))?\.mbn$/iu;

// Modern first, then legacy; named groups carry the IDs.
export function matchesCandidate(name) {
  const folded = pyRegexFold(name);
  let match = MODERN_NAME_RE.exec(folded);
  if (match) return { generation: "DAT/protobuf", match };
  match = LEGACY_NAME_RE.exec(folded);
  if (match) return { generation: "Legacy ELF", match };
  return null;
}

// --- sort + dedup -------------------------------------------------------------

// Tuple comparison over exact ints: relational operators stay exact for
// mixed Number/BigInt ids (subtraction throws on the mix), matching the
// arbitrary-precision tuple sort key.
const pyCmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

export function sortRecords(records) {
  // Tuple-key sort; JS sort is stable, so equal keys keep their original order.
  return [...records].sort((a, b) => {
    const ka = a.generation === "DAT/protobuf" ? 0 : 1;
    const kb = b.generation === "DAT/protobuf" ? 0 : 1;
    if (ka !== kb) return ka - kb;
    let order = pyCmp(a.hwid, b.hwid);
    if (order !== 0) return order;
    order = pyCmp(a.fsid, b.fsid);
    if (order !== 0) return order;
    order = pyCmp(a.bid, b.bid);
    if (order !== 0) return order;
    const fa = pyCasefold(a.inner_path);
    const fb = pyCasefold(b.inner_path);
    return fa < fb ? -1 : fa > fb ? 1 : 0;
  });
}

export function deduplicateRecords(records) {
  // (name, sha256) keep-first. A falsy digest keeps the record: the webapp
  // cannot re-hash an empty digest, so it is never deduped away.
  const seen = new Set();
  const unique = [];
  for (const record of records) {
    if (!record.sha256) {
      unique.push(record);
      continue;
    }
    const key = `${record.name}\u0000${record.sha256}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(record);
  }
  return unique;
}

// --- combo counts --------------------------------------------------------------

export function comboCounts(record, blob) {
  try {
    if (record.generation === "Legacy ELF" || record.generation === "legacy") {
      const image = new Elf32Image(blob);
      const cardName = rfcardNameFromSymbols(image);
      // LTE CA lives in the separate 50-byte array on generated legacy cards.
      const lteFound = findLegacyLteArray(blob, image);
      const lte = lteFound !== null ? lteFound[2] : 0;
      let descriptors;
      try {
        descriptors = findDescriptors(blob, image);
      } catch (err) {
        if (err instanceof ParseError) {
          if (cardName !== null) return [lte, "0+0+0=0"];
          throw err;
        }
        throw err;
      }
      const labeled = legacyTableLabels(blob, descriptors);
      let endc = 0;
      let nrCa = 0;
      let nrdc = 0;
      for (const [table, descriptor] of labeled) {
        if (table === "endc") endc += descriptor.comboCount;
        else if (table === "nr_ca") nrCa += descriptor.comboCount;
        else if (table === "nrdc") nrdc += descriptor.comboCount;
      }
      const total = endc + nrCa + nrdc;
      return [lte, `${endc}+${nrCa}+${nrdc}=${total}`];
    }
    const counts = countModernCombos(record, blob);
    const lte = hasOwn(counts, "lte_ca") ? counts.lte_ca : 0;
    const endc = hasOwn(counts, "endc") ? counts.endc : 0;
    const nrCa = hasOwn(counts, "nr_ca") ? counts.nr_ca : 0;
    const nrdc = hasOwn(counts, "nrdc") ? counts.nrdc : 0;
    const total = endc + nrCa + nrdc;
    return [lte, `${endc}+${nrCa}+${nrdc}=${total}`];
  } catch {
    return [-1, "—"];
  }
}

// --- module dispatch ------------------------------------------------------------

export function parseModule(record, blob) {
  if (record.generation === "DAT/protobuf" || record.generation === "XML DAT" || record.generation === "modern") {
    return parseModernModule(record, blob);
  }
  if (record.generation === "Legacy ELF" || record.generation === "legacy") {
    return parseLegacyModule(record, blob);
  }
  throw new ToolError(`Unknown RF-card format: ${record.generation}`);
}

// --- source scanning ------------------------------------------------------------

function buildRecord(base, lte, nr) {
  // Field order follows the module-record field declaration (output contract).
  return {
    inner_path: base.inner_path,
    name: base.name,
    generation: base.generation,
    size: base.size,
    hwid: base.hwid,
    fsid: base.fsid,
    bid: base.bid,
    external: base.external,
    source_path: base.source_path,
    sidecars: base.sidecars,
    sha256: base.sha256,
    lte_combos: lte,
    nr_combos: nr,
  };
}

// --- Apple C-series FTAB / bbfw branch (scan: decompress + fast inspect) -------
//
// One card record per CR bank. Card identity = sha256 of the COMPRESSED
// stream (the cardcache key); each bank is decompressed + header-inspected at
// scan (layout and expanded combo counts visible at load),
// while the full table parse stays deferred to card open (worker
// appleBankMemo). Records stay unsorted/deduped here: descriptors are
// already name-sorted, and identical streams dedupe naturally
// downstream (name\0sha256 card keys).

const APPLE_CR_MAGIC = 0x32787662; // bvx2

function isZipHead(head) {
  return head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04;
}

// Apple bank decode+inspect, with an optional parallel path:
// - inspectAppleBankAsync: (stream, uncompSize) => appleInfo. The hook MAY
//   consume/detach `stream` (the pool path transfers a copy), so it is only
//   called after the stream's digest was taken. Default = inline sequential
//   decode (identical records, used by node tests and non-pool scans).
// - onAppleBatch(records, warnings): progressive output. Called whenever a
//   contiguous, in-order prefix of banks completed, so the UI can render rows
//   before the scan finishes. The final return value still carries the FULL
//   record set (batches are informational; receivers dedupe by card key).
// - onAppleProgress(done, total): per-bank scan progress. Called once with
//   (0, total) once the descriptor count is known, then after every bank
//   settles (records AND warned banks count as settled) with the running
//   settled count. Informational only; never affects scan outcomes.
async function scanAppleFtab(source, name, cancelled, { inspectAppleBankAsync, onAppleBatch, onAppleProgress, onAppleMember } = {}) {
  const head = await source.read(0, Math.min(0x30, source.size));
  let descriptors = null;
  let ftabData = null; // inflated ftab member bytes (bbfw) or null (raw ftab)
  let memberName = null;
  if (isFtab(head)) {
    descriptors = await parseFtabEntriesFromSource(source);
  } else if (isZipHead(head)) {
    // bbfw/zip: reuse the container path's central-directory read to find the
    // ftab member, then slice streams from the inflated member bytes. A zip
    // WITHOUT an ftab member is a Qualcomm container, not an Apple input —
    // any failure here (no member, malformed archive) must fall through to
    // the regular FAT/container dispatch below, never abort the scan.
    try {
      ({ data: ftabData, memberName, descriptors } = await findFtabMemberInBbfw(source));
    } catch {
      return null;
    }
  } else {
    return null;
  }
  if (!descriptors.length) return null;
  // Step 3: hand the inflated ftab member back to the scanner so a bbfw card
  // open does not re-read/re-inflate the same zip member (worker seeds
  // appleMemberMemo with it). Only the zip/bbfw path has a member.
  if (ftabData && memberName) onAppleMember?.(ftabData, memberName);
  onAppleProgress?.(0, descriptors.length);

  const inspectBank = inspectAppleBankAsync ?? defaultInspectAppleBank;
  // Per-descriptor outcome (record or warning), emitted strictly in descriptor
  // order: records must keep the name-sorted order even though
  // banks complete out of order under the pool.
  const outcomes = new Array(descriptors.length).fill(null);
  let emitIndex = 0;
  let settled = 0; // banks with a final outcome (records + warned banks alike)
  const records = [];
  const warnings = [];
  const emitBatch = onAppleBatch ?? (() => {});
  const flush = () => {
    if (cancelled()) return; // no emissions past cancel; final reply drops too
    const batch = [];
    const batchWarnings = [];
    while (emitIndex < outcomes.length && outcomes[emitIndex]) {
      const { record, warning } = outcomes[emitIndex++];
      if (warning) {
        warnings.push(warning);
        batchWarnings.push(warning);
      } else {
        records.push(record);
        batch.push(record);
      }
    }
    if (batch.length || batchWarnings.length) emitBatch(batch, batchWarnings);
  };

  // Decompress + fast-inspect each bank (counts and layout
  // are visible at load). Full table parse stays deferred to card open. A bank
  // that fails to decompress/inspect is warned and skipped — never fatal.
  // Banks are independent units; the hook (pool) decides concurrency. The
  // inline default decodes synchronously, so at most one bank is materialized
  // at a time regardless of how many callbacks are parked at their awaits.
  await Promise.all(
    descriptors.map(async (desc, index) => {
      if (cancelled()) return;
      // Settle one bank: store its outcome, then report progress immediately
      // (the hook fires right after the assignment; flush stays exactly where
      // it was, so batch emission semantics are untouched).
      const settle = (outcome) => {
        outcomes[index] = outcome;
        settled += 1;
        onAppleProgress?.(settled, descriptors.length);
      };
      const stream = ftabData
        ? ftabData.subarray(desc.streamStart, desc.streamStart + desc.compSize)
        : await source.read(desc.streamStart, desc.compSize);
      const dv = new DataView(stream.buffer, stream.byteOffset, stream.byteLength);
      if (stream.length < 4 || dv.getUint32(0, true) !== APPLE_CR_MAGIC) {
        settle({
          warning: {
            tool: "apple",
            message: `apple CR bank ${desc.name}: unexpected compression magic — skipped`,
          },
        });
        flush();
        return;
      }
      const digest = await sha256HexAsync(stream);
      try {
        const appleInfo = await inspectBank(stream, desc.uncompSize);
        settle({
          record: {
            inner_path: desc.name,
            name: `${desc.name} (profile 0x${desc.profileId.toString(16).padStart(6, "0")})`,
            generation: "Apple CR",
            size: desc.uncompSize,
            hwid: 0,
            fsid: 0,
            bid: 0,
            external: true,
            source_path: name,
            sidecars: {},
            sha256: digest,
            lte_combos: null,
            nr_combos: null,
            apple: {
              profileId: desc.profileId,
              offset: desc.offset,
              compSize: desc.compSize,
              uncompSize: desc.uncompSize,
              // member-relative offsets when the ftab came from a zip (bbfw)
              member: memberName,
              layout: appleInfo.layout,
              counts: appleInfo.counts,
            },
            combo_counts_deferred: true,
          },
        });
      } catch (err) {
        settle({
          warning: {
            tool: "apple",
            message: `apple CR bank ${desc.name}: unreadable (${err && err.message ? err.message : err}) — skipped`,
          },
        });
      }
      flush();
    }),
  );
  if (cancelled()) throw new ScanCancelled();
  flush();
  if (!records.length && !warnings.length) return null;
  return { records, warnings };
}

function defaultInspectAppleBank(stream, uncompSize) {
  const bank = lzfseDecode(stream, uncompSize);
  const inspected = inspectAppleBank(bank);
  return {
    layout: inspected.layout,
    counts: {
      lte: inspected.lteCount,
      endc: inspected.endcCount,
      nrca: inspected.nrcaCount,
      nrdc: inspected.nrdcCount,
    },
  };
}

export async function scanSource(source, name, { shouldCancel, inspectAppleBankAsync, onAppleBatch, onScanProgress, onCandidate, onAppleMember, onMtkImage } = {}) {
  const cancelled = shouldCancel ?? (() => false);
  const reportProgress = onScanProgress ?? (() => {});
  if (cancelled()) throw new ScanCancelled();
  // Direct-MBN fast path: a file whose NAME already matches a candidate regex.
  // There is no filesystem path in the browser, so the file name stands in
  // for inner_path/source_path.
  const direct = matchesCandidate(name);
  if (direct) {
    const { generation, match } = direct;
    const size = source.size;
    const blob = await source.read(0, size);
    const digest = await sha256HexAsync(blob);
    const base = {
      inner_path: name,
      name,
      generation,
      size,
      hwid: identityValue(match, "hwid"),
      fsid: identityValue(match, "fsid"),
      bid: identityValue(match, "bid"),
      external: true,
      source_path: "",
      sidecars: {},
      sha256: digest,
    };
    const [lte, nr] = comboCounts(base, blob);
    const record = buildRecord(base, lte, nr);
    // Step 3: expose the exact bytes that were hashed so the worker can seed
    // its per-source blob memo and skip re-reading on the first card open.
    onCandidate?.(record, blob);
    return { records: deduplicateRecords([record]), warnings: [] };
  }

  // Apple C-series FTAB / bbfw inputs: one card per CR bank, decompressed +
  // inspected per bank (optionally on the worker pool; see scanAppleFtab).
  // The per-bank settle counter translates onto the shared scan progress hook.
  const appleScan = await scanAppleFtab(source, name, cancelled, {
    inspectAppleBankAsync,
    onAppleBatch,
    onAppleMember,
    onAppleProgress: (done, total) => reportProgress({ stage: "apple", done, total }),
  });
  if (appleScan) return appleScan;

  // MTK DRDI packaged images: one card per (bank, profile). Gated on cheap
  // magic/role heuristics, so unrelated inputs fall through untouched; a
  // cancelled mtk scan returns null and the cancel check below turns that
  // into the shared ScanCancelled unwind.
  const mtkScan = await scanMtk(source, name, cancelled, {
    onScanProgress: (info) => reportProgress(info),
    // Hand the just-decoded parts + summary to the worker so card opens skip
    // the unwrap (scanMtk seeds the memo through this hook).
    onMtkImage: (parts, summary) => onMtkImage?.(parts, summary),
  });
  if (cancelled()) throw new ScanCancelled();
  if (mtkScan) return mtkScan;

  const fat = new Fat16Image(source);
  try {
    await fat.init();
  } catch (err) {
    // Not FAT16: fall back to the universal container extractor.
    try {
      return await scanExtracted(source, name, cancelled, reportProgress, onCandidate);
    } catch (extractErr) {
      if (extractErr instanceof ScanCancelled) throw extractErr;
      return {
        records: [],
        warnings: [
          {
            tool: "container",
            message: `Input is neither a named RF MBN nor a supported FAT16 modem image; container extraction also failed: ${extractErr.message}`,
          },
        ],
      };
    }
  }

  const records = [];
  if (cancelled()) throw new ScanCancelled();
  // walk() resolves to a full entry array before any record work starts, so
  // the candidate list (and thus the count-stage total) is known upfront.
  // The gates below are the exact per-entry filters the old loop applied,
  // just hoisted: matchesCandidate non-null, and legacy ELF modules only
  // under the modem's /so tree.
  const entries = await fat.walk();
  const targets = [];
  for (const entry of entries) {
    // walk() entries carry the path only; the file name is the last segment
    // (path = parent + "/" + entry.name).
    const fileName = entry.path.slice(entry.path.lastIndexOf("/") + 1);
    const matchInfo = matchesCandidate(fileName);
    if (!matchInfo) continue;
    const { generation, match } = matchInfo;
    // Numeric legacy modules are meaningful only under the modem's /so tree.
    if (generation === "Legacy ELF" && !pyCasefold(entry.path).includes("/so/")) continue;
    targets.push({ entry, fileName, generation, match });
  }
  // Per-record combo counting is the slow loop; report the total before the
  // first record so the UI can show a real fraction.
  if (targets.length > 0) reportProgress({ stage: "count", done: 0, total: targets.length });
  for (let i = 0; i < targets.length; i++) {
    const { entry, fileName, generation, match } = targets[i];
    if (cancelled()) throw new ScanCancelled();
    // The raw cluster chain is read and sliced to the directory size: no size
    // validation, and the chain is walked even for size 0, so corrupt entries
    // are read instead of being skipped.
    const raw = (await fat.readClusters(entry.firstCluster)).slice(0, entry.size);
    const digest = await sha256HexAsync(raw);
    const base = {
      inner_path: entry.path,
      name: fileName,
      generation,
      size: entry.size,
      hwid: identityValue(match, "hwid"),
      fsid: identityValue(match, "fsid"),
      bid: identityValue(match, "bid"),
      external: false,
      source_path: "",
      sidecars: {},
      sha256: digest,
    };
    const [lte, nr] = comboCounts(base, raw);
    const record = buildRecord(base, lte, nr);
    records.push(record);
    // Step 3: the exact cluster-chain bytes that were hashed become the
    // worker's per-source blob memo entry (no second read on card open).
    onCandidate?.(record, raw);
    reportProgress({ stage: "count", done: i + 1, total: targets.length });
  }
  return { records: deduplicateRecords(sortRecords(records)), warnings: [] };
}

// --- container fallback ---------------------------------------------------------

async function scanExtracted(source, name, cancelled = () => false, onScanProgress = () => {}, onCandidate = null) {
  if (cancelled()) throw new ScanCancelled();
  // Extraction is the uncountable phase (a black-box unpacker with no known
  // output count); report it as its own stage so the UI can label the wait.
  onScanProgress?.({ stage: "extract" });
  // Inputs below the 512-byte container floor raise; extraction warnings
  // (missing tools, unsupported containers) are collected alongside the
  // records.
  const { outputs, warnings } = await extractContainer(source, name);
  const { mbns, sidecars } = discoverCandidates(outputs);
  // Same gate hoist as the FAT16 path: pre-filter with the exact gates the
  // loop below used inline, so the count stage's total is post-gate and the
  // label always lands on "counting N/N". Pure in-memory checks, no awaits.
  const targets = [];
  for (const { vfile, path } of mbns) {
    const matchInfo = matchesCandidate(vfile.name);
    if (!matchInfo) continue;
    const { generation, match } = matchInfo;
    // Numeric legacy MBNs need a "so"/"rfcards" path segment;
    // the "rfcards" allowance exists for Apple BBCFG recovery.
    const parts = new Set(pyCasefold(path).split("/").filter(Boolean));
    if (generation === "Legacy ELF" && !parts.has("so") && !parts.has("rfcards")) continue;
    targets.push({ vfile, path, generation, match });
  }
  const records = [];
  // Per-MBN combo counting is the slow loop; report the total before the
  // first record so the UI can show a real fraction.
  if (targets.length > 0) onScanProgress?.({ stage: "count", done: 0, total: targets.length });
  for (let index = 0; index < targets.length; index++) {
    if (cancelled()) throw new ScanCancelled();
    const { vfile, path, generation, match } = targets[index];
    const blob = await vfile.read();
    const digest = await sha256HexAsync(blob);
    const base = {
      inner_path: path,
      name: vfile.name,
      generation,
      size: vfile.size,
      hwid: identityValue(match, "hwid"),
      fsid: identityValue(match, "fsid"),
      bid: identityValue(match, "bid"),
      external: true,
      source_path: "",
      sidecars: sidecarsInDirectory(path, sidecars),
      sha256: digest,
    };
    const [lte, nr] = comboCounts(base, blob);
    const record = buildRecord(base, lte, nr);
    records.push(record);
    // Step 3: seed the worker's per-source blob memo with the extracted bytes.
    onCandidate?.(record, blob);
    onScanProgress?.({ stage: "count", done: index + 1, total: targets.length });
  }
  // The sorted order is identical to discovery order for every golden record
  // and deterministic across runs.
  return { records: deduplicateRecords(sortRecords(records)), warnings };
}

// --- record JSON ----------------------------------------------------------------

// Extracted-container scratch dirs (tool-generated tag prefixes) are
// normalized to the bare tag so goldens are deterministic.
const SCRATCH_DIR_RE = /^(fat|sparse|zip|tar|gzip|zstd|xz|lz4|super|payload|squashfs|erofs|ext4|7z)_[A-Za-z0-9_]+$/;

export function normalizeInnerPath(innerPath) {
  const slash = innerPath.indexOf("/");
  if (slash !== -1) {
    const m = SCRATCH_DIR_RE.exec(innerPath.slice(0, slash));
    if (m) return `${m[1]}/${innerPath.slice(slash + 1)}`;
  }
  return innerPath;
}

export function recordJson(record) {
  return {
    name: record.name,
    inner_path: normalizeInnerPath(record.inner_path),
    generation: record.generation,
    identity: recordIdentity(record.name),
    size: record.size,
    sha256: record.sha256,
    external: record.external,
    lte_combos: record.lte_combos,
    nr_combos: record.nr_combos,
    sidecars: record.sidecars ? { ...record.sidecars } : {},
  };
}

// --- web-table formatting helpers ----------------------------------------------

export function formatScsVal(scsCode) {
  try {
    const c = pyInt(scsCode);
    if (c > 0) {
      // The value is a plain decimal at any magnitude; doubles go exponential
      // >= 1e21, so render via BigInt above 2**30 and take the fast Number
      // path below it (exact up to 2**53).
      return c - 1 > 30 ? (2n ** BigInt(c - 1) * 15n).toString() : String(2 ** (c - 1) * 15);
    }
  } catch {
    // int(None) ValueError -> fall through
  }
  return "15";
}

export function formatQamVal(qamCode) {
  try {
    return pyInt(qamCode) === 2 ? "256" : "64";
  } catch {
    return "256";
  }
}

export function formatBcs(bcsNum) {
  // null/undefined stringify as "None".
  const s = String(bcsNum === null || bcsNum === undefined ? "None" : bcsNum).trim();
  return ["", "None", "-1"].includes(s) ? "All" : s;
}

export function formatUlTxSwitch(switchType) {
  try {
    const t = pyInt(switchType);
    if (t === 1) return "option 1";
    if (t === 2) return "option 2";
    if (t === 3) return "option 1,2";
  } catch {
    // int(None) ValueError -> "-"
  }
  return "-";
}

export function formatMimo(antStr) {
  if (!antStr || String(antStr).startsWith("INDEX_")) return "1";
  return String(antStr).replaceAll("_", " + ");
}

export function formatBw(bwStr) {
  if (!bwStr) return "";
  const out = String(bwStr).replaceAll("_", " + ");
  return out.endsWith(" MHz") ? out.slice(0, -4) : out;
}

export function formatScsForComp(comp, isUl = false) {
  const baseScs = formatScsVal(comp.max_scs);
  const bw = dictGet(comp, isUl ? "ul_bandwidth" : "dl_bandwidth", "");
  const bwClass = dictGet(comp, isUl ? "ul_bw_class" : "dl_bw_class", "A");
  let ccs;
  if (bw.includes("_")) ccs = bw.split("_").length;
  else if (bwClass === "B" || bwClass === "C") ccs = 2;
  else if (bwClass === "D") ccs = 3;
  else if (bwClass === "E") ccs = 4;
  else if (bwClass === "F") ccs = 5;
  else ccs = 1;
  return Array(ccs).fill(baseScs).join(" + ");
}

export function componentSortKey(comp, isUl = false) {
  let band;
  try {
    band = pyInt(dictGet(comp, "band", 0));
  } catch {
    band = 0;
  }
  const raw = dictGet(comp, isUl ? "ul_bw_class" : "dl_bw_class", "");
  const bwClass = raw || "";
  return [band, String(bwClass)];
}

// Descending sort must stay stable (equal keys keep their original order),
// so the comparator swaps argument order instead of reversing the sorted
// list.
function byComponentSortKeyDesc(isUl) {
  return (a, b) => {
    const [bandA, clsA] = componentSortKey(a, isUl);
    const [bandB, clsB] = componentSortKey(b, isUl);
    if (bandA !== bandB) return bandB - bandA;
    return clsA < clsB ? 1 : clsA > clsB ? -1 : 0;
  };
}

export function hasRealBcs(combos) {
  return combos.some((c) => {
    const val = dictGet(c, "bcs_num", null);
    return val !== null && val !== undefined && !["", "0", "None", "-1"].includes(String(val).trim());
  });
}

export function normalizeLegacyComponent(comp) {
  // Maps legacy parser sentinel values onto the modern component schema. The
  // copy is lazy: components that are already modern (the overwhelming majority)
  // are returned unchanged instead of being spread tens of thousands of times.
  let out = null;
  for (const key of ["dl_bw_class", "ul_bw_class"]) {
    if (comp[key] === "NONE") {
      if (out === null) out = { ...comp };
      out[key] = "-";
    }
  }
  for (const key of ["dl_antenna", "ul_antenna"]) {
    const ant = comp[key];
    if (typeof ant === "string") {
      if (ant === "NONE") {
        if (out === null) out = { ...comp };
        out[key] = "INDEX_0";
      } else if (ant.startsWith("ANTENNA_")) {
        if (out === null) out = { ...comp };
        out[key] = ant.slice("ANTENNA_".length);
      }
    }
  }
  return out ?? comp;
}

// --- web-table generation --------------------------------------------------------

const BAD_BW_CLASS = ["-", "0", "", "None"];

const hasBwClass = (x, key) => {
  const v = dictGet(x, key, null);
  return v !== null && v !== undefined && !BAD_BW_CLASS.includes(v);
};

const qamCell = (comps) => {
  if (comps.every((x) => formatQamVal(x.ul_qam_cap_index) === "256")) return "256";
  return comps.length ? comps.map((x) => formatQamVal(x.ul_qam_cap_index)).join(" + ") : "";
};

export function generateWebTables(combinations, components) {
  components = components.map(normalizeLegacyComponent);
  const compsByTblIdx = new Map(); // table -> Map(combo_index -> components)
  for (const comp of components) {
    const tbl = comp.table;
    const idx = pyInt(comp.combo_index);
    if (!compsByTblIdx.has(tbl)) compsByTblIdx.set(tbl, new Map());
    const byIdx = compsByTblIdx.get(tbl);
    if (!byIdx.has(idx)) byIdx.set(idx, []);
    byIdx.get(idx).push(comp);
  }
  const compsFor = (tbl, idx) => {
    const byIdx = compsByTblIdx.get(tbl);
    return byIdx && byIdx.has(idx) ? byIdx.get(idx) : [];
  };

  const hasEndcBcs = hasRealBcs(combinations.filter((c) => c.table === "endc"));
  const hasNrcaBcs = hasRealBcs(combinations.filter((c) => c.table === "nr_ca"));
  const hasLtecaBcs = hasRealBcs(combinations.filter((c) => c.table === "lte_ca"));
  const hasNrdcBcs = hasRealBcs(combinations.filter((c) => c.table === "nrdc"));

  const endcRows = [];
  const nrcaRows = [];
  const ltecaRows = [];
  const nrdcRows = [];

  for (const c of combinations) {
    const tbl = c.table;
    const idx = pyInt(c.combo_index);
    const compList = compsFor(tbl, idx);
    const bcs = formatBcs(dictGet(c, "bcs_num", "0"));

    if (tbl === "endc") {
      const lteComps = compList.filter((x) => x.technology === "LTE" && hasBwClass(x, "dl_bw_class")).sort(byComponentSortKeyDesc(false));
      const nrComps = compList.filter((x) => x.technology === "NR" && hasBwClass(x, "dl_bw_class")).sort(byComponentSortKeyDesc(false));
      const lteUl = compList.filter((x) => x.technology === "LTE" && hasBwClass(x, "ul_bw_class")).sort(byComponentSortKeyDesc(true));
      const nrUl = compList.filter((x) => x.technology === "NR" && hasBwClass(x, "ul_bw_class")).sort(byComponentSortKeyDesc(true));

      const row = {
        "LTE DL": lteComps.map((x) => `${x.band}${x.dl_bw_class}`).join(" + "),
        "LTE MIMO DL": lteComps.map((x) => formatMimo(x.dl_antenna)).join(" + "),
        "LTE DL (QAM)": "256",
        "NR DL": nrComps.map((x) => `${x.band}${x.dl_bw_class}`).join(" + "),
        "NR MIMO DL": nrComps.map((x) => formatMimo(x.dl_antenna)).join(" + "),
        "NR DL (QAM)": "256",
        "NR SCS DL (kHz)": nrComps.map((x) => formatScsForComp(x, false)).join(" + "),
        "NR BW DL (MHz)": nrComps.map((x) => formatBw(dictGet(x, "dl_bandwidth", ""))).join(" + "),
        "LTE UL": lteUl.map((x) => `${x.band}${x.ul_bw_class}`).join(" + "),
        "LTE MIMO UL": lteUl.map((x) => formatMimo(x.ul_antenna)).join(" + "),
        "LTE UL (QAM)": qamCell(lteUl),
        "NR UL": nrUl.map((x) => `${x.band}${x.ul_bw_class}`).join(" + "),
        "NR MIMO UL": nrUl.map((x) => formatMimo(x.ul_antenna)).join(" + "),
        "NR UL (QAM)": qamCell(nrUl),
        "NR SCS UL (kHz)": nrUl.map((x) => formatScsForComp(x, true)).join(" + "),
        "NR BW UL (MHz)": nrUl.map((x) => formatBw(dictGet(x, "ul_bandwidth", ""))).join(" + "),
      };
      if (hasEndcBcs) {
        row["BCS LTE"] = bcs;
        row["BCS NR"] = bcs;
        row["BCS INTRA ENDC"] = "";
      }
      endcRows.push(row);
    } else if (tbl === "nr_ca") {
      const nrDl = compList.filter((x) => hasBwClass(x, "dl_bw_class")).sort(byComponentSortKeyDesc(false));
      const nrUl = compList.filter((x) => hasBwClass(x, "ul_bw_class")).sort(byComponentSortKeyDesc(true));
      const row = {
        "NR DL": nrDl.map((x) => `${x.band}${x.dl_bw_class}`).join(" + "),
        "MIMO DL": nrDl.map((x) => formatMimo(x.dl_antenna)).join(" + "),
        "DL (QAM)": "256",
        "SCS DL (kHz)": nrDl.map((x) => formatScsForComp(x, false)).join(" + "),
        "BW DL (MHz)": nrDl.map((x) => formatBw(dictGet(x, "dl_bandwidth", ""))).join(" + "),
        "NR UL": nrUl.map((x) => `${x.band}${x.ul_bw_class}`).join(" + "),
        "MIMO UL": nrUl.map((x) => formatMimo(x.ul_antenna)).join(" + "),
        "UL (QAM)": qamCell(nrUl),
        "SCS UL (kHz)": nrUl.map((x) => formatScsForComp(x, true)).join(" + "),
        "BW UL (MHz)": nrUl.map((x) => formatBw(dictGet(x, "ul_bandwidth", ""))).join(" + "),
        "UL TX Switch": formatUlTxSwitch(dictGet(c, "ul_tx_switch_type", null)),
      };
      if (hasNrcaBcs) {
        row["BCS"] = bcs;
      }
      nrcaRows.push(row);
    } else if (tbl === "lte_ca") {
      const lteDl = compList.filter((x) => hasBwClass(x, "dl_bw_class")).sort(byComponentSortKeyDesc(false));
      const lteUl = compList.filter((x) => hasBwClass(x, "ul_bw_class")).sort(byComponentSortKeyDesc(true));
      const row = {
        "LTE DL": lteDl.map((x) => `${x.band}${x.dl_bw_class}`).join(" + "),
        "MIMO DL": lteDl.map((x) => formatMimo(x.dl_antenna)).join(" + "),
        "DL (QAM)": "256",
        "LTE UL": lteUl.map((x) => `${x.band}${x.ul_bw_class}`).join(" + "),
        "MIMO UL": lteUl.map((x) => formatMimo(x.ul_antenna)).join(" + "),
        "UL (QAM)": qamCell(lteUl),
      };
      if (hasLtecaBcs) {
        row["BCS"] = bcs;
      }
      ltecaRows.push(row);
    } else if (tbl === "nrdc") {
      const isFr1 = (x) => pyInt(dictGet(x, "band", 0)) < 257;
      const fr1Dl = compList.filter((x) => isFr1(x) && hasBwClass(x, "dl_bw_class")).sort(byComponentSortKeyDesc(false));
      const fr2Dl = compList.filter((x) => !isFr1(x) && hasBwClass(x, "dl_bw_class")).sort(byComponentSortKeyDesc(false));
      const fr1Ul = compList.filter((x) => isFr1(x) && hasBwClass(x, "ul_bw_class")).sort(byComponentSortKeyDesc(true));
      const fr2Ul = compList.filter((x) => !isFr1(x) && hasBwClass(x, "ul_bw_class")).sort(byComponentSortKeyDesc(true));
      const row = {
        "FR1 DL": fr1Dl.map((x) => `${x.band}${x.dl_bw_class}`).join(" + "),
        "FR1 MIMO DL": fr1Dl.map((x) => formatMimo(x.dl_antenna)).join(" + "),
        "FR1 DL (QAM)": fr1Dl.length ? "256" : "",
        "FR1 SCS DL (kHz)": fr1Dl.map((x) => formatScsForComp(x, false)).join(" + "),
        "FR1 BW DL (MHz)": fr1Dl.map((x) => formatBw(dictGet(x, "dl_bandwidth", ""))).join(" + "),
        "FR2 DL": fr2Dl.map((x) => `${x.band}${x.dl_bw_class}`).join(" + "),
        "FR2 MIMO DL": fr2Dl.map((x) => formatMimo(x.dl_antenna)).join(" + "),
        "FR2 DL (QAM)": fr2Dl.length ? "256" : "",
        "FR2 SCS DL (kHz)": fr2Dl.map((x) => formatScsForComp(x, false)).join(" + "),
        "FR2 BW DL (MHz)": fr2Dl.map((x) => formatBw(dictGet(x, "dl_bandwidth", ""))).join(" + "),
        "FR1 UL": fr1Ul.map((x) => `${x.band}${x.ul_bw_class}`).join(" + "),
        "FR1 MIMO UL": fr1Ul.map((x) => formatMimo(x.ul_antenna)).join(" + "),
        "FR1 UL (QAM)": qamCell(fr1Ul),
        "FR1 SCS UL (kHz)": fr1Ul.map((x) => formatScsForComp(x, true)).join(" + "),
        "FR1 BW UL (MHz)": fr1Ul.map((x) => formatBw(dictGet(x, "ul_bandwidth", ""))).join(" + "),
        "FR2 UL": fr2Ul.map((x) => `${x.band}${x.ul_bw_class}`).join(" + "),
        "FR2 MIMO UL": fr2Ul.map((x) => formatMimo(x.ul_antenna)).join(" + "),
        "FR2 UL (QAM)": qamCell(fr2Ul),
        "FR2 SCS UL (kHz)": fr2Ul.map((x) => formatScsForComp(x, true)).join(" + "),
        "FR2 BW UL (MHz)": fr2Ul.map((x) => formatBw(dictGet(x, "ul_bandwidth", ""))).join(" + "),
      };
      if (hasNrdcBcs) {
        row["BCS"] = bcs;
      }
      nrdcRows.push(row);
    }
  }

  return {
    lte_ca: ltecaRows,
    nr_ca: nrcaRows,
    endc: endcRows,
    nrdc: nrdcRows,
  };
}

// --- CSV/JSON exports ------------------------------------------------------------

// Excel formula guard: formula-lookalike cells (the leading "=" is the
// marker) become ="..." with the payload wrapped, then csv-quoted
// (QUOTE_MINIMAL). Plain values pass through.
export function csvField(value) {
  if (value === null || value === undefined) return "";
  let s = typeof value === "string" ? value : String(value);
  if (s.startsWith("=")) s = `="${s.slice(1)}"`;
  if (/[",\r\n]/.test(s)) s = `"${s.replaceAll('"', '""')}"`;
  return s;
}

// Container values are JSON-dumped compactly.
function csvCell(value) {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value) || typeof value === "object") return JSON.stringify(value);
  return value;
}

// Header is the first-seen key union over all rows, utf-8-sig BOM, CRLF line
// endings, missing keys write empty fields.
export function toCsvText(rows) {
  if (!rows || rows.length === 0) return null;
  const fields = [];
  const seen = new Set();
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      if (!seen.has(key)) {
        seen.add(key);
        fields.push(key);
      }
    }
  }
  const lines = [fields.map(csvField).join(",")];
  for (const row of rows) {
    lines.push(fields.map((f) => csvField(hasOwn(row, f) ? csvCell(row[f]) : "")).join(","));
  }
  return "\uFEFF" + lines.join("\r\n") + "\r\n";
}

// Drops the diag section from the parsed result.
function jsonSafe(parsed) {
  const out = {};
  for (const key of Object.keys(parsed)) {
    if (key !== "diag") out[key] = parsed[key];
  }
  return out;
}

// Writes {stem}_all_combos.json (indent=2 + trailing newline),
// {stem}_combinations.csv + {stem}_components.csv, the per-table web CSVs, and
// the 0xB0CD/0xB826 DIAG payload hexdumps through writeDiagText. Every
// produced file comes back as { filename, text }. "mbn" (raw blob dump) is
// handled by the UI layer, which owns the blob.
export function exportModule(record, parsed, format) {
  const stem = pyStem(record.name);
  const files = [];

  if (format === "json") {
    const text = JSON.stringify(jsonSafe(parsed), (key, value) => (typeof value === "bigint" ? value.toString() : value), 2) + "\n";
    files.push({ filename: `${stem}_all_combos.json`, text });
    return files;
  }

  if (format === "csv") {
    for (const [suffix, rows] of [["combinations", parsed.combinations], ["components", parsed.components]]) {
      const text = toCsvText(rows);
      if (text !== null) files.push({ filename: `${stem}_${suffix}.csv`, text });
    }
    return files;
  }

  if (format === "webcsv") {
    const tables = generateWebTables(parsed.combinations, parsed.components);
    const names = { lte_ca: "lteca", nr_ca: "nrca", endc: "endc", nrdc: "nrdc" };
    for (const table of ["lte_ca", "nr_ca", "endc", "nrdc"]) {
      if (!tables[table] || tables[table].length === 0) continue;
      const text = toCsvText(tables[table]);
      if (text !== null) files.push({ filename: `${stem}_${names[table]}.csv`, text });
    }
    return files;
  }

  if (format === "b0cd" || format === "b826") {
    // {stem}_0xB0CD_v41.txt / {stem}_0xB826_v22.txt. A diag-less parsed result
    // raises the shared ToolError instead of failing on a missing key.
    const logCode = format === "b0cd" ? "0xB0CD" : "0xB826";
    const version = format === "b0cd" ? 41 : 22;
    const packets = parsed.diag && parsed.diag[format];
    if (!Array.isArray(packets)) {
      throw new ToolError(`No DIAG packets were parsed for the ${logCode} export`);
    }
    files.push({ filename: `${stem}_${logCode}_v${version}.txt`, text: writeDiagText(logCode, version, packets) });
    return files;
  }

  throw new ToolError(`Unsupported export format: ${format}`);
}

// DIAG text writer (no file IO): lines joined with "\n", a blank line after
// every packet, ASCII-only by construction. The payload hex uses the bytes.js
// lowercase hex().
function writeDiagText(logCode, version, packets) {
  const lines = [
    "# Headerless Qualcomm DIAG payloads reconstructed from static RF tables.",
    `# Log ${logCode}, payload version ${version}; one Payload block per packet.`,
    "",
  ];
  for (const [label, payload] of packets) {
    lines.push(`# ${label}`, `Payload: ${hex(payload)}`, "");
  }
  return lines.join("\n");
}
