// Workbench UI (Task 11 Step 5): drag-drop + file picker import, progress bar
// bound to worker "progress" messages, cancel, record list (name, HWID
// identity, generation, LTE/NR counts), detect-and-warn warnings panel and the
// IndexedDB card-table cache (sha256-keyed). All parsing lives in worker.js;
// this module only handles JSON rows, exactly like the viewer contract.
import { ComboViewer, resetViewerState } from "./viewer.js";
import { compareCards } from "./compare.js";
import { download, downloadBytes } from "./exporter.js";
import {
  buildExportJobs,
  decodeExportBytes,
  deliveryMode,
  dedupeFilenames,
} from "./exportplan.js";
import { zipSync } from "../lib/vendor/fflate.js";
import { uniqueFileNames } from "./loadedfiles.js";
import { PARSER_BASE, buildImportEntries, resultUrl } from "./importparser.js";
import {
  MIN_CARD_PANE_PX,
  SPLITTER_STORAGE_KEY,
  STACKED_MEDIA_QUERY,
  applyStackedState,
  clampSplitterWidth,
  maxCardPaneWidth,
  parseStoredWidth,
  shouldDrag,
} from "./splitter.js";
import { recordIdentity, normalizeInnerPath } from "./lib/analyzer.js";

const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });

// ?debug turns on the worker's Step 0 instrumentation counters: every reply then
// carries a debugCounters snapshot, so a Chrome/Firefox console can assert that
// extraction/parsing happens once per source. No effect without the query flag.
if (typeof location !== "undefined" && new URLSearchParams(location.search).has("debug")) {
  worker.postMessage({ type: "debug", enabled: true, reset: true });
}

// IndexedDB no longer lives on the main thread: the worker owns the parsed-table
// cache (Step 5) so multi-MB tables are never structured-cloned here.

const els = {
  dropzone: document.getElementById("dropzone"),
  pickBtn: document.getElementById("pick-btn"),
  clearBtn: document.getElementById("clear-btn"),
  fileInput: document.getElementById("file-input"),
  progressWrap: document.getElementById("progresswrap"),
  progress: document.getElementById("progress"),
  progressLabel: document.getElementById("progress-label"),
  cancelBtn: document.getElementById("cancel-btn"),
  compareBtn: document.getElementById("compare-btn"),
  warnings: document.getElementById("warnings"),
  loadedFiles: document.getElementById("loadedfiles"),
  loadedFilesLabel: document.getElementById("loadedfiles-label"),
  loadedFilesChips: document.getElementById("loadedfiles-chips"),
  cardBody: document.getElementById("cardlist-body"),
  cardHead: document.getElementById("cardlist-head"),
  cardsEmpty: document.getElementById("cards-empty"),
  viewerHost: document.getElementById("viewerhost"),
  viewerPlaceholder: document.getElementById("viewer-placeholder"),
  workbench: document.getElementById("workbench"),
  cardPane: document.getElementById("cardpane"),
  splitter: document.getElementById("splitter"),
  splitterGhost: document.getElementById("splitter-ghost"),
  exportbar: document.getElementById("exportbar"),
  selectAllBtn: document.getElementById("select-all-btn"),
  deselectAllBtn: document.getElementById("deselect-all-btn"),
  exportTickedBtn: document.getElementById("export-ticked-btn"),
  importParserBtn: document.getElementById("import-parser-btn"),
  importDoneTick: document.getElementById("import-done-tick"),
  importResults: document.getElementById("import-results"),
  exportStatus: document.getElementById("export-status"),
};

// --- state ---------------------------------------------------------------------

const GENERATION_DISPLAY = { "DAT/protobuf": "XML DAT" };

const cards = []; // { record, sourceId, fileIndex, key }; sourceId identifies the File in the worker
const cardKeys = new Set(); // name\0sha256 dedupe across imports
const cardsByKey = new Map(); // card key -> card (row clicks / dedupe)
const checked = new Set(); // card keys (compare selection)
const loadedFiles = []; // distinct source-file names, first appearance first (chips)
let scanEntries = []; // [{ sourceId, file }] snapshot of the scan in flight/last completed
let nextSourceId = 1; // monotonically increasing; NEVER reused (cards accumulate across imports)
// Incremental card list: rows are keyed by card key and only appended; the
// header/rows are rebuilt only when the all-MTK vs all-Apple vs mixed/Qualcomm
// layout flips. Progressive Apple batches coalesce into one requestAnimationFrame.
const cardRows = new Map(); // card key -> HTMLTableRowElement
let cardListLayout = null; // "mtk" | "apple" | "qcom" currently rendered
let cardListRaf = null;
let sessionEpoch = 0; // bumped by Clear; worker replies from an earlier epoch are dropped
let scanEpoch = 0; // epoch of the scan whose replies are currently arriving
let currentScanId = 0;
let nextMessageId = 1;
let selectedCard = null;
let viewer = null;
let pendingView = null; // { cardKey }
let pendingCompare = null; // { want, have: [{label, tables}], missing: Set }
// Worker request id -> card. Correlates tables/exportBlob/error replies by the
// echoed id instead of (fileIndex, record name): names collide across imports
// and a card's fileIndex alone can point at a different file after a later
// scan. Entries are removed when the reply (or an error with that id) arrives.
const pendingReplies = new Map();
// Worker request id -> { resolve, reject } for batch-export requests; a batch
// awaits each reply before sending the next (sequential, per-card progress).
const exportWaiters = new Map();
let exporting = false; // batch export in flight (blocks re-entry)
let progressHideTimer = null; // post-completion hide timer (Rec-2)
let exportStatusTimer = null; // export bar flash hide timer

// --- helpers ---------------------------------------------------------------------

function cardKeyOf(record) {
  return `${record.name}\u0000${record.sha256 ?? ""}`;
}

function addWarning(tool, message, source) {
  els.warnings.hidden = false;
  const div = document.createElement("div");
  div.className = "warning";
  const prefix = source ? `${tool} (${source})` : tool;
  const b = document.createElement("strong");
  b.textContent = `[${prefix}] `;
  div.appendChild(b);
  div.appendChild(document.createTextNode(message));
  els.warnings.appendChild(div);
}

function setProgress(done, total, currentFile, detail) {
  // A new scan (or any per-file progress) must cancel a pending post-completion
  // hide timer, or the bar vanishes mid-scan (Rec-2).
  if (progressHideTimer !== null) {
    clearTimeout(progressHideTimer);
    progressHideTimer = null;
  }
  els.progressWrap.hidden = false;
  els.progress.max = Math.max(1, total);
  if (detail && currentFile) {
    // Unit-level detail ("banks 23/58", "counting 4/9", "extracting"): the bar
    // stays file-fraction based — the sub-file fraction from the trailing
    // "a/b" is added to the whole-file `done` (progress elements accept
    // floats). "extracting" carries no fraction, so the value stays at done.
    const m = /(\d+)\s*\/\s*(\d+)$/.exec(detail);
    els.progress.value = m && Number(m[2]) > 0 ? done + Number(m[1]) / Number(m[2]) : done;
    els.progressLabel.textContent = `Scanning ${currentFile} — ${detail}`;
  } else {
    els.progress.value = done;
    els.progressLabel.textContent = currentFile
      ? `Scanning ${currentFile} — ${done.toLocaleString("en-US")}/${total.toLocaleString("en-US")}`
      : `Scan complete — ${total.toLocaleString("en-US")} file(s)`;
  }
  els.cancelBtn.hidden = currentFile === "";
  if (currentFile === "") {
    progressHideTimer = setTimeout(() => {
      progressHideTimer = null;
      els.progressWrap.hidden = true;
    }, 2500);
  }
}

// Export bar status (same flash pattern as the viewer's status line). Progress
// updates pass sticky: true so the message survives a slow parse mid-batch;
// the final message auto-hides.
function exportStatus(message, { sticky = false } = {}) {
  clearTimeout(exportStatusTimer);
  exportStatusTimer = null;
  els.exportStatus.textContent = message;
  els.exportStatus.hidden = false;
  if (!sticky) {
    exportStatusTimer = setTimeout(() => {
      exportStatusTimer = null;
      els.exportStatus.hidden = true;
    }, 4000);
  }
}

function renderLoadedFiles() {
  els.loadedFilesChips.replaceChildren();
  els.loadedFiles.hidden = loadedFiles.length === 0;
  if (!loadedFiles.length) return;
  // Count when >1: "Loaded files (3):" — muted like the other bar labels.
  els.loadedFilesLabel.textContent =
    loadedFiles.length > 1 ? `Loaded files (${loadedFiles.length}):` : "Loaded files:";
  for (const name of loadedFiles) {
    const chip = document.createElement("span");
    chip.className = "loadedfile-chip";
    chip.textContent = name;
    els.loadedFilesChips.appendChild(chip);
  }
}

// Human-readable size: one decimal for KB/MB/GB,
// integer bytes for B, em dash for missing.
function humanSize(size) {
  if (size == null) return "—";
  let value = size;
  for (const unit of ["B", "KB", "MB", "GB"]) {
    if (value < 1024 || unit === "GB") {
      return unit === "B"
        ? `${value.toLocaleString("en-US")} B`
        : `${value.toLocaleString("en-US", { minimumFractionDigits: 1, maximumFractionDigits: 1 })} ${unit}`;
    }
    value /= 1024;
  }
  return String(value);
}

const APPLE_LAYOUT_DESC = { C4000: "C1/C1X (C4000)", C4020: "C2 (C4020)" };
const CARDLIST_HEAD_QCOM =
  '<th></th><th>Name</th><th>HWID_FSID_BID</th><th>Format</th><th>LTE combos</th><th>NR combos</th>';
const CARDLIST_HEAD_APPLE =
  '<th></th><th>CR Bank</th><th>Layout</th><th>Profile ID</th><th>LTE</th><th>EN-DC</th><th>NR-CA</th><th>NRDC</th><th>File Size</th><th>Source Path</th>';
const CARDLIST_HEAD_MTK =
  '<th></th><th>Bank</th><th>Profile</th><th>EN-DC</th><th>NR-CA</th><th>NR-SA</th><th>NR-DC</th><th>LTE CA</th><th>File Size</th><th>Source Path</th>';

function buildCardRow(card, layout) {
  const record = card.record;
  const tr = document.createElement("tr");
  tr.className = card.key === (selectedCard && selectedCard.key) ? "selected" : "";
  tr.dataset.cardKey = card.key;
  const identity = recordIdentity(record.name);
  const tdCheck = document.createElement("td");
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.checked = checked.has(card.key);
  checkbox.setAttribute("aria-label", `Select ${identity || record.name} (compare & export)`);
  tdCheck.appendChild(checkbox);
  tr.appendChild(tdCheck);

  // Apple CR rows keep their scan-time counts in record.apple.counts (their
  // lte_combos/nr_combos stay null: combo-table parsing is deferred to card
  // open). MTK rows keep theirs in record.mtk.counts the same way. When such
  // rows render under the qcom column layout (mixed imports), derive the combo
  // cells from the scan counts instead of showing "—": LTE as a plain count
  // and NR as the qcom endc+nrca+nrdc=total format (NSA=EN-DC, SA=NR-CA,
  // NR-DC=NRDC).
  const appleCounts = record.apple ? record.apple.counts : null;
  const mtkCounts = record.mtk ? record.mtk.counts : null;
  // nr_sa is the MediaTek single-carrier column; folded into the NR-CA bucket
  // of the qcom-style "endc+nrca+nrdc=total" summary (SA=NR-CA there).
  const mtkTotal = mtkCounts ? mtkCounts.endc + mtkCounts.nrca + (mtkCounts.nr_sa ?? 0) + mtkCounts.nrdc : 0;
  const lteCell = appleCounts
    ? appleCounts.lte.toLocaleString("en-US")
    : mtkCounts
      ? mtkCounts.lte.toLocaleString("en-US")
      : record.lte_combos == null
        ? "—"
        : record.lte_combos.toLocaleString("en-US");
  const nrCell = appleCounts
    ? `${appleCounts.endc}+${appleCounts.nrca}+${appleCounts.nrdc}=${
        appleCounts.endc + appleCounts.nrca + appleCounts.nrdc
      }`
    : mtkCounts
      ? `${mtkCounts.endc}+${mtkCounts.nrca + (mtkCounts.nr_sa ?? 0)}+${mtkCounts.nrdc}=${mtkTotal}`
      : String(record.nr_combos ?? "");
  // Scan counts are the only count source for apple/MTK rows and a bank
  // skipped at scan has none — guard on the actual null/undefined.
  const countCell = (counts, key) => (counts == null ? "—" : counts[key].toLocaleString("en-US"));

  const cells = layout === "mtk"
    ? [
        [String(record.mtk.bankIndex), "cell-identity"],
        [String(record.mtk.profile), "cell-identity"],
        // Counts are real combos decoded at scan time (spec §2).
        [countCell(mtkCounts, "endc"), "cell-lte"],
        [countCell(mtkCounts, "nrca"), "cell-lte"],
        [countCell(mtkCounts, "nr_sa"), "cell-lte"],
        [countCell(mtkCounts, "nrdc"), "cell-lte"],
        [countCell(mtkCounts, "lte"), "cell-lte"],
        [humanSize(record.size), "cell-nr"],
        [String(record.source_path ?? ""), "cell-nr"],
      ]
    : layout === "apple"
      ? [
          [record.inner_path, "cell-name"],
          [APPLE_LAYOUT_DESC[record.apple.layout] ?? record.apple.layout ?? "—", "cell-identity"],
          [record.apple.profileId == null ? "—" : `0x${record.apple.profileId.toString(16).toUpperCase().padStart(6, "0")}`, "cell-generation"],
          [countCell(record.apple.counts, "lte"), "cell-lte"],
          [countCell(record.apple.counts, "endc"), "cell-lte"],
          [countCell(record.apple.counts, "nrca"), "cell-lte"],
          [countCell(record.apple.counts, "nrdc"), "cell-lte"],
          [humanSize(record.size), "cell-nr"],
          [String(record.source_path ?? ""), "cell-nr"],
        ]
      : [
          [record.name, "cell-name"],
          [identity, "cell-identity"],
          [GENERATION_DISPLAY[record.generation] ?? record.generation, "cell-generation"],
          // lte_combos is null while an apple CR card's counts are deferred to card
          // open — `null >= 0` is true in JS (null coerces to 0), so a plain >=
          // check would reach null.toLocaleString() and abort the whole list
          // render. Guard on the actual null/undefined instead.
          [lteCell, "cell-lte"],
          [nrCell, "cell-nr"],
        ];
  for (const [value, cls] of cells) {
    const td = document.createElement("td");
    td.className = cls;
    td.textContent = value;
    tr.appendChild(td);
  }
  return tr;
}

// Incremental list render: append only cards that have no row yet. A layout
// flip (all-MTK vs all-Apple vs mixed/Qualcomm; the row cell sets and header
// differ) is the only case that rebuilds the already-rendered rows.
function renderCardList() {
  const allMtk = cards.length > 0 && cards.every((c) => c.record.mtk);
  const allApple = cards.length > 0 && cards.every((c) => c.record.apple);
  const layout = allMtk ? "mtk" : allApple ? "apple" : "qcom";
  if (cardListLayout !== layout) {
    cardListLayout = layout;
    els.cardHead.innerHTML = allMtk ? CARDLIST_HEAD_MTK : allApple ? CARDLIST_HEAD_APPLE : CARDLIST_HEAD_QCOM;
    cardRows.clear();
    els.cardBody.replaceChildren();
  }
  els.cardsEmpty.hidden = cards.length > 0;
  for (const card of cards) {
    if (cardRows.has(card.key)) continue;
    const tr = buildCardRow(card, layout);
    cardRows.set(card.key, tr);
    els.cardBody.appendChild(tr);
  }
  for (const [key, tr] of cardRows) {
    tr.classList.toggle("selected", selectedCard != null && key === selectedCard.key);
  }
}

function scheduleCardListRender() {
  if (cardListRaf !== null) return;
  cardListRaf = requestAnimationFrame(() => {
    cardListRaf = null;
    renderCardList();
  });
}

// Full reset for Clear: forget rows/layout and re-render the (empty) list.
function resetCardList() {
  if (cardListRaf !== null) {
    cancelAnimationFrame(cardListRaf);
    cardListRaf = null;
  }
  cardRows.clear();
  cardListLayout = null;
  els.cardBody.replaceChildren();
  renderCardList();
}

// One delegated change listener for every row's checkbox (rows are created
// incrementally, so per-row listeners would leak and defeat the point).
els.cardBody.addEventListener("change", (event) => {
  const checkbox = event.target.closest("input[type=checkbox]");
  if (!checkbox) return;
  const tr = checkbox.closest("tr[data-card-key]");
  if (!tr) return;
  if (checkbox.checked) checked.add(tr.dataset.cardKey);
  else checked.delete(tr.dataset.cardKey);
  els.compareBtn.disabled = checked.size < 2;
  updateImportParserBtn();
});

// One delegated click listener: row click opens the viewer only; ticking stays
// a checkbox-only action (owned by the change handler above).
els.cardBody.addEventListener("click", (event) => {
  if (event.target.closest("input[type=checkbox]")) return;
  const tr = event.target.closest("tr[data-card-key]");
  if (!tr) return;
  const card = cardsByKey.get(tr.dataset.cardKey);
  if (!card) return;
  selectedCard = card;
  for (const other of cardRows.values()) other.classList.remove("selected");
  tr.classList.add("selected");
  openCard(card);
});

// Reflect the checked set into the listed rows' checkboxes + the compare button
// (Select all / Deselect all mutate the set in bulk; re-rendering the list
// would drop the viewer's selected-row state for no benefit).
function syncChecks() {
  for (const [key, tr] of cardRows) {
    const checkbox = tr.querySelector("input[type=checkbox]");
    if (checkbox) checkbox.checked = checked.has(key);
  }
  els.compareBtn.disabled = checked.size < 2;
  updateImportParserBtn();
}

// --- card view -------------------------------------------------------------------

function destroyViewer() {
  if (viewer) {
    viewer.destroy();
    viewer = null;
  }
}

function renderViewer(card, tables) {
  destroyViewer();
  const record = card.record;
  const identity = recordIdentity(record.name);
  // Exports live in the export bar above the workbench;
  // the per-card header buttons were superseded by "Export ticked".
  const head = document.createElement("div");
  head.className = "card-detail";
  const title = document.createElement("span");
  title.className = "card-detail-title";
  title.textContent = record.name;
  head.appendChild(title);
  els.viewerHost.replaceChildren(head);
  viewer = new ComboViewer(els.viewerHost, tables, {
    identity,
    name: record.name,
    generation: record.generation,
    size: record.size,
    // record_json-normalized path (scratch-dir tags are not user-meaningful).
    inner_path: normalizeInnerPath(record.inner_path),
  }, { mobile: isMobileLayout() });
}

function openCard(card) {
  // A new open supersedes a still-pending one: cancel the old worker request so
  // it does not parse or reply (the worker drops an id that was cancelled before
  // its handler dequeues). Compare requests are never cancelled this way.
  if (pendingView && pendingView.id !== undefined) {
    worker.postMessage({ type: "cancel", id: pendingView.id });
    pendingReplies.delete(pendingView.id); // nothing waits on the superseded reply
  }
  const id = nextMessageId++;
  pendingView = { cardKey: card.key, id };
  pendingReplies.set(id, card);
  worker.postMessage({ type: "parseCard", id, fileIndex: card.fileIndex, sourceId: card.sourceId, record: card.record });
}

// --- compare view (compare.js) ----------------------------------------------------

async function openCompare() {
  const selected = cards.filter((c) => checked.has(c.key));
  if (selected.length < 2) return;
  // No main-thread cache to precheck: ask the worker for every selected card.
  // Cache hits (worker-side) reply immediately; the rest parse once each.
  pendingCompare = { want: selected.length, have: [], missing: new Set(selected.map((c) => c.key)) };
  for (const card of selected) {
    const id = nextMessageId++;
    pendingReplies.set(id, card);
    worker.postMessage({ type: "parseCard", id, fileIndex: card.fileIndex, sourceId: card.sourceId, record: card.record });
  }
}

function renderCompare(entries) {
  destroyViewer();
  const sections = compareCards(entries);
  const wrap = document.createElement("div");
  wrap.className = "compare";
  const h = document.createElement("h2");
  h.textContent = `Comparing ${entries.length.toLocaleString("en-US")} cards`;
  wrap.appendChild(h);
  for (const section of sections) {
    const h3 = document.createElement("h3");
    h3.textContent = `${section.kind} band presence (${section.bandHeader})`;
    wrap.appendChild(h3);

    const stats = document.createElement("p");
    stats.className = "compare-stats";
    stats.textContent = section.stats.length
      ? section.stats
          .map((s) => `${s.a} vs ${s.b}: matched ${s.inter} CA combo(s), jaccard ${(s.jaccard * 100).toFixed(1)}%, recall ${(s.recall * 100).toFixed(1)}%, precision ${(s.precision * 100).toFixed(1)}%`)
          .join("  |  ")
      : "No CA combos to compare.";
    wrap.appendChild(stats);

    const table = document.createElement("table");
    table.className = "compare-table";
    const thead = document.createElement("thead");
    thead.innerHTML = `<tr><th>Band</th>${entries.map((e) => `<th></th>`).join("")}</tr>`;
    for (const [i, th] of thead.querySelectorAll("th:not(:first-child)").entries()) {
      th.textContent = entries[i].label;
    }
    table.appendChild(thead);
    const tbody = document.createElement("tbody");
    for (const band of section.bands) {
      const tr = document.createElement("tr");
      const tdBand = document.createElement("td");
      tdBand.className = "compare-band";
      tdBand.textContent = band;
      tr.appendChild(tdBand);
      for (const present of section.presence[band]) {
        const td = document.createElement("td");
        td.className = present ? "present" : "absent";
        td.textContent = present ? "✓" : "—";
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    wrap.appendChild(table);
  }
  els.viewerHost.replaceChildren(wrap);
}

// --- batch export (ticked cards x enabled formats) ------------------------------

function enabledFormats() {
  return [...els.exportbar.querySelectorAll("input[type=checkbox][data-format]")]
    .filter((cb) => cb.checked)
    .map((cb) => cb.dataset.format);
}

// One worker request per (card, format), resolved when the complete exportBlob
// reply arrives. Requests run strictly sequentially (the worker chains them
// anyway) so a card parses exactly once via the per-File parse memo.
function requestExport(card, format) {
  return new Promise((resolve, reject) => {
    const id = nextMessageId++;
    pendingReplies.set(id, card);
    exportWaiters.set(id, { resolve, reject });
    worker.postMessage({ type: "export", id, fileIndex: card.fileIndex, sourceId: card.sourceId, record: card.record, format });
  });
}

function mimeFor(filename) {
  return filename.endsWith(".json")
    ? "application/json;charset=utf-8"
    : filename.endsWith(".txt")
      ? "text/plain;charset=utf-8"
      : "text/csv;charset=utf-8";
}

// Delivery per design: <=ZIP_FILE_THRESHOLD files download individually
// (BOM-preserving decode so CSVs stay byte-identical to the worker's utf-8-sig output);
// above it everything ships as ONE fflate zip with deduped entry names.
function deliver(collected, cardCount, failedCount) {
  const suffix = failedCount ? ` ${failedCount} export(s) failed — see warnings.` : "";
  if (!collected.length) {
    exportStatus(`Nothing was exported — see warnings.${suffix}`);
    return;
  }
  if (deliveryMode(collected.length) === "zip") {
    const names = dedupeFilenames(collected.map((f) => f.filename));
    const entries = {};
    for (const [i, f] of collected.entries()) entries[names[i]] = f.bytes;
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const zipName = `${cardCount}cards_export_${stamp}.zip`;
    downloadBytes(zipName, zipSync(entries), "application/zip");
    exportStatus(`Exported ${collected.length.toLocaleString("en-US")} file(s) from ${cardCount.toLocaleString("en-US")} card(s) as ${zipName}.${suffix}`);
  } else {
    for (const f of collected) {
      if (f.filename.endsWith(".mbn") || f.filename.endsWith(".bin")) {
        // Raw blob dumps are binary (qcom .mbn, apple/MTK .bin): download the
        // bytes untouched — the text path's UTF-8 decode would corrupt them.
        downloadBytes(f.filename, f.bytes, "application/octet-stream");
      } else {
        download(f.filename, decodeExportBytes(f.bytes), mimeFor(f.filename));
      }
    }
    exportStatus(`Exported ${collected.length.toLocaleString("en-US")} file(s) from ${cardCount.toLocaleString("en-US")} card(s).${suffix}`);
  }
}

async function exportTicked() {
  if (exporting) {
    exportStatus("An export is already running…", { sticky: true });
    return;
  }
  const ticked = cards.filter((c) => checked.has(c.key));
  if (!ticked.length) {
    exportStatus("No cards are ticked — tick at least one card to export.");
    return;
  }
  const formats = enabledFormats();
  if (!formats.length) {
    exportStatus("No export formats are enabled — tick at least one format.");
    return;
  }
  const jobs = buildExportJobs(ticked, formats);
  const cardCount = new Set(jobs.map((j) => j.card.key)).size;
  const collected = []; // { filename, bytes }
  const encoder = new TextEncoder();
  let failedCount = 0;
  exporting = true;
  els.exportTickedBtn.disabled = true;
  // Clear is disabled while a batch runs: it would orphan the in-flight
  // per-job waiters (they are rejected defensively in clearAll too).
  els.clearBtn.disabled = true;
  try {
    let lastKey = null;
    let done = 0;
    for (const job of jobs) {
      if (job.card.key !== lastKey) {
        lastKey = job.card.key;
        done += 1;
        exportStatus(`Exporting ${done.toLocaleString("en-US")}/${cardCount.toLocaleString("en-US")}…`, { sticky: true });
      }
      try {
        const files = await requestExport(job.card, job.format);
        for (const f of files) collected.push({ filename: f.filename, bytes: f.bytes ?? encoder.encode(f.text) });
      } catch {
        // The shared error handler already warned; keep exporting the rest.
        failedCount += 1;
      }
    }
    deliver(collected, cardCount, failedCount);
  } catch (err) {
    exportStatus(`Export failed: ${err && err.message ? err.message : err}`);
  } finally {
    exporting = false;
    els.exportTickedBtn.disabled = false;
    els.clearBtn.disabled = false;
  }
}

// --- import to parser (uecaps.hennes.xyz) -------------------------------------------

const IMPORT_BTN_LABEL = "Import to parser";
let importingToParser = false; // in-flight request; re-entrant clicks ignored

// Enabled iff exactly one card is ticked (spec: 0 or >=2 -> disabled). The
// button's meaning never changes (always "start an import"); the success
// tick only means "the latest import finished" and hides on selection
// change. Changes during an in-flight import don't disturb anything —
// completion applies the tick after.
function updateImportParserBtn() {
  if (importingToParser) return;
  els.importParserBtn.disabled = checked.size !== 1;
  if (checked.size !== 1) els.importDoneTick.hidden = true;
}

// One importCards request; the reply arrives on the shared exportBlob channel
// (files as text), so it reuses pendingReplies/exportWaiters incl. the
// defensive rejection in clearAll.
function requestImportTexts(card) {
  return new Promise((resolve, reject) => {
    const id = nextMessageId++;
    pendingReplies.set(id, card);
    exportWaiters.set(id, { resolve, reject });
    worker.postMessage({ type: "importCards", id, fileIndex: card.fileIndex, sourceId: card.sourceId, record: card.record });
  });
}

// Append one persistent result line: the parser result URL as an anchor
// (opens in a new tab) with the record name to its right. Lines accumulate
// for the session; only Clear/reload removes them (results stay stored on
// the parser site). Built via createElement + assigned href/textContent —
// never string HTML.
function addImportResult(id, name) {
  const line = document.createElement("span");
  line.className = "import-result-line";
  const link = document.createElement("a");
  link.href = resultUrl(id);
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.textContent = resultUrl(id);
  const label = document.createElement("span");
  label.className = "import-result-name";
  label.textContent = name;
  line.append(link, label);
  els.importResults.append(line);
  els.importResults.hidden = false;
}

async function importToParser() {
  if (importingToParser) return;
  const ticked = cards.filter((c) => checked.has(c.key));
  if (ticked.length !== 1) {
    exportStatus("Import needs exactly one ticked card.");
    return;
  }
  const card = ticked[0];
  importingToParser = true;
  els.importParserBtn.disabled = true;
  els.importParserBtn.textContent = "Importing…";
  try {
    const files = await requestImportTexts(card);
    // Suffixes match the filenames the worker's export arms produce: qcom/
    // apple cards answer with _0xB0CD_v41.txt / _0xB826_v22.txt DIAG texts,
    // MTK DRDI cards with _mtk_nr_trace.txt / _mtk_lte_ca_comb_info.txt —
    // the reply reuses them unchanged (deviation note: the plan's ".b0cd.txt"
    // strings never occur in the reply, so every lookup must key on the real
    // tail). An MTK card's qcom tails come back undefined and vice versa.
    const textFor = (suffix) => files.find((f) => f.filename && f.filename.endsWith(suffix))?.text;
    const { entries, files: importFiles } = buildImportEntries(
      textFor("_0xB0CD_v41.txt"),
      textFor("_0xB826_v22.txt"),
      card.record.name,
      textFor("_mtk_nr_trace.txt"),
      textFor("_mtk_lte_ca_comb_info.txt")
    );
    const form = new FormData();
    form.append("requests", JSON.stringify(entries));
    // File append order MUST match the inputIndexes order entries carry
    // (b0cd first when present, then b826) — the parser references uploads
    // by index. Field name is irrelevant to the server (ctx.uploadedFiles()
    // reads all uploads); "files" is descriptive.
    for (const f of importFiles) {
      form.append("files", new Blob([f.text], { type: "text/plain" }), f.filename);
    }
    const response = await fetch(`${PARSER_BASE}/parse/multiPart`, {
      method: "POST",
      body: form,
    });
    if (!response.ok) throw new Error(`parser responded ${response.status}`);
    const parsed = await response.json();
    if (!parsed || !parsed.id) throw new Error("parser response has no result id");
    importingToParser = false;
    els.importParserBtn.textContent = IMPORT_BTN_LABEL;
    els.importParserBtn.disabled = checked.size !== 1;
    els.importDoneTick.hidden = false; // "latest import finished"
    addImportResult(parsed.id, card.record.name);
    exportStatus("Imported to parser — result link added below.");
  } catch (err) {
    importingToParser = false;
    els.importParserBtn.textContent = IMPORT_BTN_LABEL;
    els.importParserBtn.disabled = checked.size !== 1;
    exportStatus(`Import failed: ${err && err.message ? err.message : err}`);
  }
}

els.importParserBtn.addEventListener("click", () => {
  if (importingToParser) return; // "Importing…" ignores re-entrant clicks
  importToParser();
});

// --- import ------------------------------------------------------------------------

function importFiles(files) {
  if (!files.length) return;
  // Assign a stable sourceId per File (never reused: cards accumulate across
  // imports). The worker registers each {sourceId, file} once during the scan
  // and resolves every later parseCard/export/importCards from the id, which is
  // what makes its per-source memos hit across messages.
  scanEntries = [...files].map((file) => ({ sourceId: nextSourceId++, file }));
  // Chip row: one pill per distinct source file, first appearance wins —
  // re-importing the same file leaves the chips unchanged.
  const names = uniqueFileNames([...loadedFiles, ...scanEntries.map((e) => e.file.name)]);
  loadedFiles.length = 0;
  loadedFiles.push(...names);
  renderLoadedFiles();
  currentScanId = nextMessageId++;
  scanEpoch = sessionEpoch;
  els.cancelBtn.hidden = false;
  setProgress(0, files.length, files[0].name);
  worker.postMessage({ type: "scan", id: currentScanId, files: scanEntries });
}

// --- worker messages ----------------------------------------------------------------

worker.onmessage = (event) => {
  const msg = event.data;
  switch (msg.type) {
    case "progress": {
      if (scanEpoch !== sessionEpoch) break; // late reply from a cleared scan
      setProgress(msg.done, msg.total, msg.currentFile, msg.detail);
      break;
    }
    case "records": {
      if (scanEpoch !== sessionEpoch) break; // late reply from a cleared scan
      for (const record of msg.records) {
        const key = cardKeyOf(record);
        if (cardKeys.has(key)) continue; // dedupe
        cardKeys.add(key);
        // The sourceId registered at scan time identifies the File inside the
        // worker; every parseCard/export sends it, so the worker resolves bytes
        // from THIS file no matter how many scans ran since the import.
        const card = { record, sourceId: scanEntries[msg.fileIndex]?.sourceId ?? null, fileIndex: msg.fileIndex, key };
        cards.push(card);
        cardsByKey.set(key, card);
      }
      for (const warning of msg.warnings ?? []) {
        addWarning(warning.tool ?? "warning", warning.message, msg.source);
      }
      // Progressive Apple batches coalesce into one rAF; only new rows append.
      scheduleCardListRender();
      break;
    }
    case "tables": {
      const card = pendingReplies.get(msg.id);
      if (!card) break; // unknown/stale request id
      pendingReplies.delete(msg.id);
      // Only the current pending view renders; a superseded open's late reply
      // (id mismatch) is dropped. The worker already owns the cache.
      if (pendingView && pendingView.cardKey === card.key && pendingView.id === msg.id) {
        pendingView = null;
        renderViewer(card, msg.tables);
      }
      if (pendingCompare && pendingCompare.missing.has(card.key)) {
        pendingCompare.missing.delete(card.key);
        pendingCompare.have.push({ label: recordIdentity(card.record.name) || card.record.name, tables: msg.tables });
        if (!pendingCompare.missing.size) {
          const have = pendingCompare.have;
          pendingCompare = null;
          renderCompare(have);
        }
      }
      break;
    }
    case "exportBlob": {
      // One reply per export request; files carries every file the format
      // produced (json=1, csv=2, webcsv=1-4, b0cd/b826=1). The batch runner
      // awaits this; a resolved waiter has no pending entry left.
      pendingReplies.delete(msg.id);
      const waiter = exportWaiters.get(msg.id);
      exportWaiters.delete(msg.id);
      if (waiter) waiter.resolve(msg.files ?? []);
      break;
    }
    case "error": {
      // An id-bearing error nobody is waiting for (a superseded open, or a
      // request orphaned by Clear failing on its released source) is stale:
      // surfacing it would put a warning into a view that no longer asked.
      if (msg.id !== undefined && !pendingReplies.has(msg.id)) break;
      if (msg.id !== undefined) {
        pendingReplies.delete(msg.id);
        const waiter = exportWaiters.get(msg.id);
        if (waiter) {
          exportWaiters.delete(msg.id);
          waiter.reject(new Error(msg.message));
        }
      }
      addWarning("error", msg.message, msg.source);
      break;
    }
    default:
      break;
  }
};

// --- DOM events -----------------------------------------------------------------------

// Import button starts disabled: no cards are ticked yet (updateImportParserBtn
// is re-invoked by syncChecks/checkbox handlers once selection changes).
updateImportParserBtn();

els.pickBtn.addEventListener("click", () => els.fileInput.click());
els.fileInput.addEventListener("change", () => {
  importFiles(els.fileInput.files);
  els.fileInput.value = "";
});
// Cancel path shared by the Cancel button and Clear: stops the in-flight scan
// (a no-op when none is running) and tears down the progress row.
function cancelInFlightScan() {
  worker.postMessage({ type: "cancel", id: currentScanId });
  if (progressHideTimer !== null) {
    clearTimeout(progressHideTimer);
    progressHideTimer = null;
  }
  els.progressWrap.hidden = true;
  els.cancelBtn.hidden = true;
}

els.cancelBtn.addEventListener("click", () => cancelInFlightScan());

// FULL reset (Clear button): cancel any in-flight scan, drop every card /
// selection / viewer / warning / chip, wipe the IndexedDB parse cache, then
// report what was cleared. No confirm() — Clear is itself the confirmation.
async function clearAll() {
  cancelInFlightScan();
  sessionEpoch++; // orphaned replies from the old scan epoch become no-ops
  // Drop in-flight batch-export waiters so nothing can deadlock on a reply
  // that Clear just orphaned; cleared pendingReplies also makes any late
  // "tables" reply a no-op instead of re-populating the wiped cache.
  for (const waiter of exportWaiters.values()) {
    waiter.reject(new Error("Export cancelled: workbench cleared."));
  }
  exportWaiters.clear();
  pendingReplies.clear();
  const cardCount = cards.length;
  cards.length = 0;
  cardKeys.clear();
  cardsByKey.clear();
  checked.clear();
  scanEntries = [];
  loadedFiles.length = 0;
  pendingView = null;
  pendingCompare = null;
  selectedCard = null;
  els.compareBtn.disabled = true;
  els.importResults.replaceChildren();
  els.importResults.hidden = true;
  els.importDoneTick.hidden = true;
  updateImportParserBtn();
  els.warnings.replaceChildren();
  els.warnings.hidden = true;
  destroyViewer();
  // Reset AFTER the teardown: destroy() just captured the dying viewer's
  // state, and Clear must not hand it to the next opened card.
  resetViewerState();
  els.viewerHost.replaceChildren(els.viewerPlaceholder);
  resetCardList();
  renderLoadedFiles();
  // Drop the worker's registered sources and memos. A new scan must NOT do this
  // (cards accumulate and keep referencing older sourceIds); only Clear does.
  worker.postMessage({ type: "release" });
  // And wipe the worker-side parsed-table cache.
  worker.postMessage({ type: "clearCache" });
  exportStatus(`Cleared ${cardCount.toLocaleString("en-US")} card(s) and the parse cache.`);
}

els.clearBtn.addEventListener("click", () => clearAll());
els.compareBtn.addEventListener("click", () => openCompare());
els.selectAllBtn.addEventListener("click", () => {
  for (const card of cards) checked.add(card.key);
  syncChecks();
});
els.deselectAllBtn.addEventListener("click", () => {
  checked.clear();
  syncChecks();
});
els.exportTickedBtn.addEventListener("click", () => exportTicked());

for (const eventName of ["dragenter", "dragover"]) {
  els.dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    els.dropzone.classList.add("drag");
  });
}
els.dropzone.addEventListener("dragleave", () => els.dropzone.classList.remove("drag"));
els.dropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  els.dropzone.classList.remove("drag");
  if (event.dataTransfer && event.dataTransfer.files.length) importFiles(event.dataTransfer.files);
});

// --- workbench splitter ------------------------------------------------------------

// localStorage can throw (privacy modes); a splitter that never persists is
// better than one that breaks the page.
function readStoredSplitterWidth() {
  try {
    return localStorage.getItem(SPLITTER_STORAGE_KEY);
  } catch {
    return null;
  }
}

function storeSplitterWidth(px) {
  try {
    localStorage.setItem(SPLITTER_STORAGE_KEY, String(Math.round(px)));
  } catch {}
}

function clearStoredSplitterWidth() {
  try {
    localStorage.removeItem(SPLITTER_STORAGE_KEY);
  } catch {}
}

function setSplitterAriaBounds() {
  els.splitter.setAttribute("aria-valuemin", String(MIN_CARD_PANE_PX));
  els.splitter.setAttribute("aria-valuemax", String(maxCardPaneWidth(els.workbench.clientWidth)));
}

function applyCardPaneWidth(px) {
  els.cardPane.style.flexBasis = `${Math.round(px)}px`;
  els.splitter.setAttribute("aria-valuenow", String(Math.round(px)));
}

function syncSplitterAria() {
  setSplitterAriaBounds();
  els.splitter.setAttribute("aria-valuenow", String(Math.round(els.cardPane.getBoundingClientRect().width)));
}

let splitterDrag = null; // { id, startX, startWidth, containerWidth, pendingWidth, raf }

function positionSplitterGhost(px) {
  // The future splitter bar will span [px, px+6]; the 2px ghost (left:0) is
  // centered on it: center = x + 1 → x = px + 2.
  els.splitterGhost.style.transform = `translateX(${Math.round(px + 2)}px)`;
}

els.splitter.addEventListener("pointerdown", (event) => {
  if (event.button !== 0) return;
  if (!shouldDrag(document.body.classList.contains("stacked"))) return;
  event.preventDefault();
  splitterDrag = {
    id: event.pointerId,
    startX: event.clientX,
    startWidth: els.cardPane.getBoundingClientRect().width,
    // Read the container width ONCE here (used for clamping in pointermove —
    // no forced layout while dragging).
    containerWidth: els.workbench.clientWidth,
    pendingWidth: null,
    raf: 0,
  };
  // Synthetic (untrusted) events have no active pointer to capture; the
  // move/up handlers still work on the splitter for those.
  try {
    els.splitter.setPointerCapture(event.pointerId);
  } catch {}
  positionSplitterGhost(splitterDrag.startWidth);
  els.splitterGhost.hidden = false;
  document.body.classList.add("dragging");
  els.splitter.classList.add("dragging");
  setSplitterAriaBounds();
});

// Ghost drag: while dragging, only the preview line moves — a transform on an
// absolutely positioned element, so NO pane layout happens per frame and the
// card-list table never re-measures mid-drag. On release the final width is
// applied in a single write, so both panes land exactly aligned with the ghost.
function scheduleDragFrame() {
  if (!splitterDrag || splitterDrag.raf) return;
  splitterDrag.raf = requestAnimationFrame(() => {
    if (!splitterDrag) return;
    splitterDrag.raf = 0;
    positionSplitterGhost(splitterDrag.pendingWidth);
    els.splitter.setAttribute("aria-valuenow", String(Math.round(splitterDrag.pendingWidth)));
  });
}

els.splitter.addEventListener("pointermove", (event) => {
  if (!splitterDrag || event.pointerId !== splitterDrag.id) return;
  splitterDrag.pendingWidth = clampSplitterWidth(
    splitterDrag.startWidth + event.clientX - splitterDrag.startX,
    splitterDrag.containerWidth // cached at drag start — no forced layout here
  );
  scheduleDragFrame();
});

function endSplitterDrag(event) {
  if (!splitterDrag || event.pointerId !== splitterDrag.id) return;
  const { raf, pendingWidth } = splitterDrag;
  splitterDrag = null;
  if (raf) cancelAnimationFrame(raf);
  els.splitterGhost.hidden = true;
  if (pendingWidth !== null) applyCardPaneWidth(pendingWidth); // single write — both panes align with the ghost
  try {
    els.splitter.releasePointerCapture(event.pointerId);
  } catch {}
  document.body.classList.remove("dragging");
  els.splitter.classList.remove("dragging");
  storeSplitterWidth(els.cardPane.getBoundingClientRect().width);
}

els.splitter.addEventListener("pointerup", endSplitterDrag);
els.splitter.addEventListener("pointercancel", endSplitterDrag);

// Double-click resets to the CSS default (44%) and forgets the stored width.
els.splitter.addEventListener("dblclick", () => {
  clearStoredSplitterWidth();
  els.cardPane.style.removeProperty("flex-basis");
  syncSplitterAria();
});

els.splitter.addEventListener("keydown", (event) => {
  if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
  event.preventDefault();
  const delta = event.key === "ArrowRight" ? 16 : -16;
  const width = clampSplitterWidth(els.cardPane.getBoundingClientRect().width + delta, els.workbench.clientWidth);
  applyCardPaneWidth(width);
  storeSplitterWidth(width);
});

window.addEventListener("resize", () => {
  setSplitterAriaBounds();
  if (els.cardPane.style.flexBasis) {
    applyCardPaneWidth(clampSplitterWidth(els.cardPane.getBoundingClientRect().width, els.workbench.clientWidth));
  }
});

// Restore the persisted width (clamped to the current window) on load.
setSplitterAriaBounds();
const storedSplitterWidth = parseStoredWidth(readStoredSplitterWidth(), els.workbench.clientWidth);
if (storedSplitterWidth !== null) applyCardPaneWidth(storedSplitterWidth);
else syncSplitterAria();

// --- stacked (mobile portrait) layout ------------------------------------------------

// Portrait phones stack the card pane above the viewer (css/app.css media
// query) and hide the splitter; leftover inline widths from drags/resizes
// would fight the stacked CSS, so transitions clear them (applyStackedState)
// and leaving stacked re-applies the persisted split like startup.
// matchMedia is feature-checked: without it the page keeps the split layout
// instead of breaking.
const stackedMq = typeof window.matchMedia === "function"
  ? window.matchMedia(STACKED_MEDIA_QUERY)
  : null;

// Mobile (stacked portrait) gate for the perf paths: windowed viewer rendering
// and the worker's fast parse lane. Desktop (split layout) never takes them.
function isMobileLayout() {
  return !!(stackedMq && stackedMq.matches);
}

function handleStackedChange(stacked) {
  applyStackedState(stacked, {
    body: document.body,
    cardPane: els.cardPane,
    storedWidth: readStoredSplitterWidth(),
    containerWidth: els.workbench.clientWidth,
    applyWidth: applyCardPaneWidth,
  });
  if (viewer && typeof viewer.setMobile === "function") viewer.setMobile(stacked); // rotation mid-view
  if (!stacked) syncSplitterAria();
}

if (stackedMq) {
  const onStackedChange = (event) => handleStackedChange(event.matches);
  if (typeof stackedMq.addEventListener === "function") {
    stackedMq.addEventListener("change", onStackedChange);
  } else if (typeof stackedMq.addListener === "function") {
    stackedMq.addListener(onStackedChange); // older Safari
  }
  // Runs after the startup restore above, so a phone opening with a stored
  // split has its inline width cleared before the stacked view first paints.
  handleStackedChange(stackedMq.matches);
}
