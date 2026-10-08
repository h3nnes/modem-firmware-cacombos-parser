// Tests for the cross-card viewer state persistence: the pure capture/prune
// helpers plus source pins for the destroy-capture / constructor-restore /
// Clear-reset wiring. ComboViewer itself stays DOM-coupled (see
// viewer_window.test.mjs), so the live wiring is pinned at source level.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  captureViewerState,
  pruneViewerState,
  resetViewerState,
} from "../js/viewer.js";

const webappDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const readWebappFile = (...parts) => readFile(join(webappDir, ...parts), "utf8");

// --- captureViewerState: faithful snapshot of the persistable pieces --------------

// A tab-state stand-in carrying every field the real tabs Map holds; capture
// must read only colFilters/sortCol/sortReverse and copy the filters.
function fakeTab(colFilters, sortCol = null, sortReverse = false) {
  return {
    colFilters,
    sortCol,
    sortReverse,
    selected: new Set([1, 2]), // card-specific: never persisted
    anchor: 1,
    overrides: { "LTE DL": 300 }, // column widths/overrides: never persisted
    widths: [300],
    rows: [{ "LTE DL": "1A" }],
    filtered: [{ "LTE DL": "1A" }],
  };
}

test("captureViewerState snapshots active key, search text and per-tab filter/sort", () => {
  const tabs = new Map([
    ["nr_ca", fakeTab({ "NR DL": "28A" }, "NR DL", false)],
    ["lte_ca", fakeTab({})],
  ]);
  assert.deepEqual(captureViewerState("nr_ca", "28A", tabs), {
    activeKey: "nr_ca",
    query: "28A",
    tabs: {
      nr_ca: { colFilters: { "NR DL": "28A" }, sortCol: "NR DL", sortReverse: false },
      lte_ca: { colFilters: {}, sortCol: null, sortReverse: false },
    },
  });
});

test("captureViewerState copies the filter objects (later edits cannot leak in)", () => {
  const state = fakeTab({ "NR DL": "28A" });
  const saved = captureViewerState("nr_ca", "", new Map([["nr_ca", state]]));
  state.colFilters["NR DL"] = "999";
  assert.deepEqual(saved.tabs.nr_ca.colFilters, { "NR DL": "28A" });
});

test("captureViewerState tolerates a null active key and missing query", () => {
  assert.deepEqual(captureViewerState(null, undefined, new Map()), {
    activeKey: null,
    query: "",
    tabs: {},
  });
});

// --- pruneViewerState: validity pass against the NEXT card ------------------------

// The new card's tabs (only tabs with rows) and their columns.
const NEW_CARD_COLUMNS = {
  lte_ca: ["LTE DL", "LTE MIMO DL", "SCS DL (kHz)"],
  nr_ca: ["NR DL", "NR UL", "SCS DL (kHz)"],
};

test("pruneViewerState returns null when there is nothing saved", () => {
  assert.equal(pruneViewerState(null, NEW_CARD_COLUMNS), null);
});

test("pruneViewerState keeps per-tab filters only for columns the new card has", () => {
  const saved = {
    activeKey: "nr_ca",
    query: "mimo",
    tabs: {
      nr_ca: { colFilters: { "NR DL": "28A", "LTE DL": "1A" }, sortCol: null, sortReverse: false },
    },
  };
  const pruned = pruneViewerState(saved, NEW_CARD_COLUMNS);
  assert.deepEqual(pruned.tabs.nr_ca.colFilters, { "NR DL": "28A" }); // "LTE DL" is not an NRCA column
  // The saved state is never mutated (the constructor could not re-prune it).
  assert.deepEqual(saved.tabs.nr_ca.colFilters, { "NR DL": "28A", "LTE DL": "1A" });
});

test("pruneViewerState drops sort columns that the new card lacks (reverse resets)", () => {
  const saved = {
    activeKey: null,
    query: "",
    tabs: {
      lte_ca: { colFilters: {}, sortCol: "NR DL", sortReverse: true }, // NR column on the LTE tab
      nr_ca: { colFilters: {}, sortCol: "NR DL", sortReverse: true },
    },
  };
  const pruned = pruneViewerState(saved, NEW_CARD_COLUMNS);
  assert.deepEqual(pruned.tabs.lte_ca, { colFilters: {}, sortCol: null, sortReverse: false });
  assert.deepEqual(pruned.tabs.nr_ca, { colFilters: {}, sortCol: "NR DL", sortReverse: true });
});

test("pruneViewerState drops tabs the new card does not render (no rows for the key)", () => {
  const saved = {
    activeKey: "nr_sa", // MTK-only tab, absent on this card
    query: "q",
    tabs: {
      nr_sa: { colFilters: { x: "1" }, sortCol: null, sortReverse: false },
      nr_ca: { colFilters: { "NR DL": "28A" }, sortCol: null, sortReverse: false },
    },
  };
  const pruned = pruneViewerState(saved, NEW_CARD_COLUMNS);
  assert.deepEqual(Object.keys(pruned.tabs).sort(), ["nr_ca"]);
  assert.equal(pruned.activeKey, null); // tab gone -> constructor falls back to the first tab
  assert.equal(pruned.query, "q");
});

test("pruneViewerState keeps the saved active tab only when the new card renders it", () => {
  const saved = { activeKey: "nr_ca", query: "", tabs: {} };
  assert.equal(pruneViewerState(saved, NEW_CARD_COLUMNS).activeKey, "nr_ca");
  assert.equal(pruneViewerState(saved, { lte_ca: ["LTE DL"] }).activeKey, null);
});

test("pruneViewerState drops whitespace-only filters to keep the state clean", () => {
  const saved = {
    activeKey: null,
    query: "",
    tabs: { nr_ca: { colFilters: { "NR DL": "   ", "NR UL": "7A" }, sortCol: null, sortReverse: false } },
  };
  assert.deepEqual(pruneViewerState(saved, NEW_CARD_COLUMNS).tabs.nr_ca.colFilters, { "NR UL": "7A" });
});

// --- capture -> prune round-trip (the actual destroy/construct flow) --------------

test("capture -> prune round-trip matches the constructor's restore contract", () => {
  // Old card: user is on NRCA with "NR DL"=28A filtered and "NR UL" sorted
  // descending, global search "n78", and the hidden LTE tab keeps its own
  // column filter (per-tab filters persist for ALL tabs).
  const tabs = new Map([
    ["lte_ca", fakeTab({ "LTE MIMO DL": "4" })],
    ["nr_ca", fakeTab({ "NR DL": "28A" }, "NR UL", true)],
  ]);
  assert.deepEqual(
    pruneViewerState(captureViewerState("nr_ca", "n78", tabs), NEW_CARD_COLUMNS),
    {
      activeKey: "nr_ca",
      query: "n78",
      tabs: {
        lte_ca: { colFilters: { "LTE MIMO DL": "4" }, sortCol: null, sortReverse: false },
        nr_ca: { colFilters: { "NR DL": "28A" }, sortCol: "NR UL", sortReverse: true },
      },
    },
  );
});

// --- reset (Clear wiring) ----------------------------------------------------------

test("resetViewerState is callable without a viewer instance", () => {
  resetViewerState();
});

// --- source pins: the DOM-coupled wiring --------------------------------------------

test("viewer.js wires capture-on-destroy and prune-restore in the constructor", async () => {
  const source = await readWebappFile("js", "viewer.js");
  assert.ok(source.includes("let savedViewerState = null;"), "a module-level saved-state object exists");
  assert.ok(
    source.includes("savedViewerState = captureViewerState(this.activeKey, this.searchEl.value, this.tabs)"),
    "destroy() captures the live state (active tab + search box + every tab)",
  );
  assert.ok(
    source.includes("pruneViewerState(savedViewerState"),
    "the constructor restores from the module-level state",
  );
  assert.ok(
    source.indexOf("pruneViewerState(savedViewerState") < source.indexOf("if (this.tabs.size === 0)"),
    "restore must patch the tabs before the initial render path",
  );
  assert.ok(source.includes("this.searchEl.value = saved.query"), "the global search text is re-applied");
  assert.ok(
    source.includes("this.tabs.has(saved.activeKey)"),
    "the saved tab only wins when the new card renders it",
  );
});

test("main.js resets the viewer persistence on Clear, after the viewer teardown", async () => {
  const source = await readWebappFile("js", "main.js");
  assert.ok(source.includes("resetViewerState"), "clearAll must reset the persistence");
  assert.ok(
    source.lastIndexOf("destroyViewer();") < source.indexOf("resetViewerState();"),
    "reset comes after destroyViewer() so the destroy-capture cannot re-populate",
  );
});
