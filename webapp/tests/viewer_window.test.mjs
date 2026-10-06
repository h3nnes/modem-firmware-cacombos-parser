// Unit tests for the Step 4 desktop/mobile viewport virtualization and the
// responsive parseCard lane. ComboViewer itself is DOM-coupled and not
// importable under node --test, so the pure range math is tested directly and
// the DOM wiring is pinned at source level (same approach as stacked.test.mjs).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_ROW_HEIGHT,
  OVERSCAN_ROWS,
  VIRTUALIZE_THRESHOLD,
  rowStripeClass,
  spacerHeights,
  visibleRange,
} from "../js/viewer.js";
import { PALETTE, bandColor, bandColorIndex } from "../js/lib/bandcolors.js";
import { STACKED_MEDIA_QUERY } from "../js/splitter.js";

const webappDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const readWebappFile = (...parts) => readFile(join(webappDir, ...parts), "utf8");

test("virtualization constants are the documented threshold/overscan", () => {
  assert.equal(VIRTUALIZE_THRESHOLD, 300);
  assert.equal(OVERSCAN_ROWS, 8);
  assert.ok(DEFAULT_ROW_HEIGHT > 0);
});

test("visibleRange renders small tables in full and windows large ones", () => {
  assert.deepEqual(visibleRange(100, 99999, 600, 20), { start: 0, end: 100 });
  // 5000 rows, scrolled to row 1000, 600px viewport, 20px rows, overscan 8
  const range = visibleRange(5000, 1000 * 20, 600, 20);
  assert.equal(range.start, 1000 - OVERSCAN_ROWS);
  assert.equal(range.end, (1000 + 30) + OVERSCAN_ROWS);
  // top of the list clamps at 0 and the window always covers at least one row
  assert.deepEqual(visibleRange(5000, 0, 600, 20).start, 0);
  const tail = visibleRange(5000, 5000 * 20, 600, 20);
  assert.equal(tail.end, 5000);
  assert.ok(tail.start < tail.end);
  // a zero viewport still yields a non-empty range
  const zero = visibleRange(5000, 40, 0, 20);
  assert.ok(zero.end > zero.start);
});

test("spacerHeights covers exactly the off-screen rows", () => {
  assert.deepEqual(spacerHeights(1000, 0, 50, 20), { top: 0, bottom: 19000 });
  assert.deepEqual(spacerHeights(1000, 100, 200, 20), { top: 2000, bottom: 16000 });
  assert.deepEqual(spacerHeights(1000, 0, 1000, 20), { top: 0, bottom: 0 });
});

test("rowStripeClass follows the filtered index, not DOM position", () => {
  assert.equal(rowStripeClass(0), "cv-row-even");
  assert.equal(rowStripeClass(1), "cv-row-odd");
  assert.equal(rowStripeClass(2), "cv-row-even");
});

test("viewer.js renders a data-i windowed window with spacers and no append marker", async () => {
  const source = await readWebappFile("js", "viewer.js");
  assert.ok(source.includes("renderRows(state)"), "renderRows must paint the window");
  assert.ok(source.includes('data-i="${index}"'), "rows must carry their filtered index");
  assert.ok(source.includes('class="cv-spacer"'), "off-screen rows need spacer rows");
  assert.ok(source.includes("visibleRange("), "the window must come from the pure range helper");
  assert.ok(source.includes("rowStripeClass(index)"), "zebra must be index-derived");
  assert.ok(source.includes('closest("tbody tr[data-i]")'), "rowFromEvent must read data-i");
  assert.ok(source.includes("this.renderRaf = requestAnimationFrame"), "scroll repaint must be rAF-coalesced");
  assert.ok(!source.includes("appendWindowRows"), "the old mobile append path is gone");
  assert.ok(!source.includes("appendMoreRow"), "the old cv-more marker is gone");
  assert.ok(!source.includes("WINDOW_INITIAL_ROWS"), "the old window constants are gone");
});

test("app.css palette classes match PALETTE index-for-index", async () => {
  const css = await readWebappFile("css", "app.css");
  for (let i = 0; i < PALETTE.length; i++) {
    const rule = `.cv .band-c${i} { color: ${PALETTE[i]}; }`;
    assert.ok(css.includes(rule), `missing palette class ${i} (${PALETTE[i]})`);
  }
  assert.ok(!css.includes("nth-child(odd)"), "spacer-safe zebra must not use nth-child");
  assert.ok(css.includes(".cv tbody tr.cv-row-odd"), "zebra uses filtered-index classes");
});

test("bandColorIndex and bandColor agree (class index renders the same color)", () => {
  for (const canonical of ["B3", "n78", "B41", "n257"]) {
    assert.equal(PALETTE[bandColorIndex(canonical)], bandColor(canonical));
  }
});

test("main.js posts every card open through the priority lane (no fast flag)", async () => {
  const source = await readWebappFile("js", "main.js");
  assert.ok(
    source.includes("function isMobileLayout()") && source.includes("stackedMq && stackedMq.matches"),
    "the stacked media query is the single mobile signal",
  );
  assert.equal(source.split("{ mobile: isMobileLayout() }").length - 1, 1, "ComboViewer gets the mobile flag");
  assert.equal(source.split('type: "parseCard"').length - 1, 2, "both view + compare posts send parseCard");
  assert.ok(!source.includes("fast: isMobileLayout()"), "the fast flag is dropped: every open is priority");
  assert.ok(source.includes("viewer.setMobile(stacked)"), "stacked transitions retarget the live viewer");
  assert.equal(STACKED_MEDIA_QUERY, "(max-width: 768px) and (orientation: portrait)");
});

test("worker.js: every parseCard replies on the priority chain", async () => {
  const source = await readWebappFile("js", "worker.js");
  assert.ok(source.includes("let parseChain = Promise.resolve();"), "priority parse lane exists");
  assert.ok(source.includes('if (msg.type === "parseCard")'), "all parseCard opens take the lane");
  assert.ok(!source.includes("&& msg.fast"), "the fast flag is gone");
});

test("main.js card list appends rows incrementally behind delegated listeners", async () => {
  const source = await readWebappFile("js", "main.js");
  assert.ok(source.includes("const cardRows = new Map()"), "a keyed row map exists");
  assert.ok(source.includes("if (cardRows.has(card.key)) continue;"), "only new cards get rows");
  assert.ok(source.includes("function scheduleCardListRender()"), "progressive batches are batched");
  assert.ok(source.includes("if (cardListRaf !== null) return;"), "the batch is rAF-coalesced");
  assert.ok(source.includes('els.cardBody.addEventListener("change"'), "one delegated change listener");
  assert.ok(source.includes('els.cardBody.addEventListener("click"'), "one delegated click listener");
  assert.equal(source.split('checkbox.addEventListener("change"').length - 1, 0, "no per-row change listeners");
  assert.equal(source.split('tr.addEventListener("click"').length - 1, 0, "no per-row click listeners");
  // A layout flip is the only rebuild path (header + rows); the flip binary is
  // 3-way (all-MTK vs all-Apple vs mixed/Qualcomm).
  assert.ok(
    source.includes("els.cardHead.innerHTML = allMtk ? CARDLIST_HEAD_MTK : allApple ? CARDLIST_HEAD_APPLE : CARDLIST_HEAD_QCOM"),
  );
  assert.ok(source.includes('const layout = allMtk ? "mtk" : allApple ? "apple" : "qcom";'), "3-way layout binary");
  assert.ok(source.includes("CARDLIST_HEAD_MTK"), "MTK header row exists");
  assert.ok(
    source.includes('<th></th><th>Bank</th><th>Profile</th><th>EN-DC</th><th>NR-CA</th><th>NR-DC</th><th>LTE CA</th><th>File Size</th><th>Source Path</th>'),
    "MTK header columns per spec §4",
  );
  assert.ok(source.includes("recordRows(card, \"mtk\")") || source.includes('layout === "mtk"'), "buildCardRow MTK branch");
  assert.ok(source.includes("cardRows.clear();") && source.includes("els.cardBody.replaceChildren();"));
  assert.ok(source.includes("cardsByKey.set(key, card)"), "row clicks resolve through the key map");
});

test("viewer.js search: lazy per-tab index + no-copy fast path", async () => {
  const source = await readWebappFile("js", "viewer.js");
  assert.ok(source.includes("export function createRowSearchIndex(rows)"), "a per-tab row index exists");
  assert.ok(source.includes("if (hasQuery && !state.searchIndex) state.searchIndex = createRowSearchIndex(state.rows)"));
  assert.ok(source.includes("if (!hasQuery && !hasColumnFilters)") && source.includes("state.filtered = state.rows;"), "no-predicate fast path aliases rows");
  assert.ok(source.includes("filterRows(state.rows, query, hasQuery ? state.searchIndex : null)"));
});
