// Unit tests for the stacked (mobile portrait) workbench layout: the pure
// stacked-state helpers in webapp/js/splitter.js, plus source-level pins for
// the two-column shell in index.html and the portrait media query in
// css/app.css (the suite runs DOM-free under node --test, and main.js's
// browser-only wiring is not importable here).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  STACKED_MEDIA_QUERY,
  applyStackedState,
  shouldDrag,
} from "../js/splitter.js";

const webappDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const readWebappFile = (...parts) => readFile(join(webappDir, ...parts), "utf8");

// Minimal classList/style doubles: applyStackedState's DOM contract is exactly
// these calls, and node --test has no DOM to observe them on.
function fakeBody(initialClasses = []) {
  const classes = new Set(initialClasses);
  return {
    classList: {
      contains: (name) => classes.has(name),
      toggle: (name, force) => {
        if (force === undefined) force = !classes.has(name);
        if (force) classes.add(name);
        else classes.delete(name);
        return force;
      },
    },
  };
}

function fakeCardPane(initialStyles = {}) {
  const props = new Map(Object.entries(initialStyles));
  return {
    style: {
      props,
      removeProperty: (name) => props.delete(name),
    },
  };
}

// --- splitter.js: stacked-state helpers --------------------------------------------

test("STACKED_MEDIA_QUERY is the portrait breakpoint and matches the app.css media query", async () => {
  assert.equal(STACKED_MEDIA_QUERY, "(max-width: 768px) and (orientation: portrait)");
  const css = await readWebappFile("css", "app.css");
  assert.ok(css.includes(`@media ${STACKED_MEDIA_QUERY}`), "app.css must carry the stacked media query");
});

test("shouldDrag: drags suppressed while stacked, allowed otherwise", () => {
  assert.equal(shouldDrag(true), false);
  assert.equal(shouldDrag(false), true);
});

test("applyStackedState(true) sets body.stacked and clears splitter-written inline styles", () => {
  const body = fakeBody();
  const cardPane = fakeCardPane({ width: "620px", "flex-basis": "620px" });
  const applied = [];
  applyStackedState(true, {
    body,
    cardPane,
    storedWidth: "620",
    containerWidth: 2000,
    applyWidth: (px) => applied.push(px),
  });
  assert.equal(body.classList.contains("stacked"), true);
  assert.deepEqual([...cardPane.style.props.keys()], []);
  assert.deepEqual(applied, []); // nothing re-applied while stacked
});

test("applyStackedState(false) clears body.stacked and re-applies the stored split", () => {
  const body = fakeBody(["stacked"]);
  const cardPane = fakeCardPane();
  const applied = [];
  applyStackedState(false, {
    body,
    cardPane,
    storedWidth: "800",
    containerWidth: 2000,
    applyWidth: (px) => applied.push(px),
  });
  assert.equal(body.classList.contains("stacked"), false);
  assert.deepEqual(applied, [800]);
});

test("applyStackedState(false) clamps the stored split to the current container", () => {
  const applied = [];
  applyStackedState(false, {
    body: fakeBody(["stacked"]),
    cardPane: fakeCardPane(),
    storedWidth: "5000",
    containerWidth: 2000,
    applyWidth: (px) => applied.push(px),
  });
  assert.deepEqual(applied, [1580]);
});

test("applyStackedState(false) without a usable stored split leaves the width alone", () => {
  for (const storedWidth of [null, undefined, "", "  ", "abc", "NaN"]) {
    const applied = [];
    applyStackedState(false, {
      body: fakeBody(),
      cardPane: fakeCardPane(),
      storedWidth,
      containerWidth: 2000,
      applyWidth: (px) => applied.push(px),
    });
    assert.deepEqual(applied, [], `storedWidth=${JSON.stringify(storedWidth)}`);
  }
});

test("applyStackedState(false) tolerates a missing applyWidth callback", () => {
  const body = fakeBody(["stacked"]);
  applyStackedState(false, {
    body,
    cardPane: fakeCardPane(),
    storedWidth: "800",
    containerWidth: 2000,
  });
  assert.equal(body.classList.contains("stacked"), false);
});

// --- index.html: two-column shell ---------------------------------------------------

async function readHtml() {
  return readWebappFile("index.html");
}

test("shell: dropzone lives inside #cardpane, above the card list", async () => {
  const html = await readHtml();
  const paneStart = html.indexOf('<aside id="cardpane">');
  assert.notEqual(paneStart, -1, "cardpane missing");
  const pane = html.slice(paneStart, html.indexOf("</aside>", paneStart));
  const dropzoneIdx = pane.indexOf('<div id="dropzone">');
  const scrollIdx = pane.indexOf('<div id="cards-scroll">');
  const listIdx = pane.indexOf('<table id="cardlist">');
  assert.notEqual(dropzoneIdx, -1, "dropzone must move into the left column");
  assert.notEqual(scrollIdx, -1, "the card list needs its own scroll wrapper");
  assert.ok(dropzoneIdx < scrollIdx && scrollIdx < listIdx, "dropzone, then the scrolling card list");
  assert.ok(pane.includes('id="pick-btn"'), "pick-btn stays in the dropzone");
  assert.ok(pane.includes('id="file-input"'), "file-input stays in the dropzone");
});

test("shell: 3x2 action grid holds the six buttons in the spec order", async () => {
  const html = await readHtml();
  const start = html.indexOf('<div id="actiongrid">');
  assert.notEqual(start, -1, "actiongrid missing");
  // Order per the mock: Select all | Export ticked | Compare selected /
  // Deselect all | Import to parser | Clear.
  const order = ["select-all-btn", "export-ticked-btn", "compare-btn", "deselect-all-btn", "import-parser-btn", "clear-btn"];
  let last = -1;
  for (const id of order) {
    const idx = html.indexOf(`id="${id}"`, start);
    assert.notEqual(idx, -1, `${id} missing from the toolbar`);
    assert.ok(idx > last, `${id} is out of order in the action grid`);
    last = idx;
  }
});

test("shell: Loaded files region sits right of the grid, inside #toolbar", async () => {
  const html = await readHtml();
  const tbStart = html.indexOf('<div id="toolbar">');
  assert.notEqual(tbStart, -1, "toolbar missing");
  const toolbar = html.slice(tbStart, html.indexOf('<section id="viewerhost">', tbStart));
  const gridIdx = toolbar.indexOf('<div id="actiongrid">');
  const loadedIdx = toolbar.indexOf('<div id="loadedfiles">');
  assert.ok(gridIdx !== -1 && loadedIdx !== -1, "both toolbar regions must exist");
  assert.ok(gridIdx < loadedIdx, "the action grid comes first, Loaded files to its right");
  assert.ok(toolbar.indexOf('id="progresswrap"', loadedIdx) > loadedIdx, "progress lives in the Loaded files region");
  assert.ok(toolbar.indexOf('id="warnings"', loadedIdx) > loadedIdx, "warnings live in the Loaded files region");
  assert.ok(toolbar.includes('id="loadedfiles-label"'), "the label is part of the region");
});

test("shell: export formats moved into a popup anchored to Export ticked", async () => {
  const html = await readHtml();
  assert.ok(!html.includes('id="exportbar"'), "the flat export bar is gone");
  const anchorStart = html.indexOf('<span id="export-anchor">');
  assert.notEqual(anchorStart, -1, "export-anchor missing");
  const anchor = html.slice(anchorStart, html.indexOf("</span>", html.indexOf('id="export-popup-actions"', anchorStart)));
  assert.ok(anchor.includes('id="export-ticked-btn"'), "the trigger button anchors the popup");
  assert.ok(anchor.includes('aria-expanded="false"') && anchor.includes('aria-haspopup="dialog"'), "the trigger is a labelled popup opener");
  assert.ok(anchor.includes('role="dialog"') && anchor.includes('aria-label="Export formats"'), "the popup is a labelled dialog");
  assert.ok(anchor.includes('id="export-popup"') && anchor.includes("hidden"), "the popup starts hidden");
  for (const format of ["mbn", "json", "csv", "webcsv", "b0cd", "b826", "mtk_nr", "mtk_lte"]) {
    assert.ok(anchor.includes(`data-format="${format}"`), `format ${format} must live in the popup`);
  }
  assert.ok(anchor.includes('id="export-confirm-btn"') && anchor.includes('id="export-cancel-btn"'), "Export/Cancel actions");
});

test("shell: status + parser results sit under the toolbar, above the viewer", async () => {
  const html = await readHtml();
  const statusIdx = html.indexOf('id="export-status"');
  const resultsIdx = html.indexOf('id="import-results"');
  const viewerIdx = html.indexOf('<section id="viewerhost">');
  assert.notEqual(statusIdx, -1, "export-status missing");
  assert.notEqual(resultsIdx, -1, "import-results missing");
  // The toolbar's REAL close tag is the last one before the status band (the
  // first </div> after <div id="toolbar"> closes #export-popup-title inside the
  // popup, so a forward scan would make the assertion vacuous).
  const toolbarEnd = html.lastIndexOf("</div>", statusIdx);
  assert.notEqual(toolbarEnd, -1, "toolbar close not found before the status band");
  assert.ok(toolbarEnd < statusIdx, "status sits AFTER the toolbar");
  assert.ok(statusIdx < resultsIdx && resultsIdx < viewerIdx, "results follow the status, still above the viewer");
  assert.ok(
    html.indexOf('id="export-status"') > html.indexOf('<div id="toolbar">'),
    "status must not be hoisted above the toolbar",
  );
});


// --- css/app.css: portrait media query -----------------------------------------------

async function readMediaQueryBlock() {
  const css = await readWebappFile("css", "app.css");
  const start = css.indexOf(`@media ${STACKED_MEDIA_QUERY}`);
  assert.notEqual(start, -1, "portrait media query missing from app.css");
  return css.slice(start);
}

function ruleInside(block, selector) {
  const start = block.indexOf(selector);
  assert.notEqual(start, -1, `${selector} rule missing from the portrait media query`);
  return block.slice(start, block.indexOf("}", start));
}

test("app.css: desktop shell lays out the toolbar grid + loaded-files divider", async () => {
  const css = await readWebappFile("css", "app.css");
  const mqStart = css.indexOf(`@media ${STACKED_MEDIA_QUERY}`);
  const desktop = css.slice(0, mqStart);

  const gridIdx = desktop.indexOf("#actiongrid {");
  assert.notEqual(gridIdx, -1, "desktop #actiongrid rule missing");
  const gridRule = desktop.slice(gridIdx, desktop.indexOf("}", gridIdx));
  assert.ok(gridRule.includes("display: grid"), "the actions render as a grid");
  assert.ok(gridRule.includes("repeat(3,"), "three columns for the 3x2 block");

  const loadedIdx = desktop.indexOf("#loadedfiles {");
  assert.notEqual(loadedIdx, -1, "desktop #loadedfiles rule missing");
  const loadedRule = desktop.slice(loadedIdx, desktop.indexOf("}", loadedIdx));
  assert.ok(loadedRule.includes("border-left: 1px solid"), "the vertical divider separates grid from Loaded files");

  const popupIdx = desktop.indexOf("#export-popup {");
  assert.notEqual(popupIdx, -1, "desktop #export-popup rule missing");
  const popupRule = desktop.slice(popupIdx, desktop.indexOf("}", popupIdx));
  assert.ok(popupRule.includes("position: absolute"), "the popup floats above the viewer, not in flow");

  const appIdx = desktop.indexOf("#app {");
  assert.notEqual(appIdx, -1);
  const appRule = desktop.slice(appIdx, desktop.indexOf("}", appIdx));
  const vhIdx = appRule.indexOf("height: 100vh;");
  const dvhIdx = appRule.indexOf("height: 100dvh;");
  assert.notEqual(vhIdx, -1, "#app keeps its 100vh height");
  assert.notEqual(dvhIdx, -1, "#app must add 100dvh for mobile browser chrome");
  assert.ok(vhIdx < dvhIdx, "100dvh must follow 100vh (fallback order)");
});

test("app.css portrait query: stacked workbench, hidden splitter, capped card pane", async () => {
  const block = await readMediaQueryBlock();
  assert.ok(ruleInside(block, "#workbench {").includes("flex-direction: column"));
  assert.ok(ruleInside(block, "#cardpane {").includes("order: 1"), "import + card list first in the single column");
  assert.ok(ruleInside(block, "#rightcol {").includes("order: 2"), "toolbar + viewer follow");

  assert.ok(ruleInside(block, "#splitter {").includes("display: none"));

  const cardpane = ruleInside(block, "#cardpane {");
  assert.ok(cardpane.includes("max-height: 45vh"), "card pane capped at 45vh");
  assert.ok(cardpane.includes("min-width: 0"), "320px desktop min-width must not survive");
  assert.ok(cardpane.includes("!important"), "inline splitter styles must be beaten");

  const viewerRule = ruleInside(block, "#viewerhost {");
  assert.ok(viewerRule.includes("min-height: 75vh"), "combo view must be at least 75vh tall in portrait");
  assert.ok(viewerRule.includes("overflow: visible"), "#viewerhost must not scroll internally in portrait");

  assert.ok(ruleInside(block, "#toolbar {").includes("flex-direction: column"));
});

test("portrait: #app switches to page-scroll sizing (height auto, min-height dvh)", async () => {
  const block = await readMediaQueryBlock();
  const appRule = ruleInside(block, "#app {");
  assert.ok(appRule.includes("height: auto"), "#app must release the viewport lock in portrait");
  const vh = appRule.indexOf("min-height: 100vh;");
  const dv = appRule.indexOf("min-height: 100dvh;");
  assert.notEqual(vh, -1, "min-height 100vh fallback required");
  assert.notEqual(dv, -1, "min-height 100dvh required");
  assert.ok(vh < dv, "100dvh must follow 100vh (fallback order)");
});

test("portrait: table rows stay page-flowed, wide tables pan inside the wrap", async () => {
  const block = await readMediaQueryBlock();
  const wrapRule = ruleInside(block, ".cv-tablewrap {");
  assert.ok(wrapRule.includes("overflow-x: auto"),
    ".cv-tablewrap must clip wide tables horizontally (a max-content table must never widen the page)");
  assert.ok(!/overflow\s*:/.test(wrapRule),
    "no shorthand overflow: the y-axis keeps page-flow (rows grow the document)");
  assert.ok(ruleInside(block, ".compare {").includes("overflow: visible"),
    ".compare must not scroll internally in portrait");
});

test("portrait: #cardpane keeps its 45vh cap while the scroller is the list wrapper", async () => {
  const block = await readMediaQueryBlock();
  const cardRule = ruleInside(block, "#cardpane {");
  assert.ok(cardRule.includes("max-height: 45vh"), "card list keeps its cap");
  assert.ok(!cardRule.includes("overflow:"), "#cardpane itself no longer scrolls (the wrapper does)");
});

test("app.css portrait query: progress bar flexes and touch polish lands", async () => {
  const block = await readMediaQueryBlock();
  assert.ok(ruleInside(block, "#progress {").includes("flex: 1"), "progress must flex so label + Cancel fit the row");

  const chip = ruleInside(block, "#loadedfiles .loadedfile-chip {");
  assert.ok(chip.includes("60vw"), "chip max-width override missing");

  assert.ok(ruleInside(block, ".cv-search-entry {").includes("min(260px, 100%)"));

  // "button {" must not match a descendant rule like "#actiongrid button {":
  // require it at line start.
  const buttonMatch = block.match(/(?:^|\n)\s*button\s*\{/);
  assert.notEqual(buttonMatch, null, "touch-target button rule missing");
  const buttonRule = block.slice(buttonMatch.index, block.indexOf("}", buttonMatch.index));
  assert.ok(buttonRule.includes("min-height"), "buttons need a bumped tap-target height");
});
