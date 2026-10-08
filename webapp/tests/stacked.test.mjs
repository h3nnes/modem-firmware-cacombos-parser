// Unit tests for the stacked (mobile portrait) workbench layout: the pure
// stacked-state helpers in webapp/js/splitter.js, plus source-level pins for
// the top-bar restructure in index.html and the portrait media query in
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

// --- index.html: top-bar restructure -------------------------------------------------

async function readTopbar() {
  const html = await readWebappFile("index.html");
  const start = html.indexOf('<header id="topbar">');
  assert.notEqual(start, -1, "topbar header missing");
  const end = html.indexOf("</header>", start);
  return html.slice(start, end);
}

test("topbar: clear-btn moved into #topbar-actions next to compare-btn, out of the dropzone", async () => {
  const topbar = await readTopbar();
  const dropzoneStart = topbar.indexOf('<div id="dropzone">');
  assert.notEqual(dropzoneStart, -1);
  const dropzone = topbar.slice(dropzoneStart, topbar.indexOf("</div>", dropzoneStart));
  const actionsStart = topbar.indexOf('<span id="topbar-actions">');
  assert.notEqual(actionsStart, -1, "topbar-actions span missing");
  const actions = topbar.slice(actionsStart, topbar.indexOf("</span>", actionsStart));
  assert.ok(actions.includes('id="clear-btn"'), "clear-btn must live in topbar-actions");
  assert.ok(actions.includes('id="compare-btn"'), "compare-btn must live in topbar-actions");
  assert.ok(!dropzone.includes('id="clear-btn"'), "clear-btn must leave the dropzone");
  assert.ok(dropzone.includes('id="pick-btn"'), "pick-btn stays in the dropzone");
  assert.ok(dropzone.includes('id="file-input"'), "file-input stays in the dropzone");
});

test("topbar DOM order: dropzone, progresswrap, topbar-actions", async () => {
  const topbar = await readTopbar();
  const dropzoneIdx = topbar.indexOf('id="dropzone"');
  const progressIdx = topbar.indexOf('id="progresswrap"');
  const actionsIdx = topbar.indexOf('id="topbar-actions"');
  assert.ok(dropzoneIdx !== -1 && progressIdx !== -1 && actionsIdx !== -1);
  assert.ok(dropzoneIdx < progressIdx, "dropzone must come before progresswrap");
  assert.ok(progressIdx < actionsIdx, "progresswrap must come before topbar-actions");
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

test("app.css: desktop gains the #topbar-actions row and #app gains 100dvh", async () => {
  const css = await readWebappFile("css", "app.css");
  const mqStart = css.indexOf(`@media ${STACKED_MEDIA_QUERY}`);
  const desktop = css.slice(0, mqStart);
  const actionsIdx = desktop.indexOf("#topbar-actions");
  assert.notEqual(actionsIdx, -1, "desktop #topbar-actions rule missing");
  const actionsRule = desktop.slice(actionsIdx, desktop.indexOf("}", actionsIdx));
  assert.ok(actionsRule.includes("display: flex"), "topbar-actions renders as a button row on desktop");

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

  assert.ok(ruleInside(block, "#splitter {").includes("display: none"));

  const cardpane = ruleInside(block, "#cardpane {");
  assert.ok(cardpane.includes("max-height: 45vh"), "card pane capped at 45vh");
  assert.ok(cardpane.includes("min-width: 0"), "320px desktop min-width must not survive");
  assert.ok(cardpane.includes("!important"), "inline splitter styles must be beaten");

  const viewerRule = ruleInside(block, "#viewerhost {");
  assert.ok(viewerRule.includes("min-height: 75vh"), "combo view must be at least 75vh tall in portrait");
  assert.ok(viewerRule.includes("overflow: visible"), "#viewerhost must not scroll internally in portrait");

  assert.ok(ruleInside(block, "#topbar {").includes("flex-direction: column"));
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

test("portrait: #cardpane keeps its 45vh internal scroll", async () => {
  const block = await readMediaQueryBlock();
  const cardRule = ruleInside(block, "#cardpane {");
  assert.ok(cardRule.includes("max-height: 45vh"), "card list keeps its cap");
  assert.ok(!cardRule.includes("overflow"), "#cardpane keeps its base overflow:auto");
});

test("app.css portrait query: progress bar flexes and touch polish lands", async () => {
  const block = await readMediaQueryBlock();
  assert.ok(ruleInside(block, "#progress {").includes("flex: 1"), "progress must flex so label + Cancel fit the row");

  const chip = ruleInside(block, "#loadedfiles .loadedfile-chip {");
  assert.ok(chip.includes("60vw"), "chip max-width override missing");

  assert.ok(ruleInside(block, ".cv-search-entry {").includes("min(260px, 100%)"));

  // "button {" must not match "#topbar-actions button {": require it at line start.
  const buttonMatch = block.match(/(?:^|\n)\s*button\s*\{/);
  assert.notEqual(buttonMatch, null, "touch-target button rule missing");
  const buttonRule = block.slice(buttonMatch.index, block.indexOf("}", buttonMatch.index));
  assert.ok(buttonRule.includes("min-height"), "buttons need a bumped tap-target height");
});
