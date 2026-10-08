// ComboViewer: the table viewer UI (tabs, band sorting, filter re-sort,
// apply-filter with nospace fallback + count label strings, SCS visibility
// rule, zebra rows, band-token coloring via bandcolors with a memoized color
// map, header-click sort with ▲/▼ indicators, selection click/ctrl/shift,
// the three-item copy context menu, per-tab CSV export and the info banner).
// - Sorting/filtering run on the already-JSON table rows in the main thread;
//   nothing here re-parses. The renderer touches the DOM only through the
//   ComboViewer class, so the pure helpers stay unit-testable in Node.
import { BAND_COLUMN_HEADERS, bandSegments, bandColor, bandColorIndex } from "./lib/bandcolors.js";
import { pyCasefold } from "./lib/modern_parser.js";
import { toCsvText } from "./lib/analyzer.js";
import { csvFilename, download } from "./exporter.js";

const ASCII_DIGITS_RE = /^[0-9]+$/;

export const TAB_DEFINITIONS = [
  ["LTE", "lte_ca"],
  // MediaTek only: single-carrier NR rows ("NR SA (1CC)").
  ["NR SA", "nr_sa"],
  ["NRCA", "nr_ca"],
  ["ENDC", "endc"],
  ["NRDC", "nrdc"],
];

export const EMPTY_COUNT_LABEL = "0 combos";

const BAND_COLUMN_SET = new Set(BAND_COLUMN_HEADERS);

// --- sort keys ------------------------------------------------------------------

// PLAIN_BAND_RE semantics: '$' matches before a single trailing \n
// and \d is Unicode Nd, matching the bandcolors.js regexes.
const PLAIN_BAND_RE = /^(\p{Nd}+)([A-Z])?(?=\n?$)/u;

// (0, ((num, letter), ...)) for fully band-parsable cells, (1, cell) otherwise.
export function bandSortKey(cell) {
  const pairs = [];
  for (const token of String(cell).split(" + ")) {
    const m = PLAIN_BAND_RE.exec(token);
    if (!m) return [1, cell];
    pairs.push([pyNdDigits(m[1]), m[2] || ""]);
  }
  return [0, pairs];
}

// Integer value over Nd digits (each Nd code point contributes its digit value).
function pyNdDigits(digits) {
  // ASCII fast path: band tokens are ASCII in practice. Number() rounds like
  // the BigInt -> Number conversion below, so the result is identical.
  if (ASCII_DIGITS_RE.test(digits)) return Number(digits);
  let value = 0n;
  for (const ch of digits) {
    const cp = ch.codePointAt(0);
    const start = ND_RUN_STARTS.find((s) => cp >= s && cp <= s + 9);
    if (start === undefined) throw new RangeError(`not a Unicode decimal digit: U+${cp.toString(16)}`);
    value = value * 10n + BigInt(cp - start);
  }
  return Number(value);
}

// Band digits are small in practice; the Nd run-start table is shared with the
// int()-over-Nd semantics used elsewhere.
const ND_RUN_STARTS = [
  48, 1632, 1776, 1984, 2406, 2534, 2662, 2790, 2918, 3046, 3174, 3302, 3430,
  3558, 3664, 3792, 3872, 4160, 4240, 6112, 6160, 6470, 6608, 6784, 6800,
  6992, 7088, 7232, 7248, 42528, 43216, 43264, 43472, 43504, 43600, 44016,
  65296, 66720, 68912, 68928, 69734, 69872, 69942, 70096, 70384, 70736,
  70864, 71248, 71360, 71376, 71386, 71472, 71904, 72016, 72688, 72784,
  73040, 73120, 73552, 90416, 92768, 92864, 93008, 93552, 118000, 120782,
  120792, 120802, 120812, 120822, 123200, 123632, 124144, 124401, 125264,
  130032,
];

const cmpScalar = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// Tuple comparison over the key shapes: (kind, payload) where payload
// is a pair array (band columns), a number (numeric columns) or a string.
// Positional compare, prefix-equal tuples: the shorter one is smaller.
export function compareKeys(a, b) {
  if (a[0] !== b[0]) return cmpScalar(a[0], b[0]);
  if (a[0] === 1) return cmpScalar(a[1], b[1]);
  const va = a[1];
  const vb = b[1];
  if (typeof va === "number") return cmpScalar(va, vb);
  const len = Math.min(va.length, vb.length);
  for (let i = 0; i < len; i++) {
    const order = cmpScalar(va[i][0], vb[i][0]);
    if (order !== 0) return order;
    const letters = cmpScalar(va[i][1], vb[i][1]);
    if (letters !== 0) return letters;
  }
  return cmpScalar(va.length, vb.length);
}

// (0, int(v)) when int() parses, (1, v) otherwise — v is the untrimmed string.
// int() strips surrounding whitespace and accepts PEP 515 digit separators
// (underscores strictly between digits: "1_0" parses, "_1"/"1_"/"1__0" don't).
function numericElseStringKey(v) {
  const s = String(v).trim();
  const m = /^[+-]?(\p{Nd}+(?:_\p{Nd}+)*)$/u.exec(s);
  if (m) {
    const value = pyNdDigits(m[1].replaceAll("_", ""));
    return [0, s.startsWith("-") ? -value : value];
  }
  return [1, v];
}

export function columnSortKey(col) {
  const bandCol = BAND_COLUMN_SET.has(col);
  return (row) => {
    const v = String(row && row[col] !== undefined && row[col] !== null ? row[col] : "");
    return bandCol ? bandSortKey(v) : numericElseStringKey(v);
  };
}

// Stable sort with the reverse flag flipping the comparison: equal keys keep
// their original relative order.
// Decorate-sort-undecorate: each row's key is computed exactly once (O(n))
// instead of twice per comparison (O(n log n) regex + Nd parses). Comparator
// and stability semantics are unchanged (modern engines sort stably; ties keep
// input order in both directions).
export function sortRows(rows, col, reverse = false) {
  const key = columnSortKey(col);
  const decorated = rows.map((row) => ({ row, k: key(row) }));
  decorated.sort(reverse ? (a, b) => compareKeys(b.k, a.k) : (a, b) => compareKeys(a.k, b.k));
  return decorated.map((d) => d.row);
}

// --- filter + count label --------------------------------------------------------

// Lazily computes each row's casefolded "all cells joined" text and its
// no-space variant once per tab, so repeated typing over a large table does not
// re-fold every cell on every keystroke (review A1: 1,236 rows x 16 cells).
export function createRowSearchIndex(rows) {
  const texts = new Array(rows.length);
  const nospace = new Array(rows.length);
  const ensure = (i) => {
    if (texts[i] === undefined) {
      const text = pyCasefold(Object.values(rows[i]).map((v) => String(v)).join(" "));
      texts[i] = text;
      nospace[i] = text.replaceAll(" ", "");
    }
  };
  return {
    text(i) {
      ensure(i);
      return texts[i];
    },
    nospace(i) {
      ensure(i);
      return nospace[i];
    },
  };
}

export function filterRows(rows, rawQuery, index = null) {
  const query = String(rawQuery ?? "").trim();
  const q = pyCasefold(query);
  if (!q) return [...rows];
  const qNospace = q.replaceAll(" ", "");
  const filtered = [];
  for (let i = 0; i < rows.length; i++) {
    const rowText = index ? index.text(i) : pyCasefold(Object.values(rows[i]).map((v) => String(v)).join(" "));
    const rowNospace = index ? index.nospace(i) : rowText.replaceAll(" ", "");
    if (rowText.includes(q) || rowNospace.includes(qNospace)) filtered.push(rows[i]);
  }
  return filtered;
}

// Per-column search (second header row): same matching as filterRows, but per
// single cell. Empty (or whitespace-only) queries pass everything.
export function matchColumn(cellText, rawQuery) {
  const q = pyCasefold(String(rawQuery ?? "").trim());
  if (!q) return true;
  const cell = pyCasefold(String(cellText ?? ""));
  const qNospace = q.replaceAll(" ", "");
  return cell.includes(q) || cell.replaceAll(" ", "").includes(qNospace);
}

// AND-combines every non-empty column filter over pre-globally-filtered rows.
// Order of composition with filterRows is irrelevant: every predicate ANDs.
export function applyColumnFilters(rows, colFilters) {
  const active = [];
  for (const [col, raw] of Object.entries(colFilters ?? {})) {
    const q = String(raw ?? "").trim();
    if (q) active.push([col, q]);
  }
  if (!active.length) return [...rows];
  return rows.filter((row) => active.every(([col, q]) => matchColumn(row[col], q)));
}

export function countLabelText(rawQuery, shown, total, hasColumnFilters = false) {
  const fmt = (n) => n.toLocaleString("en-US");
  const filtered = String(rawQuery ?? "").trim() !== "" || hasColumnFilters;
  return filtered ? `Showing ${fmt(shown)} of ${fmt(total)} combos` : `Total: ${fmt(total)} combos`;
}

// --- columns + banner ------------------------------------------------------------

export function visibleColumns(columns, showScs) {
  return columns.filter((c) => showScs || !c.includes("SCS"));
}

const fmtKb = (size) => `${(size / 1024).toLocaleString("en-US", { minimumFractionDigits: 1, maximumFractionDigits: 1 })} KB`;

export function infoBannerParts(info) {
  const parts = [];
  if (info) {
    if (info.identity) parts.push(`HWID_FSID_BID: ${info.identity}`);
    if (info.generation) parts.push(`Format: ${info.generation}`);
    if (info.size) parts.push(`Size: ${fmtKb(info.size)}`);
    if (info.inner_path) parts.push(`Path: ${info.inner_path}`);
  }
  return parts;
}

// --- memoized band colors (one color per canonical band) --------------------------

const BAND_COLOR_MEMO = new Map();
const BAND_INDEX_MEMO = new Map();

export function memoBandColor(canonical) {
  let color = BAND_COLOR_MEMO.get(canonical);
  if (color === undefined) {
    color = bandColor(canonical);
    BAND_COLOR_MEMO.set(canonical, color);
  }
  return color;
}

// Palette index for the `.band-c<index>` class; same md5 reduction as
// memoBandColor, memoized the same way.
export function memoBandIndex(canonical) {
  let index = BAND_INDEX_MEMO.get(canonical);
  if (index === undefined) {
    index = bandColorIndex(canonical);
    BAND_INDEX_MEMO.set(canonical, index);
  }
  return index;
}

// --- renderer ----------------------------------------------------------------------

const CELL_FONT_CSS = "13px ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace";
const MIN_COL_PX = 40;
const MAX_COL_PX = 2400;
// Typing on a large tab (3,906+ rows) must not re-filter + re-render per
// keystroke; applyFilter is debounced by this much. The count label updates
// with the debounced render (documented tradeoff: computing the filtered count
// immediately would run the same O(n) pass the debounce exists to skip).
const SEARCH_DEBOUNCE_MS = 150;

// Viewport virtualization (Step 4). A table above the threshold paints only
// the rows intersecting the viewport (plus OVERSCAN_ROWS either side) with a
// top/bottom spacer row; small tables keep the simple full render. Rows are
// uniform height (nowrap + table-layout: fixed + monospace), so
// visibleRange/spacerHeights are pure integer math over the full filtered
// array — selection indices, shift-click ranges, copy and CSV export keep
// referring to filtered-array indices, never DOM positions.
export const VIRTUALIZE_THRESHOLD = 300;
export const OVERSCAN_ROWS = 8;
// Fallback before the first row is measured (converges after one render).
export const DEFAULT_ROW_HEIGHT = 24;

export function visibleRange(total, scrollTop, viewportHeight, rowHeight, overscan = OVERSCAN_ROWS) {
  if (total <= VIRTUALIZE_THRESHOLD || rowHeight <= 0) return { start: 0, end: total };
  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const last = Math.min(total, Math.ceil((scrollTop + viewportHeight) / rowHeight) + overscan);
  return { start: first, end: Math.max(last, first + 1) };
}

export function spacerHeights(total, start, end, rowHeight) {
  return {
    top: Math.max(0, start * rowHeight),
    bottom: Math.max(0, (total - end) * rowHeight),
  };
}

// Zebra stripe class by FILTERED index (evenrow when idx % 2 == 0).
// Class-based so the virtualization spacer rows cannot shift parity.
export function rowStripeClass(index) {
  return index % 2 === 0 ? "cv-row-even" : "cv-row-odd";
}

const esc = (s) => String(s).replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));

function bandCellHtml(cell, header) {
  const segments = bandSegments(cell, header);
  if (!segments.length) return esc(cell);
  return segments
    .map((seg) => (seg.canonical ? `<span class="cv-band band-c${memoBandIndex(seg.canonical)}">${esc(seg.text)}</span>` : esc(seg.text)))
    .join(" + ");
}

// Code-point count (String iterator == [...s].length) without the array
// allocation; layoutColumns runs this over every cell of every table.
export const charCount = (s) => {
  let n = 0;
  for (const _ of s) n += 1;
  return n;
};

function measureCharWidth() {
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  ctx.font = CELL_FONT_CSS;
  return Math.max(1, ctx.measureText("0").width);
}

export class ComboViewer {
  // tables: {lte_ca, nr_ca, endc, nrdc} raw JSON rows; info: {identity, name,
  // generation, size, inner_path} for the banner + CSV default filename.
  // opts.mobile records the stacked layout (used for the layout flag only;
  // virtualization applies to every layout).
  constructor(host, tables, info = {}, opts = {}) {
    this.host = host;
    this.info = info;
    this.mobile = !!opts.mobile;
    this.virtual = false; // current tab paints a viewport window
    this.rowHeight = 0; // measured from the first rendered row
    this.renderRaf = null; // scroll re-render coalescing
    this.showScs = false;
    this.filterTimer = null;
    this.filterRowEl = null;
    this.filterRowSignature = null;
    this.tabs = new Map();
    this.activeKey = null;
    this.charW = measureCharWidth();
    this.widthCache = new Map(); // `${tblKey}\u0001${showScs}` -> {visible, widths}
    this.pendingResize = null;

    const root = document.createElement("div");
    root.className = "cv";
    root.innerHTML = `
      <div class="cv-header"></div>
      <div class="cv-search">
        <label class="cv-search-label" for="cv-search-input">Search:</label>
        <input id="cv-search-input" class="cv-search-entry" type="text" autocomplete="off" spellcheck="false">
        <button class="cv-clear-btn" title="Clear search" type="button">✕</button>
        <label class="cv-scs-label"><input type="checkbox" class="cv-scs-check"> Show SCS</label>
        <button class="cv-export-btn" type="button">Export CSV</button>
        <span class="cv-count"></span>
        <span class="cv-status" hidden></span>
      </div>
      <div class="cv-tabs" role="tablist"></div>
      <div class="cv-empty" hidden>No combinations found for this RF card.</div>
      <div class="cv-tablewrap" hidden><table><colgroup></colgroup><thead></thead><tbody></tbody></table></div>
      <div class="cv-contextmenu" hidden></div>
    `;
    this.root = root;
    this.bannerEl = root.querySelector(".cv-header");
    this.searchEl = root.querySelector(".cv-search-entry");
    this.clearBtn = root.querySelector(".cv-clear-btn");
    this.scsCheck = root.querySelector(".cv-scs-check");
    this.exportBtn = root.querySelector(".cv-export-btn");
    this.countEl = root.querySelector(".cv-count");
    this.statusEl = root.querySelector(".cv-status");
    this.tabsEl = root.querySelector(".cv-tabs");
    this.emptyEl = root.querySelector(".cv-empty");
    this.tableWrapEl = root.querySelector(".cv-tablewrap");
    this.colgroupEl = root.querySelector("colgroup");
    this.theadEl = root.querySelector("thead");
    this.tbodyEl = root.querySelector("tbody");
    this.menuEl = root.querySelector(".cv-contextmenu");
    this.host.appendChild(root);

    const bannerParts = infoBannerParts(info);
    this.bannerEl.textContent = bannerParts.length ? bannerParts.join("  |  ") : "RF Card Combination Viewer";

    for (const [label, tblKey] of TAB_DEFINITIONS) {
      const rows = tables && Array.isArray(tables[tblKey]) ? tables[tblKey] : [];
      if (!rows.length) continue;
      const columns = Object.keys(rows[0]);
      this.tabs.set(tblKey, {
        label,
        columns,
        rows,
        filtered: [...rows],
        visible: [],
        widths: [],
        overrides: {},
        sortCol: null,
        sortReverse: false,
        colFilters: {},
        selected: new Set(),
        anchor: null,
        searchIndex: null, // createRowSearchIndex(rows), built on first search
      });
    }

    this.bindEvents();

    if (this.tabs.size === 0) {
      this.tabsEl.innerHTML = `<button class="cv-tab active" type="button" disabled>Empty</button>`;
      this.emptyEl.hidden = false;
      this.countEl.textContent = EMPTY_COUNT_LABEL;
    } else {
      this.activeKey = this.tabs.keys().next().value;
      this.renderTabs();
      this.applyFilter();
    }
    this.searchEl.focus();
  }

  tab() {
    return this.tabs.get(this.activeKey);
  }

  renderTabs() {
    this.tabsEl.innerHTML = "";
    for (const [tblKey, info] of this.tabs) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `cv-tab${tblKey === this.activeKey ? " active" : ""}`;
      btn.textContent = `${info.label} (${info.rows.length.toLocaleString("en-US")})`;
      btn.addEventListener("click", () => {
        this.activeKey = tblKey;
        this.renderTabs();
        this.applyFilter(); // re-apply filter on tab change
      });
      this.tabsEl.appendChild(btn);
    }
  }

  // Column widths are computed from state.rows (invariant under filtering and
  // sorting) once per (tab, showScs) and cached; applyFilter/sortBy re-apply the
  // cache plus any drag overrides instead of rescanning every cell.
  layoutColumns(state, tblKey = this.activeKey) {
    const key = `${tblKey}\u0001${this.showScs}`;
    let measured = this.widthCache.get(key);
    if (!measured) {
      measured = this.#measureColumns(state);
      this.widthCache.set(key, measured);
    }
    state.visible = measured.visible;
    state.widths = measured.visible.map((col, i) => {
      const override = state.overrides[col];
      return override !== undefined ? Math.max(1, override) : measured.widths[i];
    });
  }

  #measureColumns(state) {
    const visible = visibleColumns(state.columns, this.showScs);
    const padChars = Math.max(2, Math.round(16 / this.charW));
    const minChars = Math.max(4, Math.round(45 / this.charW));
    const widths = [];
    for (const col of visible) {
      // Reserve room for the sort indicator; measurement is in characters,
      // the HTML colgroup needs pixels.
      const headerLen = charCount(col) + 2;
      let contentLen = 0;
      for (const r of state.rows) {
        const len = charCount(String(r[col] ?? ""));
        if (len > contentLen) contentLen = len;
      }
      widths.push(Math.ceil((Math.max(minChars, headerLen, contentLen) + padChars) * this.charW));
    }
    return { visible, widths };
  }

  applyFilter() {
    const state = this.tab();
    if (!state) return;
    const query = this.searchEl.value;
    const hasQuery = query.trim() !== "";
    const hasColumnFilters = Object.values(state.colFilters).some((v) => String(v ?? "").trim() !== "");
    if (!hasQuery && !hasColumnFilters) {
      // No predicate at all: state.rows is read-only (sorting replaces the
      // filtered array with a new one), so alias it instead of copying twice.
      state.filtered = state.rows;
    } else {
      if (hasQuery && !state.searchIndex) state.searchIndex = createRowSearchIndex(state.rows);
      const searched = filterRows(state.rows, query, hasQuery ? state.searchIndex : null);
      state.filtered = applyColumnFilters(searched, state.colFilters);
    }
    state.selected = new Set();
    state.anchor = null;
    if (state.sortCol) {
      // Same key function as header-click sort (viewer 5319687 fix).
      state.filtered = sortRows(state.filtered, state.sortCol, state.sortReverse);
    }
    this.layoutColumns(state);
    this.resetScroll(state);
    this.renderTable(state);
    this.countEl.textContent = countLabelText(query, state.filtered.length, state.rows.length, hasColumnFilters);
  }

  // A new result set restarts at the top: virtualized spacers are positioned
  // from scrollTop, so an old offset would paint the wrong window. Small
  // (non-virtual) tables keep their scroll position as before.
  resetScroll(state) {
    if (state.filtered.length > VIRTUALIZE_THRESHOLD && this.tableWrapEl.scrollTop !== 0) {
      this.tableWrapEl.scrollTop = 0;
    }
  }

  // The filter row is persistent DOM (one <input> per visible column of the
  // active tab). renderTable rewrites thead.innerHTML, which detaches it, so
  // the element is re-attached after each render; inputs keep their values,
  // and the focused input keeps focus + caret across the swap. Rebuilt only
  // when the (tab x visible columns) signature changes — tab switch or SCS
  // toggle — never on filter/sort re-renders, so typing never loses focus.
  syncFilterRow(state) {
    const signature = `${this.activeKey}\u0000${state.visible.join("\u0001")}`;
    if (this.filterRowEl && this.filterRowSignature === signature) return;
    this.filterRowSignature = signature;
    const tr = document.createElement("tr");
    tr.className = "cv-filterrow";
    for (const col of state.visible) {
      const th = document.createElement("th");
      const input = document.createElement("input");
      input.type = "text";
      input.className = "cv-colfilter";
      input.dataset.col = col;
      input.value = state.colFilters[col] ?? "";
      input.autocomplete = "off";
      input.spellcheck = false;
      th.appendChild(input);
      tr.appendChild(th);
    }
    this.filterRowEl = tr;
  }

  attachFilterRow() {
    if (!this.filterRowEl) return;
    this.theadEl.appendChild(this.filterRowEl);
  }

  // The sticky filter row must pin directly beneath the label row, but CSS
  // cannot know the label row's rendered height, so measure it live and set
  // an inline top on each filter cell (overrides the top:0 from
  // `.cv thead th`). Called after every render so the offset never goes
  // stale, whether the row was rebuilt or persisted.
  positionFilterRow() {
    const tr = this.theadEl.querySelector("tr.cv-filterrow");
    if (!tr) return;
    const top = `${this.theadEl.rows[0]?.offsetHeight ?? 0}px`;
    for (const th of tr.cells) th.style.top = top;
  }

  restoreFilterFocus(saved) {
    if (!saved || !this.filterRowEl || !this.filterRowEl.contains(saved.el) || !saved.el.isConnected) return;
    saved.el.focus();
    try {
      saved.el.setSelectionRange(saved.start, saved.end);
    } catch {
      // setSelectionRange throws on non-text inputs; all inputs here are text.
    }
  }

  sortBy(col) {
    const state = this.tab();
    if (!state) return;
    if (state.sortCol === col) state.sortReverse = !state.sortReverse;
    else {
      state.sortCol = col;
      state.sortReverse = false;
    }
    // The existing filtered list is sorted in place; the deterministic filter
    // makes re-filter-then-sort an equivalent path that
    // keeps the shared key function.
    state.filtered = sortRows(state.filtered, col, state.sortReverse);
    state.selected = new Set();
    state.anchor = null;
    this.layoutColumns(state);
    this.resetScroll(state);
    this.renderTable(state);
  }

  rowHtml(row, visible, index) {
    let tr = `<tr data-i="${index}" class="${rowStripeClass(index)}">`;
    for (const col of visible) {
      const cell = String(row[col] ?? "");
      tr += `<td>${BAND_COLUMN_SET.has(col) ? bandCellHtml(cell, col) : esc(cell)}</td>`;
    }
    return `${tr}</tr>`;
  }

  // Paints the rows intersecting the viewport (plus overscan) into tbody, with
  // padded spacer rows covering the off-screen rows. Scroll re-renders call this
  // alone, so the header/colgroup are never rebuilt while scrolling.
  renderRows(state) {
    const total = state.filtered.length;
    const virtual = total > VIRTUALIZE_THRESHOLD;
    const rowHeight = this.rowHeight || DEFAULT_ROW_HEIGHT;
    const viewport = this.tableWrapEl.clientHeight || 600;
    const range = virtual
      ? visibleRange(total, this.tableWrapEl.scrollTop, viewport, rowHeight)
      : { start: 0, end: total };
    const colspan = Math.max(1, state.visible.length);
    const html = [];
    if (virtual) {
      const { top } = spacerHeights(total, range.start, range.end, rowHeight);
      if (top > 0) html.push(`<tr class="cv-spacer" aria-hidden="true"><td colspan="${colspan}" style="height:${top}px"></td></tr>`);
    }
    for (let i = range.start; i < range.end; i++) html.push(this.rowHtml(state.filtered[i], state.visible, i));
    if (virtual) {
      const { bottom } = spacerHeights(total, range.start, range.end, rowHeight);
      if (bottom > 0) html.push(`<tr class="cv-spacer" aria-hidden="true"><td colspan="${colspan}" style="height:${bottom}px"></td></tr>`);
    }
    this.tbodyEl.innerHTML = html.join("");
    this.virtual = virtual;
    // Measure the uniform row height once, then re-render with exact spacers.
    if (virtual && this.rowHeight === 0) {
      const tr = this.tbodyEl.querySelector("tr[data-i]");
      // Fractional height (offsetHeight rounds), so spacer math matches layout.
      const measured = tr ? tr.getBoundingClientRect().height : 0;
      if (measured > 0) {
        this.rowHeight = measured;
        this.renderRows(state);
      }
    }
  }

  // Layout toggle (phone rotation): virtualization is layout-agnostic now, but
  // the wrap's client height changes, so re-render the visible window.
  setMobile(mobile) {
    if (this.mobile === mobile) return;
    this.mobile = mobile;
    if (this.tabs.size) this.applyFilter();
  }

  renderTable(state) {
    this.tableWrapEl.hidden = false;
    this.emptyEl.hidden = true;
    this.colgroupEl.innerHTML = state.widths.map((w) => `<col style="width:${Math.round(w)}px">`).join("");

    // Preserve focus/caret: the debounced applyFilter can fire while the user
    // is still focused in a column filter input.
    const activeInput = document.activeElement;
    const saved =
      activeInput && this.filterRowEl && this.filterRowEl.contains(activeInput) && activeInput.tagName === "INPUT"
        ? { el: activeInput, start: activeInput.selectionStart, end: activeInput.selectionEnd }
        : null;

    const arrow = state.sortReverse ? " ▼" : " ▲";
    let headerHtml = "<tr>";
    for (const col of state.visible) {
      const label = col === state.sortCol ? `${col}${arrow}` : col;
      headerHtml += `<th data-col="${esc(col)}"><div class="cv-th-inner">${esc(label)}<div class="cv-colhandle" data-col="${esc(col)}"></div></div></th>`;
    }
    headerHtml += "</tr>";
    this.theadEl.innerHTML = headerHtml;
    this.syncFilterRow(state);
    this.attachFilterRow();
    this.restoreFilterFocus(saved);

    this.renderRows(state);
    this.applySelection();
    this.positionFilterRow();
  }

  applySelection() {
    const state = this.tab();
    if (!state) return;
    for (const tr of this.tbodyEl.querySelectorAll("tr[data-i]")) {
      tr.classList.toggle("sel", state.selected.has(Number(tr.dataset.i)));
    }
  }

  rowFromEvent(event) {
    const tr = event.target.closest("tbody tr[data-i]");
    if (!tr) return -1; // spacer rows are not in the selection index space
    return Number(tr.dataset.i);
  }

  onRowClick(event) {
    const state = this.tab();
    if (!state) return;
    const row = this.rowFromEvent(event);
    if (row < 0) return;
    if (event.ctrlKey || event.metaKey) {
      if (state.selected.has(row)) state.selected.delete(row);
      else state.selected.add(row);
      state.anchor = row;
    } else if (event.shiftKey) {
      const anchor = state.anchor ?? (state.selected.size ? Math.min(...state.selected) : row);
      for (let i = Math.min(anchor, row); i <= Math.max(anchor, row); i++) state.selected.add(i);
      state.anchor = row;
    } else {
      state.selected = new Set([row]);
      state.anchor = row;
    }
    this.applySelection();
  }

  // --- copy actions (full column list) -----------------------------------------

  copyText(text) {
    navigator.clipboard.writeText(text).catch(() => this.flash("Copy failed: clipboard unavailable"));
  }

  selectedRows(state) {
    return [...state.selected].sort((a, b) => a - b).map((i) => state.filtered[i]);
  }

  copySelected() {
    const state = this.tab();
    if (!state || !state.selected.size) return;
    const lines = [state.columns.join("\t")];
    for (const row of this.selectedRows(state)) lines.push(state.columns.map((c) => String(row[c] ?? "")).join("\t"));
    this.copyText(lines.join("\n"));
  }

  copyComboOnly() {
    const state = this.tab();
    if (!state || !state.selected.size) return;
    let dlColIdx = 0;
    for (let idx = 0; idx < state.columns.length; idx++) {
      if (state.columns[idx].includes("DL")) {
        dlColIdx = idx;
        break;
      }
    }
    const combos = this.selectedRows(state).map((row) => String(row[state.columns[dlColIdx]] ?? ""));
    this.copyText(combos.join("\n"));
  }

  copyAllVisible() {
    const state = this.tab();
    if (!state) return;
    const lines = [state.columns.join("\t")];
    for (const row of state.filtered) lines.push(state.columns.map((c) => String(row[c] ?? "")).join("\t"));
    this.copyText(lines.join("\n"));
  }

  // --- context menu --------------------------------------------------------------

  showContextMenu(event) {
    const state = this.tab();
    if (!state) return;
    const row = this.rowFromEvent(event);
    if (row >= 0 && !state.selected.has(row)) {
      state.selected = new Set([row]);
      state.anchor = row;
      this.applySelection();
    }
    event.preventDefault();
    this.menuEl.innerHTML = `
      <button type="button" data-action="selected">Copy Selected Row(s)</button>
      <button type="button" data-action="combo">Copy Carrier Combo Only</button>
      <hr>
      <button type="button" data-action="all">Copy All Filtered Rows</button>
    `;
    this.menuEl.hidden = false;
    const wrap = this.host.getBoundingClientRect();
    this.menuEl.style.left = `${event.clientX - wrap.left}px`;
    this.menuEl.style.top = `${event.clientY - wrap.top}px`;
  }

  hideContextMenu() {
    this.menuEl.hidden = true;
  }

  flash(message) {
    this.statusEl.textContent = message;
    this.statusEl.hidden = false;
    clearTimeout(this.statusTimer);
    this.statusTimer = setTimeout(() => {
      this.statusEl.hidden = true;
    }, 4000);
  }

  // ✕ / Escape reset path: clear the top search AND every tab's column
  // filters (hidden tabs included); their inputs are rebuilt empty on next
  // activation because syncFilterRow reads state.colFilters.
  clearColumnFilters() {
    for (const state of this.tabs.values()) state.colFilters = {};
    if (this.filterRowEl) {
      for (const input of this.filterRowEl.querySelectorAll(".cv-colfilter")) input.value = "";
    }
  }

  // --- CSV export (via exporter.js) -----------------------------------------------

  exportCurrentTabCsv() {
    const state = this.tab();
    if (!state) return;
    const rows = state.filtered;
    if (!rows.length) {
      this.flash("No rows to export.");
      return;
    }
    const text = toCsvText(rows);
    if (text === null) {
      this.flash("No rows to export.");
      return;
    }
    download(csvFilename(this.info.identity, state.label), text);
    this.flash(`Exported ${rows.length.toLocaleString("en-US")} rows.`);
  }

  // --- events ---------------------------------------------------------------------

  bindEvents() {
    this.searchEl.addEventListener("input", () => {
      clearTimeout(this.filterTimer);
      this.filterTimer = setTimeout(() => {
        this.filterTimer = null;
        this.applyFilter();
      }, SEARCH_DEBOUNCE_MS);
    });
    // Column filter inputs: delegated on thead (survives filter-row rebuilds);
    // input events bubble. Same debounce as the top search bar.
    this.theadEl.addEventListener("input", (event) => {
      const input = event.target.closest(".cv-colfilter");
      if (!input) return;
      const state = this.tab();
      if (!state || !state.visible.includes(input.dataset.col)) return;
      state.colFilters[input.dataset.col] = input.value;
      clearTimeout(this.filterTimer);
      this.filterTimer = setTimeout(() => {
        this.filterTimer = null;
        this.applyFilter();
      }, SEARCH_DEBOUNCE_MS);
    });
    this.clearBtn.addEventListener("click", () => {
      clearTimeout(this.filterTimer);
      this.filterTimer = null;
      this.searchEl.value = "";
      this.clearColumnFilters();
      this.applyFilter();
      this.searchEl.focus();
    });
    this.scsCheck.addEventListener("change", () => {
      this.showScs = this.scsCheck.checked;
      // SCS toggle: re-layout + re-render every tab, keep selection.
      for (const [tblKey, state] of this.tabs) {
        this.layoutColumns(state, tblKey);
        if (state === this.tab()) {
          this.renderTable(state);
          this.applySelection();
        }
      }
    });
    this.exportBtn.addEventListener("click", () => this.exportCurrentTabCsv());
    // Viewport virtualization: scrolling repaints only the visible row window,
    // rAF-coalesced. Non-virtual (small) tables never rebuild on scroll.
    this.tableWrapEl.addEventListener("scroll", () => {
      const state = this.tab();
      if (!state || state.filtered.length <= VIRTUALIZE_THRESHOLD) return;
      if (this.renderRaf) return;
      this.renderRaf = requestAnimationFrame(() => {
        this.renderRaf = null;
        const active = this.tab();
        if (!active) return;
        this.renderRows(active);
        this.applySelection();
      });
    });
    this.theadEl.addEventListener("click", (event) => {
      if (event.target.closest(".cv-filterrow")) return;
      const th = event.target.closest("th");
      if (th && !event.target.closest(".cv-colhandle")) this.sortBy(th.dataset.col);
    });
    this.tbodyEl.addEventListener("click", (event) => this.onRowClick(event));
    this.tbodyEl.addEventListener("contextmenu", (event) => this.showContextMenu(event));
    this.menuEl.addEventListener("click", (event) => {
      const btn = event.target.closest("button[data-action]");
      if (!btn) return;
      if (btn.dataset.action === "selected") this.copySelected();
      else if (btn.dataset.action === "combo") this.copyComboOnly();
      else this.copyAllVisible();
      this.hideContextMenu();
    });
    this.tableWrapEl.addEventListener("mousedown", (event) => {
      const handle = event.target.closest(".cv-colhandle");
      if (!handle) return;
      event.preventDefault();
      event.stopPropagation();
      const col = handle.dataset.col;
      const state = this.tab();
      const idx = state.visible.indexOf(col);
      const startWidth = Math.round(state.widths[idx]);
      const startX = event.clientX;
      const colEl = this.colgroupEl.children[idx];
      const onMove = (moveEvent) => {
        const width = Math.min(MAX_COL_PX, Math.max(MIN_COL_PX, startWidth + (moveEvent.clientX - startX)));
        state.overrides[col] = width;
        state.widths[idx] = width;
        colEl.style.width = `${width}px`;
      };
      const onUp = () => {
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });

    // Keyboard shortcuts: Escape resets filters, Ctrl/Cmd+F focuses search.
    this.onKeydown = (event) => {
      if (event.key === "Escape") {
        this.hideContextMenu();
        const hasColFilters = [...this.tabs.values()].some((s) =>
          Object.values(s.colFilters).some((v) => String(v ?? "").trim() !== ""),
        );
        if (this.searchEl.value || hasColFilters) {
          clearTimeout(this.filterTimer);
          this.filterTimer = null;
          this.searchEl.value = "";
          this.clearColumnFilters();
          this.applyFilter();
        }
      } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
        event.preventDefault();
        this.searchEl.focus();
        this.searchEl.select();
      } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "c") {
        const state = this.tab();
        if (state && state.selected.size) {
          event.preventDefault();
          this.copySelected();
        }
      }
    };
    this.onDocumentClick = (event) => {
      if (!this.menuEl.hidden && !this.menuEl.contains(event.target)) this.hideContextMenu();
    };
    document.addEventListener("keydown", this.onKeydown);
    document.addEventListener("click", this.onDocumentClick);
  }

  destroy() {
    clearTimeout(this.statusTimer);
    clearTimeout(this.filterTimer);
    if (this.renderRaf) cancelAnimationFrame(this.renderRaf);
    document.removeEventListener("keydown", this.onKeydown);
    document.removeEventListener("click", this.onDocumentClick);
    this.root.remove();
  }
}
