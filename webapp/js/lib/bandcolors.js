// Band-color layer for the combo viewer: palette, band column headers, band
// token regexes and the md5-based color mapping. Contract, note-for-note:
//
// - bandSpans(cell, header) -> [{start, end, canonical}]: one entry per band
//   token in the " + "-joined cell. start/end are offsets into the cell string
//   measured in code points, covering the whole token. Tokens matching neither
//   /^[Bn]<Nd>+[A-Z]?(before one trailing \n)/ nor /^<Nd>+[A-Z]?$/ are skipped
//   but still advance the offset by len + 3. A prefixed token keeps its prefix
//   as written ("B3A" -> "B3" even in an NR column); a plain token gets the
//   column prefix ("B" iff the header contains "LTE", else "n"). header must
//   be in BAND_COLUMN_HEADERS exactly (case-sensitive) or the result is [].
// - bandColor(canonical) -> PALETTE index via the md5 digest read as a
//   big-endian 128-bit integer mod 40, so the reduction runs on BigInt; a JS
//   Number could not hold the digest.
// - bandSegments(cell, header) -> [{text, canonical|null}]: token-level view of
//   the same split (null canonical = unparsable token) for HTML renderers;
//   joining the texts with " + " reproduces the cell.
// - bandColorFromCell(cell, header) -> color of the first band token, else
//   null.
// - BAND_NUMBER_COLORS / bandNumberOf(canonical) / bandColorClass(canonical):
//   static per-band-number coloring (same number -> same color for LTE and
//   NR); bandColorClass names the CSS class (`band-n<k>` injected by
//   viewer.js, or the md5 `band-c<idx>` fallback for uncovered numbers).
// - bandColor(canonical) -> PALETTE[bandColorIndex(canonical)] remains the md5
//   mapping (tests + non-class consumers; also the fallback path above).
import { md5Hex } from "./hash.js";

export const PALETTE = [
  "#B71C1C", "#D32F2F", "#C2185B", "#AD1457", "#880E4F",
  "#7B1FA2", "#9C27B0", "#6A1B9A", "#512DA8", "#4527A0",
  "#3949AB", "#303F9F", "#283593", "#1A237E", "#1565C0",
  "#0D47A1", "#0277BD", "#01579B", "#00838F", "#006064",
  "#00796B", "#00695C", "#004D40", "#2E7D32", "#1B5E20",
  "#33691E", "#827717", "#8D6E63", "#795548", "#6D4C41",
  "#5D4037", "#4E342E", "#5F6368", "#455A64", "#37474F",
  "#263238", "#BF360C", "#D84315", "#E64A19", "#8E24AA",
];

export const BAND_COLUMN_HEADERS = [
  "LTE DL", "LTE UL", "NR DL", "NR UL",
  "FR1 DL", "FR2 DL", "FR1 UL", "FR2 UL",
];

const BAND_COLUMN_HEADER_SET = new Set(BAND_COLUMN_HEADERS);

// \p{Nd} covers Unicode decimal digits (category Nd); (?=\n?$) matches before
// a single trailing newline.
const BAND_RE = /^([Bn]\p{Nd}+)[A-Z]?(?=\n?$)/u;
const PLAIN_BAND_RE = /^(\p{Nd}+)([A-Z])?(?=\n?$)/u;

const codePoints = (s) => [...s].length;

export function columnBandPrefix(header) {
  return header.includes("LTE") ? "B" : "n";
}

function bandTokens(cell, header) {
  if (!BAND_COLUMN_HEADER_SET.has(header)) return null;
  const prefix = columnBandPrefix(header);
  const tokens = [];
  let pos = 0;
  for (const token of cell.split(" + ")) {
    let canonical = null;
    const prefixed = BAND_RE.exec(token);
    if (prefixed) {
      canonical = prefixed[1];
    } else {
      const plain = PLAIN_BAND_RE.exec(token);
      if (plain) canonical = prefix + plain[1];
    }
    tokens.push({ token, canonical, start: pos });
    pos += codePoints(token) + 3;
  }
  return tokens;
}

export function bandSpans(cell, header) {
  const tokens = bandTokens(cell, header);
  const spans = [];
  if (!tokens) return spans;
  for (const { token, canonical, start } of tokens) {
    if (canonical !== null) spans.push({ start, end: start + codePoints(token), canonical });
  }
  return spans;
}

export function bandSegments(cell, header) {
  const tokens = bandTokens(cell, header);
  if (!tokens) return [];
  return tokens.map(({ token, canonical }) => ({ text: token, canonical }));
}

// Exact md5-of-UTF-8-bytes read as a 128-bit integer, reduced mod m (m a
// positive integer): the digest only ever touches BigInt.
export function md5IntMod(s, m) {
  return Number(BigInt("0x" + md5Hex(new TextEncoder().encode(s))) % BigInt(m));
}

// Palette index for a canonical band. The HTML viewer renders colors through
// CSS classes (viewer.js memoBandColorClass: `.band-n<number>` from the static
// BAND_NUMBER_COLORS map, `.band-c<index>` md5 fallback) so large tbodies carry
// no inline style attributes; bandColor keeps returning the hex for tests and
// any non-class consumer.
export function bandColorIndex(canonical) {
  if (typeof canonical !== "string") {
    throw new TypeError(`bandColor: canonical must be a string, got ${typeof canonical}`);
  }
  return md5IntMod(canonical, PALETTE.length);
}

export function bandColor(canonical) {
  return PALETTE[bandColorIndex(canonical)];
}

export function bandColorFromCell(cell, header) {
  const spans = bandSpans(cell, header);
  return spans.length ? bandColor(spans[0].canonical) : null;
}

// --- static per-band-number colors (Kotlin BAND_COLORS parity) ----------------------

// The band NUMBER picks the color, so the same number wears the same color
// whether it appears as an LTE band (B<k>) or an NR band (n<k>). Numbers not
// listed (unassigned or malformed) fall back to the md5 palette through
// bandColorClass. viewer.js injects this map once per page as
// `.cv .band-n<k>` rules, keeping class-based coloring (no inline styles on
// large tbodies) with the map as the single source of truth.
export const BAND_NUMBER_COLORS = new Map([
  [1, "#EE8700"], [2, "#3F70EE"], [3, "#81A83D"], [4, "#FF01FC"], [5, "#DFCA02"],
  [6, "#BF9309"], [7, "#CB0481"], [8, "#A96B2F"], [9, "#5FEE1D"], [10, "#077E1E"],
  [11, "#49CDF0"], [12, "#8B1CC3"], [13, "#CD6B95"], [14, "#0FBB67"], [15, "#510A3A"],
  [16, "#93590C"], [17, "#D5A8DE"], [18, "#17F8B0"], [19, "#594783"], [20, "#3DF7F0"],
  [21, "#476668"], [22, "#89B53A"], [23, "#CB040D"], [24, "#0D54DF"], [25, "#4FA3B1"],
  [26, "#91F283"], [27, "#D34156"], [28, "#1CAF8C"], [29, "#57E0FA"], [30, "#03B00D"],
  [31, "#45FFDF"], [32, "#9400BF"], [33, "#C99D84"], [34, "#0BED56"], [35, "#4D3C29"],
  [36, "#8F8BFB"], [37, "#D1DACD"], [38, "#798CED"], [39, "#557972"], [40, "#117FDC"],
  [41, "#439857"], [42, "#85E729"], [43, "#C736FC"], [44, "#0986CE"], [45, "#4BD5A0"],
  [46, "#0C00F2"], [47, "#CF7345"], [48, "#11C317"], [49, "#5312EA"], [50, "#FFE1FC"],
  [51, "#4131CF"], [52, "#8380A1"], [53, "#C5CF73"], [54, "#071F46"], [55, "#496E18"],
  [56, "#8BBDEA"], [57, "#CD0CBD"], [58, "#0F5C8F"], [59, "#51AB61"], [60, "#FD7A74"],
  [61, "#3FCA46"], [62, "#811919"], [63, "#C368EB"], [64, "#05B8BD"], [65, "#470790"],
  [66, "#D18799"], [67, "#CBA534"], [68, "#0DF506"], [69, "#4F44D9"], [70, "#FB13EC"],
  [71, "#3D63BE"], [72, "#7FB290"], [73, "#C10163"], [74, "#035135"], [75, "#45A007"],
  [76, "#87EFD9"], [77, "#C93EAC"], [78, "#DD0000"], [79, "#4DDD50"], [80, "#F9AC63"],
  [81, "#3BFC35"], [82, "#7D4B08"], [83, "#BF9ADA"], [84, "#01EAAC"], [85, "#43397F"],
  [86, "#858851"], [87, "#C7D723"], [88, "#0927F6"], [89, "#4B76C8"], [90, "#F745DB"],
  [91, "#3995AD"], [92, "#7BE47F"], [93, "#BD3352"], [94, "#FF8224"], [95, "#41D2F6"],
  [96, "#8321C9"], [97, "#C5709B"], [98, "#07C06D"], [99, "#490F40"], [100, "#DFC84B"],
  [101, "#FF5DC3"], [102, "#1FF33A"], [103, "#3F88B2"], [104, "#5F1D2A"], [105, "#7FB2A1"],
  [106, "#9F4719"], [107, "#BFDC90"], [108, "#DF7108"], [109, "#FF0680"], [110, "#BFD7C6"],
  [125, "#3FD097"], [126, "#5F650F"], [127, "#7FFA86"],
  [250, "#5FE099"], [251, "#7F7511"], [252, "#9F0A89"], [253, "#BF9F00"], [254, "#DF3478"],
  [255, "#FFC9EF"], [256, "#1F5F67"], [257, "#FF8B66"], [258, "#FF8B66"], [259, "#7F1ECE"],
  [260, "#3FEF14"], [261, "#5F848C"], [262, "#7F1904"], [263, "#9FAE7B"],
]);

// Band number of a canonical ("B3"/"n78" -> 3/78), null when unparsable.
// Canonicals always match ^[Bn]\p{Nd}+$, but non-ASCII digits never occur in
// modem data and fall through to the md5 fallback via the null here.
const BAND_NUMBER_RE = /^([Bn])([0-9]+)$/;

export function bandNumberOf(canonical) {
  const m = BAND_NUMBER_RE.exec(canonical);
  return m ? Number(m[2]) : null;
}

// CSS color class for a canonical band: `band-n<k>` (color injected by
// viewer.js from BAND_NUMBER_COLORS) when the band number is covered, else
// the static md5-palette class `band-c<idx>`.
export function bandColorClass(canonical) {
  const num = bandNumberOf(canonical);
  if (num !== null && BAND_NUMBER_COLORS.has(num)) return `band-n${num}`;
  return `band-c${bandColorIndex(canonical)}`;
}
