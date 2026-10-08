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
// CSS classes `.band-c<index>` (viewer.js memoBandIndex) so large tbodies carry
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
