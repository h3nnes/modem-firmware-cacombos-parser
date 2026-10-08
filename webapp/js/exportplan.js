// Batch-export planning helpers (pure, unit-tested). The DOM wiring lives in
// main.js; this module only decides WHAT to export and HOW to deliver it:
//
// - buildExportJobs pairs the ticked cards with the enabled formats in a
//   deterministic order (card list order x canonical format order).
// - deliveryMode picks individual downloads and a single zip once the file
//   count would flood the browser's download shelf.
// - dedupeFilenames gives zip entries collision-free names: record export
//   names collide across images (the same card ships in several corpus
//   images), so repeats get _2/_3/... before the extension, deterministically.
// - decodeExportBytes decodes export payloads for download WITHOUT stripping
//   the UTF-8 BOM that toCsvText emits for CSV/Web CSV (the default
//   TextDecoder strips the BOM).

// Canonical format order: mbn, json, csv, b0cd, b826, with a "webcsv" slot
// (the viewer's per-table CSVs) after csv and the MTK DRDI trace formats at
// the end. "mbn" is the raw .mbn blob under record.name; worker.js
// special-cases it before exportModule.
export const EXPORT_FORMATS = ["mbn", "json", "csv", "webcsv", "b0cd", "b826", "mtk_nr", "mtk_lte"];

// Formats only MTK DRDI cards can produce (the worker's MTK export arm):
// a qcom/apple card ticked with them enabled is skipped silently instead of
// failing the batch with "Unsupported export format".
const MTK_ONLY_FORMATS = new Set(["mtk_nr", "mtk_lte"]);

// >20 exported files → deliver one zip instead of that many downloads.
export const ZIP_FILE_THRESHOLD = 20;

export function buildExportJobs(tickedCards, enabledFormats) {
  const formats = EXPORT_FORMATS.filter((f) => (enabledFormats ?? []).includes(f));
  const jobs = [];
  for (const card of tickedCards ?? []) {
    for (const format of formats) {
      if (MTK_ONLY_FORMATS.has(format) && !(card.record && card.record.mtk)) continue;
      jobs.push({ card, format });
    }
  }
  return jobs;
}

export function deliveryMode(fileCount) {
  return fileCount <= ZIP_FILE_THRESHOLD ? "files" : "zip";
}

// Suffix before the extension: "rf_config_x_lteca.csv" → "rf_config_x_lteca_2.csv".
// Names without a usable extension take the suffix at the very end.
function withCountSuffix(name, n) {
  const dot = name.lastIndexOf(".");
  if (dot > 0) return `${name.slice(0, dot)}_${n}${name.slice(dot)}`;
  return `${name}_${n}`;
}

export function dedupeFilenames(names) {
  const out = [];
  const used = new Set();
  const seen = new Map(); // original name -> occurrences so far
  for (const name of names) {
    const nth = seen.get(name) ?? 0;
    seen.set(name, nth + 1);
    let candidate = name;
    if (nth > 0) {
      let n = nth + 1;
      candidate = withCountSuffix(name, n);
      while (used.has(candidate)) {
        n += 1;
        candidate = withCountSuffix(name, n);
      }
    }
    used.add(candidate);
    out.push(candidate);
  }
  return out;
}

// BOM-preserving UTF-8 decode for download payloads. TextDecoder's default
// strips a leading U+FEFF ("ignoreBOM: true" means KEEP it — the flag names
// the *error*, not the byte) so Excel-relevant CSVs keep their BOM.
export function decodeExportBytes(bytes) {
  return new TextDecoder("utf-8", { ignoreBOM: true }).decode(bytes);
}
