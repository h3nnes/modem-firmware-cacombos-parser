// uecaps.hennes.xyz import helpers (pure logic; HTTP + DOM wiring in main.js).
//
// The parser endpoint POST /parse/multiPart (Javalin, CORS anyHost) takes a
// "requests" form field (JSON array of RequestMultiPart) plus uploaded files
// referenced by index: {inputIndexes:[i], type:"QLTE"|"QNR"|"MNR"|"M",
// description}. QLTE consumes a 0xB0CD hexdump text, QNR a 0xB826 hexdump
// text — exactly what the webapp's b0cd/b826 export text produces
// (analyzer.js writeDiagText: "# label\nPayload: <hex>" lines; the parser's
// splitHex splits on "Payload:"). MNR consumes a MEDIATEK NR Trace Log and M
// a MEDIATEK CA_COMB_INFO text — the webapp's mtk_nr/mtk_lte exports
// (LogType.kt: M("MEDIATEK CA_COMB_INFO"), MNR("MEDIATEK NR Trace Log")).
// A stored multi result is viewed at /view/multi/?id=<uuid> (the parser
// frontend's own library link shape); the parse response carries the id.

export const PARSER_BASE = "https://uecaps.hennes.xyz";

// One entry per non-empty packet set; inputIndexes always stay dense (they
// count only the files actually appended). b0cd -> QLTE, b826 -> QNR,
// mtk_nr -> MNR, mtk_lte -> M. The optional MTK texts let an MTK DRDI card
// import without any DIAG packets; a mixed caller (qcom texts + MTK texts)
// keeps the entry/file order stable: QLTE, QNR, MNR, M.
// Throws when every text is empty (rare, capability-less cards).
export function buildImportEntries(b0cdText, b826Text, description, mnrText, mText) {
  const has = (t) => typeof t === "string" && t.trim().length > 0;
  if (!has(b0cdText) && !has(b826Text) && !has(mnrText) && !has(mText)) {
    throw new Error("No DIAG packets to import — this card has no 0xB0CD/0xB826 or MTK trace data.");
  }
  const entries = [];
  const files = [];
  const add = (type, text, tag) => {
    entries.push({ inputIndexes: [files.length], type, description });
    files.push({ filename: `${description}.${tag}.txt`, text });
  };
  if (has(b0cdText)) add("QLTE", b0cdText, "b0cd");
  if (has(b826Text)) add("QNR", b826Text, "b826");
  if (has(mnrText)) add("MNR", mnrText, "mtk_nr");
  if (has(mText)) add("M", mText, "mtk_lte");
  return { entries, files };
}

export function resultUrl(id) {
  return `${PARSER_BASE}/view/multi/?id=${encodeURIComponent(id)}`;
}
