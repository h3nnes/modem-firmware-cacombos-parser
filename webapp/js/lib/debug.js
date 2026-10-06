// Debug-only instrumentation counters (WEBAPP_PERFORMANCE_REVIEW.md step 0).
// Off by default and never read on the hot path unless a caller bumps a counter;
// `bump` is a single Map-free property increment so leaving the calls in
// production is harmless. worker.js enables them on demand and attaches a
// snapshot to every reply so a browser session (or a Node protocol test) can
// assert that extraction/parsing happens the expected number of times.
export const debugCounters = {
  extractContainer: 0, // extractContainer() calls (per source, per open)
  parseModule: 0, // qcom parseModule() calls
  parseAppleBank: 0, // apple parseAppleBank() calls
  unwrapMtk: 0, // MTK unwrap+decode runs (cold card opens; the scan seeds the memo)
  parseMtkProfile: 0, // MTK per-card parses (mtkCardCombos derivations on parse-memo miss)
  generateWebTables: 0, // qcom viewer table builds
  generateAppleTables: 0, // apple viewer table builds
  generateMtkTables: 0, // MTK viewer table builds
  buildB826: 0, // MTK B826 v21 family encodes (mtk_export.buildB826)
  buildB0cd: 0, // MTK B0CD v41 payload builds (mtk_export.buildB0cdV41)
  renderMtkNrTrace: 0, // MTK NR trace log renders (mtk_trace.renderNrTrace)
  renderMtkLteLog: 0, // MTK LTE CA_COMB_INFO renders (mtk_trace.renderLteLog)
  fatWalk: 0, // Fat16Image.walk() traversals
  ext4Walk: 0, // Ext4Image.walk() traversals
  postMessage: 0, // worker replies posted (host<->worker transfer volume)
};

export function bump(name) {
  debugCounters[name] += 1;
}

export function snapshotDebugCounters() {
  return { ...debugCounters };
}

export function resetDebugCounters() {
  for (const name of Object.keys(debugCounters)) debugCounters[name] = 0;
}
