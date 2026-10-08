// Browser download helpers. CSV filenames are rf_config_<identity>_<label
// lower>.csv when the card has an identity, <label lower>_combos.csv otherwise.
export const TAB_LABELS = { lte_ca: "LTE", nr_ca: "NRCA", endc: "ENDC", nrdc: "NRDC" };

export function csvFilename(identity, label) {
  const lower = String(label).toLowerCase();
  return identity ? `rf_config_${identity}_${lower}.csv` : `${lower}_combos.csv`;
}

export function download(filename, text, mime = "text/csv;charset=utf-8") {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke on the next tick: revoking synchronously can cancel the download.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

// Binary variant for the batch-zip delivery (>ZIP_FILE_THRESHOLD files build
// one fflate zipSync archive on the main thread); same anchor plumbing.
export function downloadBytes(filename, bytes, mime = "application/octet-stream") {
  const blob = new Blob([bytes], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
