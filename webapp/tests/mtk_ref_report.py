"""Scan-differential reference for the MTK DRDI webapp port (tests only).

Replicates mtk-drdi-combo-parser main.py's MtkBackend.summarize decode path
(unwrap -> select_loader -> extract_capability -> tensor secondary summaries ->
supported bands) and prints a JSON projection with the exact key order the JS
summary (decodeMtkSummary) must reproduce. Invoked by webapp/tests/
mtk_scan.test.mjs via spawnSync; nothing here is imported by the app.
"""
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

REF_DIR = Path(sys.argv[1])
IMG = Path(sys.argv[2])
sys.path.insert(0, str(REF_DIR))

import mtk_universal as U  # noqa: E402
from mtk_containers import unwrap_path  # noqa: E402

parts = unwrap_path(IMG)
rep = U.Reporter()
args = SimpleNamespace(loader="auto", profile="all", out=None, device=IMG.stem,
                       stem=IMG.stem, drdi_data=None)
active, attempts, _data = U.select_loader(args, parts.rom, parts.drdi, rep,
                                          drdi_data=parts.drdi_data)
cap, states, per_profile, union, lte_bank, lte_profiles, lte_union, unresolved = \
    U.extract_capability(active, "all", rep)
secondary = U.tensor_secondary_summaries(active, "all", rep, lte_profiles=lte_profiles,
                                         lte_count=len(lte_union))
supported = U.annotate_band_participation(
    U.discover_supported_bands(active, cap, lte_bank, rep), union, lte_union)
def combo_line(combo):
    """Canonical payload projection of one decoded combo — must stay
    byte-identical to comboDigestLine() in webapp/js/lib/mtk_scan.js."""
    return json.dumps({
        "k": combo.kind,
        "c": combo.nr_physical_ccs,
        "l": [{"b": c.band, "d": c.dl_class, "u": c.ul_class, "m": list(c.dl_mimo)}
              for c in combo.lte],
        "n": [{"b": c.band, "d": c.dl_class, "u": c.ul_class,
               "c": [[cc.scs_khz, cc.dl_mimo, cc.dl_bw_mhz, cc.ul_mimo, cc.ul_bw_mhz]
                     for cc in c.ccs]} for c in combo.nr],
    }, separators=(",", ":"))


is_tensor = isinstance(active, U.TensorCdfLoader)
out = {
    "loader": active.name,
    "loader_selection": attempts,
    "banks": [b.to_dict() for b in active.banks],
    "capability_bank": hex(cap.bank_va),
    "capability_bank_index": cap.table_index,
    "profiles": U.serialize_profile_summary(states, per_profile),
    "secondary_profiles": secondary,
    "lte_bank": hex(lte_bank.bank_va) if lte_bank else None,
    "lte_bank_index": lte_bank.table_index if lte_bank else None,
    "lte_profiles": {str(k): len(v) for k, v in lte_profiles.items()},
    "physical_lte_profiles": ({str(b): {str(p): len(U.dedup_exact(rows))
                                        for p, rows in profiles.items()}
                               for b, profiles in active.lte_rows_by_bank.items()}
                              if is_tensor else None),
    "lte_union_exact_rows": len(lte_union),
    "gui_counts": U.gui_family_counts(union),
    "union": {"exact_rows": len(union),
              "kinds": dict(zip(("endc", "nrca", "lte"), map(len, U.export.classify(union, 1)))),
              "complete": not unresolved, "unresolved_profiles": unresolved},
    "supported_bands": supported,
    "validation": rep.as_dict(),
    "profile_sha256": {str(s.image.profile): hashlib.sha256(
        s.image.drdi[s.image.source_offset:s.image.end_source]).hexdigest()
        for s in states},
    "combo_digest": {str(p): hashlib.sha256(
        "\n".join(combo_line(c) for c in rows).encode()).hexdigest()
        for p, rows in per_profile.items()},
}
json.dump(out, sys.stdout)
