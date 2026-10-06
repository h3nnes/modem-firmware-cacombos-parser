#!/usr/bin/env python3
"""Regenerate the MTK differential goldens webapp/goldens/mtk/{tables,diag}.json
from the FIXED python reference parser (mtk-drdi-combo-parser).

Usage: python3 tools/generate_mtk_goldens.py [--corpus-dir DIR] [--out DIR]
       [--manifest]   # also (re)write the committed manifest.json

The reference is <corpus>/mtk-drdi-combo-parser; fixtures are the two packaged
sample images in the corpus root (both single-drdi grid images). Golden keys
mirror the tests: "<stem>/bank<index>/profile<p>" — one entry per card the
webapp scan produces (capability profiles, Tensor secondary profiles, bank-only
LTE row tables), derived exactly like mtkCardCombos() in webapp/js/lib/
mtk_scan.js.

tables.json mirrors generateMtkTables() in webapp/js/lib/mtk_tables.js — the JS
differential test compares it with deepEqualOrdered, so row key order and every
cell value must match the JS module byte-for-byte. The row schema lives in
build_tables()/class_letter()/... below and must change together with the JS
module. diag.json holds the reference's own export texts per card (b0cd/b826/
mtk_nr/mtk_lte through export_selected_formats — the run_bank_extraction path
with that card's combos), the byte-exact fixtures the Stage-D export port
differential-tests against. Both dumps stay untracked (webapp/.gitignore);
tests skip without them. manifest.json is small and COMMITTED: image digests
plus per-card counts for the count cross-check. Like the apple generator it is
NOT rewritten by a plain regen — pass --manifest after an intentional change.
"""
import argparse
import hashlib
import json
import platform
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parent.parent
IMAGES = (
    "Oppo_Find_X10_Pro_Max_5G_PMX110-modem.img",
    "mtk_pocox8pro_d8500u_modem.img",
)

# --- row schema (must stay byte-identical to js/lib/mtk_tables.js) -------------

FR2_MIN_BAND = 257
FAMILY_KEYS = {"LTE": "lte_ca", "NR SA (1CC)": "nr_sa", "NR-CA": "nr_ca",
               "EN-DC": "endc", "NRDC": "nrdc"}


def class_label(value):
    # main.py _class_name: letters for the observed range, [n] beyond.
    return chr(65 + value) if 0 <= value < 26 else f"[{value}]"


def family_for(combo):
    """The reference viewer's presentation family (backend.js familyFor)."""
    if combo.lte:
        return "EN-DC" if combo.nr else "LTE"
    if not combo.nr:
        return None
    if (any(c.band < FR2_MIN_BAND for c in combo.nr)
            and any(c.band >= FR2_MIN_BAND for c in combo.nr)):
        return "NRDC"
    return "NR SA (1CC)" if combo.nr_physical_ccs == 1 else "NR-CA"


def ordered(components, ul=False):
    """Qualcomm presentation: descending band/class order (stable sort)."""
    return sorted(
        (c for c in components if c.has_ul) if ul else list(components),
        key=lambda c: (-c.band, -(c.ul_class if ul else c.dl_class)),
    )


def bands(components, ul=False):
    return " + ".join(
        f"{c.band}{class_label(c.ul_class if ul else c.dl_class)}" for c in components)


def values(vals):
    return " + ".join("?" if v is None else str(v) for v in vals)


def nr_values(components, field, ul=False):
    out = []
    for c in components:
        for cc in c.ccs:
            if not ul or cc.ul_mimo is not None:
                out.append(getattr(cc, field))
    return values(out)


def nr_columns(dl, ul, prefix=""):
    return {
        f"{prefix}MIMO DL": nr_values(dl, "dl_mimo"),
        f"{prefix}SCS DL (kHz)": nr_values(dl, "scs_khz"),
        f"{prefix}BW DL (MHz)": nr_values(dl, "dl_bw_mhz"),
        f"{prefix}MIMO UL": nr_values(ul, "ul_mimo", True),
        f"{prefix}SCS UL (kHz)": nr_values(ul, "scs_khz", True),
        f"{prefix}BW UL (MHz)": nr_values(ul, "ul_bw_mhz", True),
    }


def build_tables(combos, lte_rows):
    """The generateMtkTables projection: per-combo presentation families over
    [lte_rows, combos] with combo_key dedup (keep-first), rows in decode
    order."""
    tables = {"lte_ca": [], "nr_sa": [], "nr_ca": [], "endc": [], "nrdc": []}
    seen = set()
    for rows in (lte_rows, combos):
        for combo in rows:
            family = family_for(combo)
            key = U.combo_key(combo)
            if family is None or key in seen:
                continue
            seen.add(key)
            lte_dl = ordered(combo.lte)
            lte_ul = ordered(combo.lte, True)
            nr_dl = ordered(combo.nr)
            nr_ul = ordered(combo.nr, True)
            lte_mimo = values([m for c in lte_dl for m in c.dl_mimo])
            if family == "LTE":
                row = {"LTE DL": bands(lte_dl), "MIMO DL": lte_mimo,
                       "LTE UL": bands(lte_ul, True)}
            elif family == "EN-DC":
                f = nr_columns(nr_dl, nr_ul, "NR ")
                row = {
                    "LTE DL": bands(lte_dl), "LTE MIMO DL": lte_mimo,
                    "NR DL": bands(nr_dl), "NR MIMO DL": f["NR MIMO DL"],
                    "NR SCS DL (kHz)": f["NR SCS DL (kHz)"],
                    "NR BW DL (MHz)": f["NR BW DL (MHz)"],
                    "LTE UL": bands(lte_ul, True), "NR UL": bands(nr_ul, True),
                    "NR MIMO UL": f["NR MIMO UL"],
                    "NR SCS UL (kHz)": f["NR SCS UL (kHz)"],
                    "NR BW UL (MHz)": f["NR BW UL (MHz)"],
                }
            elif family == "NRDC":
                row = {}
                groups = {
                    fr: ([c for c in nr_dl if (c.band < FR2_MIN_BAND) == (fr == "FR1")],
                         [c for c in nr_ul if (c.band < FR2_MIN_BAND) == (fr == "FR1")])
                    for fr in ("FR1", "FR2")
                }
                for direction in ("DL", "UL"):
                    for fr in ("FR1", "FR2"):
                        dl, ul = groups[fr]
                        f = nr_columns(dl, ul, f"{fr} ")
                        row[f"{fr} {direction}"] = bands(
                            ul if direction == "UL" else dl, direction == "UL")
                        for feature in ("MIMO", "SCS", "BW"):
                            name = (f"{fr} {feature} {direction}"
                                    + (" (kHz)" if feature == "SCS"
                                       else " (MHz)" if feature == "BW" else ""))
                            row[name] = f[name]
            else:
                f = nr_columns(nr_dl, nr_ul)
                row = {"NR DL": bands(nr_dl)}
                for name, value in f.items():
                    if " DL" in name:
                        row[name] = value
                row["NR UL"] = bands(nr_ul, True)
                for name, value in f.items():
                    if " UL" in name:
                        row[name] = value
            tables[FAMILY_KEYS[family]].append(row)
    return tables


def counts_with_nr_sa(combos, lte_rows):
    """gui_family_counts with the NR-SA presentation column the webapp added
    (the reference parser predates it): an NR row is NR SA when it is not an
    FR1/FR2 mix and decodes exactly one physical CC. Key order mirrors
    guiFamilyCounts() in webapp/js/lib/mtk_universal.js."""
    counts = dict(U.gui_family_counts(combos))
    _endc, nr, _lte = U.export.classify(combos, 1)
    nrdc = sum(any(c.band < FR2_MIN_BAND for c in row.nr)
               and any(c.band >= FR2_MIN_BAND for c in row.nr) for row in nr)
    nr_sa = sum(row.nr_physical_ccs == 1 for row in nr)
    return {"endc": counts["endc"], "nr_sa": nr_sa, "nrca": len(nr) - nrdc - nr_sa,
            "nrdc": counts["nrdc"], "lte": len(lte_rows)}


# --- per-card derivation (must stay identical to mtkCardCombos) ----------------


def card_combos(active, cap, per_profile, lte_profiles, secondary, bank_index, profile):
    if bank_index == cap.table_index and profile in per_profile:
        combos = per_profile[profile]
        if isinstance(active, U.TensorCdfLoader):
            # Tensor rows are per physical bank; a Bank-6 card must not show
            # sibling-bank rows (scanMtk's counts use the same projection).
            rows = (getattr(active, "lte_rows_by_bank", {}).get(bank_index) or {}).get(profile, ())
            return combos, U.dedup_exact(rows)
        return combos, lte_profiles.get(profile, [])
    for item in secondary:
        if item.bank_index == bank_index and item.profile == profile:
            combos = U._secondary_combos(item)
            lte = U.tensor_related_lte(active, item.profile, lte_profiles) if lte_profiles else []
            return combos, list(lte)
    rows = (getattr(active, "lte_rows_by_bank", {}).get(bank_index) or {}).get(profile, ())
    return [], U.dedup_exact(rows)


def card_keys(cap, per_profile, secondary, physical):
    """Every (bank, profile) card the webapp scan produces, scanMtk's order:
    capability profiles, Tensor secondary rows, bank-only LTE row tables —
    sorted by (bank, profile)."""
    cards = [(cap.table_index, profile) for profile in per_profile]
    cards.extend((item.bank_index, item.profile) for item in secondary)
    indexed = set(cards)
    for bank_str, profiles in (physical or {}).items():
        for profile_str in profiles:
            key = (int(bank_str), int(profile_str))
            if key not in indexed:
                indexed.add(key)
                cards.append(key)
    return sorted(cards)


# --- reference export texts (Stage-D differential fixtures) ---------------------

EXPORT_SUFFIXES = {
    "b0cd": "_0xB0CD_v41.txt",
    "b826": "_0xB826_v21_combined.txt",
    "mtk_nr": "_mtk_nr_trace.txt",
    "mtk_lte": "_mtk_lte_ca_comb_info.txt",
}


def diag_texts(combos, lte, device, stem, out_dir):
    U.export_selected_formats(combos, lte, device, out_dir, stem, frozenset(EXPORT_SUFFIXES))
    texts = {}
    for key, suffix in EXPORT_SUFFIXES.items():
        path = out_dir / f"{stem}{suffix}"
        if path.exists():
            texts[key] = path.read_text(encoding="utf-8")
    return texts


# --- golden build ----------------------------------------------------------------


def decode_image(corpus, img_name):
    parts = unwrap_path(corpus / img_name)
    rep = U.Reporter()
    stem = Path(img_name).stem
    args = SimpleNamespace(loader="auto", profile="all", out=None, device=stem,
                           stem=stem, drdi_data=None)
    active, _attempts, _data = U.select_loader(args, parts.rom, parts.drdi, rep,
                                               drdi_data=parts.drdi_data)
    cap, _states, per_profile, union, _lte_bank, lte_profiles, lte_union, unresolved = \
        U.extract_capability(active, "all", rep)
    secondary = U.decode_tensor_secondary(active, 8, rep)
    physical = ({str(b): {str(p): len(U.dedup_exact(rows)) for p, rows in profiles.items()}
                 for b, profiles in active.lte_rows_by_bank.items()}
                if isinstance(active, U.TensorCdfLoader) else None)
    return {
        "stem": stem,
        "active": active,
        "cap": cap,
        "per_profile": per_profile,
        "lte_profiles": lte_profiles,
        "secondary": secondary,
        "physical": physical,
        "union": union,
        "lte_union": lte_union,
        "unresolved": unresolved,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", default=str(REPO.parent))
    ap.add_argument("--out", default=str(REPO / "webapp" / "goldens"))
    ap.add_argument("--manifest", action="store_true",
                    help="also write the committed manifest.json (plain regen leaves it untouched)")
    args = ap.parse_args()
    corpus = Path(args.corpus_dir)
    out = Path(args.out) / "mtk"
    sys.path.insert(0, str(corpus / "mtk-drdi-combo-parser"))
    global U, export, unwrap_path
    import mtk_universal as U  # noqa: E402
    import mtk_export as export  # noqa: E402
    from mtk_containers import unwrap_path  # noqa: E402

    missing = [name for name in IMAGES if not (corpus / name).is_file()]
    if missing:
        raise SystemExit(f"corpus images missing: {missing}")

    manifest = {
        "regen": "python3 tools/generate_mtk_goldens.py --corpus-dir <corpus> --out webapp/goldens --manifest",
        "python": platform.python_version(),
        "images": {},
    }
    tables_golden = {}
    diag_golden = {}
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        for img_name in IMAGES:
            img_path = corpus / img_name
            decoded = decode_image(corpus, img_name)
            active = decoded["active"]
            cap = decoded["cap"]
            stem = decoded["stem"]
            image_entry = {
                "file": img_name,
                "size": img_path.stat().st_size,
                "sha256": hashlib.sha256(img_path.read_bytes()).hexdigest(),
                "loader": active.name,
                "capability_bank_index": cap.table_index,
                "cards": {},
            }
            for bank_index, profile in card_keys(cap, decoded["per_profile"],
                                                 decoded["secondary"], decoded["physical"]):
                combos, lte = card_combos(active, cap, decoded["per_profile"],
                                          decoded["lte_profiles"], decoded["secondary"],
                                          bank_index, profile)
                key = f"{stem}/bank{bank_index}/profile{profile}"
                tables = build_tables(combos, lte)
                tables_golden[key] = tables
                diag_golden[key] = diag_texts(combos, lte, stem, stem, tmp)
                counts = counts_with_nr_sa(combos, lte)
                image_entry["cards"][key] = {
                    "counts": counts,
                    "rows": {name: len(rows) for name, rows in tables.items()},
                }
                print(key)
            manifest["images"][stem] = image_entry

    out.mkdir(parents=True, exist_ok=True)
    (out / "tables.json").write_text(json.dumps(tables_golden, indent=1) + "\n", encoding="utf-8")
    (out / "diag.json").write_text(json.dumps(diag_golden, indent=1) + "\n", encoding="utf-8")
    if args.manifest:
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {out / 'manifest.json'}")
    print(f"wrote {out / 'tables.json'} and {out / 'diag.json'} for {len(tables_golden)} cards")


if __name__ == "__main__":
    main()
