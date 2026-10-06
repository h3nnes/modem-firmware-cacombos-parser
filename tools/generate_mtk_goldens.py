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

CLASS_LETTERS = "ABCDEFGHIJKL"
FR2_MIN_BAND = 257
UL_ABSENT_CELL = "—"  # LTE ul_class == 6 (absent uplink)


def class_letter(value):
    return CLASS_LETTERS[value] if 0 <= value < len(CLASS_LETTERS) else f"class{value}"


def lte_ul_cell(comp):
    # LteComponent.has_ul: ul_class < LTE_UL_ABSENT (6)
    return class_letter(comp.ul_class) if comp.ul_class < 6 else UL_ABSENT_CELL


def lte_token(comp):
    return f"{comp.band}{class_letter(comp.dl_class)}"


def per_cc(values):
    return "+".join("?" if v is None else str(v) for v in values)


def join_cc(comps, pick):
    return " + ".join(per_cc([pick(cc) for cc in comp.ccs]) for comp in comps)


def nr_cells(comps):
    return {
        "SCS": join_cc(comps, lambda cc: cc.scs_khz),
        "BW DL (MHz)": join_cc(comps, lambda cc: cc.dl_bw_mhz),
        "MIMO DL": join_cc(comps, lambda cc: cc.dl_mimo),
        "MIMO UL": join_cc(comps, lambda cc: cc.ul_mimo),
    }


def build_tables(combos, lte_rows):
    """The generateMtkTables projection: classify + the gui_family_counts NRDC
    split, rows in decode order (python's export path does not sort either)."""
    endc, nr_all, _lte_from_capability = export.classify(combos, 1)
    mixed = [
        any(c.band < FR2_MIN_BAND for c in row.nr)
        and any(c.band >= FR2_MIN_BAND for c in row.nr)
        for row in nr_all
    ]
    nrdc = [row for row, is_mixed in zip(nr_all, mixed) if is_mixed]
    nrca = [row for row, is_mixed in zip(nr_all, mixed) if not is_mixed]
    lte_ca = [
        {
            "Band": " + ".join(str(c.band) for c in cb.lte),
            "DL class": " + ".join(class_letter(c.dl_class) for c in cb.lte),
            "UL class": " + ".join(lte_ul_cell(c) for c in cb.lte),
            "MIMO DL": " + ".join("+".join(str(m) for m in c.dl_mimo) for c in cb.lte),
        }
        for cb in lte_rows
    ]
    nr_ca = [
        {"NR DL": " + ".join(lte_token(c) for c in cb.nr), **nr_cells(cb.nr)}
        for cb in nrca
    ]
    endc_rows = [
        {
            "LTE DL": " + ".join(lte_token(c) for c in cb.lte),
            "NR DL": " + ".join(lte_token(c) for c in cb.nr),
            "MIMO DL": join_cc(cb.nr, lambda cc: cc.dl_mimo),
            "SCS": join_cc(cb.nr, lambda cc: cc.scs_khz),
            "BW DL (MHz)": join_cc(cb.nr, lambda cc: cc.dl_bw_mhz),
        }
        for cb in endc
    ]
    nrdc_rows = [
        {
            "FR1 DL": " + ".join(lte_token(c) for c in cb.nr if c.band < FR2_MIN_BAND),
            "FR2 DL": " + ".join(lte_token(c) for c in cb.nr if c.band >= FR2_MIN_BAND),
            **nr_cells(cb.nr),
        }
        for cb in nrdc
    ]
    return {"lte_ca": lte_ca, "nr_ca": nr_ca, "endc": endc_rows, "nrdc": nrdc_rows}


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
                counts = U.gui_family_counts(combos)
                counts["lte"] = len(lte)
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
