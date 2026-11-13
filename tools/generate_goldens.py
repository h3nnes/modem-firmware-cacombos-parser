#!/usr/bin/env python3
"""Generate differential goldens from the Python parsers (permanent tool).

Usage: python3 tools/generate_goldens.py --corpus-dir DIR --out webapp/goldens
Regenerate whenever the Python parsers change; review the diff before committing.
"""
import argparse, json, re, sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "gui_version"))
import qualcomm_rf_combo_analyzer as analyzer  # noqa: E402

SAMPLES_PER_TABLE = 5          # first N rows of each web table
PARSE_SAMPLE_RATE = 20         # then every Nth row
RAW_HEX_LIMIT = 64

# Extracted-container records get inner paths like "fat_gg6rsuom/image/..." where
# the first component is a tempfile.mkdtemp(prefix=f"{tag}_") scratch dir (random
# suffix, see image_extractor._scratch_dir). Normalize it to the bare tag so
# goldens are deterministic across regeneration runs; the JS port applies the
# same rule to its own extraction paths before comparing.
SCRATCH_DIR_RE = re.compile(
    r"^(fat|sparse|zip|tar|gzip|zstd|xz|lz4|super|payload|squashfs|erofs|ext4|7z|ubi|fbpk)_[A-Za-z0-9_]+$"
)

def normalize_inner_path(inner_path: str) -> str:
    parts = inner_path.split("/", 1)
    if len(parts) == 2:
        m = SCRATCH_DIR_RE.match(parts[0])
        if m:
            return f"{m.group(1)}/{parts[1]}"
    return inner_path

def record_json(rec) -> dict:
    return {
        "name": rec.name,
        "inner_path": normalize_inner_path(rec.inner_path),
        "generation": rec.generation,
        "identity": rec.identity,
        "size": rec.size,
        "sha256": rec.sha256,
        "external": rec.external,
        "lte_combos": rec.lte_combos,
        "nr_combos": rec.nr_combos,
        "sidecars": dict(rec.sidecars),
    }

def sample_indices(n: int, seed_hex: str) -> list[int]:
    # Deterministic without RNG: first N rows plus every PARSE_SAMPLE_RATE-th.
    # seed_hex is unused; sampling is intentionally positional, not random.
    idx = set(range(min(SAMPLES_PER_TABLE, n)))
    idx.update(range(0, n, PARSE_SAMPLE_RATE))
    return sorted(idx)

def _truncate_row(row: dict) -> None:
    # Recursively truncate any "*raw_hex" string, including nested containers.
    for k, v in list(row.items()):
        if isinstance(v, str) and k.endswith("raw_hex"):
            if len(v) > RAW_HEX_LIMIT:
                row[k] = v[:RAW_HEX_LIMIT]
        elif isinstance(v, dict):
            _truncate_row(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    _truncate_row(item)

def truncate_parse(parsed: dict, seed_hex: str) -> dict:
    # parsed["combinations"] is a flat list of rows tagged with a "table" key;
    # group by table, then keep the first SAMPLES_PER_TABLE rows plus every
    # PARSE_SAMPLE_RATE-th row per table (indices from sample_indices).
    combos_by_table: dict[str, list[dict]] = {}
    for row in parsed["combinations"]:
        combos_by_table.setdefault(row.get("table", "nr_unknown"), []).append(row)
    out = {"combinations": {}, "components": [c for c in parsed["components"]]}
    for tbl, rows in combos_by_table.items():
        out["combinations"][tbl] = [dict(rows[i]) for i in sample_indices(len(rows), seed_hex)]
    _truncate_row(out)
    return out

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    corpus, out = Path(args.corpus_dir), Path(args.out)
    (out / "parse").mkdir(parents=True, exist_ok=True)
    (out / "tables").mkdir(parents=True, exist_ok=True)

    corpus_goldens = {}
    for img in sorted(corpus.glob("*")):
        if img.suffix not in (".img", ".md5") or not img.is_file():
            continue
        recs = analyzer.scan_source(img)
        corpus_goldens[img.name] = [record_json(r) for r in recs]
        img_tag = img.stem[:40].replace(" ", "_")
        for rec in recs:
            blob = analyzer.read_module(img, rec)
            parsed = analyzer.parse_module(rec, blob)
            tables = analyzer.generate_web_tables(parsed["combinations"], parsed["components"])
            safe = rec.name.replace("/", "_")
            (out / "parse" / f"{img_tag}__{safe}.json").write_text(
                json.dumps(truncate_parse(parsed, rec.sha256), indent=1) + "\n", encoding="utf-8")
            (out / "tables" / f"{img_tag}__{safe}.json").write_text(
                json.dumps(tables, indent=1) + "\n", encoding="utf-8")
        print(f"{img.name}: {len(recs)} records")

    (out / "corpus.json").write_text(json.dumps(corpus_goldens, indent=1) + "\n", encoding="utf-8")
    total = sum(len(v) for v in corpus_goldens.values())
    print(f"TOTAL: {total} records across {len(corpus_goldens)} images")

if __name__ == "__main__":
    main()
