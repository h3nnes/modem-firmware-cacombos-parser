// Stage-B scan orchestration: the webapp counterpart of mtk-drdi-combo-parser
// main.py's MtkBackend.summarize + profile_records, producing the per-(bank,
// profile) card records from the design spec §2. One packaged image decodes
// once here (counts are real combos, decoded at scan time like the python
// GUI rows); Stage C re-decodes a single profile at card open from the
// memoized parts.
//
// Return contract (spec §2): { records, warnings } or null (fall through to
// the qcom/apple paths). Fall-through is silent whenever the input was never
// positively identified as MTK — a failed head gate, an unwrap that found no
// modem set, or garbage behind a matching magic. Once md1rom+md1drdi are
// positively identified, structural failures surface as a `tool: "mtk"`
// warning with an empty record list instead, and per-profile grammar errors
// skip just that profile.
//
// The record envelope is spec-normative: generation "MediaTek DRDI", name
// "Bank <bankIndex> profile <profile>", sha256 of the decompressed profile
// image (cardcache key), and mtk { bankIndex, profile, loader, layout,
// imageMeta { bank_va, source_offset, length, relocation, alias },
// counts { endc, nrca, nrdc, lte } }. `layout` mirrors the apple record's
// layout field: the per-profile LTE CA row-table packaging detected at scan
// ("legacy32" / "extended36"), or null when the profile has no rows.
import { unwrapBytes, UnwrapError, kindOf, MTK_MAGIC } from "./mtk_containers.js";
import { indexOfBytes } from "./bytes.js";
import { sha256HexAsync } from "./hash.js";
import {
  GridLoader,
  TensorCdfLoader,
  GrammarParser,
  FeatureResolver,
  ProfileState,
  UniversalError,
  Reporter,
  establishFeaturePairs,
  decodeProfileCombos,
  dedupExact,
  classify,
  guiFamilyCounts,
  discoverSupportedBands,
  annotateBandParticipation,
  serializeProfileSummary,
  decodeTensorSecondary,
  secondaryCombos,
  tensorRelatedLte,
} from "./mtk_universal.js";

// Cheap head pre-gate (spec §2): only plausible MTK inputs are unwrapped, so
// arbitrary gzip files are never decompressed and qcom inputs fall through
// untouched. A gzip head must additionally carry a modem role token in the
// filename.
const ROLE_NAME_RE = /(?:^|[_\-.])(md1rom|md1drdi)(?=$|[.\-_])/i;

const hex = (n) => "0x" + n.toString(16);

function mtkHeadPlausible(head, name) {
  if (indexOfBytes(head, MTK_MAGIC, 0) >= 0) return true;
  const k = kindOf(head);
  if (k === "mtk") return true;
  if (k === "gzip") {
    const base = String(name).split("/").pop();
    return ROLE_NAME_RE.test(base);
  }
  return k === "android-sparse" || k === "hblr" || k === "ext4";
}

// Python json.dumps default separators (", " / ": ") — the loader-attempts
// diagnostic must read byte-identically to the reference error message.
const pyJson = (v) => {
  if (v === null) return "null";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v)) return `[${v.map(pyJson).join(", ")}]`;
  return `{${Object.entries(v).map(([k, val]) => `${JSON.stringify(k)}: ${pyJson(val)}`).join(", ")}}`;
};

// mtk_universal.select_loader for the ported loader families (tensor first
// when split-CDF parts exist, then grid). The flat/MD800 family is not ported;
// a grid rejection is terminal, recorded in the attempts list.
async function selectLoader(parts, rep) {
  const attempts = [];
  if (parts.drdi_data !== null) {
    if (!TensorCdfLoader.probe(parts.drdi)) {
      throw new UniversalError("--drdi is not a recognized split-CDF header "
        + "(expected 0x30000 bytes, 641 slot offsets, 11 bounds, 640 SHA-384 digests)");
    }
    attempts.push({ loader: "tensor", accepted: true, evidence: "split-CDF header geometry matched" });
    const loader = await TensorCdfLoader.create(parts.rom, parts.drdi, parts.drdi_data, rep);
    return [loader, attempts];
  }
  const hits = GridLoader.descriptorHits(parts.rom, parts.drdi);
  const score = GridLoader._denseScore(hits);
  try {
    const loader = new GridLoader(parts.rom, parts.drdi, rep, { descriptorHits: hits });
    const proveParser = new GrammarParser(loader, rep);
    loader.capabilityBank((im) => {
      try {
        return proveParser.findCandidateArray(im)[2].count;
      } catch (err) {
        if (err instanceof UniversalError) return null;
        throw err;
      }
    });
    attempts.push({ loader: "grid", accepted: true, evidence: `descriptor dense-run score ${score}, capability bank proved` });
    return [loader, attempts];
  } catch (err) {
    attempts.push({ loader: "grid", accepted: false, evidence: `dense-run score ${score}`, reason: String(err.message) });
    throw new UniversalError("no container loader accepted this image; attempts: " + pyJson(attempts));
  }
}

// Full scan-time decode of one unwrapped image. Returns the python summary
// shape (profiles/envelope/counts, differential-tested against report.json)
// plus the live loader/state objects scanMtk needs to build records. Per-
// profile grammar failures are fail-soft here: python's extract_capability
// aborts the whole extraction, the webapp scan skips the profile with a
// `tool: "mtk"` warning.
export async function decodeMtkSummary(parts, rep = new Reporter()) {
  const [loader, attempts] = await selectLoader(parts, rep);
  const parser = new GrammarParser(loader, rep);
  // Grid selected its bank through the same proof during selectLoader (cached);
  // Tensor proves here. Either way the CandidateNode results land in the
  // loader's shared cache and are reused by the per-profile loop below.
  const cap = loader.capabilityBank((im) => {
    try {
      return parser.findCandidateArray(im)[2].count;
    } catch (err) {
      if (err instanceof UniversalError) return null;
      throw err;
    }
  });
  const fr = new FeatureResolver(parser);
  const profileWarnings = [];
  const states = [];
  for (const im of cap.images) {
    try {
      const [, rows, info] = parser.findCandidateArray(im);
      const fts = fr.findTables(im);
      const pairs = fr.pairCandidates(rows, fts);
      const st = new ProfileState(im, rows, info, fts, pairs);
      st.pair_stats = { ...(fr.lastPairStats ?? {}) };
      states.push(st);
      rep.info("candidate_array", "candidate array located by structural invariant", {
        bank_va: hex(cap.bank_va),
        profile: im.profile,
        ...info,
        feature_tables: fts.length,
        passing_feature_pairs: pairs.length,
      });
    } catch (err) {
      if (!(err instanceof UniversalError)) throw err;
      profileWarnings.push({ tool: "mtk", message: `${err.message} — profile skipped` });
    }
  }
  if (!states.length) {
    throw new UniversalError("requested profile all is not live in capability bank");
  }
  const [resolved, unresolvedProfiles] = establishFeaturePairs(states, rep);
  const perProfile = new Map();
  const union = [];
  for (const s of resolved) {
    try {
      const combos = dedupExact(decodeProfileCombos(parser, s));
      perProfile.set(s.image.profile, combos);
      union.push(...combos);
    } catch (err) {
      if (!(err instanceof UniversalError)) throw err;
      profileWarnings.push({ tool: "mtk", message: `${err.message} — profile skipped` });
    }
  }
  if (!perProfile.size) {
    throw new UniversalError("no validated capability profiles were discovered");
  }
  const unionDedup = dedupExact(union);
  const [lteBank, lteProfiles] = loader.lteTables(cap, rep);
  const lteUnion = dedupExact([...lteProfiles.values()].flat());

  // Tensor split-CDF keeps the FR2/NRDC namespace in a sibling bank (normally
  // bank 8); the decoder is a no-op for every other container.
  const isTensor = loader instanceof TensorCdfLoader;
  const secondaryRaw = isTensor ? decodeTensorSecondary(loader, 8, rep) : [];
  const secondaryProfiles = [];
  for (const item of secondaryRaw) {
    const combos = secondaryCombos(item);
    const counts = guiFamilyCounts(combos);
    const relatedLte = lteProfiles.size ? tensorRelatedLte(loader, item.profile, lteProfiles) : [];
    secondaryProfiles.push({
      bank_index: item.bank_index,
      bank_va: hex(item.bank_va),
      profile: item.profile,
      decoded_rows: combos.length,
      expanded_rows: item.expanded_rows,
      excluded_single_fr2: item.excluded_single_fr2,
      candidate_count: item.candidate_count,
      roots: { candidate: hex(item.roots.candidate), dl_features: hex(item.roots.dl_features), ul_features: hex(item.roots.ul_features) },
      kinds: { endc: counts.endc, nrca: counts.nrca, lte: counts.lte },
      lte_count: relatedLte.length,
      gui_counts: counts,
    });
  }
  const supportedBands = annotateBandParticipation(
    discoverSupportedBands(loader, cap, lteBank, rep),
    unionDedup,
    lteUnion,
  );
  const guiCounts = guiFamilyCounts(unionDedup);
  const [uEndc, uNrca, uLte] = classify(unionDedup, 1);
  const profileSha256 = {};
  for (const s of resolved) {
    if (!perProfile.has(s.image.profile)) continue;
    profileSha256[String(s.image.profile)] = await sha256HexAsync(
      s.image.drdi.subarray(s.image.source_offset, s.image.end_source),
    );
  }
  // Per-profile digest over the DECODED combo payloads (bands, classes, MIMO
  // layers, SCS/BW per CC) in dedup order. This pins the constant maps
  // (DL_MIMO/UL_MIMO/SCS/BW table) that counts-only differentials cannot see:
  // a corrupted constant would otherwise commit green with wrong row values.
  const comboDigest = {};
  const encoder = new TextEncoder(); // UTF-8 — matches the python ref's str.encode()
  for (const [profile, combos] of perProfile) {
    comboDigest[String(profile)] = await sha256HexAsync(encoder.encode(combos.map(comboDigestLine).join("\n")));
  }
  let physicalLteProfiles = null;
  if (isTensor) {
    // Each Tensor row represents one physical bank; LTE from a sibling bank
    // must not appear under its NR bank's address/profile label.
    physicalLteProfiles = {};
    for (const [b, rows] of Object.entries(loader.lte_rows_by_bank ?? {})) {
      const byProfile = {};
      for (const [p, combos] of rows) byProfile[String(p)] = dedupExact(combos).length;
      physicalLteProfiles[String(b)] = byProfile;
    }
  }
  return {
    loader: loader.name,
    loader_selection: attempts,
    banks: loader.banks.map((b) => b.toDict()),
    capability_bank: hex(cap.bank_va),
    capability_bank_index: cap.table_index,
    profiles: serializeProfileSummary(resolved, perProfile),
    secondary_profiles: secondaryProfiles,
    lte_bank: lteBank ? hex(lteBank.bank_va) : null,
    lte_bank_index: lteBank ? lteBank.table_index : null,
    lte_profiles: Object.fromEntries(
      [...lteProfiles.entries()].sort((a, b) => a[0] - b[0]).map(([k, v]) => [String(k), v.length]),
    ),
    physical_lte_profiles: physicalLteProfiles,
    lte_union_exact_rows: lteUnion.length,
    gui_counts: guiCounts,
    union: {
      exact_rows: unionDedup.length,
      kinds: { endc: uEndc.length, nrca: uNrca.length, lte: uLte.length },
      complete: unresolvedProfiles.length === 0,
      unresolved_profiles: unresolvedProfiles,
    },
    supported_bands: supportedBands,
    validation: rep.asDict(),
    profile_sha256: profileSha256,
    combo_digest: comboDigest,
    // Live objects for record building (not part of the JSON differential).
    _loader: loader,
    _cap: cap,
    _states: resolved,
    _perProfile: perProfile,
    _lteProfiles: lteProfiles,
    _secondary: secondaryRaw,
    _warnings: profileWarnings,
  };
}

// Canonical payload projection of one decoded combo (python ref: mtk_ref_report.py
// combo_line — keep byte-identical). Kind/CCs + LTE (band, dl/ul class, per-CC
// DL MIMO) + NR (band, dl/ul class, per-CC [scs, dl_mimo, dl_bw, ul_mimo, ul_bw]).
function comboDigestLine(combo) {
  return JSON.stringify({
    k: combo.kind,
    c: combo.nr_physical_ccs,
    l: combo.lte.map((c) => ({ b: c.band, d: c.dl_class, u: c.ul_class, m: c.dl_mimo })),
    n: combo.nr.map((c) => ({
      b: c.band,
      d: c.dl_class,
      u: c.ul_class,
      c: c.ccs.map((cc) => [cc.scs_khz, cc.dl_mimo, cc.dl_bw_mhz, cc.ul_mimo, cc.ul_bw_mhz]),
    })),
  });
}

// Card-open payload for one (bank, profile) record: pure read over a
// decodeMtkSummary result's live seams — the scan already decoded every
// profile, so the worker's card open never re-unwraps or re-decodes (the
// Tensor loader in particular re-verifies 640 SHA-384 slot digests).
// Returns { combos, lteCombos }: the capability/secondary rows for the NR
// tables plus the profile's LTE CA row-table rows, both dedup-exact. LTE
// provenance mirrors scanMtk's counts: Tensor keeps per-physical-bank rows
// (a Bank-6 card must not show sibling Bank-5 rows), grid uses the merged
// per-profile projection of every bank with invariant-valid rows.
export function mtkCardCombos(summary, bankIndex, profile) {
  const loader = summary._loader;
  if (bankIndex === summary.capability_bank_index && summary._perProfile.has(profile)) {
    const combos = summary._perProfile.get(profile);
    const lteCombos = summary.physical_lte_profiles
      ? dedupExact(loader.lte_rows_by_bank?.[bankIndex]?.get(profile) ?? [])
      : (summary._lteProfiles.get(profile) ?? []);
    return { combos, lteCombos };
  }
  const secondary = summary._secondary.find(
    (item) => item.bank_index === bankIndex && item.profile === profile,
  );
  if (secondary) {
    const combos = secondaryCombos(secondary);
    // Scan-time counts use the same related-LTE projection (sum.lte_count).
    const lteCombos = summary._lteProfiles.size
      ? tensorRelatedLte(loader, secondary.profile, summary._lteProfiles)
      : [];
    return { combos, lteCombos };
  }
  // Bank-only row-table profile (Tensor physical banks without a capability
  // or secondary record; a grid profile with rows always has a capability
  // record, so this arm never fires for grid).
  const rows = loader.lte_rows_by_bank?.[bankIndex]?.get(profile) ?? [];
  return { combos: [], lteCombos: dedupExact(rows) };
}

function mtkRecord(name, sourceName, im, bankIndex, loader, counts) {
  return {
    inner_path: im.label,
    name,
    generation: "MediaTek DRDI",
    size: im.length,
    hwid: 0,
    fsid: 0,
    bid: 0,
    external: true,
    source_path: sourceName,
    sidecars: {},
    sha256: null, // filled by the caller (async digest)
    lte_combos: null,
    nr_combos: null,
    mtk: {
      bankIndex,
      profile: im.profile,
      loader,
      layout: im.lte_row_layout ?? null,
      imageMeta: {
        bank_va: hex(im.bank_va),
        source_offset: hex(im.source_offset),
        length: im.length,
        relocation: hex(im.relocation),
        alias: hex(im.alias),
      },
      counts,
    },
  };
}

// Scan one packaged image into per-(bank, profile) MTK DRDI card records.
export async function scanMtk(source, name, cancelled = () => false, hooks = {}) {
  const onScanProgress = hooks.onScanProgress ?? (() => {});
  if (cancelled()) return null;
  const head = await source.read(0, Math.min(0x10000, source.size));
  if (!mtkHeadPlausible(head, name)) return null;
  let parts;
  try {
    parts = await unwrapBytes(await source.read(0, source.size), name);
  } catch (err) {
    if (!(err instanceof UnwrapError)) throw err;
    // "no complete modem set found" (and any other parse failure behind a
    // merely plausible magic) means this was never positively an MTK modem:
    // fall through silently. Only positively-identified multi-set containers
    // are worth a warning.
    if (String(err.message).includes("different modem sets found")) {
      return {
        records: [],
        warnings: [{ tool: "mtk", message: `MTK DRDI unwrap failed: ${err.message} — skipped` }],
      };
    }
    return null;
  }
  if (cancelled()) return null;
  const rep = new Reporter();
  let summary;
  try {
    summary = await decodeMtkSummary(parts, rep);
  } catch (err) {
    if (!(err instanceof UniversalError)) throw err;
    // The image unwrapped to a real md1rom+md1drdi set, so it IS an MTK
    // modem whose decode failed structurally: warn instead of falling through.
    return {
      records: [],
      warnings: [{ tool: "mtk", message: `MTK DRDI decode failed: ${err.message} — skipped` }],
    };
  }
  // Seed the worker's card-open memo: the decode just ran, so handing the
  // parts + summary over lets the first parseCard skip the unwrap entirely
  // (same idea as the qcom/apple scan byte seeding in worker.js).
  hooks.onMtkImage?.(parts, summary);
  const loader = summary._loader;
  const cap = summary._cap;
  const records = [];
  const warnings = [...summary._warnings];

  // Capability-bank profiles (python GUI rows): full decode with real counts.
  const units = summary._states.length + summary._secondary.length;
  onScanProgress({ stage: "mtk", done: 0, total: units });
  let done = 0;
  const settle = () => {
    done += 1;
    onScanProgress({ stage: "mtk", done, total: units });
  };
  const physical = summary.physical_lte_profiles;
  for (const s of summary._states) {
    if (cancelled()) return null;
    const combos = summary._perProfile.get(s.image.profile);
    if (!combos) {
      settle();
      continue;
    }
    const im = s.image;
    const counts = guiFamilyCounts(combos);
    // Tensor rows represent one physical bank: LTE from a sibling bank keeps
    // the per-bank count, not the merged projection (python profile_records).
    const lteCount = physical
      ? (physical[String(cap.table_index)]?.[String(im.profile)] ?? 0)
      : (summary._lteProfiles.get(im.profile)?.length ?? 0);
    const record = mtkRecord(
      `Bank ${cap.table_index} profile ${im.profile}`,
      name,
      im,
      cap.table_index,
      loader.name,
      { endc: counts.endc, nrca: counts.nrca, nrdc: counts.nrdc, lte: lteCount },
    );
    record.sha256 = summary.profile_sha256[String(im.profile)];
    records.push(record);
    settle();
  }
  // Tensor secondary bank rows (independently selectable FR2/NRDC profiles).
  for (const item of summary._secondary) {
    if (cancelled()) return null;
    const sum = summary.secondary_profiles.find((x) => x.profile === item.profile);
    const im = summary._loader.banks[item.bank_index].images.find((x) => x.profile === item.profile);
    const counts = guiFamilyCounts(secondaryCombos(item));
    const record = mtkRecord(
      `Bank ${item.bank_index} profile ${item.profile}`,
      name,
      im,
      item.bank_index,
      loader.name,
      { endc: counts.endc, nrca: counts.nrca, nrdc: counts.nrdc, lte: sum.lte_count },
    );
    record.sha256 = await sha256HexAsync(im.drdi.subarray(im.source_offset, im.end_source));
    records.push(record);
    settle();
  }
  // Tensor physical LTE banks without a capability/secondary profile still
  // get a bank-only record (python profile_records).
  if (physical) {
    const indexed = new Set(records.map((r) => `${r.mtk.bankIndex}/${r.mtk.profile}`));
    for (const [b, byProfile] of Object.entries(physical)) {
      if (cancelled()) return null;
      const bank = loader.banks[Number(b)];
      for (const [p, count] of Object.entries(byProfile)) {
        if (indexed.has(`${b}/${p}`)) continue;
        const im = bank.images.find((x) => x.profile === Number(p));
        if (!im) continue;
        const record = mtkRecord(
          `Bank ${b} profile ${p}`,
          name,
          im,
          Number(b),
          loader.name,
          { endc: 0, nrca: 0, nrdc: 0, lte: count },
        );
        record.sha256 = await sha256HexAsync(im.drdi.subarray(im.source_offset, im.end_source));
        records.push(record);
      }
    }
  }
  // python GUI rows are ordered by (bank, profile); records stay deduped
  // downstream by the main thread (name\0sha256 keys).
  records.sort((a, b) => a.mtk.bankIndex - b.mtk.bankIndex || a.mtk.profile - b.mtk.profile);
  if (cancelled()) return null;
  return { records, warnings };
}
