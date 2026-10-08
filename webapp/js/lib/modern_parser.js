// Modern (DAT/protobuf) RF-card parsing core.
// Behaviour contract: identical values, dict key insertion order and
// iteration order.
//
// Result objects use snake_case keys and preserve key insertion order (the
// golden comparator checks key order). zlib decompression uses the vendored
// fflate (webapp/lib/vendor/fflate.js); the aggregated error message text of
// parseResDat differs from the raw zlib error text (candidate selection and
// results are identical).
import { StructReader, hex as bytesHex, utf8 } from "./bytes.js";
import { sha256Hex } from "./hash.js";
import { Inflate } from "../../lib/vendor/fflate.js";
import { TABLE_DISPLAY, ToolError } from "./legacy_parser.js";

export { ToolError };

const VERSION = "1.8.0";

// Doubles round every integer past 2**53. Varints that large stay exact as
// BigInt, everything at or below Number.MAX_SAFE_INTEGER stays a plain
// Number.
const MAX_SAFE_BIG = BigInt(Number.MAX_SAFE_INTEGER);

function toExactNumber(value) {
  return value <= MAX_SAFE_BIG ? Number(value) : value;
}

// Counts and offsets only index or slice byte arrays. An exact value >= 2**53
// exceeds every real buffer length; converting it to Number (still >= 2**53
// after rounding) produces an empty-slice outcome, so Number is safe on these
// paths.
function asCount(value) {
  return typeof value === "bigint" ? Number(value) : value;
}

export { TABLE_DISPLAY };

export function chunks(data, size) {
  const out = [];
  for (let p = 0; p + size <= data.length; p += size) out.push(data.subarray(p, p + size));
  return out;
}

function concatBytes(arrs) {
  let n = 0;
  for (const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

function bytesEquals(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function adler32(u8) {
  // NMAX-batched so the modulo runs every 5552 bytes instead of per byte.
  let a = 1, b = 0, i = 0;
  while (i < u8.length) {
    const n = Math.min(5552, u8.length - i);
    for (let k = 0; k < n; k++, i++) { a += u8[i]; b += a; }
    a %= 65521;
    b %= 65521;
  }
  return (b * 65536 + a) >>> 0;
}

// Strict zlib decode on top of fflate: unzlibSync skips the adler32 trailer
// and assumes it sits in the final four bytes, while a correct decoder
// verifies the trailer at the exact end of the deflate stream and ignores
// any trailing bytes. The streaming Inflate tracks the consumed bit
// position (after push() inf.p holds the unconsumed tail), so the trailer
// can be located and verified exactly. Returns the raw bytes plus the number
// of consumed input bytes (header + deflate + verified adler trailer) so
// callers can account for trailing bytes after the zlib stream.
export function inflateZlibChecked(data) {
  if (data.length < 2) throw new Error("incomplete or truncated stream");
  if ((data[0] & 15) !== 8 || (data[0] >> 4) > 7 || ((data[0] << 8) | data[1]) % 31 !== 0) {
    throw new Error("incorrect header check");
  }
  if ((data[1] >> 5) & 1) throw new Error("invalid dictionary id");
  const headerLen = ((data[1] >> 3) & 4) + 2;
  const body = data.subarray(headerLen);
  if (body.length === 0) throw new Error("incomplete or truncated stream");
  const inf = new Inflate();
  const outs = [];
  inf.ondata = (chunk) => { if (chunk.length) outs.push(chunk); };
  inf.push(body, true);
  const consumedBits = (body.length - inf.p.length) * 8 + inf.s.p;
  const trailerOff = headerLen + Math.ceil(consumedBits / 8);
  if (trailerOff + 4 > data.length) throw new Error("incomplete or truncated stream");
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  // Concatenate once and validate that buffer (the old code concatenated twice:
  // once for the Adler-32 and once for the return value).
  const raw = concatBytes(outs);
  if (adler32(raw) !== dv.getUint32(trailerOff)) throw new Error("incorrect data check");
  return { raw, consumed: trailerOff + 4 };
}

function inflateZlibStrict(data) {
  return inflateZlibChecked(data).raw;
}

// ASCII-only case-insensitive byte compare (the regex IGNORECASE behaviour).
function ciByte(u8, i, t) {
  const c = u8[i];
  return c === t || (c >= 0x41 && c <= 0x5a && c + 32 === t);
}

export function extractRfcDats(blob) {
  // Case-insensitive scan for "/rfc/<name>.dat" NUL-terminated paths
  // ([^\x00\r\n]{1,240}) plus the Large-EFS TLV validation. Greedy {1,240}
  // backtracking can only split at L = runLen - 4, so the pattern is
  // equivalent to: maximal run of non-NUL/CR/LF bytes with 5 <= runLen <= 244
  // ending in ".dat" and terminated by a NUL. Entries dedupe by name, last
  // data wins, first-appearance order.
  const byName = new Map();
  const indexOf = (from) => {
    for (let i = from; i < blob.length; i++) if (blob[i] === 0x2f) return i;
    return -1;
  };
  for (let i = indexOf(0); i >= 0 && i + 11 <= blob.length; i = indexOf(i + 1)) {
    if (!ciByte(blob, i + 1, 0x72) || !ciByte(blob, i + 2, 0x66) || !ciByte(blob, i + 3, 0x63) || !ciByte(blob, i + 4, 0x2f)) continue;
    let j = i + 5;
    while (j < blob.length && blob[j] !== 0 && blob[j] !== 13 && blob[j] !== 10) j++;
    const runLen = j - i - 5;
    if (
      blob[j] !== 0 || runLen < 5 || runLen > 244
      || !ciByte(blob, j - 4, 0x2e) || !ciByte(blob, j - 3, 0x64)
      || !ciByte(blob, j - 2, 0x61) || !ciByte(blob, j - 1, 0x74)
    ) continue;
    const name = utf8(blob, i, j);
    if (i >= 4) {
      const tlv = new StructReader(blob);
      // The path's BYTE length plus the NUL terminator is validated
      // (j - i bytes of path + 1). The decoded string's .length counts UTF-16
      // units and undercounts multi-byte paths.
      if (tlv.u16(i - 4) === 1 && tlv.u16(i - 2) === j - i + 1) {
        const dataHdr = j + 1;
        if (dataHdr + 6 <= blob.length) {
          const dataType = tlv.u16(dataHdr);
          const dataLen = tlv.u32(dataHdr + 2);
          if (dataType === 2 && dataHdr + 6 + dataLen <= blob.length) {
            const data = blob.subarray(dataHdr + 6, dataHdr + 6 + dataLen);
            const prev = byName.get(name);
            if (prev) prev.data = data;
            else byName.set(name, { name, offset: i, data });
          }
        }
      }
    }
  }
  return [...byName.values()];
}

let ENUM_CACHE = null;

export function enumAssignments() {
  // Enums used by the MPSS.DE.9.0 NR5G_8RX RFCard schema.
  if (ENUM_CACHE) return ENUM_CACHE;
  const bwNames = [
    "DEFAULT", "5", "10", "15", "20", "20_20", "20_20_20",
    "20_20_20_20", "20_20_20_20_20", "25", "30", "40", "50",
    "50_50", "50_50_50", "50_50_50_50", "50_50_50_50_50", "60",
    "70", "80", "90", "100", "100_60", "100_100", "100_100_100",
    "100_100_100_100", "100_100_100_100_100",
    "100_100_100_100_100_100", "100_100_100_100_100_100_100",
    "100_100_100_100_100_100_100_100", "40_40", "60_40",
    "100_40", "200", "200_200", "200_200_200", "200_200_200_200",
    "10_10", "25_25", "40_10", "40_20", "35", "30_20", "60_60",
    "30_30", "45", "50_5", "50_10", "50_15", "50_20", "40_15",
    "15_15", "30_25", "20_10", "20_15", "5_5", "80_80", "80_20",
    "40_30", "100_90", "30_10", "100_20", "80_40", "50_40",
    "100_50", "100_80",
  ];
  const result = {};
  bwNames.forEach((name, index) => { result[`BW_${name}`] = index; });

  const antennaNames = ["INVALID", "1", "2", "4"];
  for (let count = 2; count <= 8; count++) {
    antennaNames.push(new Array(count).fill("1").join("_"));
    for (let leading = 1; leading <= count; leading++) {
      antennaNames.push([...new Array(leading).fill("2"), ...new Array(count - leading).fill("1")].join("_"));
    }
    for (let leading = 1; leading <= count; leading++) {
      antennaNames.push([...new Array(leading).fill("4"), ...new Array(count - leading).fill("2")].join("_"));
    }
  }
  antennaNames.push("8", "8_4", "8_4_4", "8_8", "6", "4_8", "6_4", "4_6", "6_6");
  antennaNames.forEach((name, index) => { result[`ANTENNA_${name}`] = index; });
  ENUM_CACHE = result;
  return result;
}

const ENUM_SUFFIX_BLACKLIST = ["_SIZE", "_MAX_NUM", "_INVALID_INDEX", "_INVALID", "_DEFAULT"];

export function reverseEnum(enumMap, prefix) {
  const out = new Map();
  for (const [name, value] of Object.entries(enumMap)) {
    if (name.startsWith(prefix) && !ENUM_SUFFIX_BLACKLIST.some((s) => name.endsWith(s))) {
      out.set(value, name.slice(prefix.length));
    }
  }
  return out;
}

export function datPayloadCandidates(dat) {
  // RFPD default DAT = hash byte + uint32 raw size + zlib(protobuf).
  const out = [];
  const yielded = [];
  const r = new StructReader(dat);
  const zlibLimit = Math.min(32, Math.max(0, dat.length - 5));
  for (let base = 0; base < zlibLimit; base++) {
    const expected = r.u32(base + 1);
    let raw = null;
    try {
      raw = inflateZlibStrict(dat.subarray(base + 5));
    } catch {
      raw = null;
    }
    if (raw !== null && raw.length === expected) {
      if (!yielded.some((y) => bytesEquals(y, raw))) yielded.push(raw);
      out.push([base ? `${base}-byte-metadata+hash+size+zlib` : "hash+size+zlib", raw]);
    }
  }
  const rawLimit = Math.min(32, Math.max(0, dat.length - 4));
  for (let base = 0; base < rawLimit; base++) {
    const expected = r.u32(base);
    const raw = dat.subarray(base + 4);
    if (raw.length === expected && !yielded.some((y) => bytesEquals(y, raw))) {
      yielded.push(raw);
      out.push([base ? `${base}-byte-metadata+size+raw` : "size+raw", raw]);
    }
  }
  if (!yielded.some((y) => bytesEquals(y, dat))) out.push(["raw", dat]);
  return out;
}

export function readVarint(u8, pos) {
  // Fast path: up to seven payload groups (shift < 49) keep every partial
  // sum below 2**49, so the double accumulator stays exact. Longer varints
  // (up to shift < 70, i.e. ten bytes) switch to BigInt, which is exact for
  // the remaining shifts. Values above 2**53 come back as BigInt.
  let value = 0;
  let shift = 0;
  while (pos < u8.length && shift < 49) {
    const byte = u8[pos++];
    // Multiplication, not <<: protobuf varints exceed 32 bits.
    value += (byte & 0x7f) * 2 ** shift;
    if (!(byte & 0x80)) return { value, pos };
    shift += 7;
  }
  if (pos >= u8.length) throw new Error("Truncated protobuf varint");
  let exact = BigInt(value);
  while (pos < u8.length && shift < 70) {
    const byte = u8[pos++];
    exact |= BigInt(byte & 0x7f) << BigInt(shift);
    if (!(byte & 0x80)) return { value: toExactNumber(exact), pos };
    shift += 7;
  }
  throw new Error("Truncated protobuf varint");
}

export function protobufFields(data) {
  const result = new Map();
  let pos = 0;
  while (pos < data.length) {
    let key;
    ({ value: key, pos } = readVarint(data, pos));
    // number = key >> 3 and wire = key & 7 must be derived from the exact
    // arbitrary-precision key. A rounded key would misread the wire type
    // (2**53+7 rounds to 2**53, wire 0, instead of raising for wire 7), so
    // the split happens on the exact integer and only the resulting field
    // number is narrowed to a Number map key when it fits.
    const exactKey = typeof key === "bigint" ? key : BigInt(key);
    const numberBig = exactKey >> 3n;
    const wire = Number(exactKey & 7n);
    const number = toExactNumber(numberBig);
    if (number === 0) throw new Error("Invalid protobuf field zero");
    let value;
    if (wire === 0) {
      ({ value, pos } = readVarint(data, pos));
    } else if (wire === 1) {
      if (pos + 8 > data.length) throw new Error("Truncated protobuf fixed64");
      value = data.subarray(pos, pos + 8);
      pos += 8;
    } else if (wire === 2) {
      let size;
      ({ value: size, pos } = readVarint(data, pos));
      // Sizes >= 2**53 exceed any real buffer.
      const length = asCount(size);
      if (pos + length > data.length) throw new Error("Truncated protobuf length-delimited field");
      value = data.subarray(pos, pos + length);
      pos += length;
    } else if (wire === 5) {
      if (pos + 4 > data.length) throw new Error("Truncated protobuf fixed32");
      value = data.subarray(pos, pos + 4);
      pos += 4;
    } else {
      throw new Error(`Unsupported protobuf wire type ${wire}`);
    }
    if (!result.has(number)) result.set(number, []);
    result.get(number).push([wire, value]);
  }
  return result;
}

export function protoBytes(fields, number) {
  const values = [];
  for (const [wire, value] of fields.get(number) ?? []) {
    if (wire === 2) values.push(value);
  }
  // A single length-delimited field is already a view into the source buffer:
  // return it directly instead of copying through concatBytes. Callers only read
  // (hash / compare / slice), so aliasing is safe and saves the copy on the hot
  // res_dat_sha256 path.
  if (values.length === 1) return values[0];
  return concatBytes(values);
}

export function protoUint(fields, number) {
  const values = (fields.get(number) ?? []).filter(([wire]) => wire === 0).map(([, value]) => value);
  return values.length ? values[values.length - 1] : 0;
}

export function protoRepeatedUint(fields, number) {
  const result = [];
  for (const [wire, value] of fields.get(number) ?? []) {
    if (wire === 0) {
      result.push(value);
    } else if (wire === 2) {
      let pos = 0;
      while (pos < value.length) {
        let item;
        ({ value: item, pos } = readVarint(value, pos));
        result.push(item);
      }
    }
  }
  return result;
}

// Field map of the RRC container message; the key order is part of the
// output contract.
const RRC_FIELDS = [
  ["NR_band_group_table_high", "bytes", 1],
  ["NR_band_group_table_low", "bytes", 2],
  ["lte_info_per_band_sub_cap_high", "bytes", 3],
  ["nr5g_info_per_band_sub_cap_high", "bytes", 4],
  ["lte_nr5g_info_per_band_sub_cap_high", "bytes", 5],
  ["nr5g_nr5g_info_per_band_sub_cap_high", "bytes", 6],
  ["lte_info_per_band_sub_cap_high_num", "uint", 7],
  ["nr5g_info_per_band_sub_cap_high_num", "uint", 8],
  ["lte_nr5g_info_per_band_sub_cap_high_num", "uint", 9],
  ["nr5g_nr5g_info_per_band_sub_cap_high_num", "uint", 10],
  ["nr5g_band_group_indices_table_sub_cap_high", "bytes", 11],
  ["nr5g_band_group_indices_offset_table_sub_cap_high", "repeated", 12],
  ["nr5g_combo_properties_table_sub_cap_high", "bytes", 13],
  ["lte_nr5g_band_group_indices_table_sub_cap_high", "bytes", 14],
  ["lte_nr5g_band_group_indices_offset_table_sub_cap_high", "repeated", 15],
  ["lte_nr5g_combo_properties_table_sub_cap_high", "bytes", 16],
  ["nr5g_nr5g_band_group_indices_table_sub_cap_high", "bytes", 17],
  ["nr5g_nr5g_band_group_indices_offset_table_sub_cap_high", "repeated", 18],
  ["nr5g_nr5g_combo_properties_table_sub_cap_high", "bytes", 19],
  ["lte_info_per_band_sub_cap_low", "bytes", 39],
  ["nr5g_info_per_band_sub_cap_low", "bytes", 40],
  ["lte_nr5g_info_per_band_sub_cap_low", "bytes", 41],
  ["nr5g_nr5g_info_per_band_sub_cap_low", "bytes", 42],
  ["lte_info_per_band_sub_cap_low_num", "uint", 43],
  ["nr5g_info_per_band_sub_cap_low_num", "uint", 44],
  ["lte_nr5g_info_per_band_sub_cap_low_num", "uint", 45],
  ["nr5g_nr5g_info_per_band_sub_cap_low_num", "uint", 46],
  ["nr5g_band_group_indices_table_sub_cap_low", "bytes", 47],
  ["nr5g_band_group_indices_offset_table_sub_cap_low", "repeated", 48],
  ["nr5g_combo_properties_table_sub_cap_low", "bytes", 49],
  ["lte_nr5g_band_group_indices_table_sub_cap_low", "bytes", 50],
  ["lte_nr5g_band_group_indices_offset_table_sub_cap_low", "repeated", 51],
  ["lte_nr5g_combo_properties_table_sub_cap_low", "bytes", 52],
  ["nr5g_nr5g_band_group_indices_table_sub_cap_low", "bytes", 53],
  ["nr5g_nr5g_band_group_indices_offset_table_sub_cap_low", "repeated", 54],
  ["nr5g_nr5g_combo_properties_table_sub_cap_low", "bytes", 55],
  ["env_name_high", "string", 73],
  ["env_name_low", "string", 74],
];

export function makeRrcView(payload) {
  const outer = protobufFields(payload);
  const rrcMessages = (outer.get(7) ?? []).filter(([wire]) => wire === 2).map(([, value]) => value);
  if (rrcMessages.length === 0) throw new Error("res protobuf has no rrc field #7");
  const fields = protobufFields(rrcMessages[rrcMessages.length - 1]);
  const values = {};
  for (const [name, kind, number] of RRC_FIELDS) {
    if (kind === "bytes") values[name] = protoBytes(fields, number);
    else if (kind === "uint") values[name] = protoUint(fields, number);
    else if (kind === "string") {
      const raw = protoBytes(fields, number);
      values[name] = utf8(raw, 0, raw.length);
    } else values[name] = protoRepeatedUint(fields, number);
  }
  return values;
}

export function parseResDat(dat) {
  const errors = [];
  for (const [encoding, payload] of datPayloadCandidates(dat)) {
    try {
      return { encoding, payload, rrc: makeRrcView(payload) };
    } catch (exc) {
      errors.push(`${encoding}: ${exc.message}`);
    }
  }
  throw new Error("Cannot parse res DAT protobuf: " + errors.join("; "));
}

export function decodeLteCombo(raw) {
  // Native layout: bool + one pad + 6 * 8-byte per-band records = 50 bytes.
  const r = new StructReader(raw);
  const groups = [];
  for (let index = 0; index < 6; index++) {
    const pos = 2 + index * 8;
    const [band, dlCls, dlAnt, ulCls, ulAnt] = r.unpack("<HBBBBB", pos);
    if (band === 0) continue;
    const dlLetter = dlCls >= 1 && dlCls <= 26 ? String.fromCharCode(64 + dlCls) : `X${dlCls}`;
    let text = `B${band}${dlLetter}[${dlAnt}]`;
    if (ulCls) {
      const ulLetter = ulCls >= 1 && ulCls <= 26 ? String.fromCharCode(64 + ulCls) : `X${ulCls}`;
      text += `;${ulLetter}[${ulAnt}]`;
    }
    groups.push(text);
  }
  return groups.join("+");
}

export function decodeNrProperty(raw) {
  // RFPD compacts the 24 consecutive property bitfields into three bytes.
  if (raw.length < 12) throw new Error(`Short NRComboProperty: ${raw.length}`);
  const bits = raw[0] | (raw[1] << 8) | (raw[2] << 16);
  const r = new StructReader(raw);
  return {
    power_class: bits & 0x7,
    tdd_ant_swt_fdd_disruption: (bits >>> 3) & 0x1,
    simultaneousRxTxInterBandENDC: (bits >>> 4) & 0x1,
    simultaneousRxTxInterBandCA: (bits >>> 5) & 0x1,
    ul_tx_switch_type: (bits >>> 6) & 0x3,
    intra_contig_type: (bits >>> 8) & 0x7,
    srs_cs_type: (bits >>> 11) & 0x7,
    intra_ulca_dual_pa: (bits >>> 14) & 0x1,
    simultaneousRxTxInterBandSUL: (bits >>> 15) & 0x1,
    num_bands: (bits >>> 16) & 0x3f,
    has_bcs5_counterpart: (bits >>> 22) & 0x1,
    higher_power_limit: (bits >>> 23) & 0x1,
    bcs_num: raw[3],
    env_mode_mask_idx: r.u16(4),
    env_mode_subset_mask_idx: r.u16(6),
    simul_rxtx_bmap_idx: r.u16(8),
    simul_sul_rxtx_bmap_idx: r.u16(10),
  };
}

// NRBandGroup 12-byte little-endian bit layout: unit0 = tech@0-1, band@2-10,
// dl_bw_class@11-15, dl_bw_per_cc@16-22, ul_bw_class@23-27 (bits 28-31
// unused); ul_bw_per_cc
// overflows unit0 and starts unit1 at bit 32; unit1 = ul_bw_per_cc@32-38,
// dl_max_antennas_index@39-45, ul_max_antennas_index@46-52, max_scs@53-55,
// ul_qam_cap_index@56-57, srs_tx_switch_type@58-61,
// tx_switch_impact_to_rx@62-63; unit2 = tx_switch_with_another_band@64-65,
// srs_carrier_hop@66, srs_carrier_hop_src@67-68, rx_limit@69,
// num_tx_meeting_combo_pc@70-71, link_id@72-73.
export function decodeBandGroup(raw) {
  if (raw.length < 12) throw new Error(`Short NRBandGroup: ${raw.length}`);
  const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const u0 = dv.getUint32(0, true);
  const u1 = dv.getUint32(4, true);
  const u2 = dv.getUint32(8, true);
  return {
    tech: u0 & 0x3,
    band: (u0 >>> 2) & 0x1ff,
    dl_bw_class: (u0 >>> 11) & 0x1f,
    dl_bw_per_cc: (u0 >>> 16) & 0x7f,
    ul_bw_class: (u0 >>> 23) & 0x1f,
    ul_bw_per_cc: u1 & 0x7f,
    dl_max_antennas_index: (u1 >>> 7) & 0x7f,
    ul_max_antennas_index: (u1 >>> 14) & 0x7f,
    max_scs: (u1 >>> 21) & 0x7,
    ul_qam_cap_index: (u1 >>> 24) & 0x3,
    srs_tx_switch_type: (u1 >>> 26) & 0xf,
    tx_switch_impact_to_rx: (u1 >>> 30) & 0x3,
    tx_switch_with_another_band: u2 & 0x3,
    srs_carrier_hop: (u2 >>> 2) & 0x1,
    srs_carrier_hop_src: (u2 >>> 3) & 0x3,
    rx_limit: (u2 >>> 5) & 0x1,
    num_tx_meeting_combo_pc: (u2 >>> 6) & 0x3,
    link_id: (u2 >>> 8) & 0x3,
  };
}

function formatSide(bwName, antennaName) {
  let layers = antennaName ? antennaName.split("_").map((x) => parseInt(x, 10)) : [];
  const bws = bwName ? bwName.split("_").map((x) => parseInt(x, 10)) : [];
  const count = Math.max(layers.length, bws.length, 1);
  if (layers.length === 0) layers = new Array(count).fill(0);
  if (bws.length === 0) return layers.join(",");
  if (layers.length < bws.length) {
    layers = layers.concat(new Array(bws.length - layers.length).fill(layers[layers.length - 1]));
  }
  return bws.map((bw, i) => `${bw}x${layers[i]}`).join(",");
}

export function decodeNrBandGroup(bg, bwByValue, antByValue) {
  const prefix = bg.tech === 1 ? "B" : bg.tech === 2 ? "N" : `T${bg.tech}-`;
  let text;
  if (bg.dl_bw_class) {
    const dlClass = bg.dl_bw_class >= 1 && bg.dl_bw_class <= 26
      ? String.fromCharCode(64 + bg.dl_bw_class)
      : `X${bg.dl_bw_class}`;
    const dl = formatSide(bwByValue.get(bg.dl_bw_per_cc), antByValue.get(bg.dl_max_antennas_index));
    text = `${prefix}${bg.band}${dlClass}[${dl}]`;
  } else {
    // RFCard's canonical syntax for a supplementary-uplink/UL-only
    // component is N<band>_;<UL class>[<UL BW>x<antennas>].
    text = `${prefix}${bg.band}_`;
  }
  if (bg.ul_bw_class) {
    const ulClass = bg.ul_bw_class >= 1 && bg.ul_bw_class <= 26
      ? String.fromCharCode(64 + bg.ul_bw_class)
      : `X${bg.ul_bw_class}`;
    const ul = formatSide(bwByValue.get(bg.ul_bw_per_cc), antByValue.get(bg.ul_max_antennas_index));
    text += `;${ulClass}[${ul}]`;
  }
  return text;
}

export function nrSectionRecords(rrc, prefix, suffix) {
  const refRaw = rrc[`${prefix}_info_per_band_sub_cap_${suffix}`];
  const bgRaw = rrc[`NR_band_group_table_${suffix}`];
  const indexRaw = rrc[`${prefix}_band_group_indices_table_sub_cap_${suffix}`];
  const offsets = rrc[`${prefix}_band_group_indices_offset_table_sub_cap_${suffix}`];
  const propRaw = rrc[`${prefix}_combo_properties_table_sub_cap_${suffix}`];
  const refCount = asCount(rrc[`${prefix}_info_per_band_sub_cap_${suffix}_num`]);

  const refs = chunks(refRaw, 4)
    .map((item) => new StructReader(item).unpack("<HH", 0))
    .slice(0, refCount);
  const bandGroups = chunks(bgRaw, 12).map((item) => decodeBandGroup(item));
  const properties = chunks(propRaw, 12).map((item) => decodeNrProperty(item));

  const result = [];
  for (const [bgTableIndex, propIndex] of refs) {
    if (propIndex >= properties.length) continue;
    const prop = properties[propIndex];
    const count = prop.num_bands;
    if (count <= 0 || count > offsets.length) continue;
    // The flattened table contains uint16 band-group indices; offsets count
    // entries rather than bytes.
    const startEntry = asCount(offsets[count - 1]) + bgTableIndex * count;
    const start = startEntry * 2;
    const rawIndices = indexRaw.subarray(start, start + count * 2);
    if (rawIndices.length !== count * 2) continue;
    const r = new StructReader(rawIndices);
    const bgIndices = [];
    for (let i = 0; i < count; i++) bgIndices.push(r.u16(i * 2));
    const selectedGroups = [];
    let outOfRange = false;
    for (const bgIndex of bgIndices) {
      if (bgIndex >= bandGroups.length) {
        outOfRange = true;
        break;
      }
      selectedGroups.push(bandGroups[bgIndex]);
    }
    if (outOfRange || selectedGroups.length === 0) continue;
    result.push([selectedGroups, prop]);
  }
  return result;
}

export function b0cdV41Packets(rrc, suffix, packetCombos = 100) {
  // Build headerless Qualcomm 0xB0CD v41 payloads.
  const field = `lte_info_per_band_sub_cap_${suffix}`;
  const rawCombos = chunks(rrc[field], 50).slice(0, asCount(rrc[`${field}_num`]));
  const encoded = [];
  for (const raw of rawCombos) {
    const r = new StructReader(raw);
    const parts = [];
    for (let index = 0; index < 6; index++) {
      const pos = 2 + index * 8;
      const [band, dlCls, dlAnt, ulCls, ulAnt, ulQam] = r.unpack("<HBBBBB", pos);
      if (!band) continue;
      const out = new Uint8Array(7);
      const dv = new DataView(out.buffer);
      dv.setUint16(0, band, true);
      out[2] = dlCls; out[3] = ulCls; out[4] = dlAnt; out[5] = ulAnt; out[6] = ulQam;
      parts.push(out);
    }
    if (parts.length) encoded.push(concatBytes([Uint8Array.of(parts.length), ...parts]));
  }
  const result = [];
  for (let start = 0; start < encoded.length; start += packetCombos) {
    const current = encoded.slice(start, start + packetCombos);
    result.push(concatBytes([Uint8Array.of(41, current.length), ...current]));
  }
  return result;
}

export function b826V22Component(bg) {
  // Encode one RFCard band group in the 10-byte 0xB826 v22 component layout.
  if (bg.band > 0x1ff) throw new Error(`0xB826 v22 band exceeds 9 bits: ${bg.band}`);
  const dlAnt = bg.dl_max_antennas_index;
  const ulAnt = bg.ul_max_antennas_index;
  const dlBw = bg.dl_bw_per_cc;
  const ulBw = bg.ul_bw_per_cc;
  if (dlAnt > 0x7f || ulAnt > 0x1f || dlBw > 0x7f || ulBw > 0x7f) {
    throw new Error("0xB826 v22 component field exceeds its bit width");
  }
  const head = bg.band
    | ((bg.tech === 2 ? 1 : 0) << 9)
    | ((bg.dl_bw_class & 0x1f) << 10)
    | ((dlAnt & 1) << 15);
  const byte1 = ((dlAnt >> 1) & 0x3f) | ((bg.ul_bw_class & 0x03) << 6);
  const byte2 = ((bg.ul_bw_class >> 2) & 0x07) | ((ulAnt & 0x1f) << 3);
  const qam = bg.ul_qam_cap_index & 0x03;
  const byte3 = ((qam & 1) << 2) | (((qam >> 1) & 1) << 1) | ((dlBw & 1) << 7);
  const byte4 = ((dlBw >> 1) & 0x3f) | ((ulBw & 0x03) << 6);
  const byte5 = (ulBw >> 2) & 0x1f;
  const out = new Uint8Array(10);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, head, true);
  out[2] = byte1; out[3] = byte2; out[4] = byte3; out[5] = byte4; out[6] = byte5;
  return out;
}

export function b826V22Packets(records, source, packetCombos = 100) {
  // Build headerless Qualcomm 0xB826 v22 payloads.
  const encoded = [];
  for (const [bandGroups, prop] of records) {
    const count = bandGroups.length;
    if (count < 1 || count > 15) {
      throw new Error(`0xB826 v22 supports 1..15 components, got ${count}`);
    }
    const features = (count << 6) | ((prop.ul_tx_switch_type & 0x03) << 13);
    const head = new Uint8Array(15);
    new DataView(head.buffer).setUint16(0, features, true);
    encoded.push(concatBytes([head, ...bandGroups.map((bg) => b826V22Component(bg))]));
  }
  const total = encoded.length;
  const result = [];
  for (let start = 0; start < total; start += packetCombos) {
    const current = encoded.slice(start, start + packetCombos);
    const header = new Uint8Array(11);
    const dv = new DataView(header.buffer);
    dv.setUint16(0, 22, true);
    dv.setUint16(2, 0, true);
    dv.setUint16(4, total, true);
    dv.setUint16(6, start, true);
    dv.setUint16(8, current.length, true);
    header[10] = source;
    result.push(concatBytes([header, ...current]));
  }
  return result;
}

function safeClass(value) {
  return value >= 1 && value <= 26 ? String.fromCharCode(64 + value) : value === 0 ? "-" : `X${value}`;
}

function modernLteRows(rrc, suffix, antennaNames) {
  const field = `lte_info_per_band_sub_cap_${suffix}`;
  const rawRecords = chunks(rrc[field], 50).slice(0, asCount(rrc[`${field}_num`]));
  const combos = [];
  const components = [];
  rawRecords.forEach((raw, comboIndex) => {
    const expression = decodeLteCombo(raw);
    const r = new StructReader(raw);
    const comboComponents = [];
    for (let position = 0; position < 6; position++) {
      const offset = 2 + position * 8;
      const [band, dlClass, dlAnt, ulClass, ulAnt, ulQam] = r.unpack("<HBBBBB", offset);
      if (!band) continue;
      const component = {
        table: "lte_ca",
        sub_capability: suffix,
        combo_index: comboIndex,
        position: comboComponents.length,
        technology: "LTE",
        band,
        dl_bw_class_code: dlClass,
        dl_bw_class: safeClass(dlClass),
        dl_bw_code: null,
        dl_bandwidth: null,
        dl_antenna_index: dlAnt,
        dl_antenna: antennaNames.get(dlAnt) ?? `INDEX_${dlAnt}`,
        ul_bw_class_code: ulClass,
        ul_bw_class: safeClass(ulClass),
        ul_bw_code: null,
        ul_bandwidth: null,
        ul_antenna_index: ulAnt,
        ul_antenna: antennaNames.get(ulAnt) ?? `INDEX_${ulAnt}`,
        ul_qam_cap_index: ulQam,
      };
      comboComponents.push(component);
      components.push(component);
    }
    combos.push({
      table: "lte_ca",
      table_name: TABLE_DISPLAY.lte_ca,
      sub_capability: suffix,
      combo_index: comboIndex,
      expression,
      component_count: comboComponents.length,
      power_class: null,
      bcs_num: null,
      ul_tx_switch_type: null,
      higher_power_limit: null,
      raw_hex: bytesHex(raw),
    });
  });
  return [combos, components];
}

function modernNrRows(rrc, suffix, prefix, table, bwNames, antennaNames) {
  const records = nrSectionRecords(rrc, prefix, suffix);
  const combos = [];
  const components = [];
  records.forEach(([groups, prop], comboIndex) => {
    const expression = groups.map((group) => decodeNrBandGroup(group, bwNames, antennaNames)).join("+");
    groups.forEach((group, position) => {
      components.push({
        table,
        sub_capability: suffix,
        combo_index: comboIndex,
        position,
        technology: group.tech === 1 ? "LTE" : group.tech === 2 ? "NR" : `TECH_${group.tech}`,
        band: group.band,
        dl_bw_class_code: group.dl_bw_class,
        dl_bw_class: safeClass(group.dl_bw_class),
        dl_bw_code: group.dl_bw_per_cc,
        dl_bandwidth: bwNames.get(group.dl_bw_per_cc) ?? null,
        dl_antenna_index: group.dl_max_antennas_index,
        dl_antenna: antennaNames.get(group.dl_max_antennas_index) ?? `INDEX_${group.dl_max_antennas_index}`,
        ul_bw_class_code: group.ul_bw_class,
        ul_bw_class: safeClass(group.ul_bw_class),
        ul_bw_code: group.ul_bw_per_cc,
        ul_bandwidth: bwNames.get(group.ul_bw_per_cc) ?? null,
        ul_antenna_index: group.ul_max_antennas_index,
        ul_antenna: antennaNames.get(group.ul_max_antennas_index) ?? `INDEX_${group.ul_max_antennas_index}`,
        ul_qam_cap_index: group.ul_qam_cap_index,
        max_scs: group.max_scs,
        srs_tx_switch_type: group.srs_tx_switch_type,
        tx_switch_impact_to_rx: group.tx_switch_impact_to_rx,
        tx_switch_with_another_band: group.tx_switch_with_another_band,
        srs_carrier_hop: group.srs_carrier_hop,
        srs_carrier_hop_src: group.srs_carrier_hop_src,
        rx_limit: group.rx_limit,
        link_id: group.link_id,
      });
    });
    combos.push({
      table,
      table_name: TABLE_DISPLAY[table],
      sub_capability: suffix,
      combo_index: comboIndex,
      expression,
      component_count: groups.length,
      power_class: prop.power_class,
      bcs_num: prop.bcs_num,
      ul_tx_switch_type: prop.ul_tx_switch_type,
      higher_power_limit: !!prop.higher_power_limit,
      tdd_ant_swt_fdd_disruption: !!prop.tdd_ant_swt_fdd_disruption,
      simultaneous_rx_tx_endc: !!prop.simultaneousRxTxInterBandENDC,
      simultaneous_rx_tx_ca: !!prop.simultaneousRxTxInterBandCA,
      simultaneous_rx_tx_sul: !!prop.simultaneousRxTxInterBandSUL,
      intra_contig_type: prop.intra_contig_type,
      srs_cs_type: prop.srs_cs_type,
      intra_ulca_dual_pa: !!prop.intra_ulca_dual_pa,
      has_bcs5_counterpart: !!prop.has_bcs5_counterpart,
      env_mode_mask_idx: prop.env_mode_mask_idx,
      env_mode_subset_mask_idx: prop.env_mode_subset_mask_idx,
      simul_rxtx_bmap_idx: prop.simul_rxtx_bmap_idx,
      simul_sul_rxtx_bmap_idx: prop.simul_sul_rxtx_bmap_idx,
    });
  });
  return [combos, components, records];
}

// Strips exactly the Unicode whitespace set: U+0009-000D, U+001C-001F,
// U+0020, U+0085, U+00A0, U+1680, U+2000-200A, U+2028, U+2029, U+202F,
// U+205F, U+3000. JS \s additionally strips U+FEFF and misses U+0085 and
// U+001C-001F, hence the explicit class.
const PY_STRIP_RE = /^[\t\n\x0b\x0c\r\x1c-\x1f \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\t\n\x0b\x0c\r\x1c-\x1f \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/gu;

function pyStrip(text) {
  return text.replace(PY_STRIP_RE, "");
}

// Full casefold mapping: for every code point not listed here casefold ==
// lower, which String#toLowerCase replicates. The table covers the full code
// point range where casefold differs from lower(); it includes the Greek
// final sigma, the long s, ligature expansions, the Turkic dotted/dotless I,
// sharp s, and Cherokee.
const PY_CASEFOLD_DIFF = new Map([
  [0xb5, "\u03bc"], [0xdf, "ss"], [0x149, "\u02bcn"], [0x17f, "s"], [0x1f0, "j\u030c"],
  [0x345, "\u03b9"], [0x390, "\u03b9\u0308\u0301"], [0x3b0, "\u03c5\u0308\u0301"],
  [0x3c2, "\u03c3"], [0x3d0, "\u03b2"], [0x3d1, "\u03b8"], [0x3d5, "\u03c6"], [0x3d6, "\u03c0"],
  [0x3f0, "\u03ba"], [0x3f1, "\u03c1"], [0x3f5, "\u03b5"], [0x587, "\u0565\u0582"],
  [0x13a0, "\u13a0"], [0x13a1, "\u13a1"], [0x13a2, "\u13a2"], [0x13a3, "\u13a3"],
  [0x13a4, "\u13a4"], [0x13a5, "\u13a5"], [0x13a6, "\u13a6"], [0x13a7, "\u13a7"],
  [0x13a8, "\u13a8"], [0x13a9, "\u13a9"], [0x13aa, "\u13aa"], [0x13ab, "\u13ab"],
  [0x13ac, "\u13ac"], [0x13ad, "\u13ad"], [0x13ae, "\u13ae"], [0x13af, "\u13af"],
  [0x13b0, "\u13b0"], [0x13b1, "\u13b1"], [0x13b2, "\u13b2"], [0x13b3, "\u13b3"],
  [0x13b4, "\u13b4"], [0x13b5, "\u13b5"], [0x13b6, "\u13b6"], [0x13b7, "\u13b7"],
  [0x13b8, "\u13b8"], [0x13b9, "\u13b9"], [0x13ba, "\u13ba"], [0x13bb, "\u13bb"],
  [0x13bc, "\u13bc"], [0x13bd, "\u13bd"], [0x13be, "\u13be"], [0x13bf, "\u13bf"],
  [0x13c0, "\u13c0"], [0x13c1, "\u13c1"], [0x13c2, "\u13c2"], [0x13c3, "\u13c3"],
  [0x13c4, "\u13c4"], [0x13c5, "\u13c5"], [0x13c6, "\u13c6"], [0x13c7, "\u13c7"],
  [0x13c8, "\u13c8"], [0x13c9, "\u13c9"], [0x13ca, "\u13ca"], [0x13cb, "\u13cb"],
  [0x13cc, "\u13cc"], [0x13cd, "\u13cd"], [0x13ce, "\u13ce"], [0x13cf, "\u13cf"],
  [0x13d0, "\u13d0"], [0x13d1, "\u13d1"], [0x13d2, "\u13d2"], [0x13d3, "\u13d3"],
  [0x13d4, "\u13d4"], [0x13d5, "\u13d5"], [0x13d6, "\u13d6"], [0x13d7, "\u13d7"],
  [0x13d8, "\u13d8"], [0x13d9, "\u13d9"], [0x13da, "\u13da"], [0x13db, "\u13db"],
  [0x13dc, "\u13dc"], [0x13dd, "\u13dd"], [0x13de, "\u13de"], [0x13df, "\u13df"],
  [0x13e0, "\u13e0"], [0x13e1, "\u13e1"], [0x13e2, "\u13e2"], [0x13e3, "\u13e3"],
  [0x13e4, "\u13e4"], [0x13e5, "\u13e5"], [0x13e6, "\u13e6"], [0x13e7, "\u13e7"],
  [0x13e8, "\u13e8"], [0x13e9, "\u13e9"], [0x13ea, "\u13ea"], [0x13eb, "\u13eb"],
  [0x13ec, "\u13ec"], [0x13ed, "\u13ed"], [0x13ee, "\u13ee"], [0x13ef, "\u13ef"],
  [0x13f0, "\u13f0"], [0x13f1, "\u13f1"], [0x13f2, "\u13f2"], [0x13f3, "\u13f3"],
  [0x13f4, "\u13f4"], [0x13f5, "\u13f5"], [0x13f8, "\u13f0"], [0x13f9, "\u13f1"],
  [0x13fa, "\u13f2"], [0x13fb, "\u13f3"], [0x13fc, "\u13f4"], [0x13fd, "\u13f5"],
  [0x1c80, "\u0432"], [0x1c81, "\u0434"], [0x1c82, "\u043e"], [0x1c83, "\u0441"],
  [0x1c84, "\u0442"], [0x1c85, "\u0442"], [0x1c86, "\u044a"], [0x1c87, "\u0463"],
  [0x1c88, "\ua64b"], [0x1e96, "h\u0331"], [0x1e97, "t\u0308"], [0x1e98, "w\u030a"],
  [0x1e99, "y\u030a"], [0x1e9a, "a\u02be"], [0x1e9b, "\u1e61"], [0x1e9e, "ss"],
  [0x1f50, "\u03c5\u0313"], [0x1f52, "\u03c5\u0313\u0300"], [0x1f54, "\u03c5\u0313\u0301"],
  [0x1f56, "\u03c5\u0313\u0342"], [0x1f80, "\u1f00\u03b9"], [0x1f81, "\u1f01\u03b9"],
  [0x1f82, "\u1f02\u03b9"], [0x1f83, "\u1f03\u03b9"], [0x1f84, "\u1f04\u03b9"],
  [0x1f85, "\u1f05\u03b9"], [0x1f86, "\u1f06\u03b9"], [0x1f87, "\u1f07\u03b9"],
  [0x1f88, "\u1f00\u03b9"], [0x1f89, "\u1f01\u03b9"], [0x1f8a, "\u1f02\u03b9"],
  [0x1f8b, "\u1f03\u03b9"], [0x1f8c, "\u1f04\u03b9"], [0x1f8d, "\u1f05\u03b9"],
  [0x1f8e, "\u1f06\u03b9"], [0x1f8f, "\u1f07\u03b9"], [0x1f90, "\u1f20\u03b9"],
  [0x1f91, "\u1f21\u03b9"], [0x1f92, "\u1f22\u03b9"], [0x1f93, "\u1f23\u03b9"],
  [0x1f94, "\u1f24\u03b9"], [0x1f95, "\u1f25\u03b9"], [0x1f96, "\u1f26\u03b9"],
  [0x1f97, "\u1f27\u03b9"], [0x1f98, "\u1f20\u03b9"], [0x1f99, "\u1f21\u03b9"],
  [0x1f9a, "\u1f22\u03b9"], [0x1f9b, "\u1f23\u03b9"], [0x1f9c, "\u1f24\u03b9"],
  [0x1f9d, "\u1f25\u03b9"], [0x1f9e, "\u1f26\u03b9"], [0x1f9f, "\u1f27\u03b9"],
  [0x1fa0, "\u1f60\u03b9"], [0x1fa1, "\u1f61\u03b9"], [0x1fa2, "\u1f62\u03b9"],
  [0x1fa3, "\u1f63\u03b9"], [0x1fa4, "\u1f64\u03b9"], [0x1fa5, "\u1f65\u03b9"],
  [0x1fa6, "\u1f66\u03b9"], [0x1fa7, "\u1f67\u03b9"], [0x1fa8, "\u1f60\u03b9"],
  [0x1fa9, "\u1f61\u03b9"], [0x1faa, "\u1f62\u03b9"], [0x1fab, "\u1f63\u03b9"],
  [0x1fac, "\u1f64\u03b9"], [0x1fad, "\u1f65\u03b9"], [0x1fae, "\u1f66\u03b9"],
  [0x1faf, "\u1f67\u03b9"], [0x1fb2, "\u1f70\u03b9"], [0x1fb3, "\u03b1\u03b9"],
  [0x1fb4, "\u03ac\u03b9"], [0x1fb6, "\u03b1\u0342"], [0x1fb7, "\u03b1\u0342\u03b9"],
  [0x1fbc, "\u03b1\u03b9"], [0x1fbe, "\u03b9"], [0x1fc2, "\u1f74\u03b9"], [0x1fc3, "\u03b7\u03b9"],
  [0x1fc4, "\u03ae\u03b9"], [0x1fc6, "\u03b7\u0342"], [0x1fc7, "\u03b7\u0342\u03b9"],
  [0x1fcc, "\u03b7\u03b9"], [0x1fd2, "\u03b9\u0308\u0300"], [0x1fd3, "\u03b9\u0308\u0301"],
  [0x1fd6, "\u03b9\u0342"], [0x1fd7, "\u03b9\u0308\u0342"], [0x1fe2, "\u03c5\u0308\u0300"],
  [0x1fe3, "\u03c5\u0308\u0301"], [0x1fe4, "\u03c1\u0313"], [0x1fe6, "\u03c5\u0342"],
  [0x1fe7, "\u03c5\u0308\u0342"], [0x1ff2, "\u1f7c\u03b9"], [0x1ff3, "\u03c9\u03b9"],
  [0x1ff4, "\u03ce\u03b9"], [0x1ff6, "\u03c9\u0342"], [0x1ff7, "\u03c9\u0342\u03b9"],
  [0x1ffc, "\u03c9\u03b9"], [0xab70, "\u13a0"], [0xab71, "\u13a1"], [0xab72, "\u13a2"],
  [0xab73, "\u13a3"], [0xab74, "\u13a4"], [0xab75, "\u13a5"], [0xab76, "\u13a6"],
  [0xab77, "\u13a7"], [0xab78, "\u13a8"], [0xab79, "\u13a9"], [0xab7a, "\u13aa"],
  [0xab7b, "\u13ab"], [0xab7c, "\u13ac"], [0xab7d, "\u13ad"], [0xab7e, "\u13ae"],
  [0xab7f, "\u13af"], [0xab80, "\u13b0"], [0xab81, "\u13b1"], [0xab82, "\u13b2"],
  [0xab83, "\u13b3"], [0xab84, "\u13b4"], [0xab85, "\u13b5"], [0xab86, "\u13b6"],
  [0xab87, "\u13b7"], [0xab88, "\u13b8"], [0xab89, "\u13b9"], [0xab8a, "\u13ba"],
  [0xab8b, "\u13bb"], [0xab8c, "\u13bc"], [0xab8d, "\u13bd"], [0xab8e, "\u13be"],
  [0xab8f, "\u13bf"], [0xab90, "\u13c0"], [0xab91, "\u13c1"], [0xab92, "\u13c2"],
  [0xab93, "\u13c3"], [0xab94, "\u13c4"], [0xab95, "\u13c5"], [0xab96, "\u13c6"],
  [0xab97, "\u13c7"], [0xab98, "\u13c8"], [0xab99, "\u13c9"], [0xab9a, "\u13ca"],
  [0xab9b, "\u13cb"], [0xab9c, "\u13cc"], [0xab9d, "\u13cd"], [0xab9e, "\u13ce"],
  [0xab9f, "\u13cf"], [0xaba0, "\u13d0"], [0xaba1, "\u13d1"], [0xaba2, "\u13d2"],
  [0xaba3, "\u13d3"], [0xaba4, "\u13d4"], [0xaba5, "\u13d5"], [0xaba6, "\u13d6"],
  [0xaba7, "\u13d7"], [0xaba8, "\u13d8"], [0xaba9, "\u13d9"], [0xabaa, "\u13da"],
  [0xabab, "\u13db"], [0xabac, "\u13dc"], [0xabad, "\u13dd"], [0xabae, "\u13de"],
  [0xabaf, "\u13df"], [0xabb0, "\u13e0"], [0xabb1, "\u13e1"], [0xabb2, "\u13e2"],
  [0xabb3, "\u13e3"], [0xabb4, "\u13e4"], [0xabb5, "\u13e5"], [0xabb6, "\u13e6"],
  [0xabb7, "\u13e7"], [0xabb8, "\u13e8"], [0xabb9, "\u13e9"], [0xabba, "\u13ea"],
  [0xabbb, "\u13eb"], [0xabbc, "\u13ec"], [0xabbd, "\u13ed"], [0xabbe, "\u13ee"],
  [0xabbf, "\u13ef"], [0xfb00, "ff"], [0xfb01, "fi"], [0xfb02, "fl"], [0xfb03, "ffi"],
  [0xfb04, "ffl"], [0xfb05, "st"], [0xfb06, "st"], [0xfb13, "\u0574\u0576"],
  [0xfb14, "\u0574\u0565"], [0xfb15, "\u0574\u056b"], [0xfb16, "\u057e\u0576"],
  [0xfb17, "\u0574\u056d"],
]);

const ASCII_TEXT_RE = /^[\x00-\x7f]*$/;
const ASCII_DIGITS_RE = /^[0-9]+$/;

export function pyCasefold(text) {
  // ASCII fast path: casefold equals lower for ASCII, and JS toLowerCase is
  // identical over ASCII (this is not the locale-sensitive
  // toLocaleLowerCase). Generated table text is overwhelmingly ASCII, so this
  // avoids the per-character Map lookup + concatenation.
  if (ASCII_TEXT_RE.test(text)) return text.toLowerCase();
  let out = "";
  for (const ch of text) {
    const folded = PY_CASEFOLD_DIFF.get(ch.codePointAt(0));
    out += folded ?? ch.toLowerCase();
  }
  return out;
}

// Case-insensitive matching simple-folds U+0130/U+0131 onto "i" and U+017F
// onto "s" (exactly these non-ASCII code points match [a-z]/[A-Z]; ligatures
// are excluded). JS /iu natively folds U+017F and U+212A but not the Turkic
// pair, so the match input is pre-normalized here instead of relying on
// engine-specific folding.
const PY_RE_FOLD_RE = /[\u0130\u0131\u017f\u212a]/gu;

export function pyRegexFold(text) {
  return text.replace(PY_RE_FOLD_RE, (ch) => (ch === "\u017f" ? "s" : ch === "\u212a" ? "k" : "i"));
}

// Digit matching covers Unicode Nd and evaluates each Nd code point's digit
// value. Every Nd block is ten consecutive code points with digit values
// 0..9, so the block starts below are enough to evaluate arbitrary Nd runs
// exactly.
const ND_RUN_STARTS = [
  48, 1632, 1776, 1984, 2406, 2534, 2662, 2790, 2918, 3046, 3174, 3302, 3430,
  3558, 3664, 3792, 3872, 4160, 4240, 6112, 6160, 6470, 6608, 6784, 6800,
  6992, 7088, 7232, 7248, 42528, 43216, 43264, 43472, 43504, 43600, 44016,
  65296, 66720, 68912, 68928, 69734, 69872, 69942, 70096, 70384, 70736,
  70864, 71248, 71360, 71376, 71386, 71472, 71904, 72016, 72688, 72784,
  73040, 73120, 73552, 90416, 92768, 92864, 93008, 93552, 118000, 120782,
  120792, 120802, 120812, 120822, 123200, 123632, 124144, 124401, 125264,
  130032,
];

export function pyNdInt(text) {
  // ASCII fast path. <=15 digits is exactly representable as a double; longer
  // ASCII runs take the exact BigInt route without the per-character Unicode
  // block scan.
  if (ASCII_DIGITS_RE.test(text)) {
    return text.length <= 15 ? Number(text) : toExactNumber(BigInt(text));
  }
  let value = 0n;
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    const start = ND_RUN_STARTS.find((s) => cp >= s && cp <= s + 9);
    if (start === undefined) throw new RangeError(`not a Unicode decimal digit: U+${cp.toString(16)}`);
    value = value * 10n + BigInt(cp - start);
  }
  return toExactNumber(value);
}

const DAT_NAME_RE = /(?:^|\/)(\p{Nd}+)_(\p{Nd}+)_(?:res|cmn)\.dat\n?$/iu;
const MBN_NAME_RE = /rf_config_(\p{Nd}+)_(\p{Nd}+)_(\p{Nd}+)\.mbn\n?$/iu;

export function readRfcardInfo(datName, inputName, rrc) {
  // Recover the RFCard identifiers and embedded RRC environment names.
  // Case-insensitive Unicode search (\d == Nd, Nd digits read as integers)
  // and Unicode-whitespace strip on the env names.
  const datMatch = DAT_NAME_RE.exec(pyRegexFold(datName));
  const mbnMatch = MBN_NAME_RE.exec(pyRegexFold(inputName));
  let hwid = datMatch ? pyNdInt(datMatch[1]) : null;
  let fsid = datMatch ? pyNdInt(datMatch[2]) : null;
  const bid = mbnMatch ? pyNdInt(mbnMatch[3]) : null;
  if (mbnMatch) {
    if (hwid === null) hwid = pyNdInt(mbnMatch[1]);
    if (fsid === null) fsid = pyNdInt(mbnMatch[2]);
  }
  const envHigh = pyStrip(rrc.env_name_high);
  const envLow = pyStrip(rrc.env_name_low);
  let displayName = envHigh || envLow;
  if (!displayName && hwid !== null && fsid !== null) displayName = `RFCARD_HWID${hwid}_FSID${fsid}`;
  return {
    name: displayName || null,
    name_source: envHigh
      ? "res.rrc.env_name_high"
      : envLow
        ? "res.rrc.env_name_low"
        : displayName
          ? "derived_from_hwid_fsid"
          : null,
    canonical_xml_variant_name: null,
    canonical_xml_variant_name_embedded: false,
    hwid,
    fsid,
    bid,
    key: hwid !== null && fsid !== null ? `${hwid}_${fsid}` : null,
    res_dat_path: datName,
    environment_name_high: envHigh || null,
    environment_name_low: envLow || null,
  };
}

function moduleFields(record) {
  return {
    inner_path: record.inner_path,
    name: record.name,
    generation: record.generation ?? null,
    size: record.size ?? null,
    hwid: record.hwid ?? null,
    fsid: record.fsid ?? null,
    bid: record.bid ?? null,
    external: record.external ?? false,
    source_path: record.source_path ?? "",
    sidecars: record.sidecars ?? {},
    sha256: record.sha256 ?? "",
    lte_combos: record.lte_combos ?? -1,
    nr_combos: record.nr_combos ?? "",
  };
}

const SECTION_SPECS = [
  ["nr5g", "nr_ca", 4],
  ["lte_nr5g", "endc", 3],
  ["nr5g_nr5g", "nrdc", 5],
];

export function parseModernModule(record, blob) {
  const dats = extractRfcDats(blob);
  // Full case-folded endswith("_res.dat") check (e.g. "x_reſ.dat" matches);
  // toLowerCase leaves U+017F untouched.
  const resItems = dats
    .filter((d) => pyCasefold(d.name).endsWith("_res.dat"))
    .map((d) => [d.name, d.data]);
  if (resItems.length === 0) throw new ToolError("No embedded /rfc/*_res.dat was found");
  if (resItems.length > 1) {
    throw new ToolError("More than one *_res.dat was found: " + resItems.map(([name]) => name).join(", "));
  }
  const [datName, resDat] = resItems[0];
  const { encoding, payload, rrc } = parseResDat(resDat);
  const cardInfo = readRfcardInfo(datName, record.name, rrc);

  const enumMap = enumAssignments();
  const bwNames = reverseEnum(enumMap, "BW_");
  const antennaNames = reverseEnum(enumMap, "ANTENNA_");

  const combinations = [];
  const components = [];
  const b0cdPackets = [];
  const b826Packets = [];
  for (const suffix of ["high", "low"]) {
    const [lteCombos, lteComponents] = modernLteRows(rrc, suffix, antennaNames);
    combinations.push(...lteCombos);
    components.push(...lteComponents);
    const ltePackets = b0cdV41Packets(rrc, suffix);
    ltePackets.forEach((packet, index) => {
      b0cdPackets.push([`${suffix} LTE CA packet ${index + 1}/${ltePackets.length}`, packet]);
    });

    for (const [prefix, table, source] of SECTION_SPECS) {
      const [comboRows, componentRows, rawRecords] = modernNrRows(rrc, suffix, prefix, table, bwNames, antennaNames);
      combinations.push(...comboRows);
      components.push(...componentRows);
      const packets = rawRecords.length ? b826V22Packets(rawRecords, source) : [];
      packets.forEach((packet, index) => {
        b826Packets.push([
          `${suffix} ${TABLE_DISPLAY[table]} source=${source} packet ${index + 1}/${packets.length}`,
          packet,
        ]);
      });
    }
  }

  return {
    metadata: {
      tool: "Qualcomm RF Combination Extractor",
      version: VERSION,
      generation: record.generation ?? null,
      module: moduleFields(record),
      module_sha256: record.sha256 || sha256Hex(blob),
      res_dat_path: datName,
      res_dat_sha256: sha256Hex(resDat),
      dat_encoding: encoding,
      protobuf_size: payload.length,
      rfcard: cardInfo,
      diag_note: "Headerless synthetic DIAG payloads reconstructed from static RFCard tables.",
    },
    combinations,
    components,
    diag: { b0cd: b0cdPackets, b826: b826Packets },
  };
}

// Count-only fast path for scan-time comboCounts: identical table tally to
// parseModernModule().combinations without building components, DIAG packets,
// raw_hex, or metadata. Valid because modernLteRows/modernNrRows push exactly
// one combinations row per raw/section record with no filtering (verified
// against the full parse by the parity test and the golden corpus).
export function countModernCombos(record, blob) {
  const dats = extractRfcDats(blob);
  const resItems = dats
    .filter((d) => pyCasefold(d.name).endsWith("_res.dat"))
    .map((d) => [d.name, d.data]);
  if (resItems.length === 0) throw new ToolError("No embedded /rfc/*_res.dat was found");
  if (resItems.length > 1) {
    throw new ToolError("More than one *_res.dat was found: " + resItems.map(([name]) => name).join(", "));
  }
  const { rrc } = parseResDat(resItems[0][1]);
  // Throw parity with parseModernModule: identical arguments, identical error
  // propagation at the same point of the pipeline. The result (rfcard
  // metadata) is discarded — the count path skips metadata, not this call.
  readRfcardInfo(resItems[0][0], record.name, rrc);
  const counts = {};
  for (const suffix of ["high", "low"]) {
    const field = `lte_info_per_band_sub_cap_${suffix}`;
    const lteRows = chunks(rrc[field], 50).slice(0, asCount(rrc[`${field}_num`])).length;
    if (lteRows) counts.lte_ca = (counts.lte_ca ?? 0) + lteRows;
    for (const [prefix, table] of SECTION_SPECS) {
      const n = nrSectionRecords(rrc, prefix, suffix).length;
      if (n) counts[table] = (counts[table] ?? 0) + n;
    }
  }
  return counts;
}
