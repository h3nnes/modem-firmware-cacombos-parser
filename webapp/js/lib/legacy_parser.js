// Legacy ELF/RF-card parsing core plus the legacy orchestration (table
// labels, LTE array discovery, legacy module parse). Behaviour contract:
// identical values, dict key insertion order, iteration order and error
// messages.
//
// Output objects use snake_case keys and preserve key insertion order (the
// golden comparator checks key order); the internal Descriptor class stays
// camelCase.
import { StructReader, indexOfBytes } from "./bytes.js";
import { sha256Hex } from "./hash.js";
import { Elf32Image, ParseError } from "./elf.js";
// Cycle note: modern_parser.js imports TABLE_DISPLAY/ToolError from this
// module, so this import is circular. It is safe because b826V22Packets is a
// hoisted function declaration and only invoked from function bodies here.
import { b826V22Packets } from "./modern_parser.js";

export { Elf32Image, LoadSegment, DynamicSymbol, ParseError } from "./elf.js";

export class ToolError extends Error {
  constructor(message) {
    super(message);
    this.name = "ToolError";
  }
}

export const LEGACY_COMBO_RECORD_SIZE = 40;
export const LEGACY_BAND_GROUP_RECORD_SIZE = 12;
export const MODERN_COMBO_RECORD_SIZE = 44;
export const MODERN_BAND_GROUP_RECORD_SIZE = 12;
export const HI_INLINE_COMBO_RECORD_SIZE = 100;
export const HI_INLINE_BAND_GROUP_RECORD_SIZE = 8;
export const HI_INLINE_MAX_COMPONENTS = 12;
export const HI_INLINE_PROPERTY_OFFSET = 96;
export const HI_INLINE_COUNT_OFFSET = 98;
export const MAX_GROUPS_PER_COMBO = 12;
export const UNUSED_GROUP_INDEX = 0xffff;

// B826 source enum values used by Qualcomm's diagnostic serialization.
export const TABLE_SOURCE_INFO = {
  endc: ["RF_ENDC", 3],
  nrca: ["RF_NRCA", 4],
  nrdc: ["RF_NRDC", 5],
};

export const TABLE_DISPLAY = {
  lte_ca: "LTE CA",
  nr_ca: "NR-CA",
  endc: "EN-DC",
  nrdc: "NR-DC",
  nr_unknown: "NR-only (unclassified)",
};

const VERSION = "1.8.0";

// B826 source enum per table.
const B826_SOURCE = { endc: 3, nr_ca: 4, nrdc: 5 };

// Concat of Uint8Array chunks (same shape as the local helper in
// modern_parser.js; bytes.js has none).
function concatBytes(arrs) {
  let length = 0;
  for (const arr of arrs) length += arr.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const arr of arrs) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

// Qualcomm BW indexes independently correlated with B826 Versions 8-22.
export const KNOWN_BANDWIDTH_PARTS_MHZ = {
  0: [],
  1: [5],
  2: [10],
  3: [15],
  4: [20],
  5: [20],
  6: [20],
  7: [20],
  8: [20],
  9: [25],
  10: [30],
  11: [40],
  12: [50],
  13: [50],
  14: [50],
  15: [50],
  16: [50],
  17: [60],
  18: [70],
  19: [80],
  20: [90],
  21: [100],
  22: [100, 60],
  23: [100],
  24: [100],
  25: [100],
  26: [100],
  27: [100],
  28: [100],
  29: [100],
  30: [40],
  31: [60, 40],
  32: [100, 40],
  33: [200],
  34: [200],
  35: [200],
  36: [200],
  37: [10],
  38: [25],
  39: [40, 10],
  40: [40, 20],
  41: [35],
  42: [30, 20],
  43: [60],
  44: [30],
  45: [45],
  46: [50, 5],
  47: [50, 10],
  48: [50, 15],
  49: [50, 20],
  50: [40, 15],
  51: [15],
  52: [30, 25],
  53: [20, 10],
  54: [20, 15],
  55: [5],
  56: [80],
  57: [80, 20],
  58: [40, 30],
  59: [100, 90],
  60: [30, 10],
  61: [100, 20],
  62: [80, 40],
  63: [50, 40],
  64: [100, 50],
  65: [100, 80],
};

const hexU = (value, digits) => value.toString(16).toUpperCase().padStart(digits, "0");
const hexSpaced = (u8) => {
  let s = "";
  for (const b of u8) s += (s ? " " : "") + b.toString(16).padStart(2, "0");
  return s;
};

export class Descriptor {
  constructor(fields) {
    this.fileOffset = fields.fileOffset;
    this.virtualAddress = fields.virtualAddress;
    this.comboCount = fields.comboCount;
    this.combosVa = fields.combosVa;
    this.combosFileOffset = fields.combosFileOffset;
    this.bandGroupsVa = fields.bandGroupsVa;
    this.bandGroupsFileOffset = fields.bandGroupsFileOffset;
    this.antennaTableCount = fields.antennaTableCount;
    this.bandGroupCount = fields.bandGroupCount;
    this.countByteOffset = fields.countByteOffset;
    this.comboRecordSize = fields.comboRecordSize;
    this.bandGroupRecordSize = fields.bandGroupRecordSize;
    this.descriptorLayout = fields.descriptorLayout;
    this.bandGroupLayout = fields.bandGroupLayout;
    this.antennaTableVa = fields.antennaTableVa;
  }
}

export function makeAntennaTable() {
  const table = [[0, 0, 0, 0, 0, 0, 0, 0]];
  for (let width = 1; width <= 8; width++) {
    const ones = Array(width).fill(1).concat(Array(8 - width).fill(0));
    table.push(ones);
    for (let count2 = 1; count2 <= width; count2++) {
      const values = Array(count2).fill(2).concat(Array(width - count2).fill(1));
      table.push(values.concat(Array(8 - width).fill(0)));
    }
    for (let count4 = 1; count4 <= width; count4++) {
      const values = Array(count4).fill(4).concat(Array(width - count4).fill(2));
      table.push(values.concat(Array(8 - width).fill(0)));
    }
  }
  table.push(
    [8, 0, 0, 0, 0, 0, 0, 0],
    [8, 4, 0, 0, 0, 0, 0, 0],
    [8, 4, 4, 0, 0, 0, 0, 0],
    [8, 8, 0, 0, 0, 0, 0, 0],
    [4, 8, 0, 0, 0, 0, 0, 0],
  );
  if (table.length !== 86) {
    throw new Error(`Internal antenna table has ${table.length} entries, not 86.`);
  }
  return table;
}

const ANTENNA_TABLE = makeAntennaTable();

export function antennaInfo(index) {
  if (!(0 <= index && index < ANTENNA_TABLE.length)) {
    return [null, `ANTENNA_INDEX_${index}`];
  }
  const pattern = ANTENNA_TABLE[index];
  const populated = pattern.filter((value) => value);
  const name = populated.length === 0 ? "NONE" : "ANTENNA_" + populated.join("_");
  return [pattern, name];
}

export function bandwidthParts(code) {
  const parts = KNOWN_BANDWIDTH_PARTS_MHZ[code];
  return parts === undefined ? null : [...parts];
}

export function bandwidthLabel(code) {
  const parts = KNOWN_BANDWIDTH_PARTS_MHZ[code];
  if (parts === undefined) return `BW_CODE_${code}`;
  if (parts.length === 0) return "NONE";
  return parts.join("+") + " MHz";
}

export function bandwidthClassLabel(code) {
  if (code === 0) return "NONE";
  if (1 <= code && code <= 26) return String.fromCharCode(65 + code - 1);
  return `CLASS_${code}`;
}

export function readComboHeader(data, offset, countByteOffset = 27) {
  const r = new StructReader(data);
  const groupIndices = r.unpack("<12H", offset);
  const comboFlags = r.u8(offset + 24);
  const reservedByte1 = r.u8(offset + 25);
  let reservedByte2;
  let numBandEntries;
  if (countByteOffset === 26) {
    numBandEntries = r.u8(offset + 26);
    reservedByte2 = r.u8(offset + 27);
  } else if (countByteOffset === 27) {
    reservedByte2 = r.u8(offset + 26);
    numBandEntries = r.u8(offset + 27);
  } else {
    throw new Error(`Unsupported component-count byte +${countByteOffset}`);
  }
  const [reservedWord, envelopeMask, subsetMask] = r.unpack("<3I", offset + 28);
  return [groupIndices, comboFlags, reservedByte1, reservedByte2, numBandEntries, reservedWord, envelopeMask, subsetMask];
}

export function inferBandGroupLayout(
  data,
  groupsOffset,
  bandGroupCount,
  groupSize,
  antennaCount,
  { defaultLater, countByteOffset },
) {
  if (groupSize !== 12) return "compact_8";

  let usable = 0;
  let nativeAllValid = true;
  let nativeNonzeroUl = 0;

  let classAGroups = 0;
  let laterClassAShapeErrors = 0;
  let nativeClassAShapeErrors = 0;

  let laterEvidence = 0;
  let nativePrefixWord1Set = 0;
  let nativePrefixWord2Set = 0;

  const antennaComponentCount = (index) => {
    if (!(0 <= index && index < antennaCount)) return null;
    if (!(0 <= index && index < ANTENNA_TABLE.length)) return null;
    let count = 0;
    for (const value of ANTENNA_TABLE[index]) if (value) count++;
    return count;
  };

  const r = new StructReader(data);
  for (let index = 0; index < bandGroupCount; index++) {
    const offset = groupsOffset + index * groupSize;
    let words;
    try {
      words = r.unpack("<6H", offset);
    } catch (err) {
      if (err instanceof RangeError) break;
      throw err;
    }

    const ratId = words[0] & 0x3;
    const band = (words[0] >> 2) & 0x1ff;
    if (!((ratId === 1 || ratId === 2) && 1 <= band && band <= 511)) continue;
    usable++;

    const dlClass = words[0] >> 11;

    const laterUlClass = (words[1] >> 6) & 0x1f;
    const laterDlAnt = (words[2] >> 6) & 0x7f;
    const laterUlAnt = ((words[2] >> 13) & 0x07) | ((words[3] & 0x0f) << 3);

    const nativeUlClass = (words[1] >> 7) & 0x1f;
    const nativeDlAnt = (words[2] >> 7) & 0x7f;
    const nativeUlAnt = ((words[2] >> 14) & 0x03) | ((words[3] & 0x1f) << 2);

    nativePrefixWord1Set += (words[1] >> 6) & 1;
    nativePrefixWord2Set += (words[2] >> 6) & 1;

    if (nativeUlClass) nativeNonzeroUl++;

    if (nativeUlClass > 26 || nativeDlAnt >= antennaCount || nativeUlAnt >= antennaCount) {
      nativeAllValid = false;
    }

    if (dlClass === 1) {
      classAGroups++;
      const laterCount = antennaComponentCount(laterDlAnt);
      const nativeCount = antennaComponentCount(nativeDlAnt);
      if (laterCount !== 1) laterClassAShapeErrors++;
      if (nativeCount !== 1) nativeClassAShapeErrors++;
    }

    if (2 <= laterUlClass && laterUlClass <= 26 && laterUlClass === dlClass) {
      laterEvidence++;
    }
    if (
      (words[3] & 0x0f) !== 0 &&
      laterUlAnt < antennaCount &&
      laterUlAnt !== ((words[2] >> 13) & 0x07)
    ) {
      laterEvidence++;
    }
  }

  const minBad = Math.max(4, Math.floor((classAGroups * 3) / 4));
  if (
    usable >= 8 &&
    nativeAllValid &&
    classAGroups >= 4 &&
    nativeClassAShapeErrors === 0 &&
    laterClassAShapeErrors >= minBad
  ) {
    return "native_aligned_12";
  }

  if (
    usable >= 8 &&
    nativeAllValid &&
    nativeNonzeroUl >= 4 &&
    nativePrefixWord2Set === 0 &&
    nativePrefixWord1Set <= Math.max(4, Math.floor(usable / 20)) &&
    countByteOffset === 26
  ) {
    return "native_aligned_12";
  }

  if (laterEvidence || defaultLater) return "later_generated_12";
  return "x70_legacy_12";
}

export function validateCandidate(data, image, descriptorOffset, { exhaustive }) {
  if (descriptorOffset < 0 || descriptorOffset + 20 > data.length) return null;

  const r = new StructReader(data);

  if (descriptorOffset + 24 <= data.length) {
    const [inlineCount, inlinePadding] = r.unpack("<HH", descriptorOffset);
    const inlineRecordsVa = r.u32(descriptorOffset + 4);
    const inlineAntennaCount = r.u16(descriptorOffset + 8);
    const inlineRecordsOffset = image.vaToOffset(inlineRecordsVa, inlineCount * HI_INLINE_COMBO_RECORD_SIZE);
    if (
      1 <= inlineCount && inlineCount <= 100000 &&
      inlinePadding === 0 &&
      1 <= inlineAntennaCount && inlineAntennaCount <= 512 &&
      inlineRecordsOffset !== null
    ) {
      let inlineIndices;
      if (exhaustive) {
        inlineIndices = [];
        for (let i = 0; i < inlineCount; i++) inlineIndices.push(i);
      } else {
        const set = new Set([0, 1, Math.floor(inlineCount / 4), Math.floor(inlineCount / 2), inlineCount - 1]);
        inlineIndices = [...set].filter((i) => 0 <= i && i < inlineCount).sort((a, b) => a - b);
      }

      let inlineValid = true;
      for (const comboIndex of inlineIndices) {
        const recordOffset = inlineRecordsOffset + comboIndex * HI_INLINE_COMBO_RECORD_SIZE;
        const numEntries = data[recordOffset + HI_INLINE_COUNT_OFFSET];
        if (!(1 <= numEntries && numEntries <= HI_INLINE_MAX_COMPONENTS)) {
          inlineValid = false;
          break;
        }
        for (let componentIndex = 0; componentIndex < HI_INLINE_MAX_COMPONENTS; componentIndex++) {
          const componentOffset = recordOffset + componentIndex * HI_INLINE_BAND_GROUP_RECORD_SIZE;
          let any = false;
          for (let k = 0; k < HI_INLINE_BAND_GROUP_RECORD_SIZE; k++) {
            if (data[componentOffset + k]) {
              any = true;
              break;
            }
          }
          if (componentIndex >= numEntries) {
            if (any) {
              inlineValid = false;
              break;
            }
            continue;
          }
          const bandCode = r.u16(componentOffset);
          const ratId = bandCode & 0x3;
          const band = (bandCode >> 2) & 0x1ff;
          const dlClass = bandCode >> 11;
          if (
            !any ||
            !(ratId === 1 || ratId === 2) ||
            !(1 <= band && band <= 511) ||
            !(1 <= dlClass && dlClass <= 26)
          ) {
            inlineValid = false;
            break;
          }
        }
        if (!inlineValid) break;
      }

      if (inlineValid) {
        let antennaTableVa = r.u32(descriptorOffset + 12);
        if (antennaTableVa === 0 || image.vaToOffset(antennaTableVa, 1) === null) {
          antennaTableVa = null;
        }
        return [
          inlineCount,
          inlineRecordsOffset,
          0,
          inlineAntennaCount,
          -1,
          HI_INLINE_COUNT_OFFSET,
          HI_INLINE_COMBO_RECORD_SIZE,
          HI_INLINE_BAND_GROUP_RECORD_SIZE,
          "hi_inline_100",
          "compact_8",
          antennaTableVa,
        ];
      }
    }
  }

  const words = r.unpack("<5I", descriptorOffset);
  const comboCount = words[0];
  const combosVa = words[1];
  const groupsVa = words[2];
  if (!(1 <= comboCount && comboCount <= 100000)) return null;

  const layouts = [];
  const legacyAntennaCount = words[3];
  if (1 <= legacyAntennaCount && legacyAntennaCount <= 512) {
    layouts.push(["legacy_40_12", LEGACY_COMBO_RECORD_SIZE, LEGACY_BAND_GROUP_RECORD_SIZE, legacyAntennaCount, null]);
  }
  const modernAntennaVa = words[3];
  const modernAntennaCount = words[4];
  if (1 <= modernAntennaCount && modernAntennaCount <= 512 && image.vaToOffset(modernAntennaVa, 1) !== null) {
    layouts.push(["xperia_44_12", MODERN_COMBO_RECORD_SIZE, MODERN_BAND_GROUP_RECORD_SIZE, modernAntennaCount, modernAntennaVa]);
  }

  for (const [layoutName, comboSize, groupSize, antennaCount, antennaVa] of layouts) {
    const combosOffset = image.vaToOffset(combosVa, comboCount * comboSize);
    const groupsOffset = image.vaToOffset(groupsVa, groupSize);
    if (combosOffset === null || groupsOffset === null) continue;

    let recordIndices;
    if (exhaustive) {
      recordIndices = [];
      for (let i = 0; i < comboCount; i++) recordIndices.push(i);
    } else {
      const set = new Set([0, 1, Math.floor(comboCount / 4), Math.floor(comboCount / 2), comboCount - 1]);
      recordIndices = [...set].sort((a, b) => a - b);
    }

    let selectedCountOffset = null;
    let highestGroup = -1;
    for (const candidateCountOffset of [27, 26]) {
      let candidateHighest = -1;
      let valid = true;
      for (const comboIndex of recordIndices) {
        const recordOffset = combosOffset + comboIndex * comboSize;
        let header;
        try {
          header = readComboHeader(data, recordOffset, candidateCountOffset);
        } catch (err) {
          if (err instanceof RangeError) {
            valid = false;
            break;
          }
          throw err;
        }
        const numEntries = header[4];
        if (!(1 <= numEntries && numEntries <= MAX_GROUPS_PER_COMBO)) {
          valid = false;
          break;
        }
        const active = header[0].slice(0, numEntries);
        if (active.some((index) => index === UNUSED_GROUP_INDEX)) {
          valid = false;
          break;
        }
        if (numEntries < MAX_GROUPS_PER_COMBO && header[0][numEntries] !== UNUSED_GROUP_INDEX) {
          valid = false;
          break;
        }
        for (const index of active) {
          if (index > candidateHighest) candidateHighest = index;
        }
      }
      if (valid) {
        selectedCountOffset = candidateCountOffset;
        highestGroup = candidateHighest;
        break;
      }
    }

    if (selectedCountOffset === null) continue;

    const defaultLater = layoutName === "xperia_44_12" || selectedCountOffset === 26;
    if (!exhaustive) {
      const provisionalGroupLayout =
        selectedCountOffset === 26
          ? "native_aligned_12"
          : defaultLater
            ? "later_generated_12"
            : "x70_legacy_12";
      return [
        comboCount, combosOffset, groupsOffset, antennaCount, highestGroup,
        selectedCountOffset, comboSize, groupSize, layoutName, provisionalGroupLayout, antennaVa,
      ];
    }

    const bandGroupCount = highestGroup + 1;
    if (image.vaToOffset(groupsVa, bandGroupCount * groupSize) === null) continue;

    const bandGroupLayout = inferBandGroupLayout(
      data,
      groupsOffset,
      bandGroupCount,
      groupSize,
      antennaCount,
      { defaultLater, countByteOffset: selectedCountOffset },
    );

    let validGroups = true;
    for (let groupIndex = 0; groupIndex < bandGroupCount; groupIndex++) {
      const groupOffset = groupsOffset + groupIndex * groupSize;
      let words16;
      try {
        words16 = r.unpack(groupSize === 8 ? "<4H" : "<6H", groupOffset);
      } catch (err) {
        if (err instanceof RangeError) {
          validGroups = false;
          break;
        }
        throw err;
      }
      const ratId = words16[0] & 0x3;
      const band = (words16[0] >> 2) & 0x1ff;
      if (!((ratId === 1 || ratId === 2) && 1 <= band && band <= 511)) {
        validGroups = false;
        break;
      }
      let dlAntennaIndex;
      let ulAntennaIndex;
      if (bandGroupLayout === "native_aligned_12") {
        dlAntennaIndex = (words16[2] >> 7) & 0x7f;
        ulAntennaIndex = ((words16[2] >> 14) & 0x03) | ((words16[3] & 0x1f) << 2);
      } else {
        dlAntennaIndex = (words16[2] >> 6) & 0x7f;
        if (bandGroupLayout === "later_generated_12") {
          ulAntennaIndex = ((words16[2] >> 13) & 0x7) | ((words16[3] & 0xf) << 3);
        } else {
          ulAntennaIndex = (words16[2] >> 13) & 0x7;
        }
      }
      if (dlAntennaIndex >= antennaCount || ulAntennaIndex >= antennaCount) {
        validGroups = false;
        break;
      }
    }
    if (validGroups) {
      return [
        comboCount, combosOffset, groupsOffset, antennaCount, highestGroup,
        selectedCountOffset, comboSize, groupSize, layoutName, bandGroupLayout, antennaVa,
      ];
    }
  }
  return null;
}

const NAMED_COMBO_TABLE_SUFFIXES = [
  ["nr5g_nr5g_combos_info_table_sub_cap_high", "nrdc"],
  ["lte_nr5g_combos_info_table_sub_cap_high", "endc"],
  ["nr5g_combos_info_table_sub_cap_high", "nrca"],
];

export function rfcardNameFromSymbols(image) {
  const symbols = image.dynamicSymbols();
  const publicSuffixes = [
    "lte_combos_info_table_sub_cap_high",
    "nr5g_nr5g_combos_info_table_sub_cap_high",
    "lte_nr5g_combos_info_table_sub_cap_high",
    "nr5g_combos_info_table_sub_cap_high",
  ];
  for (const suffix of publicSuffixes) {
    const candidates = symbols
      .filter(
        (symbol) =>
          symbol.name.toLowerCase().endsWith(suffix) &&
          !symbol.name.toLowerCase().includes("internal"),
      )
      .map((symbol) => symbol.name)
      .sort();
    if (candidates.length > 0) {
      return candidates[0]
        .slice(0, candidates[0].length - suffix.length)
        .replace(/_+$/, "");
    }
  }

  const generatedNames = symbols
    .filter((symbol) => symbol.name.toLowerCase().startsWith("rfc_hwid"))
    .map((symbol) => symbol.name)
    .sort();
  if (generatedNames.length === 0) return null;
  let commonPrefix = generatedNames[0];
  for (const name of generatedNames.slice(1)) {
    const limit = Math.min(commonPrefix.length, name.length);
    let index = 0;
    while (index < limit && commonPrefix[index] === name[index]) index++;
    commonPrefix = commonPrefix.slice(0, index);
    if (!commonPrefix) return null;
  }
  return commonPrefix.replace(/_+$/, "") || null;
}

export function findNamedDescriptors(data, image) {
  const found = [];
  const seenOffsets = new Set();
  for (const symbol of image.dynamicSymbols()) {
    const nameLower = symbol.name.toLowerCase();
    let tableKind = null;
    for (const [suffix, kind] of NAMED_COMBO_TABLE_SUFFIXES) {
      if (nameLower.endsWith(suffix)) {
        tableKind = kind;
        break;
      }
    }
    if (tableKind === null || symbol.fileOffset === null) continue;
    if (seenOffsets.has(symbol.fileOffset)) continue;
    const layout = validateCandidate(data, image, symbol.fileOffset, { exhaustive: true });
    if (layout === null) continue;
    found.push([tableKind, makeDescriptor(data, image, symbol.fileOffset, layout), symbol.name]);
    seenOffsets.add(symbol.fileOffset);
  }

  // Band-group packing is a property of the shared group table, not of an
  // individual combo descriptor. Propagate the strongest proven layout to
  // every descriptor that references the same group-table VA.
  const groupLayoutByVa = new Map();
  const layoutPriority = { x70_legacy_12: 0, later_generated_12: 1, native_aligned_12: 2 };
  for (const [, descriptor] of found) {
    const current = groupLayoutByVa.get(descriptor.bandGroupsVa);
    if (
      current === undefined ||
      (layoutPriority[descriptor.bandGroupLayout] ?? 0) > (layoutPriority[current] ?? 0)
    ) {
      groupLayoutByVa.set(descriptor.bandGroupsVa, descriptor.bandGroupLayout);
    }
  }

  const relabeled = found.map(([kind, descriptor, symbolName]) => [
    kind,
    new Descriptor({
      ...descriptor,
      bandGroupLayout: groupLayoutByVa.has(descriptor.bandGroupsVa)
        ? groupLayoutByVa.get(descriptor.bandGroupsVa)
        : descriptor.bandGroupLayout,
    }),
    symbolName,
  ]);

  const order = { endc: 0, nrca: 1, nrdc: 2 };
  relabeled.sort((a, b) => {
    const ka = order[a[0]] ?? 9;
    const kb = order[b[0]] ?? 9;
    return ka !== kb ? ka - kb : a[1].fileOffset - b[1].fileOffset;
  });
  return relabeled;
}

export function findDescriptors(data, image) {
  const named = findNamedDescriptors(data, image);
  if (named.length > 0) {
    return named.map(([, descriptor]) => descriptor);
  }

  const candidates = [];
  for (const [rangeStart, rangeEnd] of image.mappedFileRanges()) {
    const alignedStart = Math.floor((rangeStart + 3) / 4) * 4;
    for (let offset = alignedStart; offset < rangeEnd - 15; offset += 4) {
      const quick = validateCandidate(data, image, offset, { exhaustive: false });
      if (quick === null) continue;
      candidates.push([offset, quick]);
    }
  }

  const validated = [];
  for (const [offset] of candidates) {
    const full = validateCandidate(data, image, offset, { exhaustive: true });
    if (full !== null) {
      validated.push(makeDescriptor(data, image, offset, full));
    }
  }
  if (validated.length === 0) {
    throw new ParseError(
      "No valid RF combination descriptor was found. Use --descriptor-offset if this firmware uses a different layout.",
    );
  }

  return validated.sort((a, b) => a.fileOffset - b.fileOffset);
}

const signatureKey = (rats) => [...rats].sort((a, b) => a - b).join(",");

export function descriptorRatSignatures(data, descriptor) {
  const r = new StructReader(data);
  const signatures = new Set();
  if (descriptor.descriptorLayout === "hi_inline_100") {
    for (let comboIndex = 0; comboIndex < descriptor.comboCount; comboIndex++) {
      const offset = descriptor.combosFileOffset + comboIndex * descriptor.comboRecordSize;
      const numEntries = r.u8(offset + descriptor.countByteOffset);
      const rats = new Set();
      for (let componentIndex = 0; componentIndex < numEntries; componentIndex++) {
        const bandCode = r.u16(offset + componentIndex * descriptor.bandGroupRecordSize);
        rats.add(bandCode & 0x3);
      }
      signatures.add(signatureKey(rats));
    }
    return signatures;
  }

  for (let comboIndex = 0; comboIndex < descriptor.comboCount; comboIndex++) {
    const offset = descriptor.combosFileOffset + comboIndex * descriptor.comboRecordSize;
    const [groupIndices, , , , numEntries] = readComboHeader(data, offset, descriptor.countByteOffset);
    const rats = new Set();
    for (const groupIndex of groupIndices.slice(0, numEntries)) {
      const groupOffset = descriptor.bandGroupsFileOffset + groupIndex * descriptor.bandGroupRecordSize;
      const bandCode = r.u16(groupOffset);
      rats.add(bandCode & 0x3);
    }
    signatures.add(signatureKey(rats));
  }
  return signatures;
}

export function classifyDescriptor(data, descriptor) {
  const signatures = descriptorRatSignatures(data, descriptor);
  if (signatures.size === 1 && signatures.has("1,2")) return "endc";
  if (signatures.size === 1 && signatures.has("2")) return "nrca";
  if (signatures.size === 1 && signatures.has("1")) return "lteca";
  return "unknown";
}

export function findDescriptor(data, image, tableKind = "endc") {
  const matches = findDescriptors(data, image).filter(
    (descriptor) => classifyDescriptor(data, descriptor) === tableKind,
  );
  if (matches.length === 0) {
    throw new ParseError(`No ${tableKind.toUpperCase()} RF table was found.`);
  }
  if (matches.length > 1) {
    const offsets = matches
      .map((descriptor) => `0x${descriptor.fileOffset.toString(16).toUpperCase()}`)
      .join(", ");
    throw new ParseError(
      `${tableKind.toUpperCase()} table detection is ambiguous (${offsets}); select one with --descriptor-offset.`,
    );
  }
  return matches[0];
}

export function makeDescriptor(data, image, descriptorOffset, validatedLayout = null) {
  const layout = validatedLayout ?? validateCandidate(data, image, descriptorOffset, { exhaustive: true });
  if (layout === null) {
    throw new ParseError(`0x${descriptorOffset.toString(16).toUpperCase()} is not a valid RF table descriptor.`);
  }
  const [
    layoutComboCount,
    combosOffset,
    layoutGroupsOffset,
    antennaCount,
    highestGroup,
    countByteOffset,
    comboRecordSize,
    bandGroupRecordSize,
    descriptorLayout,
    bandGroupLayout,
    antennaTableVa,
  ] = layout;
  const r = new StructReader(data);
  let comboCount = layoutComboCount;
  let groupsOffset = layoutGroupsOffset;
  let combosVa;
  let groupsVa;
  let bandGroupCount;
  let descriptorSize;
  if (descriptorLayout === "hi_inline_100") {
    comboCount = r.u16(descriptorOffset);
    combosVa = r.u32(descriptorOffset + 4);
    groupsVa = 0;
    groupsOffset = 0;
    bandGroupCount = 0;
    descriptorSize = 24;
  } else {
    [, combosVa, groupsVa] = r.unpack("<3I", descriptorOffset);
    bandGroupCount = highestGroup + 1;
    descriptorSize = 20;
  }
  return new Descriptor({
    fileOffset: descriptorOffset,
    virtualAddress: image.offsetToVa(descriptorOffset, descriptorSize),
    comboCount,
    combosVa,
    combosFileOffset: combosOffset,
    bandGroupsVa: groupsVa,
    bandGroupsFileOffset: groupsOffset,
    antennaTableCount: antennaCount,
    bandGroupCount,
    countByteOffset,
    comboRecordSize,
    bandGroupRecordSize,
    descriptorLayout,
    bandGroupLayout,
    antennaTableVa,
  });
}

export function parseBandGroup(data, descriptor, index) {
  const r = new StructReader(data);
  const offset = descriptor.bandGroupsFileOffset + index * descriptor.bandGroupRecordSize;
  const words =
    descriptor.bandGroupRecordSize === 8
      ? [...r.unpack("<4H", offset), 0, 0]
      : r.unpack("<6H", offset);
  const bandCode = words[0];
  const ratId = bandCode & 0x3;
  const band = (bandCode >> 2) & 0x1ff;
  const rat = ratId === 1 ? "LTE" : ratId === 2 ? "NR" : `RAT_${ratId}`;
  const bandLabel = rat === "LTE" ? `B${band}` : `n${band}`;
  const dlBwClassCode = bandCode >> 11;
  const dlBwClass = bandwidthClassLabel(dlBwClassCode);

  const dlBwCode = words[1] & 0x3f;

  const layout = descriptor.bandGroupLayout;
  let ulBwClassCode;
  let ulPresent;
  let field2UnknownHigh;
  let dlAntennaIndex;
  let ulAntennaIndex;
  if (layout === "native_aligned_12") {
    ulBwClassCode = (words[1] >> 7) & 0x1f;
    ulPresent = ulBwClassCode !== 0;
    field2UnknownHigh = words[1] >> 12;
    dlAntennaIndex = (words[2] >> 7) & 0x7f;
    ulAntennaIndex = ((words[2] >> 14) & 0x03) | ((words[3] & 0x1f) << 2);
  } else if (layout === "later_generated_12") {
    ulBwClassCode = (words[1] >> 6) & 0x1f;
    ulPresent = ulBwClassCode !== 0;
    field2UnknownHigh = words[1] >> 11;
    dlAntennaIndex = (words[2] >> 6) & 0x7f;
    ulAntennaIndex = ((words[2] >> 13) & 0x07) | ((words[3] & 0x0f) << 3);
  } else {
    ulPresent = ((words[1] >> 6) & 1) !== 0;
    ulBwClassCode = ulPresent ? 1 : 0;
    field2UnknownHigh = words[1] >> 7;
    dlAntennaIndex = (words[2] >> 6) & 0x7f;
    ulAntennaIndex = (words[2] >> 13) & 0x07;
  }

  const ulBwCode = words[2] & 0x3f;
  const [dlPattern, dlAntennaName] = antennaInfo(dlAntennaIndex);
  const [ulPattern, ulAntennaName] = antennaInfo(ulAntennaIndex);

  const native = layout === "native_aligned_12";
  return {
    group_index: index,
    file_offset: offset,
    file_offset_hex: `0x${offset.toString(16).toUpperCase()}`,
    raw_hex: hexSpaced(data.subarray(offset, offset + descriptor.bandGroupRecordSize)),
    raw_words: [...words],
    band_code_raw: bandCode,
    band_code_hex: `0x${hexU(bandCode, 4)}`,
    band_code_high: bandCode >> 11,
    dl_bw_class_code: dlBwClassCode,
    dl_bw_class: dlBwClass,
    rat_id: ratId,
    rat,
    band,
    band_label: bandLabel,
    band_class_label: `${bandLabel}${dlBwClass}`,
    dl_bw_code: dlBwCode,
    dl_bandwidth: bandwidthLabel(dlBwCode),
    dl_bandwidth_parts_mhz: bandwidthParts(dlBwCode),
    ul_present: ulPresent,
    ul_bw_class_code: ulBwClassCode,
    ul_bw_class: bandwidthClassLabel(ulBwClassCode),
    band_group_layout: descriptor.bandGroupLayout,
    field_2_unknown_high: field2UnknownHigh,
    native_word1_prefix_bit: native ? (words[1] >> 6) & 1 : null,
    native_word2_prefix_bit: native ? (words[2] >> 6) & 1 : null,
    x75_word1_alignment_bit: native ? (words[1] >> 6) & 1 : null,
    x75_word2_alignment_bit: native ? (words[2] >> 6) & 1 : null,
    ul_bw_code: ulBwCode,
    ul_bandwidth: bandwidthLabel(ulBwCode),
    ul_bandwidth_parts_mhz: bandwidthParts(ulBwCode),
    dl_antenna_index: dlAntennaIndex,
    dl_antenna: dlAntennaName,
    dl_antenna_pattern: dlPattern,
    ul_antenna_index: ulAntennaIndex,
    ul_antenna: ulAntennaName,
    ul_antenna_pattern: ulPattern,
    feature_word_3_raw: words[3],
    feature_word_3_hex: `0x${hexU(words[3], 4)}`,
    feature_word_4_raw: words[4],
    feature_word_4_hex: `0x${hexU(words[4], 4)}`,
    feature_word_5_raw: words[5],
    feature_word_5_hex: `0x${hexU(words[5], 4)}`,
  };
}

export function canonicalCombination(entries, { includeClasses = false } = {}) {
  const labelField = includeClasses ? "band_class_label" : "band_label";
  const lte = entries.filter((entry) => entry.rat === "LTE").sort((a, b) => a.band - b.band);
  const nr = entries.filter((entry) => entry.rat === "NR").sort((a, b) => a.band - b.band);
  const lteText = lte.map((entry) => entry[labelField]).join("+");
  const nrText = nr.map((entry) => entry[labelField]).join("+");
  if (lte.length > 0 && nr.length > 0) return `DC_${lteText}_${nrText}`;
  if (nr.length > 0) return `NRCA_${nrText}`;
  return `CA_${lteText}`;
}

const UL_TX_SWITCH_LABELS = {
  0: "none",
  1: "switched_ul",
  2: "dual_ul",
  3: "both",
};

export function decodeComboPropertyByte(value) {
  value &= 0xff;
  const powerClass = value & 0x07;
  const ulTxSwitch = (value >> 6) & 0x03;
  return {
    property_byte_raw: value,
    property_byte_hex: `0x${hexU(value, 2)}`,
    power_class_raw: powerClass,
    power_class: powerClass,
    power_class_label: powerClass ? `PC${powerClass}` : "unspecified",
    tdd_ant_swt_fdd_disruption: (value & 0x08) !== 0,
    simultaneous_rx_tx_endc: (value & 0x10) !== 0,
    simultaneous_rx_tx_ca: (value & 0x20) !== 0,
    ul_tx_switch_type_raw: ulTxSwitch,
    ul_tx_switch_type: ulTxSwitch,
    ul_tx_switch_label: UL_TX_SWITCH_LABELS[ulTxSwitch],
  };
}

const ratMixLabel = (rats) => {
  if (rats.has("LTE") && rats.has("NR") && rats.size === 2) return "EN-DC";
  if (rats.size === 1 && rats.has("NR")) return "NR-CA";
  if (rats.size === 1 && rats.has("LTE")) return "LTE-CA";
  return [...rats].sort().join("+");
};

export function parseCombo(data, descriptor, bandGroups, comboIndex) {
  const r = new StructReader(data);
  if (descriptor.descriptorLayout === "hi_inline_100") {
    const offset = descriptor.combosFileOffset + comboIndex * descriptor.comboRecordSize;
    const comboFlags = r.u8(offset + HI_INLINE_PROPERTY_OFFSET);
    const reservedByte = r.u8(offset + HI_INLINE_PROPERTY_OFFSET + 1);
    const numBandEntries = r.u8(offset + descriptor.countByteOffset);
    const bcsNum = r.u8(offset + descriptor.countByteOffset + 1);
    const inlineDescriptor = new Descriptor({
      ...descriptor,
      bandGroupsFileOffset: offset,
      bandGroupCount: numBandEntries,
    });
    const entries = [];
    for (let position = 0; position < numBandEntries; position++) {
      const entry = parseBandGroup(data, inlineDescriptor, position);
      entry.group_index = null;
      entry.position = position;
      entries.push(entry);
    }

    const rats = new Set(entries.map((entry) => entry.rat));
    const propertyFields = decodeComboPropertyByte(comboFlags);
    return {
      combo_index: comboIndex,
      file_offset: offset,
      file_offset_hex: `0x${offset.toString(16).toUpperCase()}`,
      raw_hex: hexSpaced(data.subarray(offset, offset + descriptor.comboRecordSize)),
      rat_mix: ratMixLabel(rats),
      combination_source_order: entries.map((entry) => entry.band_label).join("+"),
      combination_source_order_with_classes: entries.map((entry) => entry.band_class_label).join("+"),
      combination: canonicalCombination(entries),
      combination_with_classes: canonicalCombination(entries, { includeClasses: true }),
      group_indices: [],
      all_group_indices_raw: [],
      combo_flags: comboFlags,
      combo_flags_hex: `0x${hexU(comboFlags, 2)}`,
      ...propertyFields,
      bcs_num: bcsNum,
      higher_power_limit: null,
      reserved_byte_1: reservedByte,
      reserved_byte_2: 0,
      num_band_entries: numBandEntries,
      reserved_word: 0,
      envelope_mask: 0,
      envelope_mask_hex: "0x00000000",
      subset_mask: 0,
      subset_mask_hex: "0x00000000",
      extension_word: null,
      extension_word_hex: null,
      entries,
    };
  }

  const offset = descriptor.combosFileOffset + comboIndex * descriptor.comboRecordSize;
  const [allGroupIndices, comboFlags, reservedByte1, reservedByte2, numBandEntries, reservedWord, envelopeMask, subsetMask] =
    readComboHeader(data, offset, descriptor.countByteOffset);
  const groupIndices = allGroupIndices.slice(0, numBandEntries);
  const entries = [];
  for (let position = 0; position < groupIndices.length; position++) {
    const entry = { ...bandGroups[groupIndices[position]] };
    entry.position = position;
    entries.push(entry);
  }

  const rats = new Set(entries.map((entry) => entry.rat));
  const propertyFields = decodeComboPropertyByte(comboFlags);
  const comboExtensionWord = descriptor.comboRecordSize >= 44 ? r.u32(offset + 40) : null;

  return {
    combo_index: comboIndex,
    file_offset: offset,
    file_offset_hex: `0x${offset.toString(16).toUpperCase()}`,
    raw_hex: hexSpaced(data.subarray(offset, offset + descriptor.comboRecordSize)),
    rat_mix: ratMixLabel(rats),
    combination_source_order: entries.map((entry) => entry.band_label).join("+"),
    combination_source_order_with_classes: entries.map((entry) => entry.band_class_label).join("+"),
    combination: canonicalCombination(entries),
    combination_with_classes: canonicalCombination(entries, { includeClasses: true }),
    group_indices: [...groupIndices],
    all_group_indices_raw: [...allGroupIndices],
    combo_flags: comboFlags,
    combo_flags_hex: `0x${hexU(comboFlags, 2)}`,
    ...propertyFields,
    bcs_num: null,
    higher_power_limit: null,
    reserved_byte_1: reservedByte1,
    reserved_byte_2: reservedByte2,
    num_band_entries: numBandEntries,
    reserved_word: reservedWord,
    envelope_mask: envelopeMask,
    envelope_mask_hex: `0x${hexU(envelopeMask, 8)}`,
    subset_mask: subsetMask,
    subset_mask_hex: `0x${hexU(subsetMask, 8)}`,
    extension_word: comboExtensionWord,
    extension_word_hex:
      comboExtensionWord !== null ? `0x${hexU(comboExtensionWord, 8)}` : null,
    entries,
  };
}

export function parseDescriptor(path, data, descriptor, { discovery, tableKind, detectedTableCount, embeddedPath = null }) {
  const bandGroups =
    descriptor.descriptorLayout === "hi_inline_100"
      ? []
      : Array.from({ length: descriptor.bandGroupCount }, (_, index) => parseBandGroup(data, descriptor, index));
  const combinations = Array.from({ length: descriptor.comboCount }, (_, index) =>
    parseCombo(data, descriptor, bandGroups, index),
  );
  if (tableKind === "nrdc") {
    for (const combo of combinations) {
      combo.rat_mix = "NR-DC";
      combo.combination = combo.combination.replace("NRCA_", "NRDC_");
      combo.combination_with_classes = combo.combination_with_classes.replace("NRCA_", "NRDC_");
    }
  }
  const usedGroupIndices = [
    ...new Set(combinations.flatMap((combo) => combo.group_indices)),
  ].sort((a, b) => a - b);

  const descriptorVa = descriptor.virtualAddress;
  const [sourceName, sourceIndex] = TABLE_SOURCE_INFO[tableKind] ?? [
    `UNKNOWN_${tableKind.toUpperCase()}`,
    null,
  ];
  return {
    metadata: {
      parser: "rf_endc_parser.py",
      input_file: String(path),
      embedded_input_path: embeddedPath,
      input_size: data.length,
      input_sha256: sha256Hex(data),
      table_kind: tableKind,
      b826_source_name: sourceName,
      b826_source_index: sourceIndex,
      detected_table_count: detectedTableCount,
      descriptor_discovery: discovery,
      combo_record_size: descriptor.comboRecordSize,
      component_count_byte_offset: descriptor.countByteOffset,
      band_group_record_size: descriptor.bandGroupRecordSize,
      known_bandwidth_parts_mhz: KNOWN_BANDWIDTH_PARTS_MHZ,
      notes: [
        "Unknown bandwidth and feature codes are retained as raw values.",
        "Some rare Qualcomm bandwidth-index mappings are inferred.",
        "BC_ID is not stored in these hardware RF source records.",
        "Combination-property bits 0..2 are power class; bits 6..7 are UL TX switching.",
        "X75-native band groups use one-bit-aligned UL-class and antenna fields.",
        "Later generated band groups store UL class in word1 bits 6..10 and extend the UL antenna enum into word3 bits 0..3.",
        "DL bandwidth class uses the high five bits of band_code.",
        "B826 repacks these source records; it is not a byte-for-byte copy.",
      ],
    },
    descriptor: {
      file_offset: descriptor.fileOffset,
      file_offset_hex: `0x${descriptor.fileOffset.toString(16).toUpperCase()}`,
      virtual_address: descriptorVa,
      virtual_address_hex: descriptorVa !== null ? `0x${descriptorVa.toString(16).toUpperCase()}` : null,
      combo_count: descriptor.comboCount,
      combos_va: descriptor.combosVa,
      combos_va_hex: `0x${descriptor.combosVa.toString(16).toUpperCase()}`,
      combos_file_offset: descriptor.combosFileOffset,
      combos_file_offset_hex: `0x${descriptor.combosFileOffset.toString(16).toUpperCase()}`,
      band_groups_va: descriptor.bandGroupsVa,
      band_groups_va_hex: `0x${descriptor.bandGroupsVa.toString(16).toUpperCase()}`,
      band_groups_file_offset: descriptor.bandGroupsFileOffset,
      band_groups_file_offset_hex: `0x${descriptor.bandGroupsFileOffset.toString(16).toUpperCase()}`,
      band_group_count: descriptor.bandGroupCount,
      used_band_group_count: usedGroupIndices.length,
      used_band_group_indices: usedGroupIndices,
      antenna_table_count: descriptor.antennaTableCount,
      descriptor_layout: descriptor.descriptorLayout,
      band_group_layout: descriptor.bandGroupLayout,
      antenna_table_va: descriptor.antennaTableVa,
      antenna_table_va_hex:
        descriptor.antennaTableVa !== null ? `0x${descriptor.antennaTableVa.toString(16).toUpperCase()}` : null,
    },
    antenna_table: ANTENNA_TABLE.map((pattern, index) => ({
      index,
      pattern,
      name: antennaInfo(index)[1],
    })),
    band_groups: bandGroups,
    combinations,
  };
}

// --- legacy orchestration ----------------------------------------------------

function bytesInclude(blob, text) {
  const needle = [];
  for (const ch of text) needle.push(ch.charCodeAt(0));
  return indexOfBytes(blob, needle) >= 0;
}

export function legacyTableLabels(blob, descriptors) {
  const classified = descriptors.map((item) => [classifyDescriptor(blob, item), item]);
  const nrOnly = classified
    .filter(([kind]) => kind === "nrca")
    .map(([, item]) => item)
    .sort((a, b) => a.fileOffset - b.fileOffset);
  const nrLabels = new Map();
  if (nrOnly.length === 1) {
    const label = bytesInclude(blob, "RF_NRDC") && !bytesInclude(blob, "RF_NRCA") ? "nrdc" : "nr_ca";
    nrLabels.set(nrOnly[0], [
      label,
      "single NR-only descriptor inferred from available table/name evidence",
    ]);
  } else if (nrOnly.length > 0) {
    nrLabels.set(nrOnly[0], [
      "nr_ca",
      "first NR-only descriptor inferred as RF_NRCA by legacy descriptor order",
    ]);
    nrLabels.set(nrOnly[1], [
      "nrdc",
      "second NR-only descriptor inferred as RF_NRDC by legacy descriptor order",
    ]);
    for (const item of nrOnly.slice(2)) {
      nrLabels.set(item, ["nr_unknown", "additional NR-only descriptor cannot be classified safely"]);
    }
  }

  const result = [];
  for (const [kind, descriptor] of classified) {
    if (kind === "endc") {
      result.push(["endc", descriptor, null]);
    } else if (kind === "lteca") {
      result.push(["lte_ca", descriptor, null]);
    } else if (kind === "nrca") {
      const [table, note] = nrLabels.get(descriptor);
      result.push([table, descriptor, note]);
    }
  }
  const order = { lte_ca: 0, nr_ca: 1, endc: 2, nrdc: 3 };
  return result.sort((a, b) => {
    const ka = order[a[0]] ?? 9;
    const kb = order[b[0]] ?? 9;
    return ka !== kb ? ka - kb : a[1].fileOffset - b[1].fileOffset;
  });
}

export function findLegacyLteArray(blob, image) {
  const r = new StructReader(blob);

  const validateArray = (count, offset) => {
    if (!(1 <= count && count <= 100000)) return false;
    if (offset < 0 || offset + count * 50 > blob.length) return false;
    for (let comboIndex = 0; comboIndex < count; comboIndex++) {
      const recOff = offset + comboIndex * 50;
      const raw = blob.subarray(recOff, recOff + 50);
      if (raw.length !== 50) return false;
      let populated = 0;
      let seenEmpty = false;
      for (let componentIndex = 0; componentIndex < 6; componentIndex++) {
        const compOff = recOff + 2 + componentIndex * 8;
        const component = blob.subarray(compOff, compOff + 8);
        const [band, dlClass, dlAnt, ulClass, ulAnt, ulQam] = r.unpack("<HBBBBB", compOff);
        const reserved = component[7];
        if (band === 0) {
          if (component.some((b) => b !== 0)) return false;
          seenEmpty = true;
          continue;
        }
        if (seenEmpty) return false;
        if (
          !(1 <= band && band <= 511) ||
          !(1 <= dlClass && dlClass <= 26) ||
          dlAnt > 127 ||
          ulClass > 26 ||
          ulAnt > 31 ||
          ulQam > 15 ||
          reserved !== 0
        ) {
          return false;
        }
        populated++;
      }
      if (!(1 <= populated && populated <= 6)) return false;
    }
    return true;
  };

  const namedCandidates = new Map();
  const suffix = "_lte_combos_info_table_sub_cap_high";
  for (const symbol of image.dynamicSymbols()) {
    const name = symbol.name.toLowerCase();
    if (symbol.fileOffset === null || name.includes("internal") || !name.endsWith(suffix)) continue;
    const count = r.u16(symbol.fileOffset);
    const recordsVa = r.u32(symbol.fileOffset + 4);
    const recordsOffset = image.vaToOffset(recordsVa, count * 50);
    if (recordsOffset === null || !validateArray(count, recordsOffset)) continue;
    const key = `${recordsOffset}:${count}`;
    if (!namedCandidates.has(key)) {
      namedCandidates.set(key, [symbol.fileOffset, recordsOffset, count]);
    }
  }
  if (namedCandidates.size === 1) {
    return [...namedCandidates.values()][0];
  }
  if (namedCandidates.size > 1) {
    const details = [...namedCandidates.values()]
      .map(
        (item) =>
          `0x${item[0].toString(16).toUpperCase()}->${item[2]} records at 0x${item[1].toString(16).toUpperCase()}`,
      )
      .join(", ");
    throw new ToolError(`Ambiguous named legacy LTE CA arrays: ${details}`);
  }

  const candidates = [];
  for (const [rangeStart, rangeEnd] of image.mappedFileRanges()) {
    const alignedStart = Math.floor((rangeStart + 3) / 4) * 4;
    for (let descriptorOffset = alignedStart; descriptorOffset < rangeEnd - 7; descriptorOffset += 4) {
      const [count, recordsVa] = r.unpack("<II", descriptorOffset);
      if (!(1 <= count && count <= 100000)) continue;
      const recordsOffset = image.vaToOffset(recordsVa, count * 50);
      if (recordsOffset === null || !validateArray(count, recordsOffset)) continue;
      candidates.push([descriptorOffset, recordsOffset, count]);
    }
  }

  const unique = new Map();
  for (const item of candidates) {
    const key = `${item[1]}:${item[2]}`;
    if (!unique.has(key)) unique.set(key, item);
  }
  if (unique.size === 0) return null;

  let effective = unique;
  if (effective.size > 1) {
    // A few generated ELFs contain a valid one-record helper/internal LTE
    // array in addition to the public LTE CA table. Ignore it only when at
    // least one larger candidate exists.
    const nontrivial = new Map();
    for (const [key, item] of effective) {
      if (item[2] > 1) nontrivial.set(key, item);
    }
    if (nontrivial.size > 0) effective = nontrivial;
  }

  if (effective.size > 1) {
    const details = [...effective.values()]
      .map(
        (item) =>
          `0x${item[0].toString(16).toUpperCase()}->${item[2]} records at 0x${item[1].toString(16).toUpperCase()}`,
      )
      .join(", ");
    throw new ToolError(`Ambiguous legacy LTE CA arrays: ${details}`);
  }

  return [...effective.values()][0];
}

export function parseLegacyLteArray(record, blob, image) {
  const found = findLegacyLteArray(blob, image);
  if (found === null) return null;
  const [descriptorOffset, recordsOffset, count] = found;
  const r = new StructReader(blob);
  const combinations = [];
  for (let comboIndex = 0; comboIndex < count; comboIndex++) {
    const offset = recordsOffset + comboIndex * 50;
    const raw = blob.subarray(offset, offset + 50);
    const entries = [];
    for (let componentIndex = 0; componentIndex < 6; componentIndex++) {
      const compOff = offset + 2 + componentIndex * 8;
      const [band, dlClass, dlAnt, ulClass, ulAnt, ulQam] = r.unpack("<HBBBBB", compOff);
      if (band === 0) break;
      const [dlPattern, dlAntenna] = antennaInfo(dlAnt);
      const [ulPattern, ulAntenna] = antennaInfo(ulAnt);
      entries.push({
        position: componentIndex,
        rat: "LTE",
        band,
        band_label: `B${band}`,
        band_class_label: `B${band}${bandwidthClassLabel(dlClass)}`,
        dl_bw_class_code: dlClass,
        dl_bw_class: bandwidthClassLabel(dlClass),
        dl_bw_code: 0,
        dl_bandwidth: "not stored",
        dl_antenna_index: dlAnt,
        dl_antenna: dlAntenna,
        dl_antenna_pattern: dlPattern,
        ul_present: ulClass !== 0,
        ul_bw_class_code: ulClass,
        ul_bw_class: bandwidthClassLabel(ulClass),
        ul_bw_code: 0,
        ul_bandwidth: "not stored",
        ul_antenna_index: ulAnt,
        ul_antenna: ulAntenna,
        ul_antenna_pattern: ulPattern,
        ul_qam_cap_index: ulQam,
        group_index: null,
        feature_word_3_hex: null,
        feature_word_4_hex: null,
        feature_word_5_hex: null,
        raw_hex: hexSpaced(blob.subarray(compOff, compOff + 8)),
      });
    }
    combinations.push({
      combo_index: comboIndex,
      file_offset: offset,
      file_offset_hex: `0x${offset.toString(16).toUpperCase()}`,
      raw_hex: hexSpaced(raw),
      combo_flags: blob[offset] | (blob[offset + 1] << 8),
      envelope_mask: 0,
      subset_mask: 0,
      num_band_entries: entries.length,
      entries,
      combination: canonicalCombination(entries),
      combination_with_classes: canonicalCombination(entries, { includeClasses: true }),
    });
  }
  return {
    metadata: {
      input_file: record.name,
      table_kind: "lteca",
      descriptor_discovery: "automatic legacy 50-byte LTE array",
      record_size: 50,
      component_size: 8,
    },
    descriptor: {
      file_offset: descriptorOffset,
      file_offset_hex: `0x${descriptorOffset.toString(16).toUpperCase()}`,
      combo_count: count,
      combos_file_offset: recordsOffset,
      combos_file_offset_hex: `0x${recordsOffset.toString(16).toUpperCase()}`,
    },
    combinations,
  };
}

// Approximates the module-record field order and defaults for a plain
// {name, inner_path} record (full records pass their own fields through).
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

// Literal firmware spelling of the file stem.
function recordIdentity(record) {
  if (record.identity !== undefined) return record.identity;
  let stem = String(record.name).replace(/\.[^.]+$/, "");
  if (stem.slice(0, 10).toLowerCase() === "rf_config_") stem = stem.slice(10);
  return stem;
}

// dict.get(key, default) semantics: default applies only when the key is absent.
const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

// Pack every lte_ca combination's band groups as <HBBBBB records, chunk 100
// per 0xB0CD v41 packet. tableResults are [table, result] pairs; packets
// return as [label, Uint8Array] pairs.
export function legacyB0cdPackets(tableResults, packetCombos = 100) {
  const encoded = [];
  for (const [table, result] of tableResults) {
    if (table !== "lte_ca") continue;
    for (const combo of result.combinations) {
      const groups = [];
      for (const entry of combo.entries) {
        const ulBwClassCode = hasOwn(entry, "ul_bw_class_code")
          ? entry.ul_bw_class_code
          : entry.ul_present
            ? 1
            : 0;
        const out = new Uint8Array(7);
        const dv = new DataView(out.buffer);
        dv.setUint16(0, entry.band, true);
        out[2] = entry.dl_bw_class_code;
        out[3] = ulBwClassCode;
        out[4] = entry.dl_antenna_index;
        out[5] = entry.ul_antenna_index;
        out[6] = entry.ul_qam_cap_index || 0;
        groups.push(out);
      }
      if (groups.length) {
        encoded.push(concatBytes([Uint8Array.of(groups.length), ...groups]));
      }
    }
  }
  const packets = [];
  for (let start = 0; start < encoded.length; start += packetCombos) {
    const current = encoded.slice(start, start + packetCombos);
    packets.push(concatBytes([Uint8Array.of(41, current.length), ...current]));
  }
  return packets.map((payload, index) => [`LTE CA packet ${index + 1}/${packets.length}`, payload]);
}

// Feed endc/nr_ca/nrdc tables to the shared b826V22Packets encoder with
// conservative defaults for fields absent from the static records.
export function legacyB826Packets(tableResults) {
  const output = [];
  for (const [table, result] of tableResults) {
    const source = B826_SOURCE[table];
    if (source === undefined) continue;
    const records = [];
    for (const combo of result.combinations) {
      const groups = [];
      for (const entry of combo.entries) {
        groups.push({
          tech: entry.rat === "LTE" ? 1 : 2,
          band: entry.band,
          dl_bw_class: entry.dl_bw_class_code,
          dl_bw_per_cc: entry.dl_bw_code,
          ul_bw_class: hasOwn(entry, "ul_bw_class_code")
            ? entry.ul_bw_class_code
            : entry.ul_present
              ? 1
              : 0,
          ul_bw_per_cc: entry.ul_bw_code,
          dl_max_antennas_index: entry.dl_antenna_index,
          ul_max_antennas_index: entry.ul_antenna_index,
          ul_qam_cap_index: 0,
        });
      }
      const prop = { ul_tx_switch_type: combo.ul_tx_switch_type_raw || 0 };
      records.push([groups, prop]);
    }
    const packets = records.length ? b826V22Packets(records, source) : [];
    packets.forEach((payload, index) => {
      output.push([`${TABLE_DISPLAY[table] ?? table} source=${source} packet ${index + 1}/${packets.length}`, payload]);
    });
  }
  return output;
}

export function parseLegacyModule(record, blob) {
  const image = new Elf32Image(blob);
  const cardName = rfcardNameFromSymbols(image);
  const lteResult = parseLegacyLteArray(record, blob, image);
  let descriptors;
  try {
    descriptors = findDescriptors(blob, image);
  } catch (err) {
    if (err instanceof ParseError) {
      if (cardName === null) throw err;
      descriptors = [];
    } else {
      throw err;
    }
  }
  const labeled = legacyTableLabels(blob, descriptors);
  if (labeled.length === 0 && lteResult === null && cardName === null) {
    throw new ToolError("No LTE/NR RF-combination descriptors were classified");
  }

  const parsed = [];
  const combinations = [];
  const components = [];
  const inferenceNotes = [];

  // findLegacyLteArray already prefers the authoritative generated dynamic
  // symbol and falls back to structural scanning for stripped ELFs.
  if (lteResult !== null) {
    parsed.push(["lte_ca", lteResult]);
  }

  const tableKindMap = {
    lte_ca: "lteca",
    nr_ca: "nrca",
    endc: "endc",
    nrdc: "nrdc",
    nr_unknown: "unknown",
  };
  for (const [table, descriptor, inference] of labeled) {
    const result = parseDescriptor(record.name, blob, descriptor, {
      discovery: "automatic",
      tableKind: tableKindMap[table],
      detectedTableCount: descriptors.length,
      embeddedPath: record.inner_path,
    });
    result.metadata.resolved_table = table;
    result.metadata.classification_inference = inference;
    parsed.push([table, result]);
    if (inference) {
      inferenceNotes.push(
        `${TABLE_DISPLAY[table] ?? table} at ${result.descriptor.file_offset_hex}: ${inference}`,
      );
    }
    for (const combo of result.combinations) {
      combinations.push({
        table,
        table_name: TABLE_DISPLAY[table] ?? table,
        sub_capability: null,
        combo_index: combo.combo_index,
        expression: combo.combination_with_classes,
        component_count: combo.num_band_entries,
        power_class: combo.power_class_raw,
        bcs_num: combo.bcs_num,
        ul_tx_switch_type: combo.ul_tx_switch_type_raw,
        higher_power_limit: combo.higher_power_limit,
        descriptor_offset: result.descriptor.file_offset_hex,
        combo_flags: combo.combo_flags,
        envelope_mask: combo.envelope_mask,
        subset_mask: combo.subset_mask,
        raw_hex: combo.raw_hex,
      });
      for (const entry of combo.entries) {
        components.push({
          table,
          sub_capability: null,
          combo_index: combo.combo_index,
          position: entry.position,
          technology: entry.rat,
          band: entry.band,
          dl_bw_class_code: entry.dl_bw_class_code,
          dl_bw_class: entry.dl_bw_class,
          dl_bw_code: entry.dl_bw_code,
          dl_bandwidth: entry.dl_bandwidth,
          dl_antenna_index: entry.dl_antenna_index,
          dl_antenna: entry.dl_antenna,
          ul_bw_class_code: entry.ul_bw_class_code,
          ul_bw_class: entry.ul_bw_class,
          ul_bw_code: entry.ul_bw_code,
          ul_bandwidth: entry.ul_bandwidth,
          ul_antenna_index: entry.ul_antenna_index,
          ul_antenna: entry.ul_antenna,
          ul_qam_cap_index: null,
          group_index: entry.group_index,
          feature_word_3: entry.feature_word_3_hex,
          feature_word_4: entry.feature_word_4_hex,
          feature_word_5: entry.feature_word_5_hex,
          raw_hex: entry.raw_hex,
        });
      }
    }
  }

  // Normalize the separately stored legacy LTE table into the common
  // combination/component exports after the shared descriptor loop.
  if (lteResult !== null) {
    for (const combo of lteResult.combinations) {
      combinations.push({
        table: "lte_ca",
        table_name: TABLE_DISPLAY.lte_ca,
        sub_capability: null,
        combo_index: combo.combo_index,
        expression: combo.combination_with_classes,
        component_count: combo.num_band_entries,
        power_class: null,
        bcs_num: null,
        ul_tx_switch_type: null,
        higher_power_limit: null,
        descriptor_offset: lteResult.descriptor.file_offset_hex,
        combo_flags: combo.combo_flags,
        envelope_mask: null,
        subset_mask: null,
        raw_hex: combo.raw_hex,
      });
      for (const entry of combo.entries) {
        components.push({
          table: "lte_ca",
          sub_capability: null,
          combo_index: combo.combo_index,
          position: entry.position,
          technology: "LTE",
          band: entry.band,
          dl_bw_class_code: entry.dl_bw_class_code,
          dl_bw_class: entry.dl_bw_class,
          dl_bw_code: null,
          dl_bandwidth: "not stored",
          dl_antenna_index: entry.dl_antenna_index,
          dl_antenna: entry.dl_antenna,
          ul_bw_class_code: entry.ul_bw_class_code,
          ul_bw_class: entry.ul_bw_class,
          ul_bw_code: null,
          ul_bandwidth: "not stored",
          ul_antenna_index: entry.ul_antenna_index,
          ul_antenna: entry.ul_antenna,
          ul_qam_cap_index: entry.ul_qam_cap_index,
          group_index: null,
          feature_word_3: null,
          feature_word_4: null,
          feature_word_5: null,
          raw_hex: entry.raw_hex,
        });
      }
    }
  }

  return {
    metadata: {
      tool: "Qualcomm RF Combination Extractor",
      version: VERSION,
      generation: record.generation ?? null,
      module: moduleFields(record),
      module_sha256: record.sha256 || sha256Hex(blob),
      rfcard: {
        name: cardName,
        name_source: cardName !== null ? "ELF dynamic symbol" : null,
        canonical_xml_variant_name: null,
        canonical_xml_variant_name_embedded: false,
        hwid: record.hwid ?? null,
        fsid: record.fsid ?? null,
        bid: record.bid ?? null,
        key: recordIdentity(record),
        res_dat_path: null,
        environment_name_high: null,
        environment_name_low: null,
      },
      descriptor_count: descriptors.length,
      classification_notes: inferenceNotes,
      diag_note:
        "Headerless synthetic DIAG payloads reconstructed from legacy RF tables. Fields absent from the static record use conservative defaults.",
    },
    legacy_tables: parsed.map(([, result]) => result),
    combinations,
    components,
    diag: {
      b0cd: legacyB0cdPackets(parsed),
      b826: legacyB826Packets(parsed),
    },
  };
}
