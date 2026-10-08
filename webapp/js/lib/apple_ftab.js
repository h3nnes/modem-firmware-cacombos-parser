// FTAB / bbfw CR-bank container support (no decompression here — see lzfse.js).
// FTAB layout: magic "rkosftab" at +0x20; entry table at +0x30; entries are
// 16 bytes: 4-char tag, u32 offset LE, u32 size, u32 reserved.
// A CR entry's 12-byte envelope at <offset>: [u32 profile_id][u32 uncomp_size]
// [u32 comp_size]; the compressed stream is data[offset+12 .. +comp_size] and
// must start with the bvx2 magic (checked by the analyzer, not here, so a bad
// envelope can surface a scan warning instead of vanishing).
// Walk rules: non-CR tags are ignored, reserved != 0 stops the walk, and
// CR entries with size - 12 != comp are skipped rather than fatal.
import { zipEntries, zipEntryData } from "./extractor.js";

export const FTAB_MAGIC_OFFSET = 0x20;
const FTAB_TABLE_OFF = 0x30;
const ENTRY_STRIDE = 16;
const ENVELOPE_SIZE = 12;
const FTAB_MAGIC = "rkosftab";

// 64 KiB header window (the entry table lives in it).
const FTAB_SNIFF_WINDOW = 65536;

export function isFtab(data /* Uint8Array */) {
  if (!data || data.length < FTAB_MAGIC_OFFSET + 8) return false;
  for (let i = 0; i < 8; i++) {
    if (data[FTAB_MAGIC_OFFSET + i] !== FTAB_MAGIC.charCodeAt(i)) return false;
  }
  return true;
}

// True when at least one CR-tagged entry exists in the entry table; the
// walk stays inside the sniffed header window.
function ftabHasCrEntries(data) {
  const limit = Math.min(data.length, FTAB_SNIFF_WINDOW);
  let off = FTAB_TABLE_OFF;
  while (off + ENTRY_STRIDE <= limit) {
    if (data[off] === 67 && data[off + 1] === 82) return true; // "CR"
    off += ENTRY_STRIDE;
  }
  return false;
}

// Bank descriptor: { name: "CR04", tag: "CR04", profileId, offset, compSize,
//                    uncompSize, streamStart }  (streamStart = offset + 12)
export function parseFtabEntries(data) {
  if (!isFtab(data)) {
    throw new Error(`apple ftab: expected FTAB magic '${FTAB_MAGIC}' at +0x20`);
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const entries = [];
  let off = FTAB_TABLE_OFF;
  while (off + ENTRY_STRIDE <= data.length) {
    let printable = true;
    for (let i = 0; i < 4; i++) {
      const c = data[off + i];
      if (c < 32 || c >= 127) {
        printable = false;
        break;
      }
    }
    if (!printable) break; // non-ASCII tag ends the walk
    const tag = String.fromCharCode(data[off], data[off + 1], data[off + 2], data[off + 3]);
    const eoff = dv.getUint32(off + 4, true);
    const size = dv.getUint32(off + 8, true);
    const res = dv.getUint32(off + 12, true);
    if (res !== 0 || eoff > data.length || eoff + size > data.length) break;
    if (tag.startsWith("CR")) {
      // Malformed CR entries are skipped, not fatal.
      if (eoff + ENVELOPE_SIZE > data.length) {
        off += ENTRY_STRIDE;
        continue;
      }
      const profileId = dv.getUint32(eoff, true);
      const uncompSize = dv.getUint32(eoff + 4, true);
      const compSize = dv.getUint32(eoff + 8, true);
      if (size - ENVELOPE_SIZE !== compSize) {
        off += ENTRY_STRIDE;
        continue;
      }
      entries.push({
        name: tag,
        tag,
        profileId,
        offset: eoff,
        compSize,
        uncompSize,
        streamStart: eoff + ENVELOPE_SIZE,
      });
    }
    off += ENTRY_STRIDE;
  }
  // Extracted banks are sorted by name (case-insensitive).
  return entries.sort((a, b) => {
    const an = a.name.toLowerCase();
    const bn = b.name.toLowerCase();
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
}

// Accepts in-memory bytes or any { size, read(offset, length) } source (VFile
// regions / SlicedSource semantics: only the central directory and the chosen
// member are read, never the whole archive).
async function asZipSource(bytesOrSource, readFn) {
  if (bytesOrSource instanceof Uint8Array) {
    return { size: bytesOrSource.length, read: (o, l) => bytesOrSource.subarray(o, o + l) };
  }
  if (typeof readFn === "function" && typeof bytesOrSource?.size === "number") {
    return { size: bytesOrSource.size, read: (o, l) => readFn(o, l) };
  }
  if (typeof bytesOrSource?.read === "function" && typeof bytesOrSource?.size === "number") {
    return bytesOrSource;
  }
  throw new Error("apple ftab: bbfw input must be bytes or a sized random-access source");
}

// bbfw: zip container whose members include one named *ftab* member
// (case-insensitive substring). Discovery order: nested .bbfw members first
// (either a raw FTAB at +0x20 or a nested zip holding an ftab member), then
// direct ftab members with a c40/cellular/centauri priority sort. Returns
// { data, memberName, descriptors }
// where data is the inflated ftab member bytes (descriptors index into them)
// and memberName is the zip member the ftab came from; Error if absent.
export async function findFtabMemberInBbfw(bytesOrVFile, readFn = null) {
  const source = await asZipSource(bytesOrVFile, readFn);
  const entries = await zipEntries(source);

  // 1. Nested .bbfw members (Qualcomm/standard IPSW shape).
  const bbfwMembers = entries.filter((e) => e.name.toLowerCase().endsWith(".bbfw"));
  for (const entry of bbfwMembers) {
    let nested;
    try {
      nested = await zipEntryData(source, entry);
    } catch {
      continue; // unreadable member: try the next one
    }
    if (nested.length >= 0x28 && isFtab(nested)) {
      return { data: nested, memberName: entry.name, descriptors: parseFtabEntries(nested) };
    }
    if (nested.length >= 4 && nested[0] === 0x50 && nested[1] === 0x4b && nested[2] === 0x03 && nested[3] === 0x04) {
      try {
        const found = await findFtabMemberInBbfw(nested);
        return { ...found, memberName: `${entry.name}!${found.memberName}` };
      } catch {
        // no ftab in this nested archive: keep looking
      }
    }
  }

  // 2. Direct ftab members; cellular/c40xx/centauri names are prioritized.
  const ftabMembers = entries.filter((e) => e.name.toLowerCase().includes("ftab"));
  const priority = (name) => {
    const lower = name.toLowerCase();
    return ["c40", "cellular", "centauri"].some((k) => lower.includes(k)) ? 0 : 1;
  };
  ftabMembers.sort((a, b) => priority(a.name) - priority(b.name));
  for (const entry of ftabMembers) {
    let data;
    try {
      data = await zipEntryData(source, entry);
    } catch {
      continue;
    }
    if (isFtab(data) && ftabHasCrEntries(data)) {
      return { data, memberName: entry.name, descriptors: parseFtabEntries(data) };
    }
  }

  throw new Error("apple ftab: no valid cellular modem FTAB or CR banks found inside archive");
}

// parseFtabEntries output for the ftab member; Error if absent.
export async function findFtabInBbfw(bytesOrVFile, readFn = null) {
  return (await findFtabMemberInBbfw(bytesOrVFile, readFn)).descriptors;
}

// Worker card-open helper: resolve a record's apple.member name ("outer!inner"
// for nested bbfw zips) against the real source, descending zip scope by zip
// scope. The member list is RE-READ per scope: after descending into an inner
// zip, the outer zip's entries no longer apply.
export async function extractFtabMember(source, memberName) {
  const names = memberName.split("!");
  let data = null;
  let scope = source;
  for (const name of names) {
    const entries = await zipEntries(scope);
    const entry = entries.find((e) => e.name === name);
    if (!entry) throw new Error(`apple ftab member not found in source: ${name}`);
    data = await zipEntryData(scope, entry);
    // if the extracted member is itself a zip, descend (nested bbfw)
    if (data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b && data[2] === 0x03 && data[3] === 0x04) {
      scope = {
        size: data.length,
        read: (o, l) => data.subarray(o, o + l),
      };
    } else {
      scope = null;
    }
  }
  return data;
}

// Source-based FTAB entry walk for the fast scan path: reads only the 64 KiB
// header window (the entry table lives in it)
// plus one 12-byte envelope per CR entry — the compressed streams are read
// separately by the caller, per descriptor. Same walk rules as
// parseFtabEntries (non-ASCII tag or reserved != 0 ends the walk; CR entries
// with size - 12 != comp are skipped).
export async function parseFtabEntriesFromSource(source) {
  const window = await source.read(0, Math.min(FTAB_SNIFF_WINDOW, source.size));
  if (!isFtab(window)) {
    throw new Error(`apple ftab: expected FTAB magic '${FTAB_MAGIC}' at +0x20`);
  }
  const dv = new DataView(window.buffer, window.byteOffset, window.byteLength);
  const entries = [];
  let off = FTAB_TABLE_OFF;
  while (off + ENTRY_STRIDE <= window.length) {
    let printable = true;
    for (let i = 0; i < 4; i++) {
      const c = window[off + i];
      if (c < 32 || c >= 127) {
        printable = false;
        break;
      }
    }
    if (!printable) break;
    const tag = String.fromCharCode(window[off], window[off + 1], window[off + 2], window[off + 3]);
    const eoff = dv.getUint32(off + 4, true);
    const size = dv.getUint32(off + 8, true);
    const res = dv.getUint32(off + 12, true);
    if (res !== 0 || eoff > source.size || eoff + size > source.size) break;
    if (tag.startsWith("CR")) {
      if (eoff + ENVELOPE_SIZE > source.size) {
        off += ENTRY_STRIDE;
        continue;
      }
      const env = await source.read(eoff, ENVELOPE_SIZE);
      const edv = new DataView(env.buffer, env.byteOffset, env.byteLength);
      const profileId = edv.getUint32(0, true);
      const uncompSize = edv.getUint32(4, true);
      const compSize = edv.getUint32(8, true);
      if (size - ENVELOPE_SIZE !== compSize) {
        off += ENTRY_STRIDE;
        continue;
      }
      entries.push({
        name: tag,
        tag,
        profileId,
        offset: eoff,
        compSize,
        uncompSize,
        streamStart: eoff + ENVELOPE_SIZE,
      });
    }
    off += ENTRY_STRIDE;
  }
  return entries.sort((a, b) => {
    const an = a.name.toLowerCase();
    const bn = b.name.toLowerCase();
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
}
