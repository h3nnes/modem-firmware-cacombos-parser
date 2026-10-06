// Minimal struct-style reader. Sizes: B=1 H=2 I=4 (all LE; nothing bigger exists in the port).
// Supports Python repeat counts: "<12H" == twelve H fields.
const SIZES = { B: 1, H: 2, I: 4 };

function expandFmt(fmt) {
  // "<5H>2I" -> "HHHHHII"
  return fmt.replace(/[<>]/g, "").replace(/(\d+)([BHI])/g, (_, n, c) => c.repeat(+n));
}

export class StructReader {
  constructor(buffer, byteOffset = 0, byteLength) {
    if (!(buffer instanceof ArrayBuffer) && buffer.buffer) {
      // Accept TypedArray/DataView views (e.g. Uint8Array slices from source.read()).
      byteLength = byteLength ?? buffer.byteLength;
      byteOffset = (byteOffset || 0) + buffer.byteOffset;
      buffer = buffer.buffer;
    }
    this.dv = new DataView(buffer, byteOffset, byteLength ?? buffer.byteLength);
  }
  u8(o) { this._chk(o, 1); return this.dv.getUint8(o); }
  u16(o) { this._chk(o, 2); return this.dv.getUint16(o, true); }
  u32(o) { this._chk(o, 4); return this.dv.getUint32(o, true); }
  i16(o) { this._chk(o, 2); return this.dv.getInt16(o, true); }
  i32(o) { this._chk(o, 4); return this.dv.getInt32(o, true); }
  _chk(o, n) { if (o + n > this.dv.byteLength) throw new RangeError(`short read at ${o}+${n}/${this.dv.byteLength}`); }
  unpack(fmt, o) {
    const out = []; let off = o;
    for (const ch of expandFmt(fmt)) {
      const n = SIZES[ch];
      if (!n) throw new Error(`unsupported fmt char ${ch}`);
      out.push(ch === "B" ? this.u8(off) : ch === "H" ? this.u16(off) : this.u32(off));
      off += n;
    }
    return out;
  }
  sizeOf(fmt) {
    let total = 0;
    for (const ch of expandFmt(fmt)) {
      const n = SIZES[ch];
      if (!n) throw new Error(`unsupported fmt char ${ch}`);
      total += n;
    }
    return total;
  }
}

const HEX = "0123456789abcdef";
export function hex(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += HEX[u8[i] >> 4] + HEX[u8[i] & 15];
  return s;
}
export function hexToBytes(s) { if (s.length % 2 !== 0) throw new RangeError(`odd hex length ${s.length}`); const a = new Uint8Array(s.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16); return a; }

export function indexOfBytes(hay, needle, from = 0) {
  // needle: array/Uint8Array of bytes; needles here are ≤ 8 bytes. The
  // first-byte scan runs through TypedArray#indexOf (native, C speed) and
  // only the ≤7-byte tails are verified in JS — identical results to a naive
  // double loop, orders of magnitude faster on multi-MB haystacks.
  if (from < 0) from = 0;
  const n = needle.length;
  if (n === 0) return from <= hay.length ? from : -1;
  const limit = hay.length - n;
  const first = needle[0];
  for (let i = from; i <= limit; ) {
    const j = hay.indexOf(first, i);
    if (j < 0 || j > limit) return -1;
    let k = 1;
    while (k < n && hay[j + k] === needle[k]) k++;
    if (k === n) return j;
    i = j + 1;
  }
  return -1;
}

export function utf8(u8, start, end) {
  // ignoreBOM: true means "keep a leading U+FEFF", matching Python's
  // .decode("utf-8", "replace") which never strips it (default TextDecoder
  // would swallow the EF BB BF prefix).
  return new TextDecoder("utf-8", { ignoreBOM: true }).decode(u8.subarray(start, end)); // replacement semantics match errors="replace"
}
