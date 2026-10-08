// CRC32 (zlib-compatible) + SHA-384 for the MTK parsers: Android sparse images
// verify CRC32 exactly like zlib.crc32, and the tensor split-CDF
// header verifies 640 SHA-384 slot digests. SHA-384 is async, mirroring the
// sha256HexAsync convention in hash.js (native crypto.subtle first, pure-JS
// FIPS 180-4 fallback for insecure contexts).
import { hex } from "./bytes.js";

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

// zlib.crc32 parity: reflected poly 0xedb88320, unsigned result, running crc.
export function crc32(data, crc = 0) {
  let c = (~crc) >>> 0;
  for (let i = 0; i < data.length; i++) c = CRC_TABLE[(c ^ data[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// SHA-384 IV/round constants are floor(frac(root(prime_i)) * 2^64) — square
// roots for the IV, cube roots for K. Generated with exact BigInt integer
// roots rather than hand-typed, so a wrong constant cannot ship.
const MASK64 = (1n << 64n) - 1n;
const firstPrimes = (n) => {
  const out = [];
  for (let c = 2; out.length < n; c++) {
    let prime = true;
    for (const p of out) { if (p * p > c) break; if (c % p === 0) { prime = false; break; } }
    if (prime) out.push(c);
  }
  return out;
};
const isqrt = (n) => {
  let x = 1n << (BigInt(n.toString(2).length) / 2n + 1n);
  for (;;) { const nx = (x + n / x) >> 1n; if (nx >= x) return x; x = nx; }
};
const icbrt = (n) => {
  let x = 1n << (BigInt(n.toString(2).length) / 3n + 2n);
  for (;;) { const nx = (2n * x + n / (x * x)) / 3n; if (nx >= x) return x; x = nx; }
};
// floor(root * 2^64) mod 2^64 isolates the fractional part for any prime
// (cube roots of primes >= 8 and square roots of primes >= 4 have integer
// parts above 1, so a plain subtraction of 2^64 would be wrong).
const H384_IV = firstPrimes(16).slice(8).map((p) => isqrt(BigInt(p) << 128n) & MASK64);
const K512 = firstPrimes(80).map((p) => icbrt(BigInt(p) << 192n) & MASK64);


const rotr = (x, n) => ((x >> BigInt(n)) | (x << (64n - BigInt(n)))) & MASK64;

export function sha384HexSync(data) {
  const len = data.length;
  const padded = ((len + 17 + 127) >> 7) << 7;
  const m = new Uint8Array(padded);
  m.set(data);
  m[len] = 0x80;
  const dv = new DataView(m.buffer);
  // 128-bit big-endian bit length; len < 2^53 so len*8 < 2^56 fits the low 64.
  dv.setUint32(padded - 8, Math.floor((len * 8) / 0x100000000));
  dv.setUint32(padded - 4, (len * 8) % 0x100000000);
  const h = H384_IV.slice();
  const w = new Array(80);
  for (let off = 0; off < padded; off += 128) {
    for (let i = 0; i < 16; i++) w[i] = (BigInt(dv.getUint32(off + i * 8)) << 32n) | BigInt(dv.getUint32(off + i * 8 + 4));
    for (let i = 16; i < 80; i++) {
      const s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7n);
      const s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6n);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK64;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 80; i++) {
      const S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K512[i] + w[i]) & MASK64;
      const S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) & MASK64;
      hh = g; g = f; f = e; e = (d + t1) & MASK64; d = c; c = b; b = a; a = (t1 + t2) & MASK64;
    }
    const t = [a, b, c, d, e, f, g, hh];
    for (let i = 0; i < 8; i++) h[i] = (h[i] + t[i]) & MASK64;
  }
  const out = new Uint8Array(48);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 6; i++) {
    odv.setUint32(i * 8, Number(h[i] >> 32n));
    odv.setUint32(i * 8 + 4, Number(h[i] & 0xffffffffn));
  }
  return hex(out);
}

// Native-first like sha256HexAsync; WebCrypto accepts BufferSource, so a
// subarray view hashes exactly the viewed bytes. sha384HexSync (the pure-JS
// fallback) is exported for tests and insecure contexts.
export async function sha384HexAsync(data) {
  if (globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest("SHA-384", data);
    return hex(new Uint8Array(digest));
  }
  return sha384HexSync(data);
}
