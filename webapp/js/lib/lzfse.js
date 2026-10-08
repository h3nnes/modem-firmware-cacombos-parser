// Decode-only JS implementation of Apple's LZFSE reference decoder (BSD-3):
// src/lzfse_decode.c, lzfse_decode_base.c, lzfse_fse.c/.h, lzfse_internal.h and
// lzvn_decode_base.c — https://github.com/lzfse/lzfse
//
// Copyright (c) 2015-2016, Apple Inc. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder(s) nor the names of any
//    contributors may be used to endorse or promote products derived from this
//    software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Port notes (representational only, never semantic):
// - C pointers become integer offsets into a source Uint8Array (fixed) and a
//   destination Uint8Array (growable). JS doubles are exact only up to 2**53,
//   so the 64-bit FSE input accumulator (fse_in_stream64) is kept as a hi/lo
//   pair of 32-bit halves with the same accum_nbits invariants.
// - lzfse_decode_buffer's fixed dst_size contract cannot exist in JS, so
//   LZFSE_STATUS_DST_FULL grows the destination and resumes decoding from the
//   saved mid-block state (exactly the resume path the C decoder already
//   implements for short dst buffers). Growth policy: first capacity is the
//   caller's uncompSize hint when provided (else 64 KiB); on every DST_FULL
//   the capacity doubles (never below the current position), capped at 2 GiB
//   like the webapp's other extraction paths.
// - LZ match copies: C's ascending 8-byte-chunk loop (D >= 8 || D >= M)
//   produces the byte-ascending splat result; the port uses a whole-range
//   set() when D >= M (no overlap => memmove == direct copy) and D-sized
//   blocked set() calls otherwise (each block internally non-overlapping,
//   ascending) — byte-for-byte identical to the C result.
// - fse_decode/fse_value_decode report the next state through a module-level
//   "register" (fseDecState) to preserve the C function shape without
//   per-call allocations; C inlines them into the same loops.

const LZFSE_STATUS_OK = 0;
const LZFSE_STATUS_SRC_EMPTY = -1;
const LZFSE_STATUS_DST_FULL = -2;
const LZFSE_STATUS_ERROR = -3;

const LZFSE_ENDOFSTREAM_BLOCK_MAGIC = 0x24787662; // bvx$ (end of stream)
const LZFSE_UNCOMPRESSED_BLOCK_MAGIC = 0x2d787662; // bvx- (raw data)
const LZFSE_COMPRESSEDV1_BLOCK_MAGIC = 0x31787662; // bvx1 (compressed, uncompressed tables)
const LZFSE_COMPRESSEDV2_BLOCK_MAGIC = 0x32787662; // bvx2 (compressed, compressed tables)
const LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC = 0x6e787662; // bvxn (lzvn compressed)

const LZFSE_ENCODE_L_SYMBOLS = 20;
const LZFSE_ENCODE_M_SYMBOLS = 20;
const LZFSE_ENCODE_D_SYMBOLS = 64;
const LZFSE_ENCODE_LITERAL_SYMBOLS = 256;
const LZFSE_ENCODE_L_STATES = 64;
const LZFSE_ENCODE_M_STATES = 64;
const LZFSE_ENCODE_D_STATES = 256;
const LZFSE_ENCODE_LITERAL_STATES = 1024;
const LZFSE_MATCHES_PER_BLOCK = 10000;
const LZFSE_LITERALS_PER_BLOCK = 4 * LZFSE_MATCHES_PER_BLOCK;

const l_extra_bits = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8];
const l_base_value = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60];
const m_extra_bits = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11];
const m_base_value = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312];
const d_extra_bits = [
  0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
  4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
  8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11,
  12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
];
const d_base_value = [
  0, 1, 2, 3, 4, 6, 8, 10, 12, 16,
  20, 24, 28, 36, 44, 52, 60, 76, 92, 108,
  124, 156, 188, 220, 252, 316, 380, 444, 508, 636,
  764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580,
  4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476,
  24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684,
  131068, 163836, 196604, 229372,
];

// sizeof(lzfse_compressed_block_header_v1) in the stream for bvx1 blocks
// (natural alignment: 7*u32, i32, u16[4], i32, 3*u16, then the 4 freq tables).
const LZFSE_V1_HEADER_SIZE = 772;
// offsetof(lzfse_compressed_block_header_v2, freq): u32 magic + u32 n_raw_bytes
// + 3 * u64 packed_fields.
const LZFSE_V2_FIXED_SIZE = 32;

// C failure paths return LZFSE_STATUS_ERROR with a reason; the JS API throws.
function fail(reason) {
  throw new Error(`lzfse: ${reason}`);
}

// MARK: - FSE input stream (fse_in_* 64-bit variants; FSE_IOSTREAM_64 == 1)

// accum is kept as {hi, lo, nbits}: value = hi * 2**32 + lo, and the C
// invariant value >> accum_nbits === 0 holds after every operation.
function fseInInit(s, n, pbuf, bufStart, dv) {
  if (n) {
    if (pbuf.i < bufStart + 8) return -1; // out of range
    pbuf.i -= 8;
    s.lo = dv.getUint32(pbuf.i, true);
    s.hi = dv.getUint32(pbuf.i + 4, true);
    s.nbits = n + 64;
  } else {
    if (pbuf.i < bufStart + 7) return -1; // out of range
    pbuf.i -= 7;
    s.lo = dv.getUint32(pbuf.i, true);
    s.hi = dv.getUint32(pbuf.i + 4, true) & 0x00ffffff; // 7 bytes only
    s.nbits = n + 56;
  }
  // if ((s->accum_nbits < 56 || s->accum_nbits >= 64) || ((s->accum >> s->accum_nbits) != 0))
  let topClear;
  if (s.nbits >= 64) topClear = false;
  else if (s.nbits >= 32) topClear = (s.hi >>> (s.nbits - 32)) === 0;
  else topClear = s.hi === 0 && (s.lo >>> s.nbits) === 0;
  if (s.nbits < 56 || s.nbits >= 64 || !topClear) {
    return -1; // the incoming input is wrong (encoder should have zeroed the upper bits)
  }
  return 0; // OK
}

function fseInFlush(s, pbuf, bufStart, dv) {
  // Get number of bits to add to bring us into the desired range.
  const nbits = (63 - s.nbits) & -8;
  if (nbits === 0) return 0;
  // Convert bits to bytes and decrement buffer address, then load new data.
  const buf = pbuf.i - (nbits >> 3);
  if (buf < bufStart) return -1; // out of range
  pbuf.i = buf;
  // incoming = load8(buf) & fse_mask_lsb64(_, nbits)
  let inLo = dv.getUint32(buf, true);
  let inHi = 0;
  if (nbits > 32) {
    inHi = dv.getUint32(buf + 4, true) & ((1 << (nbits - 32)) - 1);
  } else if (nbits === 32) {
    // full 32 bits kept (JS shift counts are mod 32, so (1 << 32) - 1 == 0)
  } else {
    inLo &= (1 << nbits) - 1;
  }
  // s->accum = (s->accum << nbits) | incoming
  let shiftedLo;
  let shiftedHi;
  if (nbits < 32) {
    shiftedLo = (s.lo << nbits) >>> 0;
    shiftedHi = ((s.hi << nbits) | (s.lo >>> (32 - nbits))) >>> 0;
  } else if (nbits === 32) {
    shiftedLo = 0;
    shiftedHi = s.lo >>> 0;
  } else {
    // nbits in (32, 56]: old hi shifts out entirely; old lo lands in the high
    // half (bits [nbits, 64) of the shifted value), low half comes from incoming.
    shiftedLo = 0;
    shiftedHi = (s.lo << (nbits - 32)) >>> 0;
  }
  s.lo = (shiftedLo | inLo) >>> 0;
  s.hi = (shiftedHi | inHi) >>> 0;
  s.nbits += nbits;
  return 0; // OK
}

// Pull n bits out of the fse stream object. (C asserts n >= 0 && n <= accum_nbits.)
function fseInPull(s, n) {
  s.nbits -= n;
  const nb = s.nbits;
  // uint64_t result = s->accum >> s->accum_nbits;
  let result;
  if (nb >= 32) result = s.hi >>> (nb - 32);
  else if (nb === 0) result = s.lo; // invariant: value < 2**n <= 2**32 here
  else result = ((s.hi << (32 - nb)) | (s.lo >>> nb)) >>> 0;
  // s->accum = fse_mask_lsb64(s->accum, s->accum_nbits);
  if (nb === 0) {
    s.lo = 0;
    s.hi = 0;
  } else if (nb < 32) {
    s.lo = (s.lo & ((1 << nb) - 1)) >>> 0;
    s.hi = 0;
  } else {
    s.hi = (s.hi & ((1 << (nb - 32)) - 1)) >>> 0;
  }
  return result >>> 0;
}

// MARK: - FSE table construction (lzfse_fse.c)

function fseCheckFreq(freqTable, tableSize, numberOfStates) {
  let sumOfFreq = 0;
  for (let i = 0; i < tableSize; i++) sumOfFreq += freqTable[i];
  return sumOfFreq > numberOfStates ? -1 : 0;
}

// fse_init_decoder_table: packs fse_decoder_entry {int8 k; uint8 symbol;
// int16 delta} into int32 t[nstates] exactly like the C struct layout:
// e = (delta << 16) | (symbol << 8) | (k & 0xff).
function fseInitDecoderTable(nstates, nsymbols, freq, t) {
  const nClz = Math.clz32(nstates); // __builtin_clz (nstates is a power of 2)
  let sumOfFreq = 0;
  let ti = 0;
  for (let i = 0; i < nsymbols; i++) {
    const f = freq[i];
    if (f === 0) continue; // skip this symbol, no occurrences
    sumOfFreq += f;
    if (sumOfFreq > nstates) return -1;
    const k = Math.clz32(f) - nClz; // shift needed to ensure N <= (F<<K) < 2*N
    const j0 = ((2 * nstates) >> k) - f;
    // Initialize all states S reached by this symbol: OFFSET <= S < OFFSET + F
    for (let j = 0; j < f; j++) {
      let kk;
      let delta;
      if (j < j0) {
        kk = k;
        delta = ((f + j) << k) - nstates;
      } else {
        kk = k - 1;
        delta = (j - j0) << (k - 1);
      }
      t[ti++] = (delta << 16) | (i << 8) | kk;
    }
  }
  return 0; // OK
}

// fse_init_value_decoder_table into parallel arrays
// (fse_value_decoder_entry {total_bits, value_bits, delta, vbase}).
function fseInitValueDecoderTable(nstates, nsymbols, freq, symbolVbits, symbolVbase, tBits, tVbits, tDelta, tVbase) {
  const nClz = Math.clz32(nstates);
  let ti = 0;
  for (let i = 0; i < nsymbols; i++) {
    const f = freq[i];
    if (f === 0) continue; // skip this symbol, no occurrences
    const k = Math.clz32(f) - nClz; // shift needed to ensure N <= (F<<K) < 2*N
    const j0 = ((2 * nstates) >> k) - f;
    const vbits = symbolVbits[i];
    const vbase = symbolVbase[i];
    // Initialize all states S reached by this symbol: OFFSET <= S < OFFSET + F
    for (let j = 0; j < f; j++) {
      if (j < j0) {
        tBits[ti] = k + vbits;
        tDelta[ti] = ((f + j) << k) - nstates;
      } else {
        tBits[ti] = k - 1 + vbits;
        tDelta[ti] = (j - j0) << (k - 1);
      }
      tVbits[ti] = vbits;
      tVbase[ti] = vbase;
      ti++;
    }
  }
}

// MARK: - fse_decode / fse_value_decode (lzfse_fse.h, inlined by the C build)

let fseDecState = 0;

function fseDecode(pstate, decoderTable, inStream) {
  const e = decoderTable[pstate];
  // Update state from K bits of input + DELTA
  fseDecState = ((e >> 16) + fseInPull(inStream, e & 0xff)) & 0xffff;
  // Return the symbol for this state
  return (e >> 8) & 0xff; // fse_extract_bits(e, 8, 8)
}

function fseValueDecode(pstate, dBits, dVbits, dDelta, dVbase, inStream) {
  const entry = pstate;
  const totalBits = dBits[entry];
  const stateAndValueBits = fseInPull(inStream, totalBits);
  const valueBits = dVbits[entry];
  fseDecState = (dDelta[entry] + (stateAndValueBits >>> valueBits)) & 0xffff;
  return dVbase[entry] + (stateAndValueBits & ((1 << valueBits) - 1));
}

// MARK: - lzfse_decode_base.c

const LZFSE_FREQ_NBITS_TABLE = [
  2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
  2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
];
const LZFSE_FREQ_VALUE_TABLE = [
  0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
  0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1,
];

// lzfse_decode_v1_freq_value; nbitsOut.n receives the number of bits consumed.
function lzfseDecodeV1FreqValue(bits, nbitsOut) {
  const b = bits & 31; // lower 5 bits
  const n = LZFSE_FREQ_NBITS_TABLE[b];
  nbitsOut.n = n;
  // Special cases for > 5 bits encoding
  if (n === 8) return 8 + ((bits >>> 4) & 0xf);
  if (n === 14) return 24 + ((bits >>> 4) & 0x3ff);
  // <= 5 bits encoding from table
  return LZFSE_FREQ_VALUE_TABLE[b];
}

// get_field: extract up to 32 bits from a 64-bit BigInt field (masked in the
// BigInt domain first so the Number conversion stays exact).
function getField(v, offset, nbits) {
  return Number((v >> BigInt(offset)) & ((1n << BigInt(nbits)) - 1n));
}

// lzfse_decode_v2_header_size
function lzfseDecodeV2HeaderSize(dv, srcBase) {
  return getField(dv.getBigUint64(srcBase + 24, true), 0, 32); // packed_fields[2]
}

function newHeader1() {
  // One contiguous u16 run backs l_freq | m_freq | d_freq | literal_freq so
  // the v2 freq decode loop can fill all four tables exactly like the C
  // memcpy-free pointer walk (dst = &out->l_freq[0], dst[i] for 360 values).
  const freqBuf = new Uint16Array(
    LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS + LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS,
  );
  return {
    magic: 0,
    n_raw_bytes: 0,
    n_payload_bytes: 0,
    n_literals: 0,
    n_matches: 0,
    n_literal_payload_bytes: 0,
    n_lmd_payload_bytes: 0,
    literal_bits: 0,
    literal_state: [0, 0, 0, 0],
    lmd_bits: 0,
    l_state: 0,
    m_state: 0,
    d_state: 0,
    l_freq: freqBuf.subarray(0, LZFSE_ENCODE_L_SYMBOLS),
    m_freq: freqBuf.subarray(LZFSE_ENCODE_L_SYMBOLS, LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS),
    d_freq: freqBuf.subarray(
      LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS,
      LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS + LZFSE_ENCODE_D_SYMBOLS,
    ),
    literal_freq: freqBuf.subarray(
      LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS + LZFSE_ENCODE_D_SYMBOLS,
    ),
    flat_freq: freqBuf,
  };
}

// lzfse_decode_v1: decode all fields from a v2 header on the stream into a v1
// header object. Returns 0 on success, -1 on failure.
function lzfseDecodeV1(out, dv, srcBase) {
  // Clear all fields (memset(out, 0x00, ...))
  out.n_raw_bytes = 0;
  out.n_payload_bytes = 0;
  out.n_literals = 0;
  out.n_matches = 0;
  out.n_literal_payload_bytes = 0;
  out.n_lmd_payload_bytes = 0;
  out.literal_bits = 0;
  out.literal_state[0] = 0;
  out.literal_state[1] = 0;
  out.literal_state[2] = 0;
  out.literal_state[3] = 0;
  out.lmd_bits = 0;
  out.l_state = 0;
  out.m_state = 0;
  out.d_state = 0;
  out.flat_freq.fill(0);

  const v0 = dv.getBigUint64(srcBase + 8, true);
  const v1 = dv.getBigUint64(srcBase + 16, true);
  const v2 = dv.getBigUint64(srcBase + 24, true);

  out.magic = LZFSE_COMPRESSEDV1_BLOCK_MAGIC;
  out.n_raw_bytes = dv.getUint32(srcBase + 4, true);

  // Literal state
  out.n_literals = getField(v0, 0, 20);
  out.n_literal_payload_bytes = getField(v0, 20, 20);
  out.literal_bits = getField(v0, 60, 3) - 7;
  out.literal_state[0] = getField(v1, 0, 10);
  out.literal_state[1] = getField(v1, 10, 10);
  out.literal_state[2] = getField(v1, 20, 10);
  out.literal_state[3] = getField(v1, 30, 10);

  // L,M,D state
  out.n_matches = getField(v0, 40, 20);
  out.n_lmd_payload_bytes = getField(v1, 40, 20);
  out.lmd_bits = getField(v1, 60, 3) - 7;
  out.l_state = getField(v2, 32, 10);
  out.m_state = getField(v2, 42, 10);
  out.d_state = getField(v2, 52, 10);

  // Total payload size
  out.n_payload_bytes = out.n_literal_payload_bytes + out.n_lmd_payload_bytes;

  // Freq tables
  const flat = out.flat_freq;
  const srcEnd = srcBase + getField(v2, 0, 32); // first byte after header
  let src = srcBase + LZFSE_V2_FIXED_SIZE; // &(in->freq[0])
  let accum = 0;
  let accumNbits = 0;

  // No freq tables?
  if (srcEnd === src) return 0; // OK, freq tables were omitted

  for (let i = 0; i < LZFSE_ENCODE_L_SYMBOLS + LZFSE_ENCODE_M_SYMBOLS + LZFSE_ENCODE_D_SYMBOLS + LZFSE_ENCODE_LITERAL_SYMBOLS; i++) {
    // Refill accum, one byte at a time, until we reach end of header, or accum is full
    while (src < srcEnd && accumNbits + 8 <= 32) {
      accum |= dv.getUint8(src) << accumNbits;
      accumNbits += 8;
      src++;
    }

    // Decode and store value
    const nbitsOut = { n: 0 };
    flat[i] = lzfseDecodeV1FreqValue(accum, nbitsOut);

    if (nbitsOut.n > accumNbits) return -1; // failed

    // Consume nbits bits
    accum >>>= nbitsOut.n;
    accumNbits -= nbitsOut.n;
  }

  if (accumNbits >= 8 || src !== srcEnd) {
    return -1; // we need to end up exactly at the end of header, with less than 8 bits in accumulator
  }

  return 0;
}

// Read a bvx1 header (uncompressed tables) straight off the stream; the C
// code memcpy()s sizeof(lzfse_compressed_block_header_v1) bytes.
function readV1Header(dv, base) {
  const o = newHeader1();
  o.magic = dv.getUint32(base, true);
  o.n_raw_bytes = dv.getUint32(base + 4, true);
  o.n_payload_bytes = dv.getUint32(base + 8, true);
  o.n_literals = dv.getUint32(base + 12, true);
  o.n_matches = dv.getUint32(base + 16, true);
  o.n_literal_payload_bytes = dv.getUint32(base + 20, true);
  o.n_lmd_payload_bytes = dv.getUint32(base + 24, true);
  o.literal_bits = dv.getInt32(base + 28, true);
  o.literal_state[0] = dv.getUint16(base + 32, true);
  o.literal_state[1] = dv.getUint16(base + 34, true);
  o.literal_state[2] = dv.getUint16(base + 36, true);
  o.literal_state[3] = dv.getUint16(base + 38, true);
  o.lmd_bits = dv.getInt32(base + 40, true);
  o.l_state = dv.getUint16(base + 44, true);
  o.m_state = dv.getUint16(base + 46, true);
  o.d_state = dv.getUint16(base + 48, true);
  for (let i = 0; i < 20; i++) o.l_freq[i] = dv.getUint16(base + 50 + 2 * i, true);
  for (let i = 0; i < 20; i++) o.m_freq[i] = dv.getUint16(base + 90 + 2 * i, true);
  for (let i = 0; i < 64; i++) o.d_freq[i] = dv.getUint16(base + 130 + 2 * i, true);
  for (let i = 0; i < 256; i++) o.literal_freq[i] = dv.getUint16(base + 258 + 2 * i, true);
  return o;
}

// lzfse_check_block_header_v1: 0 if all tests passed, else a bitmask with one
// bit set per failed test (plus the sign bit).
function lzfseCheckBlockHeaderV1(header) {
  let testsResults = 0;
  testsResults |= header.magic === LZFSE_COMPRESSEDV1_BLOCK_MAGIC ? 0 : 1 << 0;
  testsResults |= header.n_literals <= LZFSE_LITERALS_PER_BLOCK ? 0 : 1 << 1;
  testsResults |= header.n_matches <= LZFSE_MATCHES_PER_BLOCK ? 0 : 1 << 2;

  const literalState = header.literal_state;
  testsResults |= literalState[0] < LZFSE_ENCODE_LITERAL_STATES ? 0 : 1 << 3;
  testsResults |= literalState[1] < LZFSE_ENCODE_LITERAL_STATES ? 0 : 1 << 4;
  testsResults |= literalState[2] < LZFSE_ENCODE_LITERAL_STATES ? 0 : 1 << 5;
  testsResults |= literalState[3] < LZFSE_ENCODE_LITERAL_STATES ? 0 : 1 << 6;

  testsResults |= header.l_state < LZFSE_ENCODE_L_STATES ? 0 : 1 << 7;
  testsResults |= header.m_state < LZFSE_ENCODE_M_STATES ? 0 : 1 << 8;
  testsResults |= header.d_state < LZFSE_ENCODE_D_STATES ? 0 : 1 << 9;

  let res = fseCheckFreq(header.l_freq, LZFSE_ENCODE_L_SYMBOLS, LZFSE_ENCODE_L_STATES);
  testsResults |= res === 0 ? 0 : 1 << 10;
  res = fseCheckFreq(header.m_freq, LZFSE_ENCODE_M_SYMBOLS, LZFSE_ENCODE_M_STATES);
  testsResults |= res === 0 ? 0 : 1 << 11;
  res = fseCheckFreq(header.d_freq, LZFSE_ENCODE_D_SYMBOLS, LZFSE_ENCODE_D_STATES);
  testsResults |= res === 0 ? 0 : 1 << 12;
  res = fseCheckFreq(header.literal_freq, LZFSE_ENCODE_LITERAL_SYMBOLS, LZFSE_ENCODE_LITERAL_STATES);
  testsResults |= res === 0 ? 0 : 1 << 13;

  if (testsResults) return testsResults | 0x80000000; // each 1 bit is a test that failed
  return 0; // OK
}

// MARK: - lzfse_decode_lmd (lzfse_decode_base.c:156-330)

// Boxed source offset for the LMD flush calls (C passes &src; JS needs one
// mutable cell — the decoder is single-threaded and non-reentrant).
const lmdFlushSrc = { i: 0 };

function lzfseDecodeLmd(s, dv) {
  const bs = s.compressed_lzfse_block_state;
  let l_state = bs.l_state;
  let m_state = bs.m_state;
  let d_state = bs.d_state;
  const inStream = bs.lmd_in_stream;
  const srcStart = s.src_begin;
  let src = s.src + bs.lmd_in_buf;
  let lit = bs.current_literal;
  let dst = s.dst;
  let symbols = bs.n_matches;
  let L = bs.l_value;
  let M = bs.m_value;
  let D = bs.d_value;
  const literals = bs.literals;
  const lBits = bs.l_bits, lVbits = bs.l_vbits, lDelta = bs.l_delta, lVbase = bs.l_vbase;
  const mBits = bs.m_bits, mVbits = bs.m_vbits, mDelta = bs.m_delta, mVbase = bs.m_vbase;
  const dBits = bs.d_bits, dVbits = bs.d_vbits, dDelta = bs.d_delta, dVbase = bs.d_vbase;
  const dstBuf = s.dst_buf;

  // Number of bytes remaining in the destination buffer, minus 32 to provide
  // a margin of safety for using overlarge copies on the fast path. This is a
  // signed quantity, and may go negative when we are close to the end of the
  // buffer. That's OK; we're careful about how we handle it in the
  // slow-and-careful match execution path.
  let remainingBytes = s.dst_end - dst - 32;

  // If L or M is non-zero, that means that we have already started decoding
  // this block, and that we needed to interrupt decoding to get more space
  // from the caller. There's a pending L, M, D triplet that we weren't able
  // to completely process. Jump ahead to finish executing that symbol before
  // decoding new values. (C: `if (L || M) goto ExecuteMatch;`)
  let executeMatch = L !== 0 || M !== 0;

  while (executeMatch || symbols > 0) {
    if (!executeMatch) {
      // Decode the next L, M, D symbol from the input stream.
      lmdFlushSrc.i = src;
      if (fseInFlush(inStream, lmdFlushSrc, srcStart, dv) !== 0) return LZFSE_STATUS_ERROR;
      src = lmdFlushSrc.i;
      L = fseValueDecode(l_state, lBits, lVbits, lDelta, lVbase, inStream);
      l_state = fseDecState;
      if (lit + L >= LZFSE_LITERALS_PER_BLOCK + 64) return LZFSE_STATUS_ERROR;
      // fse_in_flush2 is a no-op at 64 bits (FSE_IOSTREAM_64).
      M = fseValueDecode(m_state, mBits, mVbits, mDelta, mVbase, inStream);
      m_state = fseDecState;
      // fse_in_flush2: nothing.
      const newD = fseValueDecode(d_state, dBits, dVbits, dDelta, dVbase, inStream);
      d_state = fseDecState;
      D = newD !== 0 ? newD : D;
      symbols--;
    }
    executeMatch = false;

    // ExecuteMatch:
    // Error if D is out of range, so that we avoid passing through
    // uninitialized data or accessing memory out of the destination buffer.
    // (C: (uint32_t)D > dst + L - dst_begin; negative D wraps huge.)
    if (D < 0 || D > dst + L - s.dst_begin) return LZFSE_STATUS_ERROR;

    if (L + M <= remainingBytes) {
      // If we have plenty of space remaining, we can copy the literal and
      // match with 16- and 32-byte operations, without worrying about writing
      // off the end of the buffer.
      remainingBytes -= L + M;
      if (L > 0) {
        dstBuf.set(literals.subarray(lit, lit + L), dst);
        dst += L;
        lit += L;
      }
      // For the match, we have two paths; a fast copy by 16-bytes if the
      // match distance is large enough to allow it, and a more careful path
      // that applies a permutation to account for the possible overlap
      // between source and destination if the distance is small.
      if (M > 0) {
        if (D >= M) {
          // D >= M: source and target ranges cannot overlap; identical bytes
          // to C's ascending 8-byte-chunk copy.
          dstBuf.set(dstBuf.subarray(dst - D, dst - D + M), dst);
        } else {
          // D < M: overlapping splat. C's ascending chunked copy equals this
          // ascending D-sized blocked copy (each block reads only bytes the
          // previous blocks already wrote).
          for (let i = 0; i < M; i += D) {
            const n = Math.min(D, M - i);
            dstBuf.set(dstBuf.subarray(dst + i - D, dst + i - D + n), dst + i);
          }
        }
        dst += M;
      }
    } else {
      // Otherwise, we are very close to the end of the destination buffer, so
      // we cannot use wide copies that slop off the end of the region that we
      // are copying to. First, we restore the true length remaining, rather
      // than the sham value we've been using so far.
      remainingBytes += 32;
      // Now, we process the literal. Either there's space for it or there
      // isn't; if there is, we copy the whole thing and update all the
      // pointers and lengths to reflect the copy.
      if (L <= remainingBytes) {
        for (let i = 0; i < L; i++) dstBuf[dst + i] = literals[lit + i];
        dst += L;
        lit += L;
        remainingBytes -= L;
        L = 0;
      } else {
        // There isn't enough space to fit the whole literal. Copy as much of
        // it as we can, update the pointers and the value of L, and report
        // that the destination buffer is full. Note that we always write
        // right up to the end of the destination buffer.
        for (let i = 0; i < remainingBytes; i++) dstBuf[dst + i] = literals[lit + i];
        dst += remainingBytes;
        lit += remainingBytes;
        L -= remainingBytes;
        // DestinationBufferIsFull:
        bs.l_value = L;
        bs.m_value = M;
        bs.d_value = D;
        bs.l_state = l_state;
        bs.m_state = m_state;
        bs.d_state = d_state;
        bs.lmd_in_stream = inStream;
        bs.n_matches = symbols;
        bs.lmd_in_buf = src - s.src;
        bs.current_literal = lit;
        s.dst = dst;
        return LZFSE_STATUS_DST_FULL;
      }
      // The match goes just like the literal does. We copy as much as we can
      // byte-by-byte, and if we reach the end of the buffer before finishing,
      // we return to the caller indicating that the buffer is full.
      if (M <= remainingBytes) {
        for (let i = 0; i < M; i++) dstBuf[dst + i] = dstBuf[dst + i - D];
        dst += M;
        remainingBytes -= M;
        // We don't need to update M = 0, because there's no partial symbol to
        // continue executing. Either we're at the end of the block, in which
        // case we will never need to resume with this state, or we're going to
        // decode another L, M, D set, which will overwrite M anyway. But we
        // still set M = 0, to maintain the post-condition.
        M = 0;
      } else {
        for (let i = 0; i < remainingBytes; i++) dstBuf[dst + i] = dstBuf[dst + i - D];
        dst += remainingBytes;
        M -= remainingBytes;
        // DestinationBufferIsFull:
        bs.l_value = L;
        bs.m_value = M;
        bs.d_value = D;
        bs.l_state = l_state;
        bs.m_state = m_state;
        bs.d_state = d_state;
        bs.lmd_in_stream = inStream;
        bs.n_matches = symbols;
        bs.lmd_in_buf = src - s.src;
        bs.current_literal = lit;
        s.dst = dst;
        return LZFSE_STATUS_DST_FULL;
      }
      // Restore the "sham" decremented value of remaining_bytes and continue
      // to the next L, M, D triple. We'll just be back in the careful path
      // again, but this only happens at the very end of the buffer, so a
      // little minor inefficiency here is a good tradeoff for simpler code.
      remainingBytes -= 32;
    }
  }
  // Because we've finished with the whole block, we don't need to update any
  // of the blockstate fields; they will not be used again. We just update the
  // destination pointer in the state object and return.
  s.dst = dst;
  return LZFSE_STATUS_OK;
}

// MARK: - lzvn_decode (lzvn_decode_base.c)

// Opcode classes derived from the C opc_tbl jump table (256 entries).
function lzvnOpClass(opc) {
  const c = opc & 7;
  if (opc < 112) {
    if (c === 6) {
      if (opc === 6) return "eos";
      if (opc === 14 || opc === 22) return "nop";
      if (opc < 64) return "udef"; // 30, 38, 46, 54, 62
      return "pre_d"; // 70..110 step 8
    }
    if (c === 7) return "lrg_d"; // 7..111 step 8
    return "sml_d";
  }
  if (opc < 128) return "udef"; // 112..127
  if (opc < 160) {
    if (c === 6) return "pre_d"; // 134..158
    if (c === 7) return "lrg_d";
    return "sml_d";
  }
  if (opc < 192) return "med_d"; // 160..191
  if (opc < 208) {
    if (c === 6) return "pre_d"; // 198, 206
    if (c === 7) return "lrg_d"; // 199, 207
    return "sml_d";
  }
  if (opc < 224) return "udef"; // 208..223
  if (opc < 240) return opc === 224 ? "lrg_l" : "sml_l";
  return opc === 240 ? "lrg_m" : "sml_m";
}

// Both the source and destination buffers are represented by an offset and a
// length; they are *always* updated in concert using PTR_LEN_INC; however many
// bytes the pointer is advanced, the length is decremented by the same amount.
function lzvnDecode(state, srcBuf, dstBuf) {
  let srcLen = state.src_end - state.src;
  let dstLen = state.dst_end - state.dst;
  if (srcLen === 0 || dstLen === 0) return; // empty buffer

  let srcPtr = state.src;
  let dstPtr = state.dst;
  let D = state.d_prev;
  let M = 0;
  let L = 0;
  let opcLen = 0;

  // Do we have a partially expanded match saved in state?
  // action mirrors the C gotos: "lm" = copy_literal_and_match,
  // "m" = copy_match, "l" = copy_literal.
  let action = null;
  if (state.L !== 0 || state.M !== 0) {
    L = state.L;
    M = state.M;
    D = state.D;
    opcLen = 0; // we already skipped the op
    state.L = state.M = state.D = 0;
    if (M === 0) action = "l";
    else if (L === 0) action = "m";
    else action = "lm";
  }

  for (;;) {
    if (action === null) {
      const opc = srcBuf[srcPtr];
      switch (lzvnOpClass(opc)) {
        case "sml_d": {
          // "small distance": LLMMMDDD DDDDDDDD LITERAL
          state.src = srcPtr; state.dst = dstPtr; state.d_prev = D; // UPDATE_GOOD
          opcLen = 2;
          L = (opc >>> 6) & 3; // extract(opc, 6, 2)
          M = ((opc >>> 3) & 7) + 3; // extract(opc, 3, 3) + 3
          if (srcLen <= opcLen + L) return; // source truncated
          D = ((opc & 7) << 8) | srcBuf[srcPtr + 1];
          action = "lm";
          break;
        }
        case "med_d": {
          // "medium distance": 101LLMMM DDDDDDMM DDDDDDDD LITERAL
          state.src = srcPtr; state.dst = dstPtr; state.d_prev = D; // UPDATE_GOOD
          opcLen = 3;
          L = (opc >>> 3) & 3; // extract(opc, 3, 2)
          if (srcLen <= opcLen + L) return; // source truncated
          const opc23 = srcBuf[srcPtr + 1] | (srcBuf[srcPtr + 2] << 8); // load2(&src_ptr[1])
          M = (((opc & 7) << 2) | (opc23 & 3)) + 3;
          D = (opc23 >>> 2) & 0x3fff; // extract(opc23, 2, 14)
          action = "lm";
          break;
        }
        case "lrg_d": {
          // "large distance": LLMMM111 DDDDDDDD DDDDDDDD LITERAL
          state.src = srcPtr; state.dst = dstPtr; state.d_prev = D; // UPDATE_GOOD
          opcLen = 3;
          L = (opc >>> 6) & 3;
          M = ((opc >>> 3) & 7) + 3;
          if (srcLen <= opcLen + L) return; // source truncated
          D = srcBuf[srcPtr + 1] | (srcBuf[srcPtr + 2] << 8); // load2(&src_ptr[1])
          action = "lm";
          break;
        }
        case "pre_d": {
          // "previous distance": LLMMM110
          state.src = srcPtr; state.dst = dstPtr; state.d_prev = D; // UPDATE_GOOD
          opcLen = 1;
          L = (opc >>> 6) & 3;
          M = ((opc >>> 3) & 7) + 3;
          if (srcLen <= opcLen + L) return; // source truncated
          action = "lm";
          break;
        }
        case "sml_m": {
          // "small match": 1111MMMM (uses the previous match distance)
          state.src = srcPtr; state.dst = dstPtr; state.d_prev = D; // UPDATE_GOOD
          opcLen = 1;
          if (srcLen <= opcLen) return; // source truncated
          M = opc & 0xf; // extract(opc, 0, 4)
          srcPtr += opcLen; srcLen -= opcLen;
          action = "m";
          break;
        }
        case "lrg_m": {
          // "large match": 11110000 MMMMMMMM (lengths [16, 271])
          state.src = srcPtr; state.dst = dstPtr; state.d_prev = D; // UPDATE_GOOD
          opcLen = 2;
          if (srcLen <= opcLen) return; // source truncated
          M = srcBuf[srcPtr + 1] + 16;
          srcPtr += opcLen; srcLen -= opcLen;
          action = "m";
          break;
        }
        case "sml_l": {
          // "small literal": 1110LLLL LITERAL
          state.src = srcPtr; state.dst = dstPtr; state.d_prev = D; // UPDATE_GOOD
          opcLen = 1;
          L = opc & 0xf; // extract(opc, 0, 4)
          action = "l";
          break;
        }
        case "lrg_l": {
          // "large literal": 11100000 LLLLLLLL LITERAL (lengths [16, 271])
          state.src = srcPtr; state.dst = dstPtr; state.d_prev = D; // UPDATE_GOOD
          opcLen = 2;
          if (srcLen <= 2) return; // source truncated
          L = srcBuf[srcPtr + 1] + 16;
          action = "l";
          break;
        }
        case "nop": {
          // 00001110 / 00010110
          state.src = srcPtr; state.dst = dstPtr; state.d_prev = D; // UPDATE_GOOD
          opcLen = 1;
          if (srcLen <= opcLen) return; // source truncated
          srcPtr += opcLen; srcLen -= opcLen;
          continue; // load next opcode
        }
        case "eos": {
          opcLen = 8;
          if (srcLen < opcLen) return; // source truncated (no next-op byte needed)
          srcPtr += opcLen; srcLen -= opcLen;
          state.end_of_stream = 1;
          state.src = srcPtr; state.dst = dstPtr; state.d_prev = D; // UPDATE_GOOD
          return; // end-of-stream
        }
        default:
          return; // udef / invalid_match_distance: we already updated state
      }
    }

    if (action === "lm") {
      // copy_literal_and_match: advance the source pointer past the opcode,
      // so that it points at the first literal byte (if L is non-zero).
      srcPtr += opcLen; srcLen -= opcLen;
      // Now we copy the literal from the source pointer to the destination.
      if (dstLen >= 4 && srcLen >= 4) {
        // The literal is 0-3 bytes; if we are not near the end of the buffer,
        // we can safely just do a 4 byte copy (which is guaranteed to cover
        // the complete literal, and may include some other bytes as well).
        dstBuf.set(srcBuf.subarray(srcPtr, srcPtr + 4), dstPtr);
      } else if (L <= dstLen) {
        // Too close to the end of either stream for a four-byte copy; a
        // byte-by-byte copy of the literal (only ever near a buffer end).
        for (let i = 0; i < L; ++i) dstBuf[dstPtr + i] = srcBuf[srcPtr + i];
      } else {
        // Destination truncated: fill DST, and store partial match
        for (let i = 0; i < dstLen; ++i) dstBuf[dstPtr + i] = srcBuf[srcPtr + i];
        // Save state
        state.src = srcPtr + dstLen;
        state.dst = dstPtr + dstLen;
        state.L = L - dstLen;
        state.M = M;
        state.D = D;
        return; // destination truncated
      }
      // Having completed the copy of the literal, advance both the source and
      // destination pointers by the number of literal bytes.
      dstPtr += L; dstLen -= L;
      srcPtr += L; srcLen -= L;
      // Check if the match distance is valid; matches must not reference
      // bytes that preceed the start of the output buffer, nor can the match
      // distance be zero.
      if (D > dstPtr - state.dst_begin || D === 0) {
        return; // invalid_match_distance
      }
      action = "m";
    }

    if (action === "m") {
      // copy_match: copy from dst_ptr - D to dst_ptr. Overlapping copies must
      // behave like a byte-by-byte ascending copy (splat), never memmove.
      if (dstLen >= M + 7 && D >= 8) {
        // Not near the end of the buffer, distance >= 8: ascending 8-byte
        // chunk copies (each chunk non-overlapping), exactly C's loop.
        for (let i = 0; i < M; i += 8) {
          dstBuf.set(dstBuf.subarray(dstPtr + i - D, dstPtr + i - D + 8), dstPtr + i);
        }
      } else if (M <= dstLen) {
        // Byte-by-byte implementation.
        for (let i = 0; i < M; ++i) dstBuf[dstPtr + i] = dstBuf[dstPtr + i - D];
      } else {
        // Destination truncated: fill DST, and store partial match
        for (let i = 0; i < dstLen; ++i) dstBuf[dstPtr + i] = dstBuf[dstPtr + i - D];
        // Save state
        state.src = srcPtr;
        state.dst = dstPtr + dstLen;
        state.L = 0;
        state.M = M - dstLen;
        state.D = D;
        return; // destination truncated
      }
      // Update the destination pointer and length, then load the next opcode.
      dstPtr += M; dstLen -= M;
      action = null;
      continue;
    }

    if (action === "l") {
      // copy_literal: check that the source buffer is large enough to hold
      // the complete literal and at least the first byte of the next opcode.
      if (srcLen <= opcLen + L) return; // source truncated
      srcPtr += opcLen; srcLen -= opcLen;
      // Now we copy the literal from the source pointer to the destination.
      if (dstLen >= L + 7 && srcLen >= L + 7) {
        // Not near the end of the source or destination buffers: wide copies
        // are safe (the < 8 byte tail of C's store8 loop writes only slop
        // that later output overwrites before it is ever read).
        for (let i = 0; i < L; i += 8) {
          const n = Math.min(8, L - i);
          dstBuf.set(srcBuf.subarray(srcPtr + i, srcPtr + i + n), dstPtr + i);
        }
      } else if (L <= dstLen) {
        // Byte-by-byte copy.
        for (let i = 0; i < L; ++i) dstBuf[dstPtr + i] = srcBuf[srcPtr + i];
      } else {
        // Destination truncated: fill DST, and store partial match
        for (let i = 0; i < dstLen; ++i) dstBuf[dstPtr + i] = srcBuf[srcPtr + i];
        // Save state
        state.src = srcPtr + dstLen;
        state.dst = dstPtr + dstLen;
        state.L = L - dstLen;
        state.M = 0;
        state.D = D;
        return; // destination truncated
      }
      // Having completed the copy of the literal, advance both the source and
      // destination pointers by the number of literal bytes.
      dstPtr += L; dstLen -= L;
      srcPtr += L; srcLen -= L;
      action = null;
      continue; // load the first byte of the next opcode
    }
  }
}

// MARK: - lzfse_decode (lzfse_decode_base.c:332-630)

function lzfseDecodeState(src, dstBuf) {
  return {
    src: 0,
    src_begin: 0,
    src_end: src.length,
    dst: 0,
    dst_begin: 0,
    dst_end: dstBuf.length,
    dst_buf: dstBuf,
    end_of_stream: 0,
    block_magic: 0, // LZFSE_NO_BLOCK_MAGIC
    compressed_lzfse_block_state: {
      n_matches: 0,
      n_lmd_payload_bytes: 0,
      current_literal: 0,
      l_value: 0, m_value: 0, d_value: 0,
      lmd_in_stream: { hi: 0, lo: 0, nbits: 0 },
      lmd_in_buf: 0,
      l_state: 0, m_state: 0, d_state: 0,
      // fse_value_decoder_entry tables for L, M, D + the literal decoder.
      l_bits: new Uint8Array(LZFSE_ENCODE_L_STATES),
      l_vbits: new Uint8Array(LZFSE_ENCODE_L_STATES),
      l_delta: new Int16Array(LZFSE_ENCODE_L_STATES),
      l_vbase: new Int32Array(LZFSE_ENCODE_L_STATES),
      m_bits: new Uint8Array(LZFSE_ENCODE_M_STATES),
      m_vbits: new Uint8Array(LZFSE_ENCODE_M_STATES),
      m_delta: new Int16Array(LZFSE_ENCODE_M_STATES),
      m_vbase: new Int32Array(LZFSE_ENCODE_M_STATES),
      d_bits: new Uint8Array(LZFSE_ENCODE_D_STATES),
      d_vbits: new Uint8Array(LZFSE_ENCODE_D_STATES),
      d_delta: new Int16Array(LZFSE_ENCODE_D_STATES),
      d_vbase: new Int32Array(LZFSE_ENCODE_D_STATES),
      literal_decoder: new Int32Array(LZFSE_ENCODE_LITERAL_STATES),
      literals: new Uint8Array(LZFSE_LITERALS_PER_BLOCK + 64),
    },
    compressed_lzvn_block_state: { n_raw_bytes: 0, n_payload_bytes: 0, d_prev: 0 },
    uncompressed_block_state: { n_raw_bytes: 0 },
  };
}

function lzfseDecodeBlock(s, dv) {
  for (;;) {
    // Are we inside a block?
    switch (s.block_magic) {
      case 0: { // LZFSE_NO_BLOCK_MAGIC
        // We need at least 4 bytes of magic number to identify next block
        if (s.src + 4 > s.src_end) return LZFSE_STATUS_SRC_EMPTY; // SRC truncated
        const magic = dv.getUint32(s.src, true);

        if (magic === LZFSE_ENDOFSTREAM_BLOCK_MAGIC) {
          s.src += 4;
          s.end_of_stream = 1;
          return LZFSE_STATUS_OK; // done
        }

        if (magic === LZFSE_UNCOMPRESSED_BLOCK_MAGIC) {
          if (s.src + 8 > s.src_end) return LZFSE_STATUS_SRC_EMPTY; // SRC truncated
          // Setup state for uncompressed block
          s.uncompressed_block_state.n_raw_bytes = dv.getUint32(s.src + 4, true);
          s.src += 8;
          s.block_magic = magic;
          break;
        }

        if (magic === LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC) {
          if (s.src + 12 > s.src_end) return LZFSE_STATUS_SRC_EMPTY; // SRC truncated
          // Setup state for compressed LZVN block
          const bs = s.compressed_lzvn_block_state;
          bs.n_raw_bytes = dv.getUint32(s.src + 4, true);
          bs.n_payload_bytes = dv.getUint32(s.src + 8, true);
          bs.d_prev = 0;
          s.src += 12;
          s.block_magic = magic;
          break;
        }

        if (magic === LZFSE_COMPRESSEDV1_BLOCK_MAGIC || magic === LZFSE_COMPRESSEDV2_BLOCK_MAGIC) {
          let header1;
          let headerSize = 0;

          // Decode compressed headers
          if (magic === LZFSE_COMPRESSEDV2_BLOCK_MAGIC) {
            // Check we have the fixed part of the structure
            if (s.src + LZFSE_V2_FIXED_SIZE > s.src_end) return LZFSE_STATUS_SRC_EMPTY;
            // Get size, and check we have the entire structure
            const headerSize2 = lzfseDecodeV2HeaderSize(dv, s.src);
            if (s.src + headerSize2 > s.src_end) return LZFSE_STATUS_SRC_EMPTY; // SRC truncated
            header1 = newHeader1();
            if (lzfseDecodeV1(header1, dv, s.src) !== 0) return LZFSE_STATUS_ERROR; // failed
            headerSize = headerSize2;
          } else {
            if (s.src + LZFSE_V1_HEADER_SIZE > s.src_end) return LZFSE_STATUS_SRC_EMPTY; // SRC truncated
            header1 = readV1Header(dv, s.src);
            headerSize = LZFSE_V1_HEADER_SIZE;
          }

          // We require the header + entire encoded block to be present in SRC
          // during the entire block decoding. For DST, we can't easily require
          // space for the entire decoded block, because it may expand to
          // something very very large.
          if (s.src + headerSize + header1.n_literal_payload_bytes + header1.n_lmd_payload_bytes > s.src_end) {
            return LZFSE_STATUS_SRC_EMPTY; // need all encoded block
          }

          // Sanity checks
          if (lzfseCheckBlockHeaderV1(header1) !== 0) return LZFSE_STATUS_ERROR;

          // Skip header
          s.src += headerSize;

          // Setup state for compressed V1 block from header
          const bs = s.compressed_lzfse_block_state;
          bs.n_lmd_payload_bytes = header1.n_lmd_payload_bytes;
          bs.n_matches = header1.n_matches;
          fseInitDecoderTable(LZFSE_ENCODE_LITERAL_STATES, LZFSE_ENCODE_LITERAL_SYMBOLS, header1.literal_freq, bs.literal_decoder);
          fseInitValueDecoderTable(LZFSE_ENCODE_L_STATES, LZFSE_ENCODE_L_SYMBOLS, header1.l_freq, l_extra_bits, l_base_value, bs.l_bits, bs.l_vbits, bs.l_delta, bs.l_vbase);
          fseInitValueDecoderTable(LZFSE_ENCODE_M_STATES, LZFSE_ENCODE_M_SYMBOLS, header1.m_freq, m_extra_bits, m_base_value, bs.m_bits, bs.m_vbits, bs.m_delta, bs.m_vbase);
          fseInitValueDecoderTable(LZFSE_ENCODE_D_STATES, LZFSE_ENCODE_D_SYMBOLS, header1.d_freq, d_extra_bits, d_base_value, bs.d_bits, bs.d_vbits, bs.d_delta, bs.d_vbase);

          // Decode literals
          {
            const inStream = { hi: 0, lo: 0, nbits: 0 };
            const bufStart = s.src_begin;
            s.src += header1.n_literal_payload_bytes; // skip literal payload
            const pbuf = { i: s.src }; // read bits backwards from the end
            if (fseInInit(inStream, header1.literal_bits, pbuf, bufStart, dv) !== 0) {
              return LZFSE_STATUS_ERROR;
            }

            let state0 = header1.literal_state[0];
            let state1 = header1.literal_state[1];
            let state2 = header1.literal_state[2];
            let state3 = header1.literal_state[3];

            for (let i = 0; i < header1.n_literals; i += 4) {
              // n_literals is multiple of 4
              if (fseInFlush(inStream, pbuf, bufStart, dv) !== 0) return LZFSE_STATUS_ERROR; // [57, 64] bits
              bs.literals[i + 0] = fseDecode(state0, bs.literal_decoder, inStream); // 10b max
              state0 = fseDecState;
              bs.literals[i + 1] = fseDecode(state1, bs.literal_decoder, inStream); // 10b max
              state1 = fseDecState;
              bs.literals[i + 2] = fseDecode(state2, bs.literal_decoder, inStream); // 10b max
              state2 = fseDecState;
              bs.literals[i + 3] = fseDecode(state3, bs.literal_decoder, inStream); // 10b max
              state3 = fseDecState;
            }

            bs.current_literal = 0; // bs->literals
          } // literals

          // SRC is not incremented to skip the LMD payload, since we need it
          // during block decode. We will increment SRC at the end of the block
          // only after this point.

          // Initialize the L,M,D decode stream, do not start decoding matches
          // yet, and store decoder state
          {
            const inStream = { hi: 0, lo: 0, nbits: 0 };
            // read bits backwards from the end
            const pbuf = { i: s.src + header1.n_lmd_payload_bytes };
            if (fseInInit(inStream, header1.lmd_bits, pbuf, s.src, dv) !== 0) return LZFSE_STATUS_ERROR;

            bs.l_state = header1.l_state;
            bs.m_state = header1.m_state;
            bs.d_state = header1.d_state;
            bs.lmd_in_buf = pbuf.i - s.src;
            bs.l_value = 0;
            bs.m_value = 0;
            // Initialize D to an illegal value so we can't erroneously use an
            // uninitialized "previous" value.
            bs.d_value = -1;
            bs.lmd_in_stream = inStream;
          }

          s.block_magic = magic;
          break;
        }

        // Here we have an invalid magic number
        return LZFSE_STATUS_ERROR;
      }

      case LZFSE_UNCOMPRESSED_BLOCK_MAGIC: {
        const bs = s.uncompressed_block_state;

        // Compute the size (in bytes) of the data that we will actually copy.
        // This size is minimum(bs->n_raw_bytes, space in src, space in dst).
        let copySize = bs.n_raw_bytes; // bytes left to copy
        if (copySize === 0) {
          s.block_magic = 0;
          break;
        } // end of block

        if (s.src_end <= s.src) return LZFSE_STATUS_SRC_EMPTY; // need more SRC data
        if (copySize > s.src_end - s.src) copySize = s.src_end - s.src; // limit to SRC data (> 0)

        if (s.dst_end <= s.dst) return LZFSE_STATUS_DST_FULL; // need more DST capacity
        if (copySize > s.dst_end - s.dst) copySize = s.dst_end - s.dst; // limit to DST capacity (> 0)

        // Now that we know that the copy size is bounded to the source and
        // dest buffers, go ahead and copy the data. We always have copy_size > 0 here.
        s.dst_buf.set(s.src_buf.subarray(s.src, s.src + copySize), s.dst);
        s.src += copySize;
        s.dst += copySize;
        bs.n_raw_bytes -= copySize;

        break;
      }

      case LZFSE_COMPRESSEDV1_BLOCK_MAGIC:
      case LZFSE_COMPRESSEDV2_BLOCK_MAGIC: {
        const bs = s.compressed_lzfse_block_state;
        // Require the entire LMD payload to be in SRC
        if (s.src_end <= s.src || bs.n_lmd_payload_bytes > s.src_end - s.src) {
          return LZFSE_STATUS_SRC_EMPTY;
        }

        const status = lzfseDecodeLmd(s, dv);
        if (status !== LZFSE_STATUS_OK) return status;

        s.block_magic = 0; // LZFSE_NO_BLOCK_MAGIC
        s.src += bs.n_lmd_payload_bytes; // to next block
        break;
      }

      case LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC: {
        const bs = s.compressed_lzvn_block_state;
        if (bs.n_payload_bytes > 0 && s.src_end <= s.src) return LZFSE_STATUS_SRC_EMPTY; // need more SRC data

        // Init LZVN decoder state
        const dstate = {
          src: 0, src_end: 0, dst: 0, dst_begin: 0, dst_end: 0, dst_current: 0,
          L: 0, M: 0, D: 0, d_prev: 0, end_of_stream: 0,
        };
        dstate.src = s.src;
        dstate.src_end = s.src_end;
        if (dstate.src_end - s.src > bs.n_payload_bytes) {
          dstate.src_end = s.src + bs.n_payload_bytes; // limit to payload bytes
        }
        dstate.dst_begin = s.dst_begin;
        dstate.dst = s.dst;
        dstate.dst_end = s.dst_end;
        if (dstate.dst_end - s.dst > bs.n_raw_bytes) {
          dstate.dst_end = s.dst + bs.n_raw_bytes; // limit to raw bytes
        }
        dstate.d_prev = bs.d_prev;
        dstate.end_of_stream = 0;

        // Run LZVN decoder
        lzvnDecode(dstate, s.src_buf, s.dst_buf);

        // Update our state
        const srcUsed = dstate.src - s.src;
        const dstUsed = dstate.dst - s.dst;
        if (srcUsed > bs.n_payload_bytes || dstUsed > bs.n_raw_bytes) {
          return LZFSE_STATUS_ERROR; // sanity check
        }
        s.src = dstate.src;
        s.dst = dstate.dst;
        bs.n_payload_bytes -= srcUsed;
        bs.n_raw_bytes -= dstUsed;
        bs.d_prev = dstate.d_prev;

        // Test end of block
        if (bs.n_payload_bytes === 0 && bs.n_raw_bytes === 0 && dstate.end_of_stream) {
          s.block_magic = 0;
          break;
        } // block done

        // Check for invalid state
        if (bs.n_payload_bytes === 0 || bs.n_raw_bytes === 0 || dstate.end_of_stream) {
          return LZFSE_STATUS_ERROR;
        }

        // Here, block is not done and state is valid, so we need more space in dst.
        return LZFSE_STATUS_DST_FULL;
      }

      default:
        return LZFSE_STATUS_ERROR; // invalid magic
    } // switch magic
  } // block loop
}

// MARK: - lzfse_decode.c API (lzfseDecode)

const LZFSE_MAX_DST_BYTES = 2 ** 31 - 1; // same 2 GiB cap as the other extractors

// Decode an LZFSE stream. `uncompSizeHint` (optional) seeds the destination
// capacity with the exact output size when the caller knows it (e.g. the ftab
// envelope), avoiding regrowth entirely.
export function lzfseDecode(src, uncompSizeHint) {
  if (!(src instanceof Uint8Array)) fail("input must be a Uint8Array");
  const dstCap0 = Number.isInteger(uncompSizeHint) && uncompSizeHint > 0 ? uncompSizeHint : 1 << 16;
  const s = lzfseDecodeState(src, new Uint8Array(dstCap0));
  s.src_buf = src;
  // DataView over the whole source; all loads are little-endian.
  const dv = new DataView(src.buffer, src.byteOffset, src.byteLength);
  let lastStall = null; // (src,dst) cursor at the previous DST_FULL cycle
  for (;;) {
    const status = lzfseDecodeBlock(s, dv);
    if (status === LZFSE_STATUS_OK) break;
    if (status === LZFSE_STATUS_DST_FULL) {
      // JS has no fixed dst: grow and resume from the saved mid-block state.
      // A crafted stream can make zero progress per cycle (neither src nor
      // dst advanced since the previous DST_FULL) — fail instead of doubling
      // dst to the 2 GiB cap on hostile input. Legit streams always advance
      // dst within one block's buffered state.
      const cursor = `${s.src}:${s.dst}`;
      if (cursor === lastStall) fail("corrupt block: no decode progress");
      lastStall = cursor;
      let cap = s.dst_buf.length;
      if (cap >= LZFSE_MAX_DST_BYTES) fail("output exceeds 2GiB decode cap");
      cap = Math.min(cap * 2, LZFSE_MAX_DST_BYTES);
      const grown = new Uint8Array(cap);
      grown.set(s.dst_buf.subarray(0, s.dst));
      s.dst_buf = grown;
      s.dst_end = cap;
      continue;
    }
    if (status === LZFSE_STATUS_SRC_EMPTY) fail("truncated input (need more source bytes)");
    fail("corrupt block (LZFSE_STATUS_ERROR)");
  }
  return s.dst_buf.length === s.dst ? s.dst_buf : s.dst_buf.subarray(0, s.dst);
}
