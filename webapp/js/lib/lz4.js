// Pure-JS LZ4 FRAME format decoder (the browser replacement for the lz4 CLI
// / liblz4 used by external extraction). Decodes one complete frame into a
// Uint8Array. Checksum fields (header HC, per-block, content xxhash32) are
// parsed and skipped, never verified: valid streams decode byte-identically
// to the reference tools, while corrupt compressed data still fails loudly
// during block decode.

const MINMATCH = 4;

const GROW_CHUNK = 1 << 20;

function u32le(input, pos) {
  return input[pos] | (input[pos + 1] << 8) | (input[pos + 2] << 16) | (input[pos + 3] * 0x1000000);
}

function ensureCapacity(state, needed) {
  if (needed <= state.dst.length) return;
  let size = Math.max(state.dst.length, GROW_CHUNK);
  while (size < needed) size *= 2;
  const grown = new Uint8Array(size);
  grown.set(state.dst.subarray(0, state.outLen));
  state.dst = grown;
}

// One LZ4 BLOCK sequence decode into dst at outPos. Matches index dst itself,
// so linked-block windows (offsets into previously decoded blocks) work
// without extra state; the caller validates the window bound.
function decodeBlock(src, state, windowFloor) {
  let outPos = state.outLen;
  let i = 0;
  while (i < src.length) {
    const token = src[i++];
    let litLen = token >> 4;
    if (litLen === 15) {
      let b;
      do {
        if (i >= src.length) throw new Error("truncated LZ4 block: literal length");
        b = src[i++];
        litLen += b;
      } while (b === 255);
    }
    if (i + litLen > src.length) throw new Error("truncated LZ4 block: literals");
    // Grow around the in-block write position, not the block start: outLen
    // only catches up at block end, so a growth before the sync would discard
    // everything decoded so far in this block (the next match copy would then
    // replicate zeros - correct length, wrong bytes, no throw).
    state.outLen = outPos;
    ensureCapacity(state, outPos + litLen);
    state.dst.set(src.subarray(i, i + litLen), outPos);
    outPos += litLen;
    i += litLen;
    if (i >= src.length) break; // last sequence may end after the literals
    if (i + 2 > src.length) throw new Error("truncated LZ4 block: offset");
    const offset = src[i] | (src[i + 1] << 8);
    i += 2;
    if (offset === 0 || offset > outPos || outPos - offset < windowFloor) {
      throw new Error("corrupt LZ4 block: match offset");
    }
    let matchLen = (token & 15) + MINMATCH;
    if ((token & 15) === 15) {
      let b;
      do {
        if (i >= src.length) throw new Error("truncated LZ4 block: match length");
        b = src[i++];
        matchLen += b;
      } while (b === 255);
    }
    state.outLen = outPos;
    ensureCapacity(state, outPos + matchLen);
    const dst2 = state.dst;
    if (offset >= matchLen) {
      // Regions are disjoint: plain forward copy.
      dst2.set(dst2.subarray(outPos - offset, outPos - offset + matchLen), outPos);
    } else {
      // Overlapping window: byte-by-byte copy replicates the LZ4 semantics.
      for (let k = 0; k < matchLen; k++) dst2[outPos + k] = dst2[outPos - offset + k];
    }
    outPos += matchLen;
  }
  state.outLen = outPos;
}

export function decompressLz4Frame(input) {
  if (input.length >= 4 && (input[0] !== 0x04 || input[1] !== 0x22 || input[2] !== 0x4d || input[3] !== 0x18)) {
    throw new Error("Not an LZ4 frame: bad magic");
  }
  if (input.length < 7) throw new Error("truncated LZ4 frame: header");
  const flg = input[4];
  if (((flg >> 6) & 3) !== 1) throw new Error("Not an LZ4 frame: unsupported version");
  if (flg & 0x02) throw new Error("Not an LZ4 frame: reserved FLG bit set");
  const bd = input[5];
  if (bd & 0x8f) throw new Error("Not an LZ4 frame: reserved BD bits set");
  let pos = 6;
  let contentSize = null;
  if (flg & 0x08) {
    if (pos + 8 > input.length) throw new Error("truncated LZ4 frame: content size");
    let size = 0;
    for (let i = 7; i >= 0; i--) size = size * 256 + input[pos + i];
    contentSize = size;
    pos += 8;
  }
  if (flg & 0x01) pos += 4; // dictionary id
  pos += 1; // header checksum HC (skipped, not verified)
  if (pos > input.length) throw new Error("truncated LZ4 frame: header");

  const state = {
    dst: new Uint8Array(contentSize !== null ? contentSize : Math.min(Math.max(input.length * 2, GROW_CHUNK), 64 * 1024 * 1024)),
    outLen: 0,
  };
  const independent = (flg & 0x20) !== 0;
  for (;;) {
    if (pos + 4 > input.length) throw new Error("truncated LZ4 frame: block size");
    const word = u32le(input, pos);
    pos += 4;
    if (word === 0) break; // end mark
    const uncompressed = (word & 0x80000000) !== 0;
    const size = word & 0x7fffffff;
    if (pos + size > input.length) throw new Error("truncated LZ4 frame: block data");
    const blockStart = state.outLen;
    const block = input.subarray(pos, pos + size);
    pos += size;
    if (flg & 0x10) pos += 4; // block checksum (skipped, not verified)
    if (uncompressed) {
      ensureCapacity(state, state.outLen + size);
      state.dst.set(block, state.outLen);
      state.outLen += size;
    } else {
      // Independent blocks must not match into earlier blocks.
      decodeBlock(block, state, independent ? blockStart : 0);
    }
  }
  if (flg & 0x04) pos += 4; // content checksum (skipped, not verified)
  if (contentSize !== null && state.outLen !== contentSize) {
    throw new Error(`LZ4 frame content size mismatch: decoded ${state.outLen} != declared ${contentSize}`);
  }
  return contentSize !== null && state.outLen === state.dst.length ? state.dst : state.dst.subarray(0, state.outLen);
}
