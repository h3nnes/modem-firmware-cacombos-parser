import { test } from "node:test";
import assert from "node:assert/strict";
import { cp437Decode, lfnName } from "../js/lib/cp437.js";

test("cp437 high-half mapping", () => {
  assert.equal(cp437Decode([0x41, 0x9c]), "A£");
  assert.equal(cp437Decode(new Uint8Array([0x80])), "Ç");
  assert.equal(cp437Decode(new Uint8Array([0xe9])), "Θ"); // é is 0x82 in CP437; 0xe9 is Θ
  assert.equal(cp437Decode(new Uint8Array([0x82])), "é");
});

test("lfn joins utf-16 units", () => {
  assert.equal(lfnName([0x42, 0x0043]), "BC");
});

test("cp437Decode accepts Uint8Array and plain array; low half is ASCII", () => {
  assert.equal(cp437Decode(new Uint8Array([0x41, 0x42, 0x7f])), "AB\x7f");
  assert.equal(cp437Decode([0x41, 0x42, 0x7f]), "AB\x7f");
  assert.equal(cp437Decode(new Uint8Array(0)), "");
  assert.equal(cp437Decode([0x00]), "\x00");
});

test("cp437 0x80-0xFF sweep equals python table", () => {
  const expected = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ";
  const bytes = [];
  for (let i = 0x80; i <= 0xff; i++) bytes.push(i);
  assert.equal(cp437Decode(bytes), expected);
});

test("cp437Decode throws on out-of-range bytes", () => {
  assert.throws(() => cp437Decode([256]), RangeError);
  assert.throws(() => cp437Decode([-1]), RangeError);
});

test("lfnName empty array is empty string", () => {
  assert.equal(lfnName([]), "");
});

test("lfnName passes lone surrogate through like python chr()", () => {
  const s = lfnName([0xd83d]);
  assert.equal(s.length, 1);
  assert.equal(s, String.fromCharCode(0xd83d));
});
