#!/usr/bin/env node
"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/main.ts
var import_stdio = require("@modelcontextprotocol/sdk/server/stdio.js");

// src/server.ts
var import_mcp = require("@modelcontextprotocol/sdk/server/mcp.js");
var import_zod = require("zod");

// src/tools.ts
var fs = __toESM(require("fs"));
var path = __toESM(require("path"));

// ../node_modules/@noble/hashes/esm/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function abytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}
var Hash = class {
};
function createHasher(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}

// ../node_modules/@noble/hashes/esm/_md.js
function setBigUint64(view, byteOffset, value, isLE) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE);
  const _32n2 = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n2 & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE ? 4 : 0;
  const l = isLE ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE);
  view.setUint32(byteOffset + l, wl, isLE);
}
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class extends Hash {
  constructor(blockLen, outputLen, padOffset, isLE) {
    super();
    this.finished = false;
    this.length = 0;
    this.pos = 0;
    this.destroyed = false;
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    data = toBytes(data);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    clean(this.buffer.subarray(pos));
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++)
      buffer[i] = 0;
    setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to || (to = new this.constructor());
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
var SHA512_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  4089235720,
  3144134277,
  2227873595,
  1013904242,
  4271175723,
  2773480762,
  1595750129,
  1359893119,
  2917565137,
  2600822924,
  725511199,
  528734635,
  4215389547,
  1541459225,
  327033209
]);

// ../node_modules/@noble/hashes/esm/_u64.js
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
var shrSH = (h, _l, s) => h >>> s;
var shrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrSH = (h, l, s) => h >>> s | l << 32 - s;
var rotrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
var rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
function add(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}
var add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
var add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
var add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
var add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
var add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
var add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;

// ../node_modules/@noble/hashes/esm/sha2.js
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA256 = class extends HashMD {
  constructor(outputLen = 32) {
    super(64, outputLen, 8, false);
    this.A = SHA256_IV[0] | 0;
    this.B = SHA256_IV[1] | 0;
    this.C = SHA256_IV[2] | 0;
    this.D = SHA256_IV[3] | 0;
    this.E = SHA256_IV[4] | 0;
    this.F = SHA256_IV[5] | 0;
    this.G = SHA256_IV[6] | 0;
    this.H = SHA256_IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
var K512 = /* @__PURE__ */ (() => split([
  "0x428a2f98d728ae22",
  "0x7137449123ef65cd",
  "0xb5c0fbcfec4d3b2f",
  "0xe9b5dba58189dbbc",
  "0x3956c25bf348b538",
  "0x59f111f1b605d019",
  "0x923f82a4af194f9b",
  "0xab1c5ed5da6d8118",
  "0xd807aa98a3030242",
  "0x12835b0145706fbe",
  "0x243185be4ee4b28c",
  "0x550c7dc3d5ffb4e2",
  "0x72be5d74f27b896f",
  "0x80deb1fe3b1696b1",
  "0x9bdc06a725c71235",
  "0xc19bf174cf692694",
  "0xe49b69c19ef14ad2",
  "0xefbe4786384f25e3",
  "0x0fc19dc68b8cd5b5",
  "0x240ca1cc77ac9c65",
  "0x2de92c6f592b0275",
  "0x4a7484aa6ea6e483",
  "0x5cb0a9dcbd41fbd4",
  "0x76f988da831153b5",
  "0x983e5152ee66dfab",
  "0xa831c66d2db43210",
  "0xb00327c898fb213f",
  "0xbf597fc7beef0ee4",
  "0xc6e00bf33da88fc2",
  "0xd5a79147930aa725",
  "0x06ca6351e003826f",
  "0x142929670a0e6e70",
  "0x27b70a8546d22ffc",
  "0x2e1b21385c26c926",
  "0x4d2c6dfc5ac42aed",
  "0x53380d139d95b3df",
  "0x650a73548baf63de",
  "0x766a0abb3c77b2a8",
  "0x81c2c92e47edaee6",
  "0x92722c851482353b",
  "0xa2bfe8a14cf10364",
  "0xa81a664bbc423001",
  "0xc24b8b70d0f89791",
  "0xc76c51a30654be30",
  "0xd192e819d6ef5218",
  "0xd69906245565a910",
  "0xf40e35855771202a",
  "0x106aa07032bbd1b8",
  "0x19a4c116b8d2d0c8",
  "0x1e376c085141ab53",
  "0x2748774cdf8eeb99",
  "0x34b0bcb5e19b48a8",
  "0x391c0cb3c5c95a63",
  "0x4ed8aa4ae3418acb",
  "0x5b9cca4f7763e373",
  "0x682e6ff3d6b2b8a3",
  "0x748f82ee5defb2fc",
  "0x78a5636f43172f60",
  "0x84c87814a1f0ab72",
  "0x8cc702081a6439ec",
  "0x90befffa23631e28",
  "0xa4506cebde82bde9",
  "0xbef9a3f7b2c67915",
  "0xc67178f2e372532b",
  "0xca273eceea26619c",
  "0xd186b8c721c0c207",
  "0xeada7dd6cde0eb1e",
  "0xf57d4f7fee6ed178",
  "0x06f067aa72176fba",
  "0x0a637dc5a2c898a6",
  "0x113f9804bef90dae",
  "0x1b710b35131c471b",
  "0x28db77f523047d84",
  "0x32caab7b40c72493",
  "0x3c9ebe0a15c9bebc",
  "0x431d67c49c100d4c",
  "0x4cc5d4becb3e42b6",
  "0x597f299cfc657e2a",
  "0x5fcb6fab3ad6faec",
  "0x6c44198c4a475817"
].map((n) => BigInt(n))))();
var SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
var SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
var SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
var SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
var SHA512 = class extends HashMD {
  constructor(outputLen = 64) {
    super(128, outputLen, 16, false);
    this.Ah = SHA512_IV[0] | 0;
    this.Al = SHA512_IV[1] | 0;
    this.Bh = SHA512_IV[2] | 0;
    this.Bl = SHA512_IV[3] | 0;
    this.Ch = SHA512_IV[4] | 0;
    this.Cl = SHA512_IV[5] | 0;
    this.Dh = SHA512_IV[6] | 0;
    this.Dl = SHA512_IV[7] | 0;
    this.Eh = SHA512_IV[8] | 0;
    this.El = SHA512_IV[9] | 0;
    this.Fh = SHA512_IV[10] | 0;
    this.Fl = SHA512_IV[11] | 0;
    this.Gh = SHA512_IV[12] | 0;
    this.Gl = SHA512_IV[13] | 0;
    this.Hh = SHA512_IV[14] | 0;
    this.Hl = SHA512_IV[15] | 0;
  }
  // prettier-ignore
  get() {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
  }
  // prettier-ignore
  set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
    this.Ah = Ah | 0;
    this.Al = Al | 0;
    this.Bh = Bh | 0;
    this.Bl = Bl | 0;
    this.Ch = Ch | 0;
    this.Cl = Cl | 0;
    this.Dh = Dh | 0;
    this.Dl = Dl | 0;
    this.Eh = Eh | 0;
    this.El = El | 0;
    this.Fh = Fh | 0;
    this.Fl = Fl | 0;
    this.Gh = Gh | 0;
    this.Gl = Gl | 0;
    this.Hh = Hh | 0;
    this.Hl = Hl | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4) {
      SHA512_W_H[i] = view.getUint32(offset);
      SHA512_W_L[i] = view.getUint32(offset += 4);
    }
    for (let i = 16; i < 80; i++) {
      const W15h = SHA512_W_H[i - 15] | 0;
      const W15l = SHA512_W_L[i - 15] | 0;
      const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
      const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
      const W2h = SHA512_W_H[i - 2] | 0;
      const W2l = SHA512_W_L[i - 2] | 0;
      const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
      const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
      const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
      const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
      SHA512_W_H[i] = SUMh | 0;
      SHA512_W_L[i] = SUMl | 0;
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    for (let i = 0; i < 80; i++) {
      const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
      const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
      const CHIh = Eh & Fh ^ ~Eh & Gh;
      const CHIl = El & Fl ^ ~El & Gl;
      const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
      const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
      const T1l = T1ll | 0;
      const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
      const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
      const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
      const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
      Hh = Gh | 0;
      Hl = Gl | 0;
      Gh = Fh | 0;
      Gl = Fl | 0;
      Fh = Eh | 0;
      Fl = El | 0;
      ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
      Dh = Ch | 0;
      Dl = Cl | 0;
      Ch = Bh | 0;
      Cl = Bl | 0;
      Bh = Ah | 0;
      Bl = Al | 0;
      const All = add3L(T1l, sigma0l, MAJl);
      Ah = add3H(All, T1h, sigma0h, MAJh);
      Al = All | 0;
    }
    ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
    ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
    ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
    ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
    ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
    ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
    ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
    ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
  }
  roundClean() {
    clean(SHA512_W_H, SHA512_W_L);
  }
  destroy() {
    clean(this.buffer);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
};
var sha256 = /* @__PURE__ */ createHasher(() => new SHA256());
var sha512 = /* @__PURE__ */ createHasher(() => new SHA512());

// ../node_modules/@noble/hashes/esm/sha256.js
var sha2562 = sha256;

// ../node_modules/@noble/hashes/esm/sha512.js
var sha5122 = sha512;

// ../lib/digest.ts
var HEX_LENGTH = { sha256: 64, sha512: 128 };
function toHex(bytes) {
  return Buffer.from(bytes).toString("hex");
}
function digestBuffer(data) {
  return { sha256: toHex(sha2562(data)), sha512: toHex(sha5122(data)), bytes: data.length };
}
function parseDigest(input) {
  const raw = input.trim();
  if (!raw) throw new Error("Empty digest");
  const colon = raw.indexOf(":");
  if (colon > 0) {
    const tag = raw.slice(0, colon).toLowerCase();
    const body2 = raw.slice(colon + 1).toLowerCase();
    if (tag !== "sha256" && tag !== "sha512") {
      throw new Error(`Unsupported algorithm "${tag}". Supported: sha256, sha512.`);
    }
    assertHex(body2, HEX_LENGTH[tag], tag);
    return { algorithm: tag, hex: body2 };
  }
  const body = (raw.startsWith("0x") || raw.startsWith("0X") ? raw.slice(2) : raw).toLowerCase();
  if (body.length === 64) {
    assertHex(body, 64, "sha256");
    return { algorithm: "sha256", hex: body };
  }
  if (body.length === 128) {
    assertHex(body, 128, "sha512");
    return { algorithm: "sha512", hex: body };
  }
  throw new Error(
    `Invalid digest - expected sha256:<64 hex>, sha512:<128 hex>, or bare hex of either length (got ${body.length} characters).`
  );
}
function assertHex(body, expected, algorithm) {
  if (body.length !== expected) {
    throw new Error(`Invalid ${algorithm} digest - expected ${expected} hex characters, got ${body.length}.`);
  }
  if (!/^[0-9a-f]+$/.test(body)) {
    throw new Error(`Invalid ${algorithm} digest - contains non-hex characters.`);
  }
}
function parseIntegrity(integrity) {
  const candidates = [];
  for (const token of integrity.trim().split(/\s+/)) {
    const dash = token.indexOf("-");
    if (dash <= 0) continue;
    const alg = token.slice(0, dash).toLowerCase();
    if (alg !== "sha256" && alg !== "sha512") continue;
    const hex = Buffer.from(token.slice(dash + 1), "base64").toString("hex");
    if (hex.length === HEX_LENGTH[alg]) candidates.push({ algorithm: alg, hex });
  }
  if (candidates.length === 0) {
    throw new Error(`No sha256/sha512 entry in integrity string: ${integrity}`);
  }
  return candidates.find((c) => c.algorithm === "sha512") ?? candidates[0];
}

// ../lib/verdict.ts
var DEFAULT_BASE_URL = "https://verify.coderoot.app";
function bareHex(value) {
  if (!value) return null;
  const raw = value.trim().toLowerCase();
  const body = raw.startsWith("0x") ? raw.slice(2) : raw;
  return /^[0-9a-f]+$/.test(body) ? body : null;
}
function compareContentHash(acquiredSha256, endpointContentHash) {
  const ours = bareHex(acquiredSha256);
  const theirs = bareHex(endpointContentHash);
  if (!ours || !theirs) return false;
  return ours !== theirs;
}
function endpointDegraded(body) {
  if (body.degraded !== true) return null;
  const why = body.gateRevocation?.note;
  return {
    degraded: true,
    note: `The endpoint could not read the gate's revocations${why ? ` (${why})` : ""}, so a revoke made in the last minutes may be missing.`
  };
}
function normalizeVerdict(raw, fallback) {
  switch ((raw ?? "").toLowerCase()) {
    case "verified":
      return "verified";
    case "attested-bytes-unproven":
      return "attested-bytes-unproven";
    case "revoked":
      return "revoked";
    case "unregistered":
      return "unregistered";
    default:
      return fallback;
  }
}
async function getJson(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/json" }
    });
    const body = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, body };
  } finally {
    clearTimeout(timer);
  }
}
async function verifyDigest(digests, hashSource, options = {}) {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  const timeoutMs = options.timeoutMs ?? 15e3;
  if (!digests || hashSource === "none") {
    return {
      verdict: "attested-bytes-unproven",
      queried: null,
      hashSource: "none",
      reason: "No digest could be obtained for this component; nothing was queried.",
      authorCpoaRevoked: false
    };
  }
  if (hashSource === "sbom-hint") {
    return {
      verdict: "attested-bytes-unproven",
      queried: null,
      hashSource,
      reason: "The only digest available came from the SBOM itself and was confirmable nowhere else. A declared hash is never compared to an attestation.",
      authorCpoaRevoked: false
    };
  }
  if (!digests.sha256 && !digests.sha512) {
    return {
      verdict: "attested-bytes-unproven",
      queried: null,
      hashSource,
      reason: "A digest was acquired but neither sha256 nor sha512 could be queried.",
      authorCpoaRevoked: false
    };
  }
  const queried = digests.sha256 ? `sha256:${digests.sha256}` : `sha512:${digests.sha512}`;
  if (options.revokedCache?.has(queried)) {
    return {
      verdict: "revoked",
      queried,
      hashSource,
      reason: "This digest was previously observed as revoked by this client (local cache).",
      authorCpoaRevoked: false
    };
  }
  let response;
  try {
    response = await getJson(`${baseUrl}/verify/${encodeURIComponent(queried)}`, timeoutMs);
  } catch (error) {
    return {
      verdict: "attested-bytes-unproven",
      queried,
      hashSource,
      degraded: true,
      unreachable: true,
      reason: `Verify endpoint unreachable (${error.message}).`,
      authorCpoaRevoked: false
    };
  }
  if (!response.ok) {
    return {
      verdict: "attested-bytes-unproven",
      queried,
      hashSource,
      degraded: true,
      unreachable: true,
      reason: `Verify endpoint answered ${response.status}: ${response.body.error ?? "no detail"}`,
      authorCpoaRevoked: false
    };
  }
  const body = response.body;
  const verdict = normalizeVerdict(body.verdict, "unregistered");
  const partial = endpointDegraded(body);
  if (verdict === "revoked") {
    options.revokedCache?.add(queried);
  }
  return {
    verdict,
    queried,
    hashSource,
    ...partial ? { degraded: true } : {},
    reason: partial ? `${reasonFor(verdict, hashSource)} ${partial.note}` : reasonFor(verdict, hashSource),
    contentHash: body.contentHash,
    totalAttestations: body.totalAttestations,
    revokedAttestations: body.revokedAttestations,
    attestations: extractAttestations(body),
    // `?? false` would coerce an explicit `null` (chain unreadable) to false,
    // silently dropping it. Default only when the endpoint omits the field.
    authorCpoaRevoked: body.authorCpoaRevoked === void 0 ? false : body.authorCpoaRevoked,
    authorCpoaRevokedUids: body.authorCpoaRevokedUids
  };
}
function extractAttestations(body) {
  const seconds = (value) => {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? n : void 0;
  };
  const detail = /* @__PURE__ */ new Map();
  for (const a of [...body.attestations ?? [], ...body.v1Attestations ?? [], ...body.v2Attestations ?? []]) {
    if (typeof a?.id === "string" && a.id.length > 0 && !detail.has(a.id)) {
      const entry = { attester: a.attester, revokedOnChain: a.revokedOnChain };
      const attestedAt = seconds(a.blockTimestamp);
      const revokedAt = seconds(a.revokedAt);
      if (attestedAt !== void 0) entry.attestedAt = attestedAt;
      if (revokedAt !== void 0) entry.revokedAt = revokedAt;
      detail.set(a.id, entry);
    }
  }
  const uids = (body.attestationUids ?? []).filter((u) => typeof u === "string" && u.length > 0);
  const ordered = uids.length > 0 ? uids : [...detail.keys()];
  const out = ordered.map((uid) => ({ uid, ...detail.get(uid) ?? {} }));
  return out.length > 0 ? out : void 0;
}
function reasonFor(verdict, hashSource) {
  switch (verdict) {
    case "verified":
      return `An acquired ${hashSource} digest matched an attested record.`;
    case "revoked":
      return "A record exists for these bytes and has been revoked.";
    case "unregistered":
      return "No attested record exists for these bytes.";
    default:
      return "A record exists for these coordinates but no strong hash was matched.";
  }
}
async function probeCoordinates(registry, name, version, options = {}) {
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  const timeoutMs = options.timeoutMs ?? 15e3;
  const path3 = `${baseUrl}/verify/${encodeURIComponent(registry)}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
  let response;
  try {
    response = await getJson(path3, timeoutMs);
  } catch (error) {
    return {
      verdict: "attested-bytes-unproven",
      queried: null,
      hashSource: "none",
      degraded: true,
      unreachable: true,
      reason: `Verify endpoint unreachable (${error.message}).`,
      authorCpoaRevoked: false
    };
  }
  if (!response.ok) {
    return {
      verdict: "unregistered",
      queried: null,
      hashSource: "none",
      reason: `No record for ${registry}:${name}@${version}.`,
      authorCpoaRevoked: false
    };
  }
  const raw = normalizeVerdict(response.body.verdict, "attested-bytes-unproven");
  const verdict = raw === "verified" ? "attested-bytes-unproven" : raw;
  const partial = endpointDegraded(response.body);
  const reason = verdict === "revoked" ? "A record for these coordinates has been revoked." : "Coordinates matched a record; bytes were not proven (coordinates are an index, not proof).";
  return {
    verdict,
    queried: null,
    hashSource: "none",
    ...partial ? { degraded: true } : {},
    reason: partial ? `${reason} ${partial.note}` : reason,
    contentHash: response.body.contentHash,
    totalAttestations: response.body.totalAttestations,
    revokedAttestations: response.body.revokedAttestations,
    attestations: extractAttestations(response.body),
    authorCpoaRevoked: response.body.authorCpoaRevoked === void 0 ? false : response.body.authorCpoaRevoked,
    authorCpoaRevokedUids: response.body.authorCpoaRevokedUids
  };
}

// ../lib/sbom.ts
function parseNpmLockfile(doc) {
  const packages = doc["packages"] ?? {};
  const components = [];
  let purllessCount = 0;
  let purllessHashCount = 0;
  for (const [key, pkg] of Object.entries(packages)) {
    if (!key) continue;
    const segments = key.split("node_modules/");
    const pathSegment = segments[segments.length - 1];
    const name = pkg["name"] || pathSegment;
    if (!name) continue;
    const version = pkg["version"] || null;
    const integrity = pkg["integrity"];
    const declared = [];
    if (integrity) {
      try {
        const { algorithm, hex } = parseIntegrity(integrity);
        declared.push({ algorithm, hex, path: "package-lock.packages[].integrity" });
      } catch {
      }
    }
    if (!version) {
      purllessCount += 1;
      purllessHashCount += declared.length;
      continue;
    }
    const purlName = name.startsWith("@") ? `%40${name.slice(1)}` : name;
    const purl = `pkg:npm/${purlName}@${version}`;
    components.push({ purl, ecosystem: "npm", name, version, declared });
  }
  return { format: "npm-lockfile", components, purllessCount, purllessHashCount };
}
function parseLockfile(raw) {
  if (raw.trim().length === 0) {
    throw new Error("Empty lockfile - nothing to parse.");
  }
  let doc;
  try {
    doc = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Malformed lockfile JSON: ${error.message}`);
  }
  if (typeof doc["packages"] !== "object" || doc["packages"] === null) {
    throw new Error(
      "Unrecognized lockfile: expected a `packages` map (npm lockfileVersion 2 or 3). lockfileVersion 1 is not supported."
    );
  }
  return parseNpmLockfile(doc);
}
function distinctByPurl(components) {
  const seen = /* @__PURE__ */ new Map();
  for (const component of components) {
    if (!component.purl) continue;
    const existing = seen.get(component.purl);
    if (!existing) {
      seen.set(component.purl, component);
    } else if (component.declared.length > existing.declared.length) {
      seen.set(component.purl, component);
    }
  }
  return [...seen.values()];
}
function strongestDeclared(component) {
  const order = ["sha512", "sha256"];
  for (const algorithm of order) {
    const hit = component.declared.find((d) => d.algorithm === algorithm);
    if (hit) return hit;
  }
  return null;
}

// ../lib/report.ts
function summarize(records) {
  const s = {
    total: records.length,
    verified: 0,
    attestedBytesUnproven: 0,
    unregistered: 0,
    revoked: 0,
    mismatch: 0,
    notQueried: 0,
    degraded: 0,
    authorCpoaRevoked: 0
  };
  for (const r of records) {
    if (r.verdict === "verified") s.verified += 1;
    else if (r.verdict === "revoked") s.revoked += 1;
    else if (r.verdict === "unregistered") s.unregistered += 1;
    else s.attestedBytesUnproven += 1;
    if (!r.queried) s.notQueried += 1;
    if (r.degraded) s.degraded += 1;
    if (r.mismatch) s.mismatch += 1;
    if (r.authorCpoaRevoked !== false && r.authorCpoaRevoked !== void 0) s.authorCpoaRevoked += 1;
  }
  return s;
}
function toEvidenceRecord(component, outcome, digests) {
  const algorithm = outcome.queried ? outcome.queried.split(":")[0] : null;
  const record = {
    purl: component.purl ?? "",
    ecosystem: component.ecosystem,
    name: component.name,
    version: component.version,
    verdict: outcome.verdict,
    hashSource: outcome.hashSource,
    queried: outcome.queried,
    algorithm,
    digests,
    reason: outcome.reason
  };
  if (outcome.degraded) record.degraded = true;
  if (outcome.mismatch) record.mismatch = true;
  if (outcome.attestations !== void 0) record.attestations = outcome.attestations;
  if (outcome.attestationUids?.length) record.attestationUids = outcome.attestationUids;
  if (outcome.authorCpoaRevoked !== false && outcome.authorCpoaRevoked !== void 0) {
    record.authorCpoaRevoked = outcome.authorCpoaRevoked;
  }
  if (outcome.authorCpoaRevokedUids?.length) record.authorCpoaRevokedUids = outcome.authorCpoaRevokedUids;
  return record;
}

// ../lib/batch.ts
async function pool(items, workers, fn) {
  const out = new Array(items.length);
  let cursor = 0;
  await Promise.all(
    Array.from({ length: Math.max(1, workers) }, async () => {
      while (cursor < items.length) {
        const index = cursor++;
        out[index] = await fn(items[index]);
      }
    })
  );
  return out;
}
function fromDeclared(declared, hashSource) {
  if (!declared) return { hashSource: "none", digests: [], declared: null };
  const digests = [`${declared.algorithm}:${declared.hex}`];
  if (declared.algorithm === "sha256") return { hashSource, sha256: declared.hex, digests, declared };
  if (declared.algorithm === "sha512") return { hashSource, sha512: declared.hex, digests, declared };
  return { hashSource, digests, declared };
}
async function acquire(component, offline, declaredSource, registryUrl = "https://registry.npmjs.org") {
  const declared = strongestDeclared(component);
  if (offline || component.ecosystem !== "npm" || !component.version) return fromDeclared(declared, declaredSource);
  try {
    const packument = await (await fetch(`${registryUrl.replace(/\/+$/, "")}/${component.name}`)).json();
    const tarball = packument.versions?.[component.version]?.dist?.tarball;
    if (!tarball) return fromDeclared(declared, declaredSource);
    const bytes = new Uint8Array(await (await fetch(tarball)).arrayBuffer());
    const set = digestBuffer(bytes);
    return {
      hashSource: "bytes",
      sha256: set.sha256,
      sha512: set.sha512,
      digests: [`sha256:${set.sha256}`, `sha512:${set.sha512}`],
      declared
    };
  } catch {
    return fromDeclared(declared, declaredSource);
  }
}
async function verifyComponent(component, options) {
  return (await verifyComponentDetailed(component, options)).record;
}
async function verifyComponentDetailed(component, options) {
  const verifyOptions2 = options.verify ?? {};
  const acquired = await acquire(component, options.offline ?? false, options.declaredSource, options.registryUrl);
  const outcome = options.offline ? {
    verdict: "attested-bytes-unproven",
    queried: null,
    hashSource: acquired.hashSource,
    reason: "Offline: resolved and classified, but not queried."
  } : await verifyDigest(
    acquired.sha256 || acquired.sha512 ? { sha256: acquired.sha256 ?? "", sha512: acquired.sha512 ?? "", bytes: 0 } : null,
    acquired.hashSource,
    verifyOptions2
  );
  let mismatch = false;
  if (!options.offline && acquired.sha256 && acquired.hashSource === "bytes" && component.ecosystem === "npm" && component.version) {
    const coordinates = await probeCoordinates(component.ecosystem, component.name ?? "", component.version, verifyOptions2);
    mismatch = compareContentHash(acquired.sha256, coordinates.contentHash);
    if (!mismatch && options.declaredSource === "lockfile" && acquired.declared) {
      const ours = acquired.declared.algorithm === "sha512" ? acquired.sha512 : acquired.sha256;
      if (ours) mismatch = compareContentHash(ours, acquired.declared.hex);
    }
  }
  const record = toEvidenceRecord(
    component,
    {
      verdict: outcome.verdict,
      hashSource: outcome.hashSource,
      queried: outcome.queried,
      reason: outcome.reason,
      degraded: outcome.degraded,
      mismatch,
      attestations: outcome.totalAttestations,
      attestationUids: outcome.attestations?.map((a) => a.uid),
      authorCpoaRevoked: outcome.authorCpoaRevoked,
      authorCpoaRevokedUids: outcome.authorCpoaRevokedUids
    },
    acquired.digests
  );
  return { record, result: { ...outcome, mismatch } };
}
async function verifyComponents(components, options) {
  let done = 0;
  return pool(components, options.concurrency ?? 8, async (component) => {
    const record = await verifyComponent(component, options);
    options.onProgress?.(++done, components.length);
    return record;
  });
}

// src/tools.ts
var EAS_VIEW = "https://base-sepolia.easscan.org/attestation/view/";
var LOCKFILE_NAME = /(^|[.\-_])(package-lock|npm-shrinkwrap)\.json$/;
var iso = (seconds) => seconds ? new Date(seconds * 1e3).toISOString() : null;
function attestationsOf(refs, uids) {
  const list = refs ?? (uids ?? []).map((uid) => ({ uid }));
  return list.map((a) => ({
    uid: a.uid,
    attester: a.attester ?? null,
    attestedAt: iso(a.attestedAt),
    revokedAt: iso(a.revokedAt),
    easUrl: `${EAS_VIEW}${a.uid}`
  }));
}
function judge(verdict, flags) {
  if (verdict === "revoked") return { action: "refuse", advice: "Revoked: do not install, ship or pin it. Tell the user which component it is and its attestation UIDs." };
  if (flags.mismatch) return { action: "stop", advice: "The bytes differ from what is attested for this name and version. Report it; do not retry from another source to make it pass." };
  if (flags.authorCpoaRevoked !== false) return { action: "caution", advice: "The producing agent has lost its authority, or that could not be checked. Refuse in a release or deploy step." };
  if (flags.degraded) return { action: "caution", advice: "The answer may miss a recent revoke. Refuse in a release or deploy step; elsewhere report it and check again later." };
  if (verdict === "verified") return { action: "proceed", advice: "These exact bytes are attested and not revoked." };
  if (verdict === "unregistered") return { action: "caution", advice: "No attestation for these bytes. Not a failure for a dependency check, but refuse it in a release or deploy step." };
  return { action: "stop", advice: "The name and version are attested, but these bytes were not proven. Treat as unverified: get the artifact from its registry and check the file itself." };
}
function fromVerdict(result) {
  const flags = {
    mismatch: result.mismatch === true,
    degraded: result.degraded === true,
    authorCpoaRevoked: result.authorCpoaRevoked === void 0 ? false : result.authorCpoaRevoked
  };
  return { verdict: result.verdict, ...judge(result.verdict, flags), reason: result.reason, queried: result.queried, hashSource: result.hashSource, ...flags, attestations: attestationsOf(result.attestations) };
}
function fromRecord(record) {
  const flags = {
    mismatch: record.mismatch === true,
    degraded: record.degraded === true,
    authorCpoaRevoked: record.authorCpoaRevoked === void 0 ? false : record.authorCpoaRevoked
  };
  return { verdict: record.verdict, ...judge(record.verdict, flags), reason: record.reason, queried: record.queried, hashSource: record.hashSource, ...flags, attestations: attestationsOf(void 0, record.attestationUids) };
}
var verifyOptions = (options) => options.verifyUrl ? { baseUrl: options.verifyUrl } : {};
async function checkHash(digest, source, options = {}) {
  const { algorithm, hex } = parseDigest(digest);
  const set = { sha256: algorithm === "sha256" ? hex : "", sha512: algorithm === "sha512" ? hex : "", bytes: 0 };
  return fromVerdict(await verifyDigest(set, source, verifyOptions(options)));
}
async function checkPackage(name, version, options = {}) {
  const component = { purl: `pkg:npm/${name}@${version}`, ecosystem: "npm", name, version, declared: [] };
  const { result } = await verifyComponentDetailed(component, {
    declaredSource: "sbom-hint",
    verify: verifyOptions(options),
    ...options.registryUrl ? { registryUrl: options.registryUrl } : {}
  });
  return { package: `${name}@${version}`, ...fromVerdict(result) };
}
async function checkLockfile(input, options = {}) {
  let raw;
  if (input.content !== void 0) raw = input.content;
  else if (input.path) {
    if (!LOCKFILE_NAME.test(path.basename(input.path))) throw new Error("path must name a package-lock.json or npm-shrinkwrap.json");
    raw = fs.readFileSync(input.path, "utf8");
  } else throw new Error("give either path or content");
  let components = distinctByPurl(parseLockfile(raw).components);
  const distinct = components.length;
  if (input.limit && input.limit < components.length) components = components.slice(0, input.limit);
  const records = await verifyComponents(components, {
    declaredSource: "lockfile",
    concurrency: options.concurrency ?? 8,
    verify: verifyOptions(options),
    ...options.registryUrl ? { registryUrl: options.registryUrl } : {}
  });
  const results = records.map((r) => ({ purl: r.purl, ...fromRecord(r) }));
  const attention = results.filter((r) => r.verdict === "revoked" || r.mismatch || r.degraded || r.authorCpoaRevoked !== false);
  const summary = { ...summarize(records), distinct, checked: records.length };
  const failed = summary.revoked > 0 || summary.mismatch > 0;
  const advice = failed ? "At least one package is revoked or its bytes differ from what is attested. Do not install or ship this lockfile; report the packages in attention." : attention.length > 0 ? "Nothing revoked or mismatched, but some answers need attention (degraded, or a revoked author). Refuse in a release or deploy step." : "Nothing revoked or mismatched. Unregistered packages are common and are not a failure for a dependency check.";
  return {
    action: failed ? "refuse" : attention.length > 0 ? "caution" : "proceed",
    advice,
    summary,
    attention,
    ...input.details ? { components: results } : {}
  };
}

// ../lib/version.ts
var fs2 = __toESM(require("fs"));
var path2 = __toESM(require("path"));
function packageVersion() {
  for (const candidate of [path2.join(__dirname, "..", "package.json"), path2.join(__dirname, "..", "..", "package.json")]) {
    try {
      const pkg = JSON.parse(fs2.readFileSync(candidate, "utf8"));
      if (pkg.name === "@coderoot-eth/verify" && pkg.version) return pkg.version;
    } catch {
    }
  }
  return "0.0.0";
}

// src/server.ts
var readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };
function reply(result) {
  return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], structuredContent: result };
}
function failure(error) {
  return { isError: true, content: [{ type: "text", text: error.message }] };
}
function createServer(options = {}) {
  const server = new import_mcp.McpServer({ name: "coderoot", version: packageVersion() });
  server.registerTool(
    "verify_package",
    {
      title: "Verify an npm package version",
      description: "Download an npm package version, hash its tarball, and check those bytes against CodeRoot attestations. Use before adding or upgrading a dependency. Returns the verdict, what to do (action), and the EAS attestations behind it.",
      inputSchema: { name: import_zod.z.string().min(1).describe("npm package name, e.g. axios or @scope/pkg"), version: import_zod.z.string().min(1).describe("exact version, e.g. 1.7.9") },
      annotations: readOnly
    },
    async ({ name, version }) => {
      try {
        return reply(await checkPackage(name, version, options));
      } catch (error) {
        return failure(error);
      }
    }
  );
  server.registerTool(
    "verify_hash",
    {
      title: "Verify a digest",
      description: "Check one tagged digest (sha256:<hex> or sha512:<hex>) against CodeRoot attestations. Use when you hold a digest from a lockfile, a registry or your own hashing. Never pass a digest copied from an SBOM.",
      inputSchema: {
        digest: import_zod.z.string().regex(/^(sha256:[0-9a-fA-F]{64}|sha512:[0-9a-fA-F]{128})$/).describe("tagged digest"),
        source: import_zod.z.enum(["lockfile", "registry", "bytes"]).default("lockfile").describe("where the digest came from")
      },
      annotations: readOnly
    },
    async ({ digest, source }) => {
      try {
        return reply(await checkHash(digest, source, options));
      } catch (error) {
        return failure(error);
      }
    }
  );
  server.registerTool(
    "verify_lockfile",
    {
      title: "Verify a package-lock.json",
      description: "Check every package in an npm package-lock.json (lockfileVersion 2 or 3). Returns a summary, the packages that need attention (revoked, mismatched, degraded), and an action for the whole lockfile. Give a path to the file or its content.",
      inputSchema: {
        path: import_zod.z.string().optional().describe("path to package-lock.json or npm-shrinkwrap.json"),
        content: import_zod.z.string().optional().describe("the lockfile JSON, instead of a path"),
        limit: import_zod.z.number().int().positive().optional().describe("check only the first N distinct packages"),
        details: import_zod.z.boolean().default(false).describe("include the result for every package")
      },
      annotations: readOnly
    },
    async ({ path: path3, content, limit, details }) => {
      try {
        return reply(await checkLockfile({ ...path3 ? { path: path3 } : {}, ...content !== void 0 ? { content } : {}, ...limit ? { limit } : {}, details }, options));
      } catch (error) {
        return failure(error);
      }
    }
  );
  return server;
}

// src/main.ts
async function main() {
  const server = createServer({
    ...process.env["CODEROOT_VERIFY_URL"] ? { verifyUrl: process.env["CODEROOT_VERIFY_URL"] } : {},
    ...process.env["CODEROOT_NPM_REGISTRY"] ? { registryUrl: process.env["CODEROOT_NPM_REGISTRY"] } : {}
  });
  await server.connect(new import_stdio.StdioServerTransport());
}
main().catch((error) => {
  process.stderr.write(`coderoot-mcp: ${error.message}
`);
  process.exit(1);
});
/*! Bundled license information:

@noble/hashes/esm/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
