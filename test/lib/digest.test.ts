/**
 * Tests for lib/digest.ts.
 *
 * The axios@1.7.9 constants below were measured from real bytes:
 * the tarball from registry.npmjs.org was downloaded once, and
 *   - sha512(bytes) reproduced the packument's `dist.integrity` exactly
 *   - sha256(bytes) reproduced the contentHash returned by
 *     https://verify.coderoot.app/verify/npm/axios/1.7.9
 * That pairing is the whole point of the module, so it is pinned here.
 * No network: the digests are constants, the bytes are not refetched.
 */

import {
  digestBuffer,
  digestFile,
  parseDigest,
  parseIntegrity,
  tagged,
  taggedPair,
} from '../../lib/digest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/** axios 1.7.9 tarball, measured. */
const AXIOS = {
  bytes: 547981,
  sha256: '634e3ed585d7c8857f00cb7556f79422614e8defd008f8bb34b6018c1faefa0f',
  integrity: 'sha512-LhLcE7Hbiryz8oMDdDptSrWowmB4Bl6RCt6sIJKpRB4XtVf0iEgewX3au/pJqm+Py1kCASkb/FFKjxQaLtxJvw==',
};

describe('digestBuffer', () => {
  it('computes both algorithms over the same bytes', () => {
    const set = digestBuffer(Buffer.from('abc'));
    // NIST FIPS 180-4 published vectors for "abc".
    expect(set.sha256).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(set.sha512).toBe(
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
        '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
    );
    expect(set.bytes).toBe(3);
  });

  it('handles empty input', () => {
    const set = digestBuffer(Buffer.alloc(0));
    expect(set.sha256).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(set.bytes).toBe(0);
  });
});

describe('digestFile', () => {
  it('hashes a file and reports its length', () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'digest-')), 'a.txt');
    fs.writeFileSync(file, 'abc');
    const set = digestFile(file);
    expect(set.sha256).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(set.bytes).toBe(3);
  });

  it('throws on a missing file', () => {
    expect(() => digestFile('/nonexistent/nope.tgz')).toThrow(/File not found/);
  });
});

describe('parseIntegrity', () => {
  it("decodes npm's sha512 integrity to the hex the registry attests", () => {
    const { algorithm, hex } = parseIntegrity(AXIOS.integrity);
    expect(algorithm).toBe('sha512');
    expect(hex).toHaveLength(128);
  });

  it('prefers sha512 when an SRI string carries several entries', () => {
    const sri = `sha256-${Buffer.from('a'.repeat(32)).toString('base64')} ${AXIOS.integrity}`;
    expect(parseIntegrity(sri).algorithm).toBe('sha512');
  });

  it('ignores sha1, which is never proof', () => {
    const sha1 = `sha1-${Buffer.from('a'.repeat(20)).toString('base64')}`;
    expect(() => parseIntegrity(sha1)).toThrow(/No sha256\/sha512 entry/);
  });
});

describe('parseDigest', () => {
  it('accepts every form the verify API accepts', () => {
    for (const input of [AXIOS.sha256, `0x${AXIOS.sha256}`, `sha256:${AXIOS.sha256}`]) {
      expect(parseDigest(input)).toEqual({ algorithm: 'sha256', hex: AXIOS.sha256 });
    }
  });

  it('infers sha512 from an untagged 128-hex digest', () => {
    expect(parseDigest('a'.repeat(128)).algorithm).toBe('sha512');
  });

  it('is case-insensitive and trims', () => {
    expect(parseDigest(`  SHA256:${AXIOS.sha256.toUpperCase()}  `).hex).toBe(AXIOS.sha256);
  });

  it('rejects a tagged digest whose length contradicts its tag', () => {
    // Never silently reinterpret: a mislabelled digest is an error, not a sha256.
    expect(() => parseDigest(`sha512:${AXIOS.sha256}`)).toThrow(/expected 128 hex/);
  });

  it('rejects unsupported algorithms rather than guessing from length', () => {
    // PyPI's blake2b_256 is also 64 hex - length must never imply sha256.
    expect(() => parseDigest(`blake2b_256:${AXIOS.sha256}`)).toThrow(/Unsupported algorithm/);
  });

  it('rejects non-hex and wrong lengths', () => {
    expect(() => parseDigest('z'.repeat(64))).toThrow(/non-hex/);
    expect(() => parseDigest('abc')).toThrow(/Invalid digest/);
    expect(() => parseDigest('')).toThrow(/Empty digest/);
  });
});

describe('tagged output', () => {
  it('renders the tagged hashes[] form, sha256 first', () => {
    expect(tagged('sha512', 'ff')).toBe('sha512:ff');
    const pair = taggedPair({ sha256: 'aa', sha512: 'bb', bytes: 1 });
    expect(pair).toEqual(['sha256:aa', 'sha512:bb']);
  });
});

describe('the SHA-256 / SHA-512 bridge', () => {
  it('derives both digests of one artifact from one read of its bytes', () => {
    // The API records SHA-256; npm publishes SHA-512. Neither converts to the
    // other - holding the bytes is the only way to have both.
    const bytes = Buffer.from('artifact contents');
    const set = digestBuffer(bytes);
    expect(set.sha256).toHaveLength(64);
    expect(set.sha512).toHaveLength(128);
    expect(set.sha256).not.toBe(set.sha512.slice(0, 64));
  });
});
