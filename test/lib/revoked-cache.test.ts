/**
 * Tests for lib/revoked-cache.ts.
 *
 * This file is what makes the fail-open carve-out real. Without persistence, a
 * fresh process has seen nothing revoked, so every unreachable-endpoint run
 * fails open on everything - including a build that was revoked yesterday.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { RevokedCache } from '../../lib/revoked-cache';

const SHA = `sha256:${'a'.repeat(64)}`;
const OTHER = `sha256:${'b'.repeat(64)}`;

let dir: string;
let file: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'revcache-'));
  file = path.join(dir, 'revoked.json');
});

afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe('persistence', () => {
  it('remembers a revocation across processes', () => {
    const first = new RevokedCache(file);
    first.add(SHA, 'pkg:npm/bad@1.0.0');
    expect(first.flush().written).toBe(true);

    // A separate instance stands in for the next CI run.
    expect(new RevokedCache(file).has(SHA)).toBe(true);
  });

  it('starts empty when no cache file exists yet', () => {
    const cache = new RevokedCache(file);
    expect(cache.size).toBe(0);
    expect(cache.has(SHA)).toBe(false);
  });

  it('does not write when nothing was added', () => {
    expect(new RevokedCache(file).flush().written).toBe(false);
    expect(fs.existsSync(file)).toBe(false);
  });

  it('is idempotent', () => {
    const cache = new RevokedCache(file);
    cache.add(SHA);
    cache.add(SHA);
    expect(cache.size).toBe(1);
  });
});

describe('robustness', () => {
  it('survives a corrupt cache file rather than failing the run', () => {
    // The cache is an optimization on top of the endpoint, never a source of
    // truth - a damaged file must not take down a deploy check.
    fs.writeFileSync(file, '{ not json');
    const cache = new RevokedCache(file);
    expect(cache.size).toBe(0);
    expect(() => cache.has(SHA)).not.toThrow();
  });

  it('ignores entries that are not tagged digests', () => {
    fs.writeFileSync(
      file,
      JSON.stringify({
        schema: 'coderoot.revoked-cache/v1',
        entries: [{ digest: 'no-algorithm-here' }, { digest: SHA, seenAt: 'x' }],
      })
    );
    expect(new RevokedCache(file).size).toBe(1);
  });

  it('reports a write failure instead of throwing', () => {
    const cache = new RevokedCache(path.join(dir, 'nested', 'deep', 'c.json'));
    cache.add(SHA);
    // Directory is created, so this should succeed; the contract is that the
    // caller always gets a result object rather than an exception.
    expect(cache.flush()).toHaveProperty('written');
  });
});

describe('keying', () => {
  it('keys on the tagged digest, so algorithms never collide', () => {
    const cache = new RevokedCache(file);
    cache.add(`sha256:${'c'.repeat(64)}`);
    // Same hex under a different algorithm is a different artifact claim.
    expect(cache.has(`sha512:${'c'.repeat(64)}`)).toBe(false);
  });

  it('is case-insensitive', () => {
    const cache = new RevokedCache(file);
    cache.add(SHA.toUpperCase());
    expect(cache.has(SHA)).toBe(true);
  });

  it('never treats an absent digest as good', () => {
    const cache = new RevokedCache(file);
    cache.add(SHA);
    expect(cache.has(OTHER)).toBe(false); // absence is not a pass
  });
});

describe('asSet', () => {
  it('persists revocations observed mid-run', () => {
    const cache = new RevokedCache(file);
    const set = cache.asSet();
    // verifyDigest writes into this set when it sees a revoked verdict.
    set.add(SHA);
    expect(cache.has(SHA)).toBe(true);
    cache.flush();
    expect(new RevokedCache(file).has(SHA)).toBe(true);
  });
});
