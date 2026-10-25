/**
 * Tests for bin/verify-sbom.ts: mismatch detection and the revoked cache,
 * matching what coderoot-action already does for the single-hash path.
 *
 * `acquire()` fetches the real npm registry, which a unit test must not do, so
 * `global.fetch` is stubbed with one fixed packument/tarball. The verify
 * endpoint is a local stub, same pattern as verdict.test.ts.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as http from 'http';
import { AddressInfo } from 'net';
import { runVerifySbom } from '../../bin/verify-sbom';

const FIXTURE = path.join(__dirname, '..', 'fixtures', 'sbom', 'single-npm-component.cyclonedx.json');
// This fixture's integrity is a random value that does not match TARBALL_BYTES
// below: deliberate, so it also serves as the lockfile-integrity mismatch case.
const LOCKFILE_FIXTURE = path.join(
  __dirname, '..', 'fixtures', 'sbom', 'single-npm-component.package-lock.json'
);
// This one's integrity is TARBALL_BYTES' real sha512, for the no-mismatch case.
const LOCKFILE_MATCHING_FIXTURE = path.join(
  __dirname, '..', 'fixtures', 'sbom', 'single-npm-component-matching.package-lock.json'
);
const TARBALL_BYTES = Buffer.from('demo package bytes');

function tarballSha256(): string {
  return require('crypto').createHash('sha256').update(TARBALL_BYTES).digest('hex');
}

let server: http.Server;
let baseUrl: string;
let verdictBody: Record<string, unknown> = {};
let coordinatesBody: Record<string, unknown> = {};
let realFetch: typeof fetch;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url ?? '');
    const send = (code: number, body: unknown) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (url.startsWith('/verify/npm/demo-pkg/')) return send(200, coordinatesBody);
    if (url.startsWith('/verify/sha256:')) return send(200, verdictBody);
    send(404, { error: 'not found' });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

beforeEach(() => {
  realFetch = global.fetch;
  verdictBody = { verdict: 'verified', totalAttestations: 1 };
  coordinatesBody = { verdict: 'attested-bytes-unproven', contentHash: `0x${tarballSha256()}` };

  global.fetch = jest.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url === 'https://registry.npmjs.org/demo-pkg') {
      return new Response(
        JSON.stringify({ versions: { '1.0.0': { dist: { tarball: 'https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz' } } } })
      );
    }
    if (url === 'https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz') {
      return new Response(TARBALL_BYTES);
    }
    // Everything else (the verify endpoint calls from lib/verdict.ts) goes to
    // the real fetch, which reaches the local stub server started above.
    return realFetch(input as never, init);
  }) as unknown as typeof fetch;
});

afterEach(() => {
  global.fetch = realFetch;
});

function tmpCachePath(): string {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-sbom-cache-')), 'revoked-cache.json');
}

describe('mismatch detection', () => {
  it('flags a mismatch when the acquired bytes disagree with the coordinate route', async () => {
    coordinatesBody = { verdict: 'attested-bytes-unproven', contentHash: `0x${'f'.repeat(64)}` };
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-sbom-')), 'report.json');
    const code = await runVerifySbom([
      '--sbom', FIXTURE, '--json', out, '--base-url', baseUrl, '--no-cache',
    ]);
    const report = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(report.records[0].mismatch).toBe(true);
    expect(report.summary.mismatch).toBe(1);
    expect(code).toBe(2);
  });

  it('does not flag a mismatch when the digests agree', async () => {
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-sbom-')), 'report.json');
    const code = await runVerifySbom([
      '--sbom', FIXTURE, '--json', out, '--base-url', baseUrl, '--no-cache',
    ]);
    const report = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(report.records[0].mismatch).toBeUndefined();
    expect(code).toBe(0);
  });

  it('never probes coordinates in --offline mode, so it cannot mismatch', async () => {
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-sbom-')), 'report.json');
    await runVerifySbom(['--sbom', FIXTURE, '--json', out, '--offline', '--no-cache']);
    expect(global.fetch).not.toHaveBeenCalled();
    const report = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(report.records[0].hashSource).toBe('none');
    expect(report.records[0].mismatch).toBeUndefined();
  });
});

describe('the revoked cache', () => {
  it('asks verify first: a live answer wins over a cached revoke', async () => {
    const cacheFile = tmpCachePath();
    fs.writeFileSync(
      cacheFile,
      JSON.stringify({
        schema: 'coderoot.revoked-cache/v1',
        entries: [{ digest: `sha256:${tarballSha256()}`, seenAt: new Date().toISOString() }],
      })
    );
    process.env['CODEROOT_REVOKED_CACHE'] = cacheFile;
    try {
      const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-sbom-')), 'report.json');
      const code = await runVerifySbom(['--sbom', FIXTURE, '--json', out, '--base-url', baseUrl]);
      const report = JSON.parse(fs.readFileSync(out, 'utf8'));
      expect(report.records[0].verdict).toBe('verified');
      expect(code).toBe(0);
    } finally {
      delete process.env['CODEROOT_REVOKED_CACHE'];
    }
  });

  it('fails a cached-revoked digest when verify cannot be read', async () => {
    const cacheFile = tmpCachePath();
    fs.writeFileSync(
      cacheFile,
      JSON.stringify({
        schema: 'coderoot.revoked-cache/v1',
        entries: [{ digest: `sha256:${tarballSha256()}`, seenAt: new Date().toISOString() }],
      })
    );
    process.env['CODEROOT_REVOKED_CACHE'] = cacheFile;
    try {
      const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-sbom-')), 'report.json');
      const code = await runVerifySbom(['--sbom', FIXTURE, '--json', out, '--base-url', 'http://127.0.0.1:1']);
      const report = JSON.parse(fs.readFileSync(out, 'utf8'));
      expect(report.records[0].verdict).toBe('revoked');
      expect(code).toBe(1);
    } finally {
      delete process.env['CODEROOT_REVOKED_CACHE'];
    }
  });

  it('--no-cache skips the cache even for a digest seen revoked before', async () => {
    const cacheFile = tmpCachePath();
    fs.writeFileSync(
      cacheFile,
      JSON.stringify({
        schema: 'coderoot.revoked-cache/v1',
        entries: [{ digest: `sha256:${tarballSha256()}`, seenAt: new Date().toISOString() }],
      })
    );
    process.env['CODEROOT_REVOKED_CACHE'] = cacheFile;
    try {
      const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-sbom-')), 'report.json');
      await runVerifySbom(['--sbom', FIXTURE, '--json', out, '--base-url', baseUrl, '--no-cache']);
      const report = JSON.parse(fs.readFileSync(out, 'utf8'));
      // The live stub still says verified; only the cache would have said otherwise.
      expect(report.records[0].verdict).toBe('verified');
    } finally {
      delete process.env['CODEROOT_REVOKED_CACHE'];
    }
  });

  it('records a live revocation into the cache for a later run to see', async () => {
    verdictBody = { verdict: 'revoked', totalAttestations: 1, revokedAttestations: 1 };
    const cacheFile = tmpCachePath();
    process.env['CODEROOT_REVOKED_CACHE'] = cacheFile;
    try {
      const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-sbom-')), 'report.json');
      await runVerifySbom(['--sbom', FIXTURE, '--json', out, '--base-url', baseUrl]);
      const saved = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
      expect(saved.entries.map((e: { digest: string }) => e.digest)).toContain(`sha256:${tarballSha256()}`);
    } finally {
      delete process.env['CODEROOT_REVOKED_CACHE'];
    }
  });
});

describe('--lockfile', () => {
  it('--sbom and --lockfile are mutually exclusive', async () => {
    const code = await runVerifySbom(['--sbom', FIXTURE, '--lockfile', LOCKFILE_FIXTURE]);
    expect(code).toBe(3);
  });

  it('is tagged npm-lockfile in the report, by its basename', async () => {
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-lock-')), 'report.json');
    await runVerifySbom(['--lockfile', LOCKFILE_FIXTURE, '--json', out, '--base-url', baseUrl, '--no-cache']);
    const report = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(report.source.format).toBe('npm-lockfile');
    expect(report.source.file).toBe('single-npm-component.package-lock.json');
  });

  it('prefers hashing the real tarball over the declared integrity when reachable', async () => {
    // acquire() always prefers bytes it can hash itself over a declared
    // record, lockfile or not - the whole point of the `bytes` tier ranking
    // above `lockfile`/`registry` in the tier order.
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-lock-')), 'report.json');
    await runVerifySbom(['--lockfile', LOCKFILE_FIXTURE, '--json', out, '--base-url', baseUrl, '--no-cache']);
    const report = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(report.records[0].hashSource).toBe('bytes');
    expect(report.records[0].queried).toBe(`sha256:${tarballSha256()}`);
  });

  it('flags a mismatch when the registry tarball disagrees with the lockfile integrity', async () => {
    // LOCKFILE_FIXTURE's integrity does not match TARBALL_BYTES.
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-lock-')), 'report.json');
    const code = await runVerifySbom([
      '--lockfile', LOCKFILE_FIXTURE, '--json', out, '--base-url', baseUrl, '--no-cache',
    ]);
    const report = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(report.records[0].mismatch).toBe(true);
    expect(report.summary.mismatch).toBe(1);
    expect(code).toBe(2);
  });

  it('does not flag a mismatch when the registry tarball matches the lockfile integrity', async () => {
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-lock-')), 'report.json');
    const code = await runVerifySbom([
      '--lockfile', LOCKFILE_MATCHING_FIXTURE, '--json', out, '--base-url', baseUrl, '--no-cache',
    ]);
    const report = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(report.records[0].mismatch).toBeUndefined();
    expect(code).toBe(0);
  });

  it('never compares against lockfile integrity for an SBOM input', async () => {
    // A declared hash from an SBOM is a hint, never evidence - this check is
    // --lockfile only. FIXTURE (the cyclonedx one) carries no declared hash
    // at all, so this would only regress silently; asserted explicitly.
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-lock-')), 'report.json');
    await runVerifySbom(['--sbom', FIXTURE, '--json', out, '--base-url', baseUrl, '--no-cache']);
    const report = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(report.records[0].mismatch).toBeUndefined();
  });

  it('falls back to the lockfile tier offline, never sbom-hint, and keeps the sha512', async () => {
    const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cr-lock-')), 'report.json');
    const code = await runVerifySbom([
      '--lockfile', LOCKFILE_FIXTURE, '--json', out, '--offline', '--no-cache',
    ]);
    expect(global.fetch).not.toHaveBeenCalled();
    const report = JSON.parse(fs.readFileSync(out, 'utf8'));
    expect(report.records[0].hashSource).toBe('lockfile');
    expect(report.records[0].digests[0]).toMatch(/^sha512:/);
    // Not queryable (sha512-only), not a failure either - a batch run only
    // fails on revoked/mismatch.
    expect(report.records[0].verdict).toBe('attested-bytes-unproven');
    expect(code).toBe(0);
  });
});
