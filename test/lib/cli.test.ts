/**
 * Dispatcher tests for `coderoot verify`.
 *
 * These run the real entry points against a local stub rather than the live
 * endpoint, and assert the exit codes a deploy script depends on. The two
 * mappings differ deliberately - see bin/coderoot.ts.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as http from 'http';
import { AddressInfo } from 'net';
import { runVerifyHash } from '../../bin/verify-hash';
import { runVerifySbom } from '../../bin/verify-sbom';

const ATTESTED = '634e3ed585d7c8857f00cb7556f79422614e8defd008f8bb34b6018c1faefa0f';
const REVOKED = 'a'.repeat(64);
// Verify answered, but could not read the gate's revocations.
const GATE_UNREAD_VERIFIED = '9'.repeat(64);
const GATE_UNREAD_UNREGISTERED = '8'.repeat(64);
const GATE_UNREAD_REVOKED = '7'.repeat(64);
const gateUnread = { degraded: true, gateRevocation: { checked: false, revoked: null, releaseIds: [], note: 'HTTP 500' } };

let server: http.Server;
let baseUrl: string;
let logged: string[] = [];
let spies: jest.SpyInstance[] = [];

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url ?? '');
    res.writeHead(200, { 'content-type': 'application/json' });
    if (url.includes(ATTESTED)) {
      res.end(
        JSON.stringify({
          verdict: 'verified',
          contentHash: `0x${ATTESTED}`,
          totalAttestations: 2,
          // Live shape: a flat list across both eras, plus the
          // legacy per-era arrays that only enrich a UID.
          attestationUids: [`0x${'e'.repeat(64)}`, `0x${'f'.repeat(64)}`],
          v1Attestations: [{ id: `0x${'e'.repeat(64)}`, attester: '0xabc', revokedOnChain: false }],
        })
      );
    } else if (url.includes(REVOKED)) {
      res.end(JSON.stringify({ verdict: 'revoked', totalAttestations: 1, revokedAttestations: 1 }));
    } else if (url.includes(GATE_UNREAD_VERIFIED)) {
      res.end(JSON.stringify({ verdict: 'verified', totalAttestations: 1, ...gateUnread }));
    } else if (url.includes(GATE_UNREAD_UNREGISTERED)) {
      res.end(JSON.stringify({ verdict: 'unregistered', totalAttestations: 0, ...gateUnread }));
    } else if (url.includes(GATE_UNREAD_REVOKED)) {
      // The chain said revoked, so the endpoint does not mark it degraded; a
      // client must still refuse even if it ever did.
      res.end(JSON.stringify({ verdict: 'revoked', totalAttestations: 1, revokedAttestations: 1, ...gateUnread }));
    } else {
      res.end(JSON.stringify({ verdict: 'unregistered', totalAttestations: 0 }));
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

beforeEach(() => {
  logged = [];
  const capture = (...args: unknown[]) => {
    logged.push(args.join(' '));
  };
  spies = [
    jest.spyOn(console, 'log').mockImplementation(capture),
    jest.spyOn(console, 'error').mockImplementation(capture),
    jest.spyOn(process.stdout, 'write').mockImplementation(((chunk: string) => {
      logged.push(String(chunk));
      return true;
    }) as never),
    jest.spyOn(process.stderr, 'write').mockImplementation(((chunk: string) => {
      logged.push(String(chunk));
      return true;
    }) as never),
  ];
});

afterEach(() => {
  for (const spy of spies) spy.mockRestore();
});

describe('coderoot verify --hash (the deploy-time check)', () => {
  it('exits 0 on an attested digest', async () => {
    const code = await runVerifyHash(['--hash', `sha256:${ATTESTED}`, '--base-url', baseUrl, '--no-cache']);
    expect(code).toBe(0);
    expect(logged.join('\n')).toContain('verified');
  });

  it('exits 1 on a revoked digest', async () => {
    const code = await runVerifyHash(['--hash', `sha256:${REVOKED}`, '--base-url', baseUrl, '--no-cache']);
    expect(code).toBe(1);
  });

  it('exits 2 on an unregistered digest - no record is not a pass', async () => {
    const code = await runVerifyHash(['--hash', `sha256:${'c'.repeat(64)}`, '--base-url', baseUrl, '--no-cache']);
    expect(code).toBe(2);
  });

  it('exits 3 when no input is given', async () => {
    expect(await runVerifyHash([])).toBe(3);
  });

  it('queries sha512 directly - the endpoint no longer rejects it', async () => {
    // 'd'.repeat(128), not 'a': the stub's REVOKED fixture is 'a'.repeat(64),
    // a substring of 'a'.repeat(128), which would false-match.
    const code = await runVerifyHash([
      '--hash', `sha512:${'d'.repeat(128)}`, '--base-url', baseUrl, '--no-cache',
    ]);
    // No sha512 fixture in this stub, so it falls to unregistered - exit 2.
    expect(code).toBe(2);
  });

  it('refuses --hash and --file together rather than guessing', async () => {
    expect(await runVerifyHash(['--hash', `sha256:${ATTESTED}`, '--file', '/tmp/x'])).toBe(3);
  });

  it('reports the EAS uid, so the record can be re-checked without CodeRoot', async () => {
    await runVerifyHash(['--hash', `sha256:${ATTESTED}`, '--base-url', baseUrl, '--no-cache', '--json']);
    expect(logged.join('\n')).toContain(`0x${'e'.repeat(64)}`);
  });
});

describe('--json digests array (sha256-only vs sha512-only vs --file)', () => {
  it('a sha512 --hash reports only the sha512 digest, no empty sha256 entry', async () => {
    await runVerifyHash([
      '--hash', `sha512:${'d'.repeat(128)}`, '--base-url', baseUrl, '--no-cache', '--json',
    ]);
    const out = logged.join('\n');
    const json = JSON.parse(out.slice(out.indexOf('{'), out.lastIndexOf('}') + 1));
    expect(json.digests).toEqual([`sha512:${'d'.repeat(128)}`]);
  });

  it('a sha256 --hash reports only the sha256 digest', async () => {
    await runVerifyHash(['--hash', `sha256:${ATTESTED}`, '--base-url', baseUrl, '--no-cache', '--json']);
    const out = logged.join('\n');
    const json = JSON.parse(out.slice(out.indexOf('{'), out.lastIndexOf('}') + 1));
    expect(json.digests).toEqual([`sha256:${ATTESTED}`]);
  });

  it('--file reports both digests, computed from the one read', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-file-'));
    const file = path.join(dir, 'artifact.bin');
    fs.writeFileSync(file, 'test artifact bytes');
    await runVerifyHash(['--file', file, '--base-url', baseUrl, '--no-cache', '--json']);
    const out = logged.join('\n');
    const json = JSON.parse(out.slice(out.indexOf('{'), out.lastIndexOf('}') + 1));
    expect(json.digests).toHaveLength(2);
    expect(json.digests[0]).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(json.digests[1]).toMatch(/^sha512:[0-9a-f]{128}$/);
  });
});

describe('--source (how a --hash digest was obtained)', () => {
  it('defaults to lockfile when --source is not given', async () => {
    await runVerifyHash(['--hash', `sha256:${ATTESTED}`, '--base-url', baseUrl, '--no-cache', '--json']);
    const out = logged.join('\n');
    const json = JSON.parse(out.slice(out.indexOf('{'), out.lastIndexOf('}') + 1));
    expect(json.hashSource).toBe('lockfile');
  });

  it('--source registry labels an image digest correctly, not lockfile', async () => {
    await runVerifyHash([
      '--hash', `sha256:${ATTESTED}`, '--source', 'registry', '--base-url', baseUrl, '--no-cache', '--json',
    ]);
    const out = logged.join('\n');
    const json = JSON.parse(out.slice(out.indexOf('{'), out.lastIndexOf('}') + 1));
    expect(json.hashSource).toBe('registry');
  });

  it('rejects an invalid --source as a usage error', async () => {
    const code = await runVerifyHash(['--hash', `sha256:${ATTESTED}`, '--source', 'sbom-hint']);
    expect(code).toBe(3);
    expect(logged.join('\n')).toMatch(/--source must be one of/);
  });
});

describe('coderoot verify --sbom (batch)', () => {
  const sbom = require.resolve('../fixtures/sbom/cyclonedxnpm-extref.cyclonedx.json');

  it('exits 0 offline, with nothing queried', async () => {
    // Offline, every component falls to sbom-hint and none is queried.
    const code = await runVerifySbom(['--sbom', sbom, '--offline']);
    expect(code).toBe(0);
    expect(logged.join('\n')).toContain('not queried');
  });

  it('exits 3 when --sbom is missing', async () => {
    expect(await runVerifySbom([])).toBe(3);
  });

  it('exits 3 on a file that is not there', async () => {
    expect(await runVerifySbom(['--sbom', '/nonexistent/bom.json'])).toBe(3);
  });
});

describe('--agent-id is rejected locally', () => {
  it('exits 3 and points at the gateway', async () => {
    // Only the AgentRoot gateway can sign the per-request assertion, so a CLI
    // that accepted this could only ever build a request the gate refuses.
    const code = await runVerifyHash(['--agent-id', 'agent-123', '--hash', `sha256:${ATTESTED}`]);
    expect(code).toBe(3);
    expect(logged.join('\n')).toMatch(/AgentRoot gateway/i);
    expect(logged.join('\n')).toMatch(/coderoot_submit/);
  });
});

describe('attestationUids (the supported field)', () => {
  it('prefers the flat list over the per-era arrays', async () => {
    await runVerifyHash(['--hash', `sha256:${ATTESTED}`, '--base-url', baseUrl, '--no-cache', '--json']);
    const out = logged.join('\n');
    // The stub returns two UIDs in attestationUids; both must reach the output.
    expect(out).toContain(`0x${'e'.repeat(64)}`);
    expect(out).toContain(`0x${'f'.repeat(64)}`);
  });
});

describe('item 2 done-condition: the four cases, end to end', () => {
  // The priorities page names exactly these four. Two were covered only at the
  // verdict layer before; a deploy script depends on the CLI's exit code, so
  // they are asserted here through the real entry point.
  const dead = 'http://127.0.0.1:1'; // nothing listens

  it('exits 0 on an attested hash', async () => {
    expect(
      await runVerifyHash(['--hash', `sha256:${ATTESTED}`, '--base-url', baseUrl, '--no-cache'])
    ).toBe(0);
  });

  it('exits non-zero on unregistered and on revoked', async () => {
    expect(
      await runVerifyHash(['--hash', `sha256:${'c'.repeat(64)}`, '--base-url', baseUrl, '--no-cache'])
    ).not.toBe(0);
    expect(
      await runVerifyHash(['--hash', `sha256:${REVOKED}`, '--base-url', baseUrl, '--no-cache'])
    ).not.toBe(0);
  });

  it('exits 4 on an unreachable endpoint for an unknown hash - a release job refuses', async () => {
    const code = await runVerifyHash([
      '--hash', `sha256:${'d'.repeat(64)}`, '--base-url', dead, '--no-cache', '--json',
    ]);
    expect(code).toBe(4);
    const out = logged.join('\n');
    expect(out).toMatch(/unreachable/i);
    // The message goes to stderr and the report to stdout; the capture here
    // merges both, so pick the JSON object out rather than parsing the lot.
    const json = JSON.parse(out.slice(out.indexOf('{'), out.lastIndexOf('}') + 1));
    expect(json.degraded).toBe(true);
    expect(json.unreachable).toBe(true);
    expect(json.exitCode).toBe(4);
  });

  it('--warn-on-degraded keeps the old fail-open for a job that only needs a warning', async () => {
    const code = await runVerifyHash([
      '--hash', `sha256:${'d'.repeat(64)}`, '--base-url', dead, '--no-cache', '--warn-on-degraded',
    ]);
    expect(code).toBe(0);
    expect(logged.join('\n')).toMatch(/warning: the verify endpoint was unreachable; passing anyway/);
  });

  it('exits non-zero on an unreachable endpoint for a hash it has seen revoked', async () => {
    // An outage must not become a way to ship a build you already revoked.
    const cacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-cache-'));
    const cacheFile = path.join(cacheDir, 'revoked.json');
    fs.writeFileSync(
      cacheFile,
      JSON.stringify({
        schema: 'coderoot.revoked-cache/v1',
        entries: [{ digest: `sha256:${REVOKED}`, seenAt: '2026-09-10T00:00:00.000Z' }],
      })
    );
    process.env['CODEROOT_REVOKED_CACHE'] = cacheFile;
    try {
      const code = await runVerifyHash(['--hash', `sha256:${REVOKED}`, '--base-url', dead]);
      expect(code).toBe(1);
      expect(logged.join('\n')).toMatch(/previously observed as revoked/i);
    } finally {
      delete process.env['CODEROOT_REVOKED_CACHE'];
    }
  });

  it('prints which case applied', async () => {
    // "print which case applied" is part of the done-condition: a silent pass
    // and a silent fail-open look identical in a CI log.
    await runVerifyHash(['--hash', `sha256:${'e'.repeat(64)}`, '--base-url', dead, '--no-cache']);
    expect(logged.join('\n')).toMatch(/endpoint unreachable|failed open/i);
  });
});

describe('degraded: verify answered but could not read the gate', () => {
  const run = (hash: string, ...extra: string[]) =>
    runVerifyHash(['--hash', `sha256:${hash}`, '--base-url', baseUrl, '--no-cache', ...extra]);
  const jsonOut = () => {
    const out = logged.join('\n');
    return JSON.parse(out.slice(out.indexOf('{'), out.lastIndexOf('}') + 1));
  };

  it('a verified answer that is degraded refuses with exit 4, and says why', async () => {
    expect(await run(GATE_UNREAD_VERIFIED, '--json')).toBe(4);
    const json = jsonOut();
    expect(json.verdict).toBe('verified');
    expect(json.degraded).toBe(true);
    expect(json.unreachable).toBe(false);
    expect(json.reason).toMatch(/could not read the gate's revocations \(HTTP 500\)/);
    expect(logged.join('\n')).toMatch(/error: verify could not read the gate's revocations.*Refusing \(exit 4\)/);
  });

  it('--warn-on-degraded lets it pass with a warning', async () => {
    expect(await run(GATE_UNREAD_VERIFIED, '--warn-on-degraded')).toBe(0);
    const out = logged.join('\n');
    expect(out).toMatch(/warning: verify could not read the gate's revocations; passing anyway/);
    expect(out).toMatch(/note {4}gate revocations could not be read; passed with a warning/);
  });

  it('an answer that already refuses keeps its own code: unregistered stays 2', async () => {
    expect(await run(GATE_UNREAD_UNREGISTERED)).toBe(2);
    expect(await run(GATE_UNREAD_UNREGISTERED, '--warn-on-degraded')).toBe(2);
  });

  it('revoked is 1 whatever else is said', async () => {
    expect(await run(GATE_UNREAD_REVOKED)).toBe(1);
    expect(await run(GATE_UNREAD_REVOKED, '--warn-on-degraded')).toBe(1);
  });

  it('an endpoint that predates the gate read (no degraded field) is not degraded', async () => {
    expect(await run(ATTESTED, '--json')).toBe(0);
    expect(jsonOut().degraded).toBe(false);
  });

  it('a batch run only warns: degraded components do not change its exit code', async () => {
    // npm's own integrity is queried (an SBOM-declared hash never is).
    // 64 bytes of 0x99 is '9' x 128 in hex, which the stub answers as degraded.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-lock-'));
    const lockfile = path.join(dir, 'package-lock.json');
    fs.writeFileSync(
      lockfile,
      JSON.stringify({
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': { name: 'app' },
          'node_modules/gated': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/gated/-/gated-1.0.0.tgz',
            integrity: `sha512-${Buffer.alloc(64, 0x99).toString('base64')}`,
          },
        },
      })
    );
    const code = await runVerifySbom(['--lockfile', lockfile, '--base-url', baseUrl]);
    expect(code).toBe(0);
    expect(logged.join('\n')).toMatch(/degraded \(not fully checked; warning only, never fails a batch\): 1/);
  });
});
