/**
 * Tests for lib/verdict.ts.
 *
 * Runs against a local stub, never the live endpoint, matching the shapes
 * actually observed at verify.coderoot.app:
 *   /verify/npm/axios/1.7.9  -> attested-bytes-unproven (+ legacy status "Verified")
 *   /verify/<sha256>         -> verified
 *   /verify/sha512:<128 hex> -> 200, honestly answering what the index has.
 *                               A v1 record (indexed by sha256 only) comes
 *                               back unregistered; a v2 record answers
 *                               correctly.
 */

import * as http from 'http';
import { AddressInfo } from 'net';
import { verifyDigest, probeCoordinates, assertQueryable, compareContentHash } from '../../lib/verdict';
import { DigestSet } from '../../lib/digest';

const AXIOS_SHA256 = '634e3ed585d7c8857f00cb7556f79422614e8defd008f8bb34b6018c1faefa0f';
const REVOKED_SHA256 = 'a'.repeat(64);
const UNKNOWN_SHA256 = 'b'.repeat(64);
const AGENT_KILLED_SHA256 = 'c'.repeat(64);
const AGENT_CHAIN_UNREADABLE_SHA256 = 'd'.repeat(64);
// sha512 of a known v2-attested, revoked manifest, cross-checked against its
// sha256.
const SHA512_V2_FIXTURE =
  '28e2b5acdf1b2e49e332fccd25c2a1e7e7d090bab753a3b6446f2a351a6495c203cc62a0e29dc4e15b4f4468a085f624dd11af081ee441c045ff250cb80bf04d';

const digests = (sha256: string): DigestSet => ({ sha256, sha512: 'f'.repeat(128), bytes: 100 });

let server: http.Server;
let baseUrl: string;
let requests: string[] = [];

beforeAll(async () => {
  server = http.createServer((req, res) => {
    requests.push(req.url ?? '');
    const url = decodeURIComponent(req.url ?? '');
    const send = (code: number, body: unknown) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };

    // A sha512 query against a record only ever indexed by sha256 (v1) comes
    // back unregistered - the index's honest answer, not a rejection.
    // SHA512_V2_FIXTURE below is the one sha512 value this stub recognizes,
    // modeling a v2 record that IS indexed that way.
    if (url.includes(SHA512_V2_FIXTURE)) {
      return send(200, {
        verdict: 'revoked',
        totalAttestations: 1,
        revokedAttestations: 1,
        attestationUids: [`0x${'9a'.repeat(32)}`],
      });
    }
    if (url.includes('sha512:')) {
      return send(200, { verdict: 'unregistered', totalAttestations: 0 });
    }
    if (url.includes(AXIOS_SHA256)) {
      return send(200, {
        verdict: 'verified',
        contentHash: `0x${AXIOS_SHA256}`,
        totalAttestations: 1,
        revokedAttestations: 0,
        attestations: [{ id: `0x${'b1'.repeat(32)}`, attester: '0xf3ca', revokedOnChain: false }],
      });
    }
    if (url.includes(REVOKED_SHA256)) {
      return send(200, { verdict: 'revoked', totalAttestations: 1, revokedAttestations: 1 });
    }
    if (url.includes(AGENT_KILLED_SHA256)) {
      // Verdict stays verified (the bytes are still attested); the agent that
      // shipped them has since been killed.
      return send(200, {
        verdict: 'verified',
        totalAttestations: 1,
        authorCpoaRevoked: true,
        authorCpoaRevokedUids: [`0x${'e1'.repeat(32)}`],
      });
    }
    if (url.includes(AGENT_CHAIN_UNREADABLE_SHA256)) {
      return send(200, {
        verdict: 'verified',
        totalAttestations: 1,
        authorCpoaRevoked: null,
        authorCpoaRevokedUids: [],
      });
    }
    if (url.startsWith('/verify/npm/axios/')) {
      // The live coordinate route: legacy status says "Verified", verdict does not.
      return send(200, {
        verdict: 'attested-bytes-unproven',
        status: 'Verified',
        contentHash: `0x${AXIOS_SHA256}`,
        totalAttestations: 1,
      });
    }
    if (url.startsWith('/verify/npm/ghost/')) {
      return send(404, { error: 'not found' });
    }
    if (url.startsWith('/verify/npm/gated/')) {
      // Verify answered, but could not read the gate's revocations.
      return send(200, {
        verdict: 'attested-bytes-unproven',
        totalAttestations: 1,
        degraded: true,
        gateRevocation: { checked: false, revoked: null, releaseIds: [], note: 'no answer within 3000ms' },
      });
    }
    return send(200, { verdict: 'unregistered', totalAttestations: 0 });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));
beforeEach(() => {
  requests = [];
});

describe('verifyDigest', () => {
  it('returns verified when an acquired digest matches an attested record', async () => {
    const result = await verifyDigest(digests(AXIOS_SHA256), 'lockfile', { baseUrl });
    expect(result.verdict).toBe('verified');
    expect(result.queried).toBe(`sha256:${AXIOS_SHA256}`);
    expect(result.hashSource).toBe('lockfile');
  });

  it('queries with sha256 even though sha512 is present', async () => {
    await verifyDigest(digests(AXIOS_SHA256), 'registry', { baseUrl });
    expect(requests[0]).toContain('sha256%3A');
    expect(requests[0]).not.toContain('sha512');
  });

  it('defaults authorCpoaRevoked to false when the endpoint omits it', async () => {
    const result = await verifyDigest(digests(AXIOS_SHA256), 'lockfile', { baseUrl });
    expect(result.authorCpoaRevoked).toBe(false);
  });

  it('stays verified but flags authorCpoaRevoked when the authoring agent was killed', async () => {
    const result = await verifyDigest(digests(AGENT_KILLED_SHA256), 'lockfile', { baseUrl });
    expect(result.verdict).toBe('verified');
    expect(result.authorCpoaRevoked).toBe(true);
    expect(result.authorCpoaRevokedUids).toEqual([`0x${'e1'.repeat(32)}`]);
  });

  it('carries authorCpoaRevoked: null when the chain could not be read', async () => {
    const result = await verifyDigest(digests(AGENT_CHAIN_UNREADABLE_SHA256), 'lockfile', { baseUrl });
    expect(result.verdict).toBe('verified');
    expect(result.authorCpoaRevoked).toBeNull();
  });

  it('queries sha512 directly when it is the only digest held', async () => {
    // A sha512-only digest (chiefly a lockfile's own `integrity`) is queried
    // directly against a v2 record instead of being reported unqueryable.
    const sha512Only: DigestSet = { sha256: '', sha512: SHA512_V2_FIXTURE, bytes: 100 };
    const result = await verifyDigest(sha512Only, 'lockfile', { baseUrl });
    expect(result.queried).toBe(`sha512:${SHA512_V2_FIXTURE}`);
    expect(result.verdict).toBe('revoked');
    expect(requests).toHaveLength(1);
  });

  it('prefers sha256 over sha512 when both are held, to reach older v1-only records', async () => {
    const both: DigestSet = { sha256: AXIOS_SHA256, sha512: SHA512_V2_FIXTURE, bytes: 100 };
    const result = await verifyDigest(both, 'bytes', { baseUrl });
    expect(result.queried).toBe(`sha256:${AXIOS_SHA256}`);
  });

  it('a sha512 query against a sha256-only (v1) record honestly comes back unregistered', async () => {
    // Not a rejection any more - the index genuinely has nothing under that
    // key for a v1 record. Distinguishing this from "sha512 isn't accepted"
    // is the reason assertQueryable no longer blocks sha512 outright.
    const sha512Only: DigestSet = { sha256: '', sha512: 'c'.repeat(128), bytes: 100 };
    const result = await verifyDigest(sha512Only, 'lockfile', { baseUrl });
    expect(result.queried).toBe(`sha512:${'c'.repeat(128)}`);
    expect(result.verdict).toBe('unregistered');
  });

  it('never reports verified for an sbom-hint digest, and does not query at all', async () => {
    // A declared hash is not evidence. cdxgen's Go SHA-256 matches
    // nothing obtainable, so querying it would manufacture a false mismatch.
    const result = await verifyDigest(digests(AXIOS_SHA256), 'sbom-hint', { baseUrl });
    expect(result.verdict).toBe('attested-bytes-unproven');
    expect(result.queried).toBeNull();
    expect(requests).toHaveLength(0);
  });

  it('reports unregistered when no record exists', async () => {
    const result = await verifyDigest(digests(UNKNOWN_SHA256), 'registry', { baseUrl });
    expect(result.verdict).toBe('unregistered');
  });

  it('reports revoked and remembers it', async () => {
    const revokedCache = new Set<string>();
    const result = await verifyDigest(digests(REVOKED_SHA256), 'lockfile', { baseUrl, revokedCache });
    expect(result.verdict).toBe('revoked');
    expect(revokedCache.has(`sha256:${REVOKED_SHA256}`)).toBe(true);
  });

  it('every early-return branch sets authorCpoaRevoked explicitly, never leaves it undefined', async () => {
    const revokedCache = new Set<string>([`sha256:${REVOKED_SHA256}`]);
    const fromCache = await verifyDigest(digests(REVOKED_SHA256), 'lockfile', { baseUrl, revokedCache });
    expect(fromCache.authorCpoaRevoked).toBe(false);

    const noDigest = await verifyDigest(null, 'none', { baseUrl });
    expect(noDigest.authorCpoaRevoked).toBe(false);

    const sbomHint = await verifyDigest(digests(AXIOS_SHA256), 'sbom-hint', { baseUrl });
    expect(sbomHint.authorCpoaRevoked).toBe(false);

    const neitherDigest = await verifyDigest({ sha256: '', sha512: '', bytes: 0 }, 'lockfile', { baseUrl });
    expect(neitherDigest.authorCpoaRevoked).toBe(false);

    const unreachable = await verifyDigest(digests(UNKNOWN_SHA256), 'lockfile', {
      baseUrl: 'http://127.0.0.1:1',
    });
    expect(unreachable.authorCpoaRevoked).toBe(false);
  });

  it('handles a component with no obtainable digest without querying', async () => {
    const result = await verifyDigest(null, 'none', { baseUrl });
    expect(result.verdict).toBe('attested-bytes-unproven');
    expect(requests).toHaveLength(0);
  });
});

describe('unreachable endpoint (fail open, except known revoked)', () => {
  const dead = 'http://127.0.0.1:1'; // nothing listens here

  it('fails open for an unknown digest, and says so', async () => {
    const result = await verifyDigest(digests(UNKNOWN_SHA256), 'lockfile', {
      baseUrl: dead,
      timeoutMs: 1000,
    });
    expect(result.verdict).toBe('attested-bytes-unproven');
    expect(result.degraded).toBe(true);
    expect(result.reason).toMatch(/unreachable/i);
  });

  it('still reports revoked for a digest it has seen revoked before', async () => {
    const revokedCache = new Set([`sha256:${REVOKED_SHA256}`]);
    const result = await verifyDigest(digests(REVOKED_SHA256), 'lockfile', {
      baseUrl: dead,
      timeoutMs: 1000,
      revokedCache,
    });
    expect(result.verdict).toBe('revoked');
    expect(result.degraded).toBeUndefined();
  });
});

describe('probeCoordinates (Ruling 2)', () => {
  it('downgrades a "verified" coordinate answer to attested-bytes-unproven', async () => {
    // Even if the endpoint said verified, name@version is an index, not proof.
    const result = await probeCoordinates('npm', 'axios', '1.7.9', { baseUrl });
    expect(result.verdict).toBe('attested-bytes-unproven');
    expect(result.reason).toMatch(/not proof/i);
  });

  it('reports unregistered for unknown coordinates', async () => {
    const result = await probeCoordinates('npm', 'ghost', '9.9.9', { baseUrl });
    expect(result.verdict).toBe('unregistered');
  });

  it("carries the endpoint's degraded flag and its reason through", async () => {
    const result = await probeCoordinates('npm', 'gated', '1.0.0', { baseUrl });
    expect(result.degraded).toBe(true);
    expect(result.unreachable).toBeUndefined();
    expect(result.reason).toMatch(/could not read the gate's revocations \(no answer within 3000ms\)/);
  });

  it('an endpoint without the flag is not degraded', async () => {
    const result = await probeCoordinates('npm', 'axios', '1.7.9', { baseUrl });
    expect(result.degraded).toBeUndefined();
  });

  it('an unreachable endpoint is degraded and unreachable', async () => {
    const result = await probeCoordinates('npm', 'axios', '1.7.9', { baseUrl: 'http://127.0.0.1:1' });
    expect(result.degraded).toBe(true);
    expect(result.unreachable).toBe(true);
  });
});

describe('assertQueryable', () => {
  it('accepts sha256 in any accepted input form', () => {
    for (const input of [AXIOS_SHA256, `0x${AXIOS_SHA256}`, `sha256:${AXIOS_SHA256}`]) {
      expect(assertQueryable(input)).toBe(`sha256:${AXIOS_SHA256}`);
    }
  });

  it('accepts sha512 - the endpoint no longer rejects it', () => {
    expect(assertQueryable(`sha512:${'a'.repeat(128)}`)).toBe(`sha512:${'a'.repeat(128)}`);
  });
});

describe('attestation UIDs (client request 1)', () => {
  it('records the EAS uid so a third party can re-check without CodeRoot', async () => {
    const result = await verifyDigest(digests(AXIOS_SHA256), 'bytes', { baseUrl });
    expect(result.attestations?.[0]?.uid).toBe(`0x${'b1'.repeat(32)}`);
    expect(result.attestations?.[0]?.revokedOnChain).toBe(false);
  });

  it('omits the field entirely when the endpoint returns none', async () => {
    const result = await verifyDigest(digests(UNKNOWN_SHA256), 'registry', { baseUrl });
    expect(result.attestations).toBeUndefined();
  });
});

describe('compareContentHash (client request 2)', () => {
  it('flags a real disagreement between acquired bytes and the attested digest', () => {
    expect(compareContentHash('a'.repeat(64), `0x${'b'.repeat(64)}`)).toBe(true);
  });

  it('agrees across the 0x prefix and case', () => {
    expect(compareContentHash(AXIOS_SHA256, `0x${AXIOS_SHA256.toUpperCase()}`)).toBe(false);
  });

  it('treats a missing digest as nothing to compare, not a mismatch', () => {
    // No contentHash means the endpoint told us nothing - silence is not proof
    // of disagreement, and must never fail a build.
    expect(compareContentHash(AXIOS_SHA256, undefined)).toBe(false);
    expect(compareContentHash(AXIOS_SHA256, '')).toBe(false);
    expect(compareContentHash(AXIOS_SHA256, 'not-hex')).toBe(false);
  });
});
