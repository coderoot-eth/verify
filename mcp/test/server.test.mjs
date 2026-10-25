// Drives the built server (dist/main.js) over stdio with the SDK's own client,
// against a local stand-in for the verify endpoint and the npm registry.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const MAIN = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'main.js');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const sha512 = (b) => crypto.createHash('sha512').update(b).digest();
const UID = (c) => `0x${c.repeat(64)}`;

// Tarballs the stand-in registry serves, and what the endpoint says about each.
const TARBALLS = {
  'good@1.0.0': Buffer.from('good tarball'),
  'swapped@1.0.0': Buffer.from('bytes npm serves'),
  'bad@1.0.0': Buffer.from('revoked tarball'),
};
const VERIFIED = sha256(TARBALLS['good@1.0.0']);
const REVOKED = sha256(TARBALLS['bad@1.0.0']);
const DEGRADED = 'd'.repeat(64);

let stub;
let base;
const seen = [];
const clients = [];

function verifyAnswer(hex) {
  if (hex === VERIFIED) {
    return { verdict: 'verified', attestationUids: [UID('a')], v2Attestations: [{ id: UID('a'), attester: '0xb343', revokedOnChain: false, blockTimestamp: '1792584782', revokedAt: '0' }] };
  }
  if (hex === REVOKED) {
    return { verdict: 'revoked', attestationUids: [UID('b')], v2Attestations: [{ id: UID('b'), attester: '0xb343', revokedOnChain: true, blockTimestamp: '1792400000', revokedAt: '1792584600' }] };
  }
  if (hex === DEGRADED) return { verdict: 'verified', degraded: true, gateRevocation: { checked: false, note: 'gate unreachable' }, attestationUids: [UID('c')] };
  return { verdict: 'unregistered', attestationUids: [] };
}

before(async () => {
  stub = http.createServer((req, res) => {
    seen.push(req.url);
    const send = (status, body, type = 'application/json') => {
      res.writeHead(status, { 'content-type': type });
      res.end(type === 'application/json' ? JSON.stringify(body) : body);
    };
    const url = decodeURIComponent(req.url);
    let m;
    if ((m = /^\/verify\/sha(?:256|512):([0-9a-f]+)$/.exec(url))) return send(200, verifyAnswer(m[1]));
    if ((m = /^\/verify\/npm\/(.+)\/([^/]+)$/.exec(url))) {
      // The coordinate route: what is attested for this name and version.
      const attested = m[1] === 'swapped' ? 'f'.repeat(64) : sha256(TARBALLS[`${m[1]}@${m[2]}`] ?? Buffer.from(''));
      return send(200, { verdict: 'attested-bytes-unproven', contentHash: `0x${attested}` });
    }
    if ((m = /^\/registry\/tarballs\/(.+)$/.exec(url))) return send(200, TARBALLS[m[1]], 'application/octet-stream');
    if ((m = /^\/registry\/(.+)$/.exec(url))) {
      const versions = {};
      for (const key of Object.keys(TARBALLS)) {
        const [name, version] = key.split('@');
        if (name === m[1]) versions[version] = { dist: { tarball: `${base}/registry/tarballs/${key}` } };
      }
      return Object.keys(versions).length ? send(200, { versions }) : send(404, { error: 'not found' });
    }
    send(404, {});
  });
  await new Promise((resolve) => stub.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${stub.address().port}`;
});

// Close every server even when a test fails before its own close.
after(async () => {
  await Promise.allSettled(clients.map((c) => c.close()));
  stub.close();
});

async function connect(env = {}) {
  const client = new Client({ name: 'test', version: '0' });
  clients.push(client);
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [MAIN],
      env: { ...process.env, CODEROOT_VERIFY_URL: base, CODEROOT_NPM_REGISTRY: `${base}/registry`, ...env },
    })
  );
  return client;
}

const call = async (client, name, args) => client.callTool({ name, arguments: args });

test('three read-only tools, and nothing that attests or revokes', async () => {
  const client = await connect();
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name).sort(), ['verify_hash', 'verify_lockfile', 'verify_package']);
  for (const t of tools) assert.equal(t.annotations.readOnlyHint, true, t.name);
  await client.close();
});

test('verify_hash: each verdict maps to an action, with the attestation on EAS', async () => {
  const client = await connect();
  const verified = (await call(client, 'verify_hash', { digest: `sha256:${VERIFIED}` })).structuredContent;
  assert.equal(verified.verdict, 'verified');
  assert.equal(verified.action, 'proceed');
  assert.deepEqual(verified.attestations[0], {
    uid: UID('a'),
    attester: '0xb343',
    attestedAt: '2026-10-21T12:13:02.000Z',
    revokedAt: null,
    easUrl: `https://base-sepolia.easscan.org/attestation/view/${UID('a')}`,
  });

  const revoked = (await call(client, 'verify_hash', { digest: `sha256:${REVOKED}` })).structuredContent;
  assert.equal(revoked.verdict, 'revoked');
  assert.equal(revoked.action, 'refuse');
  assert.equal(revoked.attestations[0].revokedAt, '2026-10-21T12:10:00.000Z');

  const unregistered = (await call(client, 'verify_hash', { digest: `sha256:${'e'.repeat(64)}` })).structuredContent;
  assert.equal(unregistered.verdict, 'unregistered');
  assert.equal(unregistered.action, 'caution');

  const degraded = (await call(client, 'verify_hash', { digest: `sha256:${DEGRADED}` })).structuredContent;
  assert.equal(degraded.degraded, true);
  assert.equal(degraded.action, 'caution');
  await client.close();
});

test('verify_hash: an unreachable endpoint is degraded, never a pass', async () => {
  const client = await connect({ CODEROOT_VERIFY_URL: 'http://127.0.0.1:1' });
  const result = (await call(client, 'verify_hash', { digest: `sha256:${VERIFIED}` })).structuredContent;
  assert.equal(result.degraded, true);
  assert.notEqual(result.action, 'proceed');
  await client.close();
});

test('verify_hash: an untagged or malformed digest is refused before any request', async () => {
  const client = await connect();
  const before = seen.length;
  for (const digest of [VERIFIED, `md5:${'a'.repeat(32)}`, `sha256:${'a'.repeat(63)}`]) {
    const result = await call(client, 'verify_hash', { digest });
    assert.equal(result.isError, true, digest);
  }
  assert.equal(seen.length, before);
  await client.close();
});

test('verify_package: hashes the tarball npm serves, and flags bytes that differ from what is attested', async () => {
  const client = await connect();
  const good = (await call(client, 'verify_package', { name: 'good', version: '1.0.0' })).structuredContent;
  assert.equal(good.package, 'good@1.0.0');
  assert.equal(good.hashSource, 'bytes');
  assert.equal(good.queried, `sha256:${VERIFIED}`);
  assert.equal(good.action, 'proceed');
  assert.ok(seen.includes('/registry/tarballs/good@1.0.0'), 'the tarball was downloaded');

  const swapped = (await call(client, 'verify_package', { name: 'swapped', version: '1.0.0' })).structuredContent;
  assert.equal(swapped.mismatch, true);
  assert.equal(swapped.action, 'stop');

  const missing = (await call(client, 'verify_package', { name: 'nowhere', version: '1.0.0' })).structuredContent;
  assert.equal(missing.verdict, 'attested-bytes-unproven');
  assert.equal(missing.queried, null, 'a name and version alone are never sent as proof');
  assert.notEqual(missing.action, 'proceed');
  await client.close();
});

function lockfile(names) {
  const packages = { '': { name: 'app', version: '1.0.0' } };
  for (const [name, version, bytes] of names) {
    packages[`node_modules/${name}`] = { version, integrity: `sha512-${sha512(bytes).toString('base64')}` };
  }
  return JSON.stringify({ name: 'app', lockfileVersion: 3, packages });
}

test('verify_lockfile: a revoked package refuses the lockfile and is named in attention', async () => {
  const client = await connect();
  const content = lockfile([
    ['good', '1.0.0', TARBALLS['good@1.0.0']],
    ['bad', '1.0.0', TARBALLS['bad@1.0.0']],
  ]);
  const result = (await call(client, 'verify_lockfile', { content })).structuredContent;
  assert.equal(result.action, 'refuse');
  assert.equal(result.summary.revoked, 1);
  assert.deepEqual(result.attention.map((a) => a.purl), ['pkg:npm/bad@1.0.0']);
  assert.equal(result.components, undefined, 'per-package results only on request');

  const detailed = (await call(client, 'verify_lockfile', { content, details: true })).structuredContent;
  assert.equal(detailed.components.length, 2);
  await client.close();
});

test('verify_lockfile: unregistered packages alone do not fail a dependency check', async () => {
  const client = await connect();
  const many = Array.from({ length: 60 }, (_, i) => [`pkg${i}`, '1.0.0', Buffer.from(`pkg${i}`)]);
  const result = (await call(client, 'verify_lockfile', { content: lockfile(many) })).structuredContent;
  assert.equal(result.summary.checked, 60);
  assert.equal(result.summary.revoked, 0);
  assert.equal(result.action, 'proceed');

  const limited = (await call(client, 'verify_lockfile', { content: lockfile(many), limit: 5 })).structuredContent;
  assert.equal(limited.summary.checked, 5);
  assert.equal(limited.summary.distinct, 60);
  await client.close();
});

test('verify_lockfile: a partial scan is never proceed, even when everything checked is clean', async () => {
  const client = await connect();
  // Good first, revoked second: limit 1 checks only the good one.
  const content = lockfile([
    ['good', '1.0.0', TARBALLS['good@1.0.0']],
    ['bad', '1.0.0', TARBALLS['bad@1.0.0']],
  ]);
  const partial = (await call(client, 'verify_lockfile', { content, limit: 1 })).structuredContent;
  assert.equal(partial.complete, false);
  assert.equal(partial.summary.checked, 1);
  assert.equal(partial.summary.distinct, 2);
  assert.equal(partial.summary.unchecked, 1);
  assert.equal(partial.summary.revoked, 0);
  assert.notEqual(partial.action, 'proceed');
  assert.match(partial.advice, /1 of 2 packages were not checked/);

  // A revoke among the checked packages still refuses a partial scan.
  const revokedFirst = lockfile([
    ['bad', '1.0.0', TARBALLS['bad@1.0.0']],
    ['good', '1.0.0', TARBALLS['good@1.0.0']],
  ]);
  assert.equal((await call(client, 'verify_lockfile', { content: revokedFirst, limit: 1 })).structuredContent.action, 'refuse');

  const full = (await call(client, 'verify_lockfile', { content })).structuredContent;
  assert.equal(full.complete, true);
  assert.equal(full.summary.unchecked, 0);
  assert.equal(full.action, 'refuse');
  await client.close();
});

test('verify_lockfile: a package whose bytes cannot be proven stops the whole lockfile', async () => {
  const client = await connect();
  // No integrity, and the registry does not know the package (as for a private dependency).
  const content = JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/private-dependency': { version: '1.0.0' } } });
  const result = (await call(client, 'verify_lockfile', { content, details: true })).structuredContent;
  assert.equal(result.complete, true);
  assert.equal(result.summary.notQueried, 1);
  assert.equal(result.components[0].action, 'stop');
  assert.equal(result.action, 'stop');
  assert.deepEqual(result.attention.map((a) => a.purl), ['pkg:npm/private-dependency@1.0.0']);

  // A revoked package still outranks it.
  const both = JSON.stringify({ lockfileVersion: 3, packages: {
    'node_modules/private-dependency': { version: '1.0.0' },
    'node_modules/bad': { version: '1.0.0', integrity: `sha512-${sha512(TARBALLS['bad@1.0.0']).toString('base64')}` },
  } });
  assert.equal((await call(client, 'verify_lockfile', { content: both })).structuredContent.action, 'refuse');
  await client.close();

  // The same with the registry and the endpoint both unreachable.
  const offline = await connect({ CODEROOT_VERIFY_URL: 'http://127.0.0.1:1', CODEROOT_NPM_REGISTRY: 'http://127.0.0.1:1' });
  const unreachable = (await call(offline, 'verify_lockfile', { content })).structuredContent;
  assert.equal(unreachable.action, 'stop');
  assert.equal(unreachable.attention.length, 1);
  await offline.close();
});

test('verify_lockfile: malformed input and paths that are not a lockfile are errors', async () => {
  const client = await connect();
  assert.equal((await call(client, 'verify_lockfile', { content: '{ not json' })).isError, true);
  assert.equal((await call(client, 'verify_lockfile', { content: '{"lockfileVersion":1}' })).isError, true);
  assert.equal((await call(client, 'verify_lockfile', { path: '/etc/hosts' })).isError, true);
  assert.equal((await call(client, 'verify_lockfile', {})).isError, true);
  await client.close();
});
