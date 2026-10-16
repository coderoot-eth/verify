/**
 * Tests for lib/image.ts (`coderoot hash --image`).
 *
 * `execFileSync` is mocked here so the suite does not depend on `crane` or network access;
 * the live behavior is exercised manually (see README) against
 * docker.io/library/node:20-alpine.
 */

import { execFileSync } from 'child_process';
import { resolveImageDigest, crossCheckAgainstCrane, realPlatforms } from '../../lib/image';

jest.mock('child_process', () => ({ execFileSync: jest.fn() }));

const mockedExec = execFileSync as jest.Mock;

const INDEX_MANIFEST = {
  mediaType: 'application/vnd.oci.image.index.v1+json',
  manifests: [
    { digest: 'sha256:' + 'a'.repeat(64), platform: { architecture: 'amd64', os: 'linux' } },
    { digest: 'sha256:' + 'b'.repeat(64), platform: { architecture: 'arm64', os: 'linux', variant: 'v8' } },
    {
      digest: 'sha256:' + 'c'.repeat(64),
      platform: { architecture: 'unknown', os: 'unknown' },
      annotations: { 'vnd.docker.reference.type': 'attestation-manifest' },
    },
  ],
};

const SINGLE_MANIFEST = { mediaType: 'application/vnd.oci.image.manifest.v1+json', config: {} };

beforeEach(() => {
  mockedExec.mockReset();
});

describe('realPlatforms', () => {
  it('drops attestation-manifest entries and unknown-platform entries', () => {
    const filtered = realPlatforms(INDEX_MANIFEST.manifests);
    expect(filtered).toHaveLength(2);
    expect(filtered.map((m) => m.platform?.architecture)).toEqual(['amd64', 'arm64']);
  });
});

describe('resolveImageDigest', () => {
  it('resolves a multi-arch index to the index digest, filtering decoy entries', () => {
    mockedExec.mockReturnValue(Buffer.from(JSON.stringify(INDEX_MANIFEST)));
    const resolved = resolveImageDigest('example.com/multi:latest');
    expect(resolved.kind).toBe('index');
    expect(resolved.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(resolved.sha512).toMatch(/^sha512:[0-9a-f]{128}$/);
    expect(resolved.platformCount).toBe(2);
    expect(resolved.attestationManifestCount).toBe(1);
  });

  it('resolves a single-arch manifest to its own digest directly', () => {
    mockedExec.mockReturnValue(Buffer.from(JSON.stringify(SINGLE_MANIFEST)));
    const resolved = resolveImageDigest('example.com/single:latest');
    expect(resolved.kind).toBe('single');
    expect(resolved.platformCount).toBeUndefined();
  });

  it('throws when crane is not on PATH or the ref cannot be resolved', () => {
    mockedExec.mockImplementation(() => {
      throw new Error('exec: "crane": executable file not found in $PATH');
    });
    expect(() => resolveImageDigest('example.com/missing:latest')).toThrow(/crane manifest/);
  });

  it('throws on a manifest that is not valid JSON', () => {
    mockedExec.mockReturnValue(Buffer.from('not json'));
    expect(() => resolveImageDigest('example.com/bad:latest')).toThrow(/could not parse manifest/);
  });
});

describe('crossCheckAgainstCrane', () => {
  it('passes when crane digest agrees with the resolved answer', () => {
    mockedExec.mockReturnValue(Buffer.from(JSON.stringify(SINGLE_MANIFEST)));
    const resolved = resolveImageDigest('example.com/single:latest');
    mockedExec.mockReturnValue(resolved.digest + '\n');
    expect(crossCheckAgainstCrane('example.com/single:latest', resolved)).toBe(resolved.digest);
  });

  it('throws when crane digest disagrees - the finding a naive port would hide', () => {
    mockedExec.mockReturnValue(Buffer.from(JSON.stringify(SINGLE_MANIFEST)));
    const resolved = resolveImageDigest('example.com/single:latest');
    mockedExec.mockReturnValue(`sha256:${'9'.repeat(64)}\n`);
    expect(() => crossCheckAgainstCrane('example.com/single:latest', resolved)).toThrow(/digest mismatch/);
  });
});
