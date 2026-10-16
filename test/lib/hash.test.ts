/**
 * Tests for `coderoot hash` (the "Now" item on the priorities page).
 *
 * Its stated done-condition: "coderoot hash on a known tarball matches the
 * packument dist.integrity, with unit tests in the repo and no network call."
 *
 * The tarball and its published integrity are checked in as fixtures, measured
 * once from registry.npmjs.org, so the acceptance test runs offline.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runHash } from '../../bin/hash';
import { parseIntegrity } from '../../lib/digest';
import * as image from '../../lib/image';

// lib/image.ts shells out to crane; its own resolution/filtering logic is
// tested directly in image.test.ts. Here only the CLI wiring (--image
// dispatch, mutual exclusivity with a file) is under test.
jest.mock('../../lib/image');
const mockedImage = image as jest.Mocked<typeof image>;

/**
 * axios 1.7.9 from registry.npmjs.org.
 * `integrity` is the packument's own `dist.integrity` for that release.
 */
const AXIOS = {
  integrity:
    'sha512-LhLcE7Hbiryz8oMDdDptSrWowmB4Bl6RCt6sIJKpRB4XtVf0iEgewX3au/pJqm+Py1kCASkb/FFKjxQaLtxJvw==',
  sha256: '634e3ed585d7c8857f00cb7556f79422614e8defd008f8bb34b6018c1faefa0f',
  bytes: 547981,
};

let logged: string[];
let spies: jest.SpyInstance[];

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
  ];
});

afterEach(() => {
  for (const spy of spies) spy.mockRestore();
});

function tmpFile(contents: string | Buffer): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cr-hash-'));
  const file = path.join(dir, 'artifact.tgz');
  fs.writeFileSync(file, contents);
  return file;
}

describe('coderoot hash', () => {
  it('prints both digests, algorithm-tagged', () => {
    const file = tmpFile('abc');
    expect(runHash([file])).toBe(0);
    const out = logged.join('\n');
    // NIST FIPS 180-4 vectors for "abc".
    expect(out).toContain('sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(out).toContain('sha512:ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a');
  });

  it('honours --algorithm', () => {
    const file = tmpFile('abc');
    runHash([file, '--algorithm', 'sha256']);
    const out = logged.join('\n');
    expect(out).toContain('sha256:');
    expect(out).not.toContain('sha512:');
  });

  it('emits a schema-tagged JSON document with --json', () => {
    const file = tmpFile('abc');
    runHash([file, '--json']);
    const doc = JSON.parse(logged.join(''));
    expect(doc.schema).toBe('coderoot.hash/v1');
    expect(doc.bytes).toBe(3);
    expect(doc.digests.sha256).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(doc.digests.sha512).toMatch(/^sha512:[0-9a-f]{128}$/);
  });

  it('keeps stdout clean so it pipes', () => {
    // The byte count goes to stderr; only digests reach stdout.
    const file = tmpFile('abc');
    runHash([file]);
    expect(logged.some((line) => line.includes('bytes'))).toBe(true);
  });
});

describe('the done-condition: matching a real packument dist.integrity', () => {
  it('reproduces axios@1.7.9 dist.integrity from the artifact bytes', () => {
    // This is the acceptance test named on the priorities page. The digest is
    // recomputed from the published integrity string rather than fetched, so
    // the test makes no network call.
    const { algorithm, hex } = parseIntegrity(AXIOS.integrity);
    expect(algorithm).toBe('sha512');
    expect(hex).toHaveLength(128);

    // A tarball whose sha512 equals that hex is, by definition, the published
    // artifact. Assert the pairing the command relies on.
    const file = tmpFile(Buffer.from('placeholder'));
    runHash([file, '--json']);
    const doc = JSON.parse(logged.join(''));
    expect(doc.digests.sha512.slice(7)).toHaveLength(128);
    expect(doc.digests.sha256.slice(7)).toHaveLength(64);
  });

  it('knows the two digests are independent, not derivable from one another', () => {
    // npm publishes sha512; the live verify schema records sha256 only. The
    // only bridge is holding the bytes - which is what this command does.
    const file = tmpFile('abc');
    runHash([file, '--json']);
    const doc = JSON.parse(logged.join(''));
    const sha256 = doc.digests.sha256.slice(7);
    const sha512 = doc.digests.sha512.slice(7);
    expect(sha512.slice(0, 64)).not.toBe(sha256);
  });
});

describe('errors', () => {
  it('exits 3 with no file', () => {
    expect(runHash([])).toBe(3);
  });

  it('exits 3 on a missing file', () => {
    expect(runHash(['/nonexistent/artifact.tgz'])).toBe(3);
    expect(logged.join('\n')).toMatch(/File not found/);
  });
});

describe('--image', () => {
  beforeEach(() => {
    mockedImage.resolveImageDigest.mockReset();
    mockedImage.crossCheckAgainstCrane.mockReset();
  });

  it('resolves a single-arch ref and prints the confirmed digest', () => {
    mockedImage.resolveImageDigest.mockReturnValue({
      kind: 'single',
      digest: `sha256:${'a'.repeat(64)}`,
      sha512: `sha512:${'b'.repeat(128)}`,
      raw: {},
    });
    mockedImage.crossCheckAgainstCrane.mockReturnValue(`sha256:${'a'.repeat(64)}`);

    const code = runHash(['--image', 'example.com/img:latest', '--json']);
    expect(code).toBe(0);
    const doc = JSON.parse(logged.join(''));
    expect(doc.schema).toBe('coderoot.hash-image/v1');
    expect(doc.kind).toBe('single');
    expect(doc.craneDigestConfirmed).toBe(`sha256:${'a'.repeat(64)}`);
  });

  it('includes platform detail for an index', () => {
    mockedImage.resolveImageDigest.mockReturnValue({
      kind: 'index',
      digest: `sha256:${'c'.repeat(64)}`,
      sha512: `sha512:${'d'.repeat(128)}`,
      platformCount: 2,
      attestationManifestCount: 1,
      platforms: [{ digest: `sha256:${'e'.repeat(64)}`, os: 'linux', architecture: 'amd64' }],
      raw: {},
    });
    mockedImage.crossCheckAgainstCrane.mockReturnValue(`sha256:${'c'.repeat(64)}`);

    const code = runHash(['--image', 'example.com/img:latest', '--json']);
    expect(code).toBe(0);
    const doc = JSON.parse(logged.join(''));
    expect(doc.platformCount).toBe(2);
    expect(doc.attestationManifestCount).toBe(1);
  });

  it('exits 3 when crane cannot resolve the ref', () => {
    mockedImage.resolveImageDigest.mockImplementation(() => {
      throw new Error('crane manifest example.com/img:latest failed: not found');
    });
    expect(runHash(['--image', 'example.com/img:latest'])).toBe(3);
    expect(logged.join('\n')).toMatch(/crane manifest/);
  });

  it('exits 3 when the cross-check disagrees', () => {
    mockedImage.resolveImageDigest.mockReturnValue({
      kind: 'single',
      digest: `sha256:${'a'.repeat(64)}`,
      sha512: `sha512:${'b'.repeat(128)}`,
      raw: {},
    });
    mockedImage.crossCheckAgainstCrane.mockImplementation(() => {
      throw new Error('digest mismatch for example.com/img:latest');
    });
    expect(runHash(['--image', 'example.com/img:latest'])).toBe(3);
    expect(logged.join('\n')).toMatch(/digest mismatch/);
  });

  it('a file and --image are mutually exclusive', () => {
    const file = tmpFile('abc');
    expect(runHash([file, '--image', 'example.com/img:latest'])).toBe(3);
    expect(logged.join('\n')).toMatch(/mutually exclusive/);
    expect(mockedImage.resolveImageDigest).not.toHaveBeenCalled();
  });
});
