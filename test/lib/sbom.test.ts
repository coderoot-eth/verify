/**
 * Tests for lib/sbom.ts.
 *
 * Fixtures are trimmed from real generator output, keeping the structures
 * that break parsers rather than synthetic shapes.
 */

import * as path from 'path';
import {
  parseSbom,
  parseSbomFile,
  parseLockfile,
  parseLockfileFile,
  distinctByPurl,
  strongestDeclared,
  SbomComponent,
} from '../../lib/sbom';

const fixture = (name: string) => path.join(__dirname, '..', 'fixtures', 'sbom', name);

describe('CycloneDX', () => {
  it('reads hashes from externalReferences, where cyclonedx-npm puts them', () => {
    // A parser reading only components[].hashes[] reports zero for this file.
    const sbom = parseSbomFile(fixture('cyclonedxnpm-extref.cyclonedx.json'));
    expect(sbom.format).toBe('cyclonedx');
    expect(sbom.components.length).toBeGreaterThan(0);

    const withHashes = sbom.components.filter((c) => c.declared.length > 0);
    expect(withHashes.length).toBe(sbom.components.length);

    const hash = withHashes[0].declared[0];
    expect(hash.path).toBe('externalReferences[].hashes[]');
    expect(hash.algorithm).toBe('sha512');
    expect(hash.hex).toHaveLength(128);
    // The reference type is what says which artifact the digest is of.
    expect(hash.refType).toBe('distribution');
  });

  it('URL-decodes the purl so scoped packages key correctly', () => {
    const sbom = parseSbomFile(fixture('cyclonedxnpm-extref.cyclonedx.json'));
    const scoped = sbom.components.find((c) => c.name.startsWith('@'));
    expect(scoped?.purl).toContain('@');
    expect(scoped?.purl).not.toContain('%40');
    expect(scoped?.ecosystem).toBe('npm');
  });

  it('walks nested components', () => {
    const doc = JSON.stringify({
      bomFormat: 'CycloneDX',
      components: [
        {
          purl: 'pkg:npm/outer@1.0.0',
          components: [{ purl: 'pkg:npm/inner@2.0.0' }],
        },
      ],
    });
    const purls = parseSbom(doc).components.map((c) => c.purl);
    expect(purls).toContain('pkg:npm/outer@1.0.0');
    expect(purls).toContain('pkg:npm/inner@2.0.0');
  });

  it('decodes base64 hash content as well as hex', () => {
    const hex = 'ab'.repeat(32);
    const doc = JSON.stringify({
      bomFormat: 'CycloneDX',
      components: [
        {
          purl: 'pkg:npm/a@1.0.0',
          hashes: [{ alg: 'SHA-256', content: Buffer.from(hex, 'hex').toString('base64') }],
        },
      ],
    });
    expect(parseSbom(doc).components[0].declared[0].hex).toBe(hex);
  });

  it('sets aside purl-less components instead of counting them as coverage', () => {
    // Syft's `type: file` entries: digests of files on disk, no identity to join.
    const doc = JSON.stringify({
      bomFormat: 'CycloneDX',
      components: [
        { name: 'some-file', type: 'file', hashes: [{ alg: 'SHA-256', content: 'ab'.repeat(32) }] },
        { purl: 'pkg:npm/real@1.0.0' },
      ],
    });
    const sbom = parseSbom(doc);
    expect(sbom.components).toHaveLength(1);
    expect(sbom.purllessCount).toBe(1);
    expect(sbom.purllessHashCount).toBe(1);
  });
});

describe('SPDX', () => {
  it('finds the purl in externalRefs', () => {
    const sbom = parseSbomFile(fixture('syft-purl.spdx.json'));
    expect(sbom.format).toBe('spdx');
    expect(sbom.components.length).toBeGreaterThan(0);
    expect(sbom.components[0].purl).toMatch(/^pkg:/);
  });

  it('reads packages[].checksums[] but never packageVerificationCode', () => {
    const doc = JSON.stringify({
      spdxVersion: 'SPDX-2.3',
      packages: [
        {
          name: 'a',
          versionInfo: '1.0.0',
          externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/a@1.0.0' }],
          checksums: [{ algorithm: 'SHA256', checksumValue: 'cd'.repeat(32) }],
          // A hash over a file set, not of the published artifact - must be ignored.
          packageVerificationCode: { packageVerificationCodeValue: 'ff'.repeat(20) },
        },
      ],
    });
    const declared = parseSbom(doc).components[0].declared;
    expect(declared).toHaveLength(1);
    expect(declared[0].path).toBe('packages[].checksums[]');
    expect(declared[0].hex).toBe('cd'.repeat(32));
  });

  it('unwraps the GitHub dependency-graph envelope', () => {
    const doc = JSON.stringify({
      sbom: {
        spdxVersion: 'SPDX-2.3',
        packages: [
          {
            name: 'a',
            externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/a@1.0.0' }],
          },
        ],
      },
    });
    expect(parseSbom(doc).components[0].purl).toBe('pkg:npm/a@1.0.0');
  });
});

describe('distinctByPurl', () => {
  it('counts packages, not occurrences', () => {
    const components: SbomComponent[] = [
      { purl: 'pkg:npm/a@1.0.0', ecosystem: 'npm', name: 'a', version: '1.0.0', declared: [] },
      { purl: 'pkg:npm/a@1.0.0', ecosystem: 'npm', name: 'a', version: '1.0.0', declared: [] },
      { purl: 'pkg:npm/a@2.0.0', ecosystem: 'npm', name: 'a', version: '2.0.0', declared: [] },
    ];
    // Two versions of one name are two packages; the duplicate occurrence is one.
    expect(distinctByPurl(components)).toHaveLength(2);
  });

  it('keeps the occurrence that carries a hash', () => {
    const bare: SbomComponent = {
      purl: 'pkg:npm/a@1.0.0', ecosystem: 'npm', name: 'a', version: '1.0.0', declared: [],
    };
    const rich: SbomComponent = {
      ...bare,
      declared: [{ algorithm: 'sha512', hex: 'f'.repeat(128), path: 'components[].hashes[]' }],
    };
    expect(distinctByPurl([bare, rich])[0].declared).toHaveLength(1);
  });
});

describe('strongestDeclared', () => {
  const make = (algs: string[]): SbomComponent => ({
    purl: 'pkg:npm/a@1.0.0',
    ecosystem: 'npm',
    name: 'a',
    version: '1.0.0',
    declared: algs.map((algorithm) => ({
      algorithm,
      hex: 'a'.repeat(algorithm === 'sha512' ? 128 : 64),
      path: 'components[].hashes[]' as const,
    })),
  });

  it('prefers sha512 over sha256', () => {
    expect(strongestDeclared(make(['sha256', 'sha512']))?.algorithm).toBe('sha512');
  });

  it('never returns sha1 or md5 - they are not proof', () => {
    expect(strongestDeclared(make(['sha1', 'md5']))).toBeNull();
  });

  it('never returns blake2b-256, which is also 64 hex', () => {
    // Length must never be used to infer an algorithm.
    expect(strongestDeclared(make(['blake2b-256']))).toBeNull();
  });
});

describe('errors', () => {
  it('rejects a document that is neither format', () => {
    expect(() => parseSbom('{"hello":"world"}')).toThrow(/Unrecognized SBOM/);
  });

  it('reports a missing file clearly', () => {
    expect(() => parseSbomFile('/nonexistent/sbom.json')).toThrow(/SBOM not found/);
  });
});

describe('generators that produce nothing', () => {
  it('names an empty document as an empty generator output, not bad JSON', () => {
    // npmsbom on the npm CLI lockfile and cyclonedx-py on poetry.lock each
    // wrote a 0-byte file. "Unexpected end of JSON input" would hide that.
    expect(() => parseSbom('')).toThrow(/generator produced no output/);
    expect(() => parseSbom('   \n ')).toThrow(/generator produced no output/);
  });

  it('still reports genuinely malformed JSON as malformed', () => {
    expect(() => parseSbom('{"components": [')).toThrow(/Malformed SBOM JSON/);
  });
});

describe('npm lockfile', () => {
  const lockfile = () => parseLockfileFile(fixture('sample.package-lock.json'));

  it('skips the root entry (the project itself, not a dependency)', () => {
    const parsed = lockfile();
    expect(parsed.components.some((c) => c.name === 'sample-project')).toBe(false);
  });

  it('reads version and integrity for a plain entry', () => {
    const axios = lockfile().components.find((c) => c.name === 'axios');
    expect(axios?.version).toBe('1.7.9');
    expect(axios?.purl).toBe('pkg:npm/axios@1.7.9');
    expect(axios?.declared).toHaveLength(1);
    expect(axios?.declared[0].algorithm).toBe('sha512');
    expect(axios?.declared[0].path).toBe('package-lock.packages[].integrity');
  });

  it('builds a correctly %40-encoded purl for a scoped package', () => {
    const scoped = lockfile().components.find((c) => c.name === '@scope/pkg');
    expect(scoped?.purl).toBe('pkg:npm/%40scope/pkg@2.0.0');
  });

  it('takes the last node_modules/-prefixed segment as the name, not a prefix strip', () => {
    // node_modules/axios/node_modules/follow-redirects is package
    // follow-redirects installed inside axios's own tree, not a package
    // literally named "axios/node_modules/follow-redirects".
    const nested = lockfile().components.filter((c) => c.name === 'follow-redirects');
    expect(nested).toHaveLength(2);
    expect(nested.map((c) => c.version).sort()).toEqual(['1.15.6', '1.15.9']);
  });

  it('keeps both occurrences of a name at different versions as distinct purls', () => {
    const purls = lockfile()
      .components.filter((c) => c.name === 'follow-redirects')
      .map((c) => c.purl);
    expect(new Set(purls).size).toBe(2);
  });

  it('uses the entry\'s own name for an npm alias, not the install path', () => {
    // "foo": "npm:ms@2.1.3" in package.json installs at node_modules/foo,
    // but the entry's own name field says "ms", the real registry package.
    const parsed = lockfile();
    expect(parsed.components.some((c) => c.name === 'foo')).toBe(false);
    const aliased = parsed.components.find((c) => c.name === 'ms');
    expect(aliased?.version).toBe('2.1.3');
    expect(aliased?.purl).toBe('pkg:npm/ms@2.1.3');
  });

  it('records no declared hash for an entry with no integrity, rather than failing', () => {
    const none = lockfile().components.find((c) => c.name === 'no-integrity-pkg');
    expect(none?.declared).toEqual([]);
  });

  it('drops a sha1-only integrity rather than treating it as proof', () => {
    const sha1Only = lockfile().components.find((c) => c.name === 'sha1-only-pkg');
    expect(sha1Only?.declared).toEqual([]);
  });

  it('is tagged as the npm-lockfile format', () => {
    expect(lockfile().format).toBe('npm-lockfile');
  });

  it('rejects a lockfile with no packages map', () => {
    expect(() => parseLockfile('{"lockfileVersion": 1, "dependencies": {}}')).toThrow(
      /Unrecognized lockfile/
    );
  });

  it('rejects an empty lockfile as an empty generator, not bad JSON', () => {
    expect(() => parseLockfile('')).toThrow(/Empty lockfile/);
  });

  it('reports a missing file clearly', () => {
    expect(() => parseLockfileFile('/nonexistent/package-lock.json')).toThrow(/Lockfile not found/);
  });
});
