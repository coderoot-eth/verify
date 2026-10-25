/**
 * Verify a list of components: obtain a digest for each, ask the endpoint, and
 * check the bytes against what is attested for the same name and version.
 *
 * The tier order is lockfile -> bytes -> registry -> sbom-hint -> none. For npm,
 * the client downloads the tarball and hashes it itself whenever it can: it
 * then holds the artifact, not someone else's record of what it should be.
 */

import { SbomComponent, strongestDeclared } from './sbom';
import { verifyDigest, probeCoordinates, compareContentHash, HashSource, VerifyOptions, VerdictResult } from './verdict';
import { digestBuffer } from './digest';
import { toEvidenceRecord, EvidenceRecord } from './report';

export interface BatchOptions {
  /**
   * What a digest the input merely declares counts as. An SBOM's declared hash
   * is a hint and never queried; a package-lock.json's `integrity` is npm's own
   * install-time record, so it is `lockfile` and queried normally.
   */
  declaredSource: 'sbom-hint' | 'lockfile';
  /** Resolve and classify only; never call the network. */
  offline?: boolean;
  /** Parallel lookups (default 8). */
  concurrency?: number;
  verify?: VerifyOptions;
  /** npm registry to fetch packuments and tarballs from (default https://registry.npmjs.org). */
  registryUrl?: string;
  /** Called after each component, with how many are done. */
  onProgress?: (done: number, total: number) => void;
}

interface Acquired {
  hashSource: HashSource;
  sha256?: string;
  sha512?: string;
  digests: string[];
  /** The strongest digest the input declared, kept to compare against fetched bytes. */
  declared: ReturnType<typeof strongestDeclared>;
}

/** Run `fn` over items with a fixed number of workers, preserving order. */
async function pool<T, R>(items: T[], workers: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
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

/** A declared digest, shaped for the result. */
function fromDeclared(declared: ReturnType<typeof strongestDeclared>, hashSource: HashSource): Acquired {
  if (!declared) return { hashSource: 'none', digests: [], declared: null };
  const digests = [`${declared.algorithm}:${declared.hex}`];
  if (declared.algorithm === 'sha256') return { hashSource, sha256: declared.hex, digests, declared };
  if (declared.algorithm === 'sha512') return { hashSource, sha512: declared.hex, digests, declared };
  return { hashSource, digests, declared };
}

async function acquire(
  component: SbomComponent,
  offline: boolean,
  declaredSource: 'sbom-hint' | 'lockfile',
  registryUrl = 'https://registry.npmjs.org'
): Promise<Acquired> {
  const declared = strongestDeclared(component);
  if (offline || component.ecosystem !== 'npm' || !component.version) return fromDeclared(declared, declaredSource);

  try {
    const packument = (await (await fetch(`${registryUrl.replace(/\/+$/, '')}/${component.name}`)).json()) as {
      versions?: Record<string, { dist?: { tarball?: string } }>;
    };
    const tarball = packument.versions?.[component.version]?.dist?.tarball;
    if (!tarball) return fromDeclared(declared, declaredSource);

    const bytes = new Uint8Array(await (await fetch(tarball)).arrayBuffer());
    const set = digestBuffer(bytes);
    return {
      hashSource: 'bytes',
      sha256: set.sha256,
      sha512: set.sha512,
      digests: [`sha256:${set.sha256}`, `sha512:${set.sha512}`],
      declared,
    };
  } catch {
    return fromDeclared(declared, declaredSource);
  }
}

/** Verify one component and return its evidence record. */
export async function verifyComponent(component: SbomComponent, options: BatchOptions): Promise<EvidenceRecord> {
  return (await verifyComponentDetailed(component, options)).record;
}

/** As verifyComponent, plus the endpoint's full answer (attesters and on-chain times). */
export async function verifyComponentDetailed(
  component: SbomComponent,
  options: BatchOptions
): Promise<{ record: EvidenceRecord; result: VerdictResult }> {
  const verifyOptions = options.verify ?? {};
  const acquired = await acquire(component, options.offline ?? false, options.declaredSource, options.registryUrl);
  const outcome: VerdictResult = options.offline
    ? {
        verdict: 'attested-bytes-unproven' as const,
        queried: null,
        hashSource: acquired.hashSource,
        reason: 'Offline: resolved and classified, but not queried.',
      }
    : await verifyDigest(
        acquired.sha256 || acquired.sha512
          ? { sha256: acquired.sha256 ?? '', sha512: acquired.sha512 ?? '', bytes: 0 }
          : null,
        acquired.hashSource,
        verifyOptions
      );

  // Both mismatch checks need bytes the client hashed itself.
  let mismatch = false;
  if (!options.offline && acquired.sha256 && acquired.hashSource === 'bytes' && component.ecosystem === 'npm' && component.version) {
    const coordinates = await probeCoordinates(component.ecosystem, component.name ?? '', component.version, verifyOptions);
    mismatch = compareContentHash(acquired.sha256, coordinates.contentHash);
    if (!mismatch && options.declaredSource === 'lockfile' && acquired.declared) {
      const ours = acquired.declared.algorithm === 'sha512' ? acquired.sha512 : acquired.sha256;
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
      authorCpoaRevokedUids: outcome.authorCpoaRevokedUids,
    },
    acquired.digests
  );
  return { record, result: { ...outcome, mismatch } };
}

/** Verify components in parallel, preserving their order. */
export async function verifyComponents(components: SbomComponent[], options: BatchOptions): Promise<EvidenceRecord[]> {
  let done = 0;
  return pool(components, options.concurrency ?? 8, async (component) => {
    const record = await verifyComponent(component, options);
    options.onProgress?.(++done, components.length);
    return record;
  });
}
