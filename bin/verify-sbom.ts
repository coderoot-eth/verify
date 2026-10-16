#!/usr/bin/env ts-node
/**
 * coderoot verify --sbom <file>
 * coderoot verify --lockfile <file>
 *
 * The batch verification client: parse an SBOM or a package-lock.json,
 * resolve every component by identity, query the verify endpoint for each
 * obtainable digest, and emit one JSON report plus an exit code.
 *
 *   --sbom <path>      CycloneDX or SPDX document
 *   --lockfile <path>  npm package-lock.json, lockfileVersion 2 or 3
 *   --json <path>      write the report here (default: stdout)
 *   --limit <n>        max components to process (default: all)
 *   --concurrency <n>  parallel lookups (default: 8)
 *   --offline          resolve and classify, but never call the network
 *   --base-url <url>   verify endpoint (default: https://verify.coderoot.app)
 *   --no-cache         skip the last-known-revoked cache
 *
 * Exactly one of --sbom / --lockfile is required. Both feed the same
 * pipeline; only what an unacquired declared digest falls back to differs -
 * see acquire()'s `declaredSource` argument.
 *
 * Exit: 0 clean · 1 revoked · 2 mismatch · 3 usage/parse error.
 *
 * stdout carries only the JSON report, so it pipes into jq. Progress and the
 * human summary go to stderr.
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseSbomFile, parseLockfileFile, distinctByPurl, strongestDeclared, SbomComponent } from '../lib/sbom';
import { verifyDigest, probeCoordinates, compareContentHash, HashSource } from '../lib/verdict';
import { digestBuffer } from '../lib/digest';
import { buildReport, renderSummary, toEvidenceRecord, EvidenceRecord, EXIT } from '../lib/report';
import { RevokedCache } from '../lib/revoked-cache';

const TOOL_VERSION = '0.1.0-m2';

interface Args {
  help?: boolean;
  sbom?: string;
  lockfile?: string;
  json?: string;
  limit?: number;
  concurrency: number;
  offline: boolean;
  baseUrl?: string;
  cache: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { concurrency: 8, offline: false, cache: true };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const next = () => argv[++i];
    if (flag === '--sbom') args.sbom = next();
    else if (flag === '--lockfile') args.lockfile = next();
    else if (flag === '--json') args.json = next();
    else if (flag === '--limit') args.limit = Number(next());
    else if (flag === '--concurrency') args.concurrency = Number(next());
    else if (flag === '--base-url') args.baseUrl = next();
    else if (flag === '--offline') args.offline = true;
    else if (flag === '--no-cache') args.cache = false;
    else if (flag === '--help' || flag === '-h') {
      console.error(
        'usage: coderoot verify --sbom <file> [--json <out>] [--limit n] [--offline] [--no-cache]\n' +
          '       coderoot verify --lockfile <file> [--json <out>] [--limit n] [--offline] [--no-cache]'
      );
      args.help = true;
    }
  }
  return args;
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

/**
 * Acquire a digest for one component.
 *
 * The tier order is lockfile -> bytes -> registry -> sbom-hint -> none.
 * Here the npm registry stands in for the lockfile/registry tiers when there
 * is no real lockfile to read (the packument's dist.integrity IS the
 * lockfile value), and `bytes` is reached by hashing the tarball we
 * downloaded, which is always preferred when reachable: we then hold the
 * actual artifact, not someone else's record of what it should be.
 *
 * `declaredSource` decides what an unacquired declared digest falls back to
 * when nothing stronger is reachable (offline, unresolvable ecosystem, or no
 * tarball). An SBOM's declared hash is a hint and never queried. A
 * package-lock.json's `integrity`, by contrast, is npm's own install-time
 * record of what was fetched, not a third party's guess, so it is classified
 * `lockfile` and queried normally - the HashSource type already ranks it
 * above `bytes` for exactly this reason.
 */
interface Acquired {
  hashSource: HashSource;
  sha256?: string;
  sha512?: string;
  digests: string[];
  /**
   * The strongest digest the input document itself declared, kept even when
   * `bytes` wins the query, so a caller can compare fetched bytes against
   * what was declared (e.g. a lockfile's install-time `integrity`).
   */
  declared: ReturnType<typeof strongestDeclared>;
}

/** A declared digest, shaped for the result - sha256 only goes in the queryable field. */
function fromDeclared(
  declared: ReturnType<typeof strongestDeclared>,
  hashSource: HashSource
): Acquired {
  if (!declared) return { hashSource: 'none', digests: [], declared: null };
  const digests = [`${declared.algorithm}:${declared.hex}`];
  if (declared.algorithm === 'sha256') return { hashSource, sha256: declared.hex, digests, declared };
  if (declared.algorithm === 'sha512') return { hashSource, sha512: declared.hex, digests, declared };
  return { hashSource, digests, declared };
}

async function acquire(
  component: SbomComponent,
  offline: boolean,
  declaredSource: 'sbom-hint' | 'lockfile' = 'sbom-hint'
): Promise<Acquired> {
  const declared = strongestDeclared(component);

  if (offline || component.ecosystem !== 'npm' || !component.version) {
    // Nothing obtainable without the network, or an ecosystem this build
    // does not resolve. `lockfile` vs `sbom-hint` still matters for the
    // report: the former is a trustworthy source, the latter is a hint
    // only.
    return fromDeclared(declared, declaredSource);
  }

  try {
    const packument = (await (await fetch(`https://registry.npmjs.org/${component.name}`)).json()) as {
      versions?: Record<string, { dist?: { tarball?: string } }>;
    };
    const tarball = packument.versions?.[component.version]?.dist?.tarball;
    if (!tarball) return fromDeclared(declared, declaredSource);

    const bytes = new Uint8Array(await (await fetch(tarball)).arrayBuffer());
    const set = digestBuffer(bytes);
    // We hold the artifact and hashed it ourselves: that is the `bytes` tier,
    // and the only way to have both algorithms for the same artifact. `declared`
    // still carries the document's own hash (if any), for the caller to compare
    // against these bytes - see the Acquired interface doc.
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

/** Run the batch verification. Returns the exit code; never exits. */
export async function runVerifySbom(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  if (args.help) return EXIT.ERROR;
  if (!args.sbom && !args.lockfile) {
    console.error('error: --sbom <file> or --lockfile <file> is required');
    return EXIT.ERROR;
  }
  if (args.sbom && args.lockfile) {
    console.error('error: --sbom and --lockfile are mutually exclusive');
    return EXIT.ERROR;
  }

  const inputPath = (args.sbom ?? args.lockfile) as string;
  const declaredSource: 'sbom-hint' | 'lockfile' = args.lockfile ? 'lockfile' : 'sbom-hint';

  const startedAt = new Date().toISOString();
  let parsed;
  try {
    parsed = args.lockfile ? parseLockfileFile(args.lockfile) : parseSbomFile(args.sbom as string);
  } catch (error) {
    console.error(`error: ${(error as Error).message}`);
    return EXIT.ERROR;
  }

  // Coverage is counted over distinct purls, never occurrences.
  let components = distinctByPurl(parsed.components);
  const distinct = components.length;
  if (args.limit && args.limit < components.length) components = components.slice(0, args.limit);

  process.stderr.write(
    `parsed ${parsed.components.length} components (${distinct} distinct) from ${path.basename(inputPath)}\n` +
      `verifying ${components.length}${args.offline ? ' (offline)' : ''}...\n`
  );

  const cache = args.cache ? new RevokedCache() : null;
  const verifyOptions = {
    ...(args.baseUrl ? { baseUrl: args.baseUrl } : {}),
    ...(cache ? { revokedCache: cache.asSet() } : {}),
  };

  let done = 0;
  const records: EvidenceRecord[] = await pool(components, args.concurrency, async (component) => {
    const acquired = await acquire(component, args.offline, declaredSource);
    // --offline means resolve and classify, never call the network. Checked
    // explicitly here rather than relying on verifyDigest to decline a query
    // on its own.
    const outcome = args.offline
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

    // Two mismatch checks, both only possible once bytes were fetched.
    let mismatch = false;
    if (acquired.sha256 && acquired.hashSource === 'bytes' && component.ecosystem === 'npm' && component.version) {
      // Against the coordinate route's contentHash (the hash route never returns one).
      const coordinates = await probeCoordinates(
        component.ecosystem,
        component.name ?? '',
        component.version,
        verifyOptions
      );
      mismatch = compareContentHash(acquired.sha256, coordinates.contentHash);

      // Against the lockfile's own declared integrity, when there is one.
      if (!mismatch && declaredSource === 'lockfile' && acquired.declared) {
        const ours = acquired.declared.algorithm === 'sha512' ? acquired.sha512 : acquired.sha256;
        if (ours) mismatch = compareContentHash(ours, acquired.declared.hex);
      }
    }

    if (++done % 25 === 0) process.stderr.write(`  ${done}/${components.length}\n`);
    return toEvidenceRecord(
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
  });
  cache?.flush();

  const report = buildReport({
    file: path.basename(inputPath),
    format: parsed.format,
    components: parsed.components.length,
    distinct,
    startedAt,
    records,
    toolVersion: TOOL_VERSION,
  });

  const json = JSON.stringify(report, null, 2);
  if (args.json) {
    fs.writeFileSync(args.json, json);
    process.stderr.write(`\nreport -> ${args.json}\n`);
  } else {
    process.stdout.write(json + '\n');
  }

  process.stderr.write('\n' + renderSummary(report) + '\n');
  return report.exitCode;
}

// Direct invocation: `ts-node bin/verify-sbom.ts …` still works.
if (require.main === module) {
  runVerifySbom(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error: unknown) => {
      console.error(`error: ${(error as Error).message}`);
      process.exit(EXIT.ERROR);
    }
  );
}
