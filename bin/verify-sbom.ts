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
import { parseSbomFile, parseLockfileFile, distinctByPurl } from '../lib/sbom';
import { buildReport, renderSummary, EXIT } from '../lib/report';
import { RevokedCache } from '../lib/revoked-cache';
import { verifyComponents } from '../lib/batch';
import { packageVersion } from '../lib/version';

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

  const records = await verifyComponents(components, {
    declaredSource,
    offline: args.offline,
    concurrency: args.concurrency,
    verify: verifyOptions,
    onProgress: (done, total) => {
      if (done % 25 === 0) process.stderr.write(`  ${done}/${total}\n`);
    },
  });
  cache?.flush();

  const report = buildReport({
    file: path.basename(inputPath),
    format: parsed.format,
    components: parsed.components.length,
    distinct,
    startedAt,
    records,
    toolVersion: packageVersion(),
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
