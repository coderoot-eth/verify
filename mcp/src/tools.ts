/**
 * The checks behind the MCP tools. Every answer rests on a digest of the
 * bytes: a name and version alone never come back verified.
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseDigest } from '../../lib/digest';
import { verifyDigest, VerifyOptions, VerdictResult, AttestationRef, HashSource, Verdict } from '../../lib/verdict';
import { parseLockfile, distinctByPurl, SbomComponent } from '../../lib/sbom';
import { verifyComponentDetailed, verifyComponents } from '../../lib/batch';
import { summarize, EvidenceRecord } from '../../lib/report';

export interface CheckOptions {
  /** The verify endpoint (default https://verify.coderoot.app). */
  verifyUrl?: string;
  /** The npm registry (default https://registry.npmjs.org). */
  registryUrl?: string;
  /** Parallel lookups for a lockfile (default 8). */
  concurrency?: number;
}

/**
 * What the agent should do with an answer:
 * - proceed: the bytes are attested and not revoked
 * - caution: fine as a dependency, but refuse it as the artifact you ship or deploy
 * - stop: do not use it until the mismatch or unproven bytes are explained
 * - refuse: never use it
 */
export type Action = 'proceed' | 'caution' | 'stop' | 'refuse';

export interface Attestation {
  uid: string;
  attester: string | null;
  attestedAt: string | null;
  revokedAt: string | null;
  /** The attestation on EAS, checkable without CodeRoot. */
  easUrl: string;
}

export interface CheckResult {
  verdict: Verdict;
  action: Action;
  advice: string;
  reason: string;
  queried: string | null;
  hashSource: HashSource;
  mismatch: boolean;
  degraded: boolean;
  authorCpoaRevoked: boolean | null;
  attestations: Attestation[];
}

const EAS_VIEW = 'https://base-sepolia.easscan.org/attestation/view/';
const LOCKFILE_NAME = /(^|[.\-_])(package-lock|npm-shrinkwrap)\.json$/;

const iso = (seconds: number | undefined): string | null => (seconds ? new Date(seconds * 1000).toISOString() : null);

function attestationsOf(refs: AttestationRef[] | undefined, uids?: string[]): Attestation[] {
  const list: AttestationRef[] = refs ?? (uids ?? []).map((uid) => ({ uid }));
  return list.map((a) => ({
    uid: a.uid,
    attester: a.attester ?? null,
    attestedAt: iso(a.attestedAt),
    revokedAt: iso(a.revokedAt),
    easUrl: `${EAS_VIEW}${a.uid}`,
  }));
}

/** The action for one artifact, as AGENTS.md states it for a release or deploy step. */
function judge(verdict: Verdict, flags: { mismatch: boolean; degraded: boolean; authorCpoaRevoked: boolean | null }): { action: Action; advice: string } {
  if (verdict === 'revoked') return { action: 'refuse', advice: 'Revoked: do not install, ship or pin it. Tell the user which component it is and its attestation UIDs.' };
  if (flags.mismatch) return { action: 'stop', advice: 'The bytes differ from what is attested for this name and version. Report it; do not retry from another source to make it pass.' };
  if (flags.authorCpoaRevoked !== false) return { action: 'caution', advice: 'The producing agent has lost its authority, or that could not be checked. Refuse it as the artifact you ship or deploy.' };
  if (flags.degraded) return { action: 'caution', advice: 'The answer may miss a recent revoke. Refuse it as the artifact you ship or deploy; otherwise report it and check again later.' };
  if (verdict === 'verified') return { action: 'proceed', advice: 'These exact bytes are attested and not revoked.' };
  if (verdict === 'unregistered') return { action: 'caution', advice: 'No attestation for these bytes. Not a failure for a dependency; refuse it only as the artifact you ship or deploy.' };
  return { action: 'stop', advice: 'The name and version are attested, but these bytes were not proven. Treat as unverified: get the artifact from its registry and check the file itself.' };
}

function fromVerdict(result: VerdictResult): CheckResult {
  const flags = {
    mismatch: result.mismatch === true,
    degraded: result.degraded === true,
    authorCpoaRevoked: result.authorCpoaRevoked === undefined ? false : result.authorCpoaRevoked,
  };
  return { verdict: result.verdict, ...judge(result.verdict, flags), reason: result.reason, queried: result.queried, hashSource: result.hashSource, ...flags, attestations: attestationsOf(result.attestations) };
}

function fromRecord(record: EvidenceRecord): CheckResult {
  const flags = {
    mismatch: record.mismatch === true,
    degraded: record.degraded === true,
    authorCpoaRevoked: record.authorCpoaRevoked === undefined ? false : record.authorCpoaRevoked,
  };
  return { verdict: record.verdict, ...judge(record.verdict, flags), reason: record.reason, queried: record.queried, hashSource: record.hashSource, ...flags, attestations: attestationsOf(undefined, record.attestationUids) };
}

const verifyOptions = (options: CheckOptions): VerifyOptions => (options.verifyUrl ? { baseUrl: options.verifyUrl } : {});

/** Check one digest the caller already holds, tagged `sha256:<hex>` or `sha512:<hex>`. */
export async function checkHash(digest: string, source: 'lockfile' | 'registry' | 'bytes', options: CheckOptions = {}): Promise<CheckResult> {
  const { algorithm, hex } = parseDigest(digest);
  const set = { sha256: algorithm === 'sha256' ? hex : '', sha512: algorithm === 'sha512' ? hex : '', bytes: 0 };
  return fromVerdict(await verifyDigest(set, source, verifyOptions(options)));
}

/** Check an npm package version: the client downloads the tarball and hashes it itself. */
export async function checkPackage(name: string, version: string, options: CheckOptions = {}): Promise<CheckResult & { package: string }> {
  const component: SbomComponent = { purl: `pkg:npm/${name}@${version}`, ecosystem: 'npm', name, version, declared: [] };
  const { result } = await verifyComponentDetailed(component, {
    declaredSource: 'sbom-hint',
    verify: verifyOptions(options),
    ...(options.registryUrl ? { registryUrl: options.registryUrl } : {}),
  });
  return { package: `${name}@${version}`, ...fromVerdict(result) };
}

export interface LockfileResult {
  action: Action;
  advice: string;
  /** False when `limit` left packages unchecked: the action then covers only the checked ones. */
  complete: boolean;
  summary: ReturnType<typeof summarize> & { distinct: number; checked: number; unchecked: number };
  /** Components that need attention: revoked, mismatched, degraded, or with a revoked author. */
  attention: Array<CheckResult & { purl: string }>;
  components?: Array<CheckResult & { purl: string }>;
}

/** Check every package in a package-lock.json. */
export async function checkLockfile(
  input: { path?: string; content?: string; limit?: number; details?: boolean },
  options: CheckOptions = {}
): Promise<LockfileResult> {
  let raw: string;
  if (input.content !== undefined) raw = input.content;
  else if (input.path) {
    if (!LOCKFILE_NAME.test(path.basename(input.path))) throw new Error('path must name a package-lock.json or npm-shrinkwrap.json');
    raw = fs.readFileSync(input.path, 'utf8');
  } else throw new Error('give either path or content');

  let components = distinctByPurl(parseLockfile(raw).components);
  const distinct = components.length;
  if (input.limit && input.limit < components.length) components = components.slice(0, input.limit);

  const records = await verifyComponents(components, {
    declaredSource: 'lockfile',
    concurrency: options.concurrency ?? 8,
    verify: verifyOptions(options),
    ...(options.registryUrl ? { registryUrl: options.registryUrl } : {}),
  });
  const results = records.map((r) => ({ purl: r.purl, ...fromRecord(r) }));
  const attention = results.filter((r) => r.verdict === 'revoked' || r.mismatch || r.degraded || r.authorCpoaRevoked !== false);

  const summary = { ...summarize(records), distinct, checked: records.length, unchecked: distinct - records.length };
  const complete = summary.unchecked === 0;
  const failed = summary.revoked > 0 || summary.mismatch > 0;
  const partial = complete ? '' : ` ${summary.unchecked} of ${distinct} packages were not checked, so this says nothing about them; check without limit before relying on the lockfile.`;
  const advice = failed
    ? 'At least one package is revoked or its bytes differ from what is attested. Do not install or ship this lockfile; report the packages in attention.' + partial
    : !complete
      ? `Nothing revoked or mismatched among the packages checked.${partial}`
      : attention.length > 0
        ? 'Nothing revoked or mismatched, but some answers need attention (degraded, or a revoked author). Check those again before relying on them.'
        : 'Nothing revoked or mismatched. Unregistered packages are common and are not a failure for a dependency check.';
  return {
    action: failed ? 'refuse' : !complete || attention.length > 0 ? 'caution' : 'proceed',
    advice,
    complete,
    summary,
    attention,
    ...(input.details ? { components: results } : {}),
  };
}
