/**
 * Batch verification report + exit codes.
 *
 * Turns a run over an SBOM into one JSON document and one exit status, so a CI
 * job can act on it without parsing prose.
 *
 * Exit codes carry the policy, and the distinction that matters is between
 * "failed" and "cannot be proven":
 *
 *   0  clean - everything verified, or unverifiable by nature
 *   1  revoked - at least one component is revoked (must be impossible to miss)
 *   2  mismatch - an acquired strong digest disagreed with an attested record
 *   3  usage/parse error
 *
 * Alpine can never be verified: APKINDEX publishes SHA-1 and nothing else
 * Exiting non-zero on that would be wrong, and would teach teams to
 * add `continue-on-error: true`, which disables the check they installed.
 */

import { SbomComponent } from './sbom';
import { HashSource, Verdict } from './verdict';

export const EXIT = { CLEAN: 0, REVOKED: 1, MISMATCH: 2, ERROR: 3 } as const;

/** One component's outcome. This object is the evidence record (spec/evidence-record.md). */
export interface EvidenceRecord {
  purl: string;
  ecosystem: string | null;
  name: string;
  version: string | null;
  verdict: Verdict;
  hashSource: HashSource;
  /** The tagged digest actually sent, or null when nothing was queried. */
  queried: string | null;
  /** Algorithm of the acquired digest, kept beside it - never inferred later. */
  algorithm: string | null;
  /** Every digest held for this artifact, tagged; may hold more than `queried`. */
  digests: string[];
  reason: string;
  degraded?: boolean;
  /**
   * True when the acquired digest disagreed with the digest the endpoint holds
   * for these coordinates. Rides on top of a verdict; it is not a fifth one.
   */
  mismatch?: boolean;
  attestations?: number | undefined;
  /**
   * EAS attestation UIDs backing this answer. Recorded so a third party can
   * re-check the attestation on EAS directly, without CodeRoot in the loop.
   */
  attestationUids?: string[];
  /**
   * True/null carries the same meaning as the live field: the authoring agent's
   * CPoA is revoked, or its chain could not be read. A batch only warns on this;
   * a single-artifact check refuses.
   */
  authorCpoaRevoked?: boolean | null;
  authorCpoaRevokedUids?: string[];
}

export interface RunReport {
  schema: 'coderoot.verification-run/v1';
  tool: { name: string; version: string };
  source: { file: string; format: string; components: number; distinct: number };
  startedAt: string;
  finishedAt: string;
  summary: {
    total: number;
    verified: number;
    attestedBytesUnproven: number;
    unregistered: number;
    revoked: number;
    mismatch: number;
    notQueried: number;
    degraded: number;
    authorCpoaRevoked: number;
  };
  hashSources: Record<string, number>;
  exitCode: number;
  records: EvidenceRecord[];
}

export function summarize(records: EvidenceRecord[]): RunReport['summary'] {
  const s = {
    total: records.length,
    verified: 0,
    attestedBytesUnproven: 0,
    unregistered: 0,
    revoked: 0,
    mismatch: 0,
    notQueried: 0,
    degraded: 0,
    authorCpoaRevoked: 0,
  };
  for (const r of records) {
    if (r.verdict === 'verified') s.verified += 1;
    else if (r.verdict === 'revoked') s.revoked += 1;
    else if (r.verdict === 'unregistered') s.unregistered += 1;
    else s.attestedBytesUnproven += 1;
    if (!r.queried) s.notQueried += 1;
    if (r.degraded) s.degraded += 1;
    // Counted separately from the verdicts: a mismatch is a flag on a record,
    // not a verdict of its own, but it is what drives exit code 2.
    if (r.mismatch) s.mismatch += 1;
    // check only warns on this (never fails the job) - verify is where the
    // same flag is a refusal. true or null (chain unreadable) both count.
    if (r.authorCpoaRevoked !== false && r.authorCpoaRevoked !== undefined) s.authorCpoaRevoked += 1;
  }
  return s;
}

/**
 * Decide the run's exit status.
 *
 * Revoked outranks mismatch: a revoked build is a live instruction to stop,
 * while a mismatch is a discrepancy to investigate.
 */
export function exitCodeFor(summary: RunReport['summary']): number {
  if (summary.revoked > 0) return EXIT.REVOKED;
  if (summary.mismatch > 0) return EXIT.MISMATCH;
  return EXIT.CLEAN;
}

export function buildReport(args: {
  file: string;
  format: string;
  components: number;
  distinct: number;
  startedAt: string;
  records: EvidenceRecord[];
  toolVersion: string;
}): RunReport {
  const summary = summarize(args.records);
  const hashSources: Record<string, number> = {};
  for (const r of args.records) hashSources[r.hashSource] = (hashSources[r.hashSource] ?? 0) + 1;

  return {
    schema: 'coderoot.verification-run/v1',
    tool: { name: 'coderoot', version: args.toolVersion },
    source: {
      file: args.file,
      format: args.format,
      components: args.components,
      distinct: args.distinct,
    },
    startedAt: args.startedAt,
    finishedAt: new Date().toISOString(),
    summary,
    hashSources,
    exitCode: exitCodeFor(summary),
    records: args.records,
  };
}

/** Human summary for stderr, so stdout stays pure JSON and pipeable. */
export function renderSummary(report: RunReport): string {
  const s = report.summary;
  const pct = (n: number) => (s.total === 0 ? '0.0' : ((100 * n) / s.total).toFixed(1));
  const lines = [
    `SBOM      ${report.source.file}`,
    `format    ${report.source.format}  ${report.source.components} components, ${report.source.distinct} distinct`,
    '',
    `verified                 ${String(s.verified).padStart(5)}  ${pct(s.verified)}%`,
    `attested-bytes-unproven  ${String(s.attestedBytesUnproven).padStart(5)}  ${pct(s.attestedBytesUnproven)}%`,
    `unregistered             ${String(s.unregistered).padStart(5)}  ${pct(s.unregistered)}%`,
    `revoked                  ${String(s.revoked).padStart(5)}  ${pct(s.revoked)}%`,
    '',
    `not queried (sbom-hint/none): ${s.notQueried}`,
  ];
  if (s.degraded > 0) {
    lines.push(`degraded (not fully checked; warning only, never fails a batch): ${s.degraded}`);
  }
  if (s.authorCpoaRevoked > 0) {
    lines.push(`authorCpoaRevoked (warning only, never fails check): ${s.authorCpoaRevoked}`);
  }
  lines.push('', `exit ${report.exitCode}`);
  return lines.join('\n');
}

/** Build one evidence record from a component and its verdict. */
export function toEvidenceRecord(
  component: SbomComponent,
  outcome: {
    verdict: Verdict;
    hashSource: HashSource;
    queried: string | null;
    reason: string;
    degraded?: boolean | undefined;
    mismatch?: boolean | undefined;
    attestations?: number | undefined;
    attestationUids?: string[] | undefined;
    authorCpoaRevoked?: boolean | null | undefined;
    authorCpoaRevokedUids?: string[] | undefined;
  },
  digests: string[]
): EvidenceRecord {
  const algorithm = outcome.queried ? outcome.queried.split(':')[0] : null;
  const record: EvidenceRecord = {
    purl: component.purl ?? '',
    ecosystem: component.ecosystem,
    name: component.name,
    version: component.version,
    verdict: outcome.verdict,
    hashSource: outcome.hashSource,
    queried: outcome.queried,
    algorithm,
    digests,
    reason: outcome.reason,
  };
  if (outcome.degraded) record.degraded = true;
  if (outcome.mismatch) record.mismatch = true;
  if (outcome.attestations !== undefined) record.attestations = outcome.attestations;
  if (outcome.attestationUids?.length) record.attestationUids = outcome.attestationUids;
  if (outcome.authorCpoaRevoked !== false && outcome.authorCpoaRevoked !== undefined) {
    record.authorCpoaRevoked = outcome.authorCpoaRevoked;
  }
  if (outcome.authorCpoaRevokedUids?.length) record.authorCpoaRevokedUids = outcome.authorCpoaRevokedUids;
  return record;
}
