/**
 * The local last-known-revoked cache.
 *
 * Fail-open says: when the verify endpoint is unreachable,
 * warn and exit 0 rather than blocking a deploy on an outage. That rule has one
 * carve-out - a digest this client has previously seen `revoked` still fails,
 * even with the endpoint down.
 *
 * Without somewhere to keep that knowledge, the carve-out is empty: a fresh
 * process has seen nothing, so every unreachable-endpoint run fails open on
 * everything, and an attacker who can break the connection can ship a revoked
 * build. This file is what makes the exception real across runs.
 *
 * What it is:
 *
 *   - append-only, keyed on the TAGGED digest (`sha256:<hex>`), so a digest can
 *     never be confused with the same hex under another algorithm
 *   - one JSON file, default `~/.coderoot/revoked-cache.json`
 *   - entries are never evicted by age. A revocation does not expire, and a
 *     cache that forgets one is worse than no cache - it would fail open on
 *     exactly the digest it was built to catch
 *   - it only ever ADDS a failure. A digest absent from the cache is not
 *     treated as good, and the cache is never consulted when the endpoint is
 *     reachable, so a revocation that is later lifted upstream is still
 *     observed correctly on any successful query
 *
 * What it is not: a verdict store. It answers one question - "have I ever seen
 * this exact digest revoked?" - and nothing else.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export interface RevokedEntry {
  /** Tagged digest, e.g. "sha256:<64 hex>". */
  digest: string;
  /** When this client first saw it revoked, ISO 8601 UTC. */
  seenAt: string;
  /** Coordinates, when known - for the human reading the file. */
  purl?: string;
}

interface CacheFile {
  schema: 'coderoot.revoked-cache/v1';
  entries: RevokedEntry[];
}

const EMPTY: CacheFile = { schema: 'coderoot.revoked-cache/v1', entries: [] };

export function defaultCachePath(): string {
  return (
    process.env['CODEROOT_REVOKED_CACHE'] ??
    path.join(os.homedir(), '.coderoot', 'revoked-cache.json')
  );
}

export class RevokedCache {
  private readonly file: string;
  private readonly digests = new Set<string>();
  private entries: RevokedEntry[] = [];
  private dirty = false;

  constructor(file: string = defaultCachePath()) {
    this.file = file;
    this.load();
  }

  /**
   * A malformed or unreadable cache must never take the run down: it is an
   * optimization on top of the endpoint's answer, not a source of truth.
   */
  private load(): void {
    try {
      if (!fs.existsSync(this.file)) return;
      const parsed = JSON.parse(fs.readFileSync(this.file, 'utf8')) as CacheFile;
      if (!Array.isArray(parsed.entries)) return;
      for (const entry of parsed.entries) {
        if (typeof entry?.digest === 'string' && entry.digest.includes(':')) {
          this.entries.push(entry);
          this.digests.add(entry.digest.toLowerCase());
        }
      }
    } catch {
      // Start empty rather than fail; the endpoint still governs live answers.
    }
  }

  /** Has this exact tagged digest ever been seen revoked? */
  has(taggedDigest: string): boolean {
    return this.digests.has(taggedDigest.toLowerCase());
  }

  /** Record a revocation. Idempotent. */
  add(taggedDigest: string, purl?: string): void {
    const key = taggedDigest.toLowerCase();
    if (this.digests.has(key)) return;
    this.digests.add(key);
    const entry: RevokedEntry = { digest: key, seenAt: new Date().toISOString() };
    if (purl) entry.purl = purl;
    this.entries.push(entry);
    this.dirty = true;
  }

  /** Persist if anything was added. Failure to write is reported, not thrown. */
  flush(): { written: boolean; error?: string } {
    if (!this.dirty) return { written: false };
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      const payload: CacheFile = { schema: EMPTY.schema, entries: this.entries };
      fs.writeFileSync(this.file, JSON.stringify(payload, null, 2));
      this.dirty = false;
      return { written: true };
    } catch (error) {
      return { written: false, error: (error as Error).message };
    }
  }

  get size(): number {
    return this.digests.size;
  }

  get path(): string {
    return this.file;
  }

  /** The Set the verify functions take, backed by this cache. */
  asSet(): Set<string> {
    // Proxy writes back into the cache so a revocation observed mid-run persists.
    const cache = this;
    const set = new Set<string>(this.digests);
    const originalAdd = set.add.bind(set);
    set.add = (value: string) => {
      cache.add(value);
      return originalAdd(value);
    };
    return set;
  }
}
