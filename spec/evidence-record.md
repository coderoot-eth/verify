# Evidence record

`coderoot.verification-run/v1` is what `coderoot verify --sbom` and `--lockfile` write. It records
what was obtained and where it came from, never what a document claimed, so a third party can
re-check each answer without rerunning the tool or trusting it.

## Run envelope

```json
{
  "schema": "coderoot.verification-run/v1",
  "tool": { "name": "coderoot", "version": "0.1.0" },
  "source": { "file": "bom.cdx.json", "format": "cyclonedx", "components": 629, "distinct": 612 },
  "startedAt": "…",
  "finishedAt": "…",
  "summary": {
    "total": 612, "verified": 0, "attestedBytesUnproven": 0, "unregistered": 612,
    "revoked": 0, "mismatch": 0, "notQueried": 0, "degraded": 0, "authorCpoaRevoked": 0
  },
  "hashSources": { "bytes": 612 },
  "exitCode": 0,
  "records": []
}
```

| field | meaning |
|---|---|
| `schema` | exactly `coderoot.verification-run/v1` |
| `tool` | what produced the run |
| `source.file`, `source.format` | the input's basename; `cyclonedx` \| `spdx` \| `npm-lockfile` |
| `source.components` | components in the input, occurrences included |
| `source.distinct` | distinct purls: **the denominator for every percentage** |
| `startedAt`, `finishedAt` | ISO 8601 UTC. A re-check may legitimately differ later, for example after a revoke |
| `summary` | counts over `records`. `notQueried` is a property of the components; `degraded` of the run's conditions. A run with a high `degraded` count proves nothing and should be repeated |
| `hashSources` | count per source tier |
| `exitCode` | see [verdicts.md](verdicts.md#exit-codes) |

Both `components` and `distinct` are required because they differ: a package used by two projects
appears twice in a document, and counting occurrences overstates coverage.

## Record

One per distinct purl.

```json
{
  "purl": "pkg:npm/axios@1.7.9",
  "ecosystem": "npm",
  "name": "axios",
  "version": "1.7.9",
  "verdict": "verified",
  "hashSource": "bytes",
  "queried": "sha256:634e3ed585d7c8857f00cb7556f79422614e8defd008f8bb34b6018c1faefa0f",
  "algorithm": "sha256",
  "digests": [
    "sha256:634e3ed585d7c8857f00cb7556f79422614e8defd008f8bb34b6018c1faefa0f",
    "sha512:…"
  ],
  "reason": "An acquired bytes digest matched an attested record.",
  "attestations": 1,
  "attestationUids": ["0xb14a81dee57bae98fbaa5a3be33ac314bf109611c47b2d544f4745452e190f63"]
}
```

| field | meaning |
|---|---|
| `purl` | full package URL, URL-decoded. The identity and the dedupe key |
| `ecosystem`, `name`, `version` | from the purl; `version` may be `null` when the input omits it |
| `verdict` | one of the four in [verdicts.md](verdicts.md) |
| `hashSource` | `lockfile` \| `bytes` \| `registry` \| `sbom-hint` \| `none` |
| `queried` | the tagged digest sent to the endpoint, or `null` when nothing was sent |
| `algorithm` | the queried digest's algorithm, or `null`. Never inferred from length |
| `digests` | every digest held for the artifact, tagged. May hold more than `queried` |
| `reason` | why this verdict, in words |
| `mismatch` | optional; see [verdicts.md](verdicts.md#flags-on-top-of-a-verdict) |
| `degraded` | optional; the answer could not be fully checked |
| `authorCpoaRevoked`, `authorCpoaRevokedUids` | optional; as returned by the endpoint |
| `attestations` | optional; the number of records behind the answer |
| `attestationUids` | optional; the EAS UID of every attestation behind the answer |

`queried: null` is deliberate, not missing data: a `sbom-hint` or `none` component has nothing
worth asking about, and comparing a declared digest to an attestation manufactures a false
mismatch.

`attestationUids` is what makes the record evidence rather than a report: each UID can be
re-checked on EAS directly ([eas-schemas.md](eas-schemas.md)), and stays checkable without the
endpoint.

## The last-known-revoked cache

An unreachable endpoint must not block every deploy, so a batch fails open. The one exception is
a digest this client has previously seen `revoked`: it fails anyway, from a local cache.

| property | value |
|---|---|
| location | `~/.coderoot/revoked-cache.json`, or `CODEROOT_REVOKED_CACHE` |
| schema | `coderoot.revoked-cache/v1` |
| key | the tagged digest (`sha256:<hex>`), lowercase |
| growth | append-only; entries never expire |

```json
{
  "schema": "coderoot.revoked-cache/v1",
  "entries": [{ "digest": "sha256:…", "seenAt": "…", "purl": "pkg:npm/example@1.0.0" }]
}
```

- Keyed on the tagged digest, so the same hex under another algorithm never collides.
- A revocation does not expire. A cache that forgot one would fail open on exactly the digest it
  exists to catch.
- It only ever adds a failure. A digest absent from it is not treated as good, and it is not
  consulted while the endpoint answers, so a lifted revocation is observed on the next query.
- A corrupt cache never fails the run; an unreadable file starts empty.

`--no-cache` skips reading and writing it.

## Re-checking a record

1. Fetch the artifact named by `purl` from its registry.
2. Hash it. Every entry in `digests` must match.
3. Send `queried` to the verify endpoint. The verdict must match `verdict`, unless the
   attestation's state has changed since `finishedAt`.

Records are not signed: they are reproducible, not tamper-evident.
