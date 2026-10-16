# Verdicts, flags and exit codes

**The purl is only an index; the hash is the trust.** A component is never reported verified
because its name and version matched.

## Verdicts

Four, closed:

| verdict | meaning | a pass? |
|---|---|---|
| `verified` | a digest of the bytes in hand matched an attested record that is not revoked | yes |
| `attested-bytes-unproven` | a record exists for the name and version, but no strong digest of these bytes matched it | **no** |
| `unregistered` | no record exists for these bytes | no |
| `revoked` | a record exists for these bytes and has been revoked | no, and never |

A name@version lookup can answer at most `attested-bytes-unproven`. The coordinate route for
axios 1.7.9 answers `attested-bytes-unproven`; the hash route for the same release's SHA-256
answers `verified`.

## Flags on top of a verdict

None of these is a fifth verdict.

| flag | set when | effect |
|---|---|---|
| `mismatch` | a strong digest of the bytes in hand differs from the `contentHash` the coordinate route holds for that name and version, or from a lockfile's own `integrity` | exit 2 |
| `authorCpoaRevoked` | `true`: the agent that produced an attested release has had its authority (CPoA) revoked. The bytes are still attested. `null`: the chain could not be read | a single-artifact check exits 2 for `true` or `null`, never 1. A batch counts it and warns |
| `degraded` | verify could not be reached, or answered without reading the gate's revocations, so a revoke made minutes ago may be missing | see exit codes |

A digest that exists only inside an SBOM (`sbom-hint`) is never sent to the endpoint, so it can
never raise `mismatch`.

## Where a digest came from

Every answer records its `hashSource`, strongest first:

| source | meaning | queried? |
|---|---|---|
| `lockfile` | npm's own install-time record (`package-lock.json` `integrity`) | yes |
| `bytes` | the client hashed the artifact itself | yes |
| `registry` | the registry's published digest (npm `dist.integrity`), or a digest resolved from a container registry | yes |
| `sbom-hint` | a digest that appears only inside an SBOM | **never** |
| `none` | no digest obtainable | no |

A component whose only digest is an `sbom-hint`, or that has none, is reported
`attested-bytes-unproven` with `queried: null`: nothing about its bytes was proven.

An SBOM generator's declared digest is not evidence: cdxgen writes a SHA-256 with no
correspondence to the published bytes for every Go component it lists.

## Exit codes

### `coderoot verify --hash` / `--file`: one artifact, deploy time

The question is "may I start this build?", where no record is not a yes.

| code | meaning |
|--:|---|
| 0 | `verified` |
| 1 | `revoked` |
| 2 | `unregistered`, `attested-bytes-unproven`, or `authorCpoaRevoked` |
| 3 | usage error |
| 4 | `degraded`: could not be fully checked. `--warn-on-degraded` turns this into a warning and exit 0 |

### `coderoot verify --sbom` / `--lockfile`: a population

Most of the ecosystem is unattested, so `unregistered` is reported, not failed.

| code | meaning |
|--:|---|
| 0 | nothing failed: every component verified, unregistered, or unverifiable by nature |
| 1 | at least one `revoked` |
| 2 | at least one `mismatch` |
| 3 | usage or parse error |

Revoked outranks mismatch. `authorCpoaRevoked` and `degraded` are counted in the summary and
warned about; they do not change a batch's exit code. An unreachable endpoint warns and exits 0
for a batch, except for a digest previously seen `revoked`, which fails from the local cache (see
[evidence-record.md](evidence-record.md#the-last-known-revoked-cache)).

**Unverifiable is not failure.** Alpine publishes SHA-1 only, so an Alpine package can never be
verified. It is reported and exits 0.

## Algorithms

`sha256` and `sha512` are both queryable, and the algorithm always travels with the digest
(`sha256:<hex>`). Length never implies an algorithm: PyPI's `blake2b_256` is also 64 hex
characters. When the client holds the artifact it computes both digests from one read, records
both, and queries SHA-256 first, because older records are indexed by SHA-256 only. SHA-1 and MD5
are never proof.
