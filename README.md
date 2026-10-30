# @coderoot-eth/verify

Check that the dependencies and artifacts you use are the bytes their publisher released, and
that the release is still trusted, against CodeRoot's public attestations.

New to CodeRoot? Start with ["What CodeRoot is and why"](https://github.com/coderoot-eth/verify/blob/main/AGENTS.md#what-coderoot-is-and-why) in AGENTS.md.

**The purl is only an index; the hash is the trust.** A component is never reported verified
because its name and version matched. Each answer rests on a digest of the bytes, and names the
EAS attestation UIDs behind it, so anyone can re-check it on chain without CodeRoot.

```bash
npx @coderoot-eth/verify verify --file ./axios-1.7.9.tgz
```

```
✓ verified
  digest  sha256:634e3ed585d7c8857f00cb7556f79422614e8defd008f8bb34b6018c1faefa0f
  bytes   547981
  reason  An acquired bytes digest matched an attested record.
  uid     0xb14a81dee57bae98fbaa5a3be33ac314bf109611c47b2d544f4745452e190f63
```

Node 20 or later. One runtime dependency, `@noble/hashes`.

## Install

```bash
npm install --save-dev @coderoot-eth/verify     # the `coderoot` command, and the library
npx @coderoot-eth/verify <command>              # or run it without installing
```

## `coderoot verify`

```bash
coderoot verify --file <path>       # one artifact, hashed here
coderoot verify --hash <alg:hex>    # one artifact, by digest
coderoot verify --lockfile <path>   # every package in a package-lock.json
coderoot verify --sbom <path>       # every component in a CycloneDX or SPDX document
```

### One artifact: `--file`, `--hash`

```bash
coderoot verify --file <path> [--json] [--no-cache] [--warn-on-degraded]
coderoot verify --hash <alg:hex> [--source lockfile|registry|bytes] [--json] [--no-cache] [--warn-on-degraded]
```

The check a deploy step runs before it starts a build: "may I use these bytes?" No record is not
a yes.

| exit | meaning |
|--:|---|
| 0 | verified |
| 1 | revoked |
| 2 | unregistered, attested but these bytes unproven, or the producing agent's authority revoked |
| 3 | usage error |
| 4 | could not be fully checked |

**A degraded answer refuses.** Verify reads revocations from the chain and from the gate, and a
revoke from either wins. When one cannot be read, a revoke made minutes ago may be missing, so
the answer is degraded and exits 4. `--warn-on-degraded` makes it a warning instead, for jobs that
only report. A digest this client has already seen revoked fails from its local cache even when
the endpoint is down.

`--source` records how a `--hash` digest was obtained: `lockfile` (the default), `registry` (for
example a container digest from `coderoot hash --image`), or `bytes`.

### A population: `--lockfile`, `--sbom`

```bash
coderoot verify --lockfile <path> [--json <out>] [--limit n] [--offline] [--concurrency n] [--no-cache]
coderoot verify --sbom <path>     [--json <out>] [--limit n] [--offline] [--concurrency n] [--no-cache]
```

Parses the input, de-duplicates on the full purl, obtains a digest per component, queries the
endpoint, and writes one JSON report ([spec/evidence-record.md](spec/evidence-record.md)). stdout
carries only JSON; progress and the summary go to stderr.

```
$ coderoot verify --lockfile package-lock.json --json report.json
parsed 365 components (337 distinct) from package-lock.json

format    npm-lockfile  365 components, 337 distinct

verified                     0  0.0%
attested-bytes-unproven      0  0.0%
unregistered               337  100.0%
revoked                      0  0.0%

exit 0
```

| exit | meaning |
|--:|---|
| 0 | nothing failed |
| 1 | at least one component revoked |
| 2 | at least one mismatch: the bytes differ from what is attested, or from the lockfile's own `integrity` |
| 3 | usage or parse error |

Most of the ecosystem is not attested yet, so a batch reports `unregistered` and does not fail on
it.

- **`--lockfile`** reads lockfileVersion 2 or 3 directly: the installed name and version per
  `node_modules` path, including npm aliases and nested duplicates at other versions. Its
  `integrity` is npm's own install-time record, so it is queried.
- **`--sbom`** reads all three places a digest can sit: `components[].hashes[]`,
  `components[].externalReferences[].hashes[]` and SPDX `packages[].checksums[]`. A digest that
  exists only in the SBOM is recorded as a hint and never sent: SBOM generators write digests that
  do not correspond to the published bytes.
- Where it can, the client downloads the artifact and hashes it itself, and checks it against the
  digest attested for that name and version.

## `coderoot hash`

What you are holding, with no network call.

```bash
coderoot hash <file> [--json] [--algorithm sha256|sha512|both]
coderoot hash --image <ref> [--json]
```

`--image` resolves the digest to attest for a container image: the index digest for a multi-arch
image, the manifest digest otherwise. It needs [`crane`](https://github.com/google/go-containerregistry/tree/main/cmd/crane)
on `PATH`, cross-checks every answer against `crane digest`, and leaves out the "attestation
manifest" entries a BuildKit index carries next to its real platforms.

## SHA-256 and SHA-512

Neither converts to the other, and the only bridge is the bytes. Holding an artifact, the client
computes both from one read, records both, and queries SHA-256 first, because older records are
indexed by SHA-256 only. A lockfile usually holds only npm's SHA-512, which is queried directly.
The algorithm always travels with the digest (`sha256:<hex>`); length never implies it.

## Library

```ts
import { digestFile, verifyDigest } from '@coderoot-eth/verify';

const digests = digestFile('axios-1.7.9.tgz');
const result = await verifyDigest(digests, 'bytes');
console.log(result.verdict, result.attestations?.map((a) => a.uid));
```

## For AI agents

[AGENTS.md](AGENTS.md) says which command to run, how to read each verdict, and what an agent must
refuse. The same checks are available as MCP tools in [`@coderoot-eth/mcp`](mcp/README.md).

## Specification

- [Verdicts, flags and exit codes](spec/verdicts.md)
- [Evidence record](spec/evidence-record.md)
- [The verify endpoint](spec/verify-endpoint.md)
- [Attestation schemas](spec/eas-schemas.md)
- [Submitting a release](spec/submit.md)

## Development

```bash
npm ci
npm test
npm run build
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
