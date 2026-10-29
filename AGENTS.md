# AGENTS.md

Instructions for AI coding agents that add, upgrade or ship dependencies and artifacts.

**The purl is only an index; the hash is the trust.** Never treat a package as verified because
its name and version look right. Verify the bytes.

## Which command

Install nothing globally; run through `npx`.

| situation | command |
|---|---|
| You hold the file (a tarball, a binary, a build output) | `npx @coderoot-eth/verify verify --file <path> --json` |
| You hold only a digest | `npx @coderoot-eth/verify verify --hash sha256:<hex> --source <lockfile\|registry\|bytes> --json` |
| You changed `package-lock.json`, or a release is about to ship | `npx @coderoot-eth/verify verify --lockfile package-lock.json` |
| You have an SBOM | `npx @coderoot-eth/verify verify --sbom <path>` |
| You need the digest of a container image | `npx @coderoot-eth/verify hash --image <ref> --json`, then `verify --hash <digest> --source registry` (needs `crane`) |
| You need the digests of a file | `npx @coderoot-eth/verify hash <path> --json` |

Prefer `--file` over `--hash` when you have the file: the answer then rests on bytes you hashed
yourself. With `--hash`, say where the digest came from with `--source` (`lockfile` is the
default). Never pass a digest you copied from an SBOM: a declared digest is not evidence.

`--lockfile` and `--sbom` print the JSON report to stdout and the summary to stderr. Pass
`--json <path>` only to write the report to a file, and keep that file out of the repository.

## Two kinds of check

- **Dependencies** (a lockfile or an SBOM, including right before a release): most of the
  ecosystem is not attested yet, so `unregistered` is reported, not refused. Refuse on `revoked`
  and on a mismatch.
- **The artifact you ship or deploy** (your own build, an image, a tarball you are about to
  publish or start): only `verified` passes. Refuse `unregistered` too.

The rules below that say "in a release or deploy step" are about the second kind.

## Reading the answer

| `verdict` | what it means | what you do |
|---|---|---|
| `verified` | these exact bytes are attested and not revoked | proceed |
| `attested-bytes-unproven` | the name and version are attested, but these bytes did not match | **stop**. Treat as unverified; get the artifact from its registry and check it with `--file` |
| `unregistered` | no attestation exists for these bytes | not a failure for a dependency. **Refuse** it for the artifact you ship or deploy |
| `revoked` | the bytes were attested and the attestation was revoked | **refuse**, always. Do not install, ship or pin it. Tell the user which component and its `attestationUids` |

Flags on top of a verdict:

| flag | what you do |
|---|---|
| `mismatch: true` | **stop**. The bytes in hand are not the bytes attested for that name and version. Report it; do not retry with another source to make it pass |
| `authorCpoaRevoked: true` or `null` | **refuse** in a release or deploy step. The bytes are attested, but the agent that produced them has lost its authority, or that could not be checked |
| `degraded: true` | the answer may miss a recent revoke. **Refuse** in a release or deploy step; elsewhere, report it and re-run later |

## Exit codes

`verify --file` / `--hash`: `0` verified · `1` revoked · `2` unregistered, unproven or
`authorCpoaRevoked` · `3` usage error · `4` could not be fully checked.

`verify --lockfile` / `--sbom`: `0` nothing failed · `1` a revoked component · `2` a mismatch ·
`3` usage or parse error. Read the JSON report for unregistered, degraded and
`authorCpoaRevoked` counts.

Never add `|| true`, `continue-on-error`, `--warn-on-degraded` or `--no-cache` to make a failing
check pass. If a check fails, stop and tell the user why.

## What you must not do

- Never report a component as verified from its name and version.
- Never compare a digest you read from an SBOM against an attestation.
- Never assume an algorithm from a digest's length; always send it tagged (`sha256:`, `sha512:`).
- Never treat an unreachable endpoint as a pass in a release or deploy step.
- Never submit a release for approval on your own. Releases are submitted by the publisher's CI
  with its GitHub identity token, and every attestation needs a person's approval.

## Details

- [spec/verdicts.md](spec/verdicts.md): verdicts, flags, exit codes
- [spec/evidence-record.md](spec/evidence-record.md): the JSON report
- [spec/verify-endpoint.md](spec/verify-endpoint.md): the public endpoint
- [spec/eas-schemas.md](spec/eas-schemas.md): re-checking an attestation on chain

## Releasing your own package

To set up a public npm package to release through CodeRoot, call the MCP tool `setup_release`
with the package name and its GitHub repository, write the two workflows it returns, and tell the
user the steps it lists for a person. Release by pushing a tag `v<version>` that matches
`package.json`.

- After the release run, the release waits for a person. Until they approve, `verify_package`
  answers `unregistered`: report the review link from the submit job and wait.
- Deploy only a version that answers `verified`, through the deploy workflow.
- After a revoke, call `release_history` and deploy its `latestVerified` version. Never deploy the
  revoked one again.
- Never approve or revoke a release, never try to, and never add an npm token or other secret to
  the repository.

## Over MCP

`@coderoot-eth/mcp` exposes the same checks as tools: `verify_package`, `verify_hash` and
`verify_lockfile`, plus `setup_release` and `release_history` for releasing a package. Each
verification answer includes an `action`:

| `action` | you |
|---|---|
| `proceed` | use it |
| `caution` | may use it as a dependency; refuse it as the artifact you ship or deploy |
| `stop` | do not use it until the mismatch or unproven bytes are explained |
| `refuse` | never use it |

Setup is in [mcp/README.md](mcp/README.md).
