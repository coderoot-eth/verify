# @coderoot-eth/mcp

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent check dependencies and
artifacts against CodeRoot's public attestations before it uses them, and set up a package to
release through CodeRoot. It is read-only: it can verify and hand out the release setup, and it
cannot approve, attest or revoke anything.

New to CodeRoot? Start with ["What CodeRoot is and why"](https://github.com/coderoot-eth/verify/blob/main/AGENTS.md#what-coderoot-is-and-why) in AGENTS.md.

Every answer rests on a digest of the bytes. A name and version alone never come back verified.

## Tools

| tool | input | checks |
|---|---|---|
| `verify_package` | `name`, `version` | downloads the npm tarball, hashes it, verifies the bytes, and flags bytes that differ from what is attested for that name and version |
| `verify_hash` | `digest` (`sha256:<hex>` or `sha512:<hex>`), `source` | one digest the agent already holds |
| `verify_lockfile` | `path` or `content`, optional `limit`, `details` | every package in a `package-lock.json` (lockfileVersion 2 or 3) |
| `setup_release` | `package`, `repository`, optional `node` | returns the release and deploy workflows for a package, and the steps only a person can do |
| `release_history` | `name`, optional `limit` | checks the newest published versions by their bytes and names `latestVerified`, the version to deploy or move back to |

Each answer carries the verdict, an `action` for the agent, the reason, and every attestation
behind it with its attester, its on-chain times and a link to it on EAS:

```json
{
  "verdict": "verified",
  "action": "proceed",
  "advice": "These exact bytes are attested and not revoked.",
  "queried": "sha256:7dd824ef…1402",
  "hashSource": "bytes",
  "mismatch": false,
  "degraded": false,
  "authorCpoaRevoked": false,
  "attestations": [
    {
      "uid": "0xb064a4c9…07fb",
      "attester": "0xb343…c565",
      "attestedAt": "2026-10-21T12:13:02.000Z",
      "revokedAt": null,
      "easUrl": "https://base-sepolia.easscan.org/attestation/view/0xb064a4c9…07fb"
    }
  ]
}
```

| `action` | when | the agent |
|---|---|---|
| `proceed` | `verified` | uses it |
| `caution` | `unregistered`, a degraded answer, or a revoked producing agent | may use it as a dependency; refuses it as the artifact it ships or deploys |
| `stop` | the bytes differ from what is attested, or are unproven | does not use it until that is explained |
| `refuse` | `revoked` | never uses it |

`verify_lockfile` returns a summary, the packages that need attention, and one action for the
whole lockfile, the strictest among its packages: `refuse` when any package is revoked or
mismatched, `stop` when a package's bytes could not be proven (for example no digest could be
obtained). Unregistered packages are common and do not fail it. `details: true` adds the result for every package. With `limit`, only the first
packages are checked: the result says `complete: false` with the number left unchecked, and its
action is never `proceed`.

## Releasing a package through CodeRoot

`setup_release` returns two workflows to write into the package's repository:

- `.github/workflows/release.yml`: on a tag `v1.2.3`, builds and tests once, publishes that
  tarball from the `npm-publish` environment with npm trusted publishing and provenance (no npm
  token exists), then submits the same tarball to CodeRoot with the job's GitHub identity token.
- `.github/workflows/deploy.yml`: run with a version; it fetches the tarball npm serves, checks it
  with `coderoot-eth/action` in `verify` mode, and deploys only on `verified`.

It also returns the steps only a person can do: create the `npm-publish` environment, add the
trusted publisher on npm, ask a CodeRoot workspace admin to link the repository, workflow and
package, and approve or revoke each release in the CodeRoot queue.

| after | `verify_package` answers | the agent |
|---|---|---|
| the release run submits | `unregistered` | waits: the release is with a person (the submit job prints the review link) |
| a person approves | `verified` | deploys that version |
| a person revokes | `revoked` | stops deploying it, calls `release_history`, deploys its `latestVerified`, and gives the person its `personSteps` |

After a revoke, npm still serves the revoked version, and it may still be `latest`. Only a package
owner can move `latest` back and deprecate it, with their own npm login: trusted publishing lets the
release workflow publish and nothing else. `release_history` returns those commands in
`personSteps`, for example:

```
npm dist-tag add @acme/widget@1.0.0 latest
npm deprecate @acme/widget@1.1.0 "Revoked in CodeRoot. Use 1.0.0 or a later verified release."
```

Approving and revoking stay with a person. This server has no tool for either, and the gate
refuses anyone else.

## Set up

Claude Code:

```bash
claude mcp add coderoot -- npx -y @coderoot-eth/mcp
```

Claude Desktop, Cursor and other clients with a JSON config:

```json
{
  "mcpServers": {
    "coderoot": { "command": "npx", "args": ["-y", "@coderoot-eth/mcp"] }
  }
}
```

Node 20 or later.

| variable | default |
|---|---|
| `CODEROOT_VERIFY_URL` | `https://verify.coderoot.app` |
| `CODEROOT_NPM_REGISTRY` | `https://registry.npmjs.org` |

## Development

The server is built from the library in this repository and bundled into one file, so it always
carries the same verification code as `@coderoot-eth/verify`.

```bash
npm ci                 # at the repository root
npm test -w mcp        # builds, then drives the server over stdio
```

License: Apache-2.0.
