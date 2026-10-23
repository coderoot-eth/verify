# @coderoot-eth/mcp

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent check dependencies and
artifacts against CodeRoot's public attestations before it uses them. It is read-only: it can
verify, and it cannot attest or revoke anything.

Every answer rests on a digest of the bytes. A name and version alone never come back verified.

## Tools

| tool | input | checks |
|---|---|---|
| `verify_package` | `name`, `version` | downloads the npm tarball, hashes it, verifies the bytes, and flags bytes that differ from what is attested for that name and version |
| `verify_hash` | `digest` (`sha256:<hex>` or `sha512:<hex>`), `source` | one digest the agent already holds |
| `verify_lockfile` | `path` or `content`, optional `limit`, `details` | every package in a `package-lock.json` (lockfileVersion 2 or 3) |

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
whole lockfile: `refuse` when any package is revoked or mismatched. Unregistered packages are common
and do not fail it. `details: true` adds the result for every package. With `limit`, only the first
packages are checked: the result says `complete: false` with the number left unchecked, and its
action is never `proceed`.

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
