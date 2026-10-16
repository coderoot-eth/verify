# The verify endpoint

`https://verify.coderoot.app` answers, without credentials, whether bytes are attested. It reads
the attestations on chain (see [eas-schemas.md](eas-schemas.md)) and the gate's own revocations;
a revoke from either wins.

## Routes

| route | answers |
|---|---|
| `GET /verify/<algorithm>:<hex>` | the bytes with that digest. `algorithm` is `sha256` or `sha512` |
| `GET /verify/<registry>/<name>/<version>` | the release at those coordinates. At most `attested-bytes-unproven`, never `verified`; carries `contentHash` for mismatch detection |

A scoped npm name is URL-encoded as one path segment.

## Response

Fields a client relies on (both routes):

| field | meaning |
|---|---|
| `verdict` | `verified` \| `attested-bytes-unproven` \| `unregistered` \| `revoked` |
| `attestationUids` | every EAS attestation UID behind the answer, as one flat list. Read UIDs from here only |
| `totalAttestations`, `revokedAttestations` | counts |
| `degraded` | `true` when the gate's revocations could not be read; the answer may miss a recent revoke |
| `gateRevocation` | `{ checked, revoked, releaseIds }`: what the gate's revocation list said |
| `revocationSource` | where the revocation state was read from |
| `authorCpoaRevoked` | `true` \| `false` \| `null`, with `authorCpoaRevokedUids` |
| `contentHash` | coordinate route only: the attested SHA-256 for these coordinates, `0x`-prefixed |
| `algorithm`, `hash`, `inputForm` | hash route only: the digest as the endpoint parsed it |
| `packages` | hash route only: `registry:name@version` for each attested release with these bytes |

`attestations[]`, `v1Attestations[]` and `v2Attestations[]` carry the decoded records per schema
version. Their split follows the schema versions and is not a stable interface; use
`attestationUids` for UIDs.

A client that cannot reach the endpoint treats the answer as degraded.

## Examples

`GET /verify/sha256:634e3ed585d7c8857f00cb7556f79422614e8defd008f8bb34b6018c1faefa0f` (axios 1.7.9):

```json
{
  "hash": "634e3ed585d7c8857f00cb7556f79422614e8defd008f8bb34b6018c1faefa0f",
  "algorithm": "sha256",
  "inputForm": "tagged",
  "verdict": "verified",
  "revocationSource": "chain",
  "gateRevocation": { "checked": true, "revoked": false, "releaseIds": [] },
  "degraded": false,
  "authorCpoaRevoked": false,
  "authorCpoaRevokedUids": [],
  "attestationUids": ["0xb14a81dee57bae98fbaa5a3be33ac314bf109611c47b2d544f4745452e190f63"],
  "totalAttestations": 1,
  "revokedAttestations": 0,
  "packages": ["npm:axios@1.7.9"]
}
```

`GET /verify/npm/axios/1.7.9` answers `attested-bytes-unproven` with
`"contentHash": "0x634e3ed5…0fa0f"`: the release is attested, but a name and version prove no bytes.

`GET /verify/sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` answers
`revoked`, with two UIDs, one from each of two schema versions.
