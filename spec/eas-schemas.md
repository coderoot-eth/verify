# Attestation schemas

CodeRoot attestations are [EAS](https://attest.org) attestations on **Base Sepolia**, through the
EAS contract at `0x4200000000000000000000000000000000000021`. All three schemas have no resolver
and are revocable. Anyone can re-check an attestation by its UID on EAS directly, without
CodeRoot in the loop.

| version | schema UID | identifies the bytes by |
|---|---|---|
| v0 | `0x78969a9426ada4f4c438ae8bacbccd6ea24b0af504a4f2dd5dcc58673d2a3d03` | `hash` + `algo` |
| v1 | `0xc8f8019adc6640c2bca1c6637f9929cdf51e71f83044e885d6ae4e12785031d9` | `contentHash` (SHA-256) |
| v2 | `0x98766b7724f86c29edd71ae0cadabdd07ac68155a521de0fe689ddabcb133343` | `contentSha256` and `contentSha512` |

Each UID is `keccak256(schema string, resolver 0x0, revocable true)` over the exact strings below.

## v0

```
string hash,string algo,string digest,string root
```

## v1

```
string packageName,string packageVersion,string registry,bytes32 contentHash,string repositoryUrl,string commitHash,string buildSystem,string sigstoreLogIndex,string metadataUri
```

`contentHash` is the SHA-256 of the published artifact. A record of this version is found by
SHA-256 only, so a SHA-512 query for it answers `unregistered`. Optional strings are `""`, never
absent.

## v2

```
string releaseId,string registry,string packageName,string packageVersion,bytes32 contentSha256,bytes contentSha512,string commitHash,string buildSystem,string sigstoreLogIndex,bytes32 policyHash,bytes32 recordCommitment,string attesterRole
```

| field | meaning |
|---|---|
| `releaseId` | the release this attests, as the gate names it |
| `registry`, `packageName`, `packageVersion` | the coordinates |
| `contentSha256`, `contentSha512` | both digests of the exact artifact bytes; either finds the record |
| `commitHash`, `buildSystem`, `sigstoreLogIndex` | where it was built, when known |
| `policyHash` | the policy the release was approved under |
| `recordCommitment` | a commitment to the off-chain signed record of the approval |
| `attesterRole` | the role of the key that signed the attestation |

## Revocation

A revoke is an EAS revocation of the attestation UID, or an entry in the gate's revocation list.
The verify endpoint reads both, and revoked from either wins.
