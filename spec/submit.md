# Submitting a release

A publisher releases on npm with trusted publishing, then submits the release to CodeRoot, where
a person approves it and CodeRoot attests it. CodeRoot never publishes and never holds a registry
token.

- **`published`**: the version is live on npm (`npm publish`).
- **`staged`**: the version is staged on npm (`npm stage publish`) and goes live only when a
  maintainer approves it there. CodeRoot attests it first.

Scope: public npm packages from public GitHub repositories, published with provenance.

Gate: `https://secure.coderoot.app`.

## Sign-in

A GitHub Actions identity token, audience exactly `secure.coderoot.app`, sent as
`Authorization: Bearer <token>`. The job needs `permissions: id-token: write`. No stored secret
is involved, and no other credential is accepted for these flows.

The gate checks the token's issuer, audience, expiry and signature, then that its repository
(by numeric `repository_id` and `repository_owner_id`), its workflow file (from `workflow_ref`)
and the package are linked to the workspace. For a job inside a reusable workflow, the workflow
that counts is the caller, which is also what npm's provenance names.

Run the submit step in a job with no environment that npm trusts, so the job that holds this
token cannot publish.

## 1. Upload the tarball

`POST /v1/artifacts`, `multipart/form-data` with one part named `file`, or
`application/octet-stream`. Upload the exact bytes that were published or staged; pack once and
publish that file. The gate hashes the upload itself:

```json
{
  "upload_id": "upl_…",
  "size_bytes": 18234,
  "hashes": ["sha256:…", "sha512:…"],
  "expires_at": "…"
}
```

For `staged`, also upload the Sigstore provenance bundle passed to `npm stage publish
--provenance-file`, the same way. `npm stage publish --provenance` builds its bundle in memory and
never writes it out, so a staged release makes the bundle first (for example with
`actions/attest-build-provenance`, one subject: `pkg:npm/<name>@<version>` with the tarball's
SHA-512) and passes the file to npm.

## 2. Submit

`POST /v1/submit` with `Idempotency-Key: <UUIDv4>`.

```json
{
  "artifact": { "upload_id": "upl_…", "kind": "npm-tarball", "filename": "acme-widget-1.2.3.tgz" },
  "hashes": ["sha256:…", "sha512:…"],
  "coordinates": { "registry": "npm", "name": "@acme/widget", "version": "1.2.3" },
  "flow": "staged",
  "stage_id": "65e9ba3c-7a59-4ac1-823e-e51c0b4fadcc",
  "provenance": { "upload_id": "upl_…", "sha256": "sha256:…" },
  "source": {
    "repo": "https://github.com/acme/widget",
    "commit": "<40 hex>",
    "build_system": "github-actions",
    "build_uri": "https://github.com/acme/widget/actions/runs/<run id>"
  },
  "signatures": [],
  "evidence": [],
  "agent": null,
  "submitter_note": "@acme/widget@1.2.3 via GitHub Actions"
}
```

| field | rule |
|---|---|
| `artifact.upload_id` | from step 1 |
| `hashes` | both `sha256:` and `sha512:`, lowercase, equal to the upload receipt |
| `coordinates` | strict semver and a valid npm name |
| `flow` | `published` or `staged` |
| `stage_id` | `staged` only: the id `npm stage publish` prints (`staged with id <uuid>`), lowercase |
| `provenance` | `staged` only: the bundle's `upload_id` and its SHA-256 |
| `signatures`, `evidence` | arrays, `[]` when empty; never omitted |
| `agent` | `null` |

Unknown fields anywhere are refused. Keys go in the order shown, serialized with two-space
indent and no trailing newline. The same key with the same bytes within 24 hours replays the
original response (`200`, `idempotent_replay: true`); deriving the key from the body bytes makes
a retry safe.

A `201` returns the submission:

```json
{
  "submission_id": "sub_…",
  "state": "pending_review",
  "policy_grade": "human-required",
  "attestation": { "state": "none", "eas_uid": null, "tx_hash": null },
  "publish": { "state": "none", "registry_url": null },
  "review_url": "https://coderoot.app/review/detail?id=sub_…",
  "idempotent_replay": false
}
```

## What happens next

Every attestation needs a person's approval. Approval creates the signed record and queues the
attestation; `publish` stays `none`, because the publisher already put the release on npm.

| check | `verified` means |
|---|---|
| `provenance` | the bundle's signature, certificate and log entry verify; its one subject is `pkg:npm/<name>@<version>` with the submitted SHA-512; its repository, workflow and commit match the identity token and the link. For `published` the gate reads the bundle from npm; for `staged`, from the upload |
| `registry` | npm serves the version with `dist.integrity` equal to the submitted SHA-512 |

For `staged`, `registry` is `pending` until npm serves the version; a failed read of npm is
retried and stays `pending`. If npm then serves other bytes, `registry` is `mismatch` and the
release goes to a person. An attestation only ever vouches for the uploaded bytes.

## Refusals

Errors are `{ "error": { "id", "message", "detail", "request_id" } }`.

| status | id | when |
|--:|---|---|
| 400 | `body_invalid` | a shape error, with `detail.path`; includes a missing `flow` with an identity token |
| 400 | `hash_mismatch` | `hashes` differ from what the gate computed |
| 400 | `hash_set_incomplete` | not both algorithms |
| 400 | `hash_format_invalid` | not tagged lowercase hex |
| 400 | `coordinates_invalid` | bad semver or npm name |
| 400 | `artifact_upload_not_found` | unknown or expired `upload_id` |
| 400 | `idempotency_key_missing` | no `Idempotency-Key` |
| 401 | `credential_invalid` | identity token refused; `detail.reason` `issuer` \| `audience` \| `expired` |
| 403 | `github_oidc_required` | a flow submitted with any other credential |
| 403 | `repository_not_authorized` | repository, workflow or package not linked to the workspace |
| 409 | `idempotency_key_reused` | same key, different body |
| 409 | `package_identity_pending` | this release is already waiting for review |
| 409 | `package_identity_already_released` | this release is already attested |
| 422 | `staged_proof_unavailable` | `staged` without `provenance` |
| 422 | `provenance_invalid` | the bundle does not prove this release; `detail.reason` names why |
