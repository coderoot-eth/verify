# Security policy

Report a vulnerability privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability**. Do not open a public issue for it.

Include what you found, how to reproduce it, and the version you ran (`npm ls @coderoot-eth/verify`)
or the commit.

## In scope

- A component reported `verified` when its bytes do not match an attested record.
- A revoked release that is not refused (`verify` exits 0, or a batch exits 0 with a revoked
  component).
- A digest compared or reported under the wrong algorithm.
- Anything that makes the client send an SBOM-declared digest to the endpoint, or trust a name and
  version as proof of bytes.

Answers from `verify.coderoot.app` itself are reported the same way.
