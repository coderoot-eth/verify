#!/usr/bin/env bash
# Pack @coderoot-eth/verify and the coderoot wrapper, install both from the
# tarballs into an empty project, and check `npx coderoot` behaves like the
# real command: same output, same exit codes.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

(cd "$root" && npm pack --silent --pack-destination "$work" >/dev/null)
(cd "$root/wrapper" && npm pack --silent --pack-destination "$work" >/dev/null)
cd "$work"
npm init -y >/dev/null
npm install --silent --no-audit --no-fund ./coderoot-eth-verify-*.tgz ./coderoot-*.tgz

printf 'wrapper test bytes' > artifact.bin
want="sha256:$(shasum -a 256 artifact.bin | cut -d' ' -f1)"
got="$(npx --no-install coderoot hash artifact.bin --json | node -p 'JSON.parse(require("fs").readFileSync(0)).digests.sha256')"
[ "$got" = "$want" ] || { echo "hash: expected $want, got $got"; exit 1; }
echo "ok  npx coderoot hash prints the file's digest"

set +e
npx --no-install coderoot verify --hash nonsense >/dev/null 2>&1; code=$?
set -e
[ "$code" = 3 ] || { echo "usage error: expected exit 3, got $code"; exit 1; }
echo "ok  a usage error keeps exit code 3"

set +e
npx --no-install coderoot >/dev/null 2>&1; code=$?
set -e
[ "$code" != 0 ] || { echo "no command: expected a non-zero exit"; exit 1; }
echo "ok  no command prints usage and fails"

set +e
npx --no-install coderoot verify --hash sha256:a7839cbbf036fd2a4ee4fc9c9c6fc90c58f3c15336fa436af0d8900abe17016c --no-cache >/dev/null 2>&1; code=$?
set -e
[ "$code" = 1 ] || { echo "revoked release: expected exit 1, got $code"; exit 1; }
echo "ok  a revoked release exits 1 (live endpoint)"
