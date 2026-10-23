# coderoot

Runs the `coderoot` command from [`@coderoot-eth/verify`](https://github.com/coderoot-eth/verify),
so this works with nothing installed:

```bash
npx coderoot verify --file ./axios-1.7.9.tgz
npx coderoot verify --lockfile package-lock.json
npx coderoot hash ./dist/app.tgz
```

Arguments, output and exit codes are those of `@coderoot-eth/verify`. To use the library, or to
pin a version in a project, install `@coderoot-eth/verify` directly.

License: Apache-2.0.
