#!/usr/bin/env node
'use strict';

// Hands everything to @coderoot-eth/verify's own coderoot command and keeps its exit code.
const { spawnSync } = require('child_process');
const path = require('path');

const pkgPath = require.resolve('@coderoot-eth/verify/package.json');
const bin = require(pkgPath).bin.coderoot;
const result = spawnSync(process.execPath, [path.join(path.dirname(pkgPath), bin), ...process.argv.slice(2)], { stdio: 'inherit' });
if (result.error) {
  console.error(`coderoot: ${result.error.message}`);
  process.exit(3);
}
process.exit(result.status === null ? 3 : result.status);
