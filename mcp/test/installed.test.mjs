// Packs @coderoot-eth/mcp, installs the tarball into an empty project, and starts
// the installed server: it must run on its own and report its own version.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const MCP = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const { version } = JSON.parse(fs.readFileSync(path.join(MCP, 'package.json'), 'utf8'));

test('an installed @coderoot-eth/mcp starts on its own and reports its own version', async (t) => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-install-'));
  t.after(() => fs.rmSync(work, { recursive: true, force: true }));
  const tarball = execFileSync('npm', ['pack', '--silent', '--pack-destination', work], { cwd: MCP, encoding: 'utf8' }).trim().split('\n').pop();
  execFileSync('npm', ['init', '-y'], { cwd: work, stdio: 'ignore' });
  execFileSync('npm', ['install', '--silent', '--no-audit', '--no-fund', path.join(work, tarball)], { cwd: work, stdio: 'inherit' });

  const bin = path.join(work, 'node_modules', '@coderoot-eth', 'mcp', 'dist', 'main.js');
  const client = new Client({ name: 'test', version: '0' });
  t.after(() => client.close());
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [bin], cwd: work }));

  assert.deepEqual(client.getServerVersion(), { name: 'coderoot', version });
  const { tools } = await client.listTools();
  assert.equal(tools.length, 5);
});
