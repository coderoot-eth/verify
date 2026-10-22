import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server';

// stdout carries the protocol; anything for a person goes to stderr.
async function main(): Promise<void> {
  const server = createServer({
    ...(process.env['CODEROOT_VERIFY_URL'] ? { verifyUrl: process.env['CODEROOT_VERIFY_URL'] } : {}),
    ...(process.env['CODEROOT_NPM_REGISTRY'] ? { registryUrl: process.env['CODEROOT_NPM_REGISTRY'] } : {}),
  });
  await server.connect(new StdioServerTransport());
}

main().catch((error: unknown) => {
  process.stderr.write(`coderoot-mcp: ${(error as Error).message}\n`);
  process.exit(1);
});
