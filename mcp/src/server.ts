import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { checkHash, checkPackage, checkLockfile, CheckOptions } from './tools';
/** This package's version, baked in by build.mjs. */
declare const __MCP_VERSION__: string;
export const VERSION: string = typeof __MCP_VERSION__ === 'string' ? __MCP_VERSION__ : '0.0.0-dev';

const readOnly = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;

function reply(result: object) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }], structuredContent: result as Record<string, unknown> };
}

function failure(error: unknown) {
  return { isError: true, content: [{ type: 'text' as const, text: (error as Error).message }] };
}

/** An MCP server with three read-only tools. It can verify; it can never attest or revoke. */
export function createServer(options: CheckOptions = {}): McpServer {
  const server = new McpServer({ name: 'coderoot', version: VERSION });

  server.registerTool(
    'verify_package',
    {
      title: 'Verify an npm package version',
      description:
        'Download an npm package version, hash its tarball, and check those bytes against CodeRoot attestations. ' +
        'Use before adding or upgrading a dependency. Returns the verdict, what to do (action), and the EAS attestations behind it.',
      inputSchema: { name: z.string().min(1).describe('npm package name, e.g. axios or @scope/pkg'), version: z.string().min(1).describe('exact version, e.g. 1.7.9') },
      annotations: readOnly,
    },
    async ({ name, version }) => {
      try {
        return reply(await checkPackage(name, version, options));
      } catch (error) {
        return failure(error);
      }
    }
  );

  server.registerTool(
    'verify_hash',
    {
      title: 'Verify a digest',
      description:
        'Check one tagged digest (sha256:<hex> or sha512:<hex>) against CodeRoot attestations. ' +
        'Use when you hold a digest from a lockfile, a registry or your own hashing. Never pass a digest copied from an SBOM.',
      inputSchema: {
        digest: z.string().regex(/^(sha256:[0-9a-fA-F]{64}|sha512:[0-9a-fA-F]{128})$/).describe('tagged digest'),
        source: z.enum(['lockfile', 'registry', 'bytes']).default('lockfile').describe('where the digest came from'),
      },
      annotations: readOnly,
    },
    async ({ digest, source }) => {
      try {
        return reply(await checkHash(digest, source, options));
      } catch (error) {
        return failure(error);
      }
    }
  );

  server.registerTool(
    'verify_lockfile',
    {
      title: 'Verify a package-lock.json',
      description:
        'Check every package in an npm package-lock.json (lockfileVersion 2 or 3). Returns a summary, the packages that need ' +
        'attention (revoked, mismatched, degraded), and an action for the whole lockfile. Give a path to the file or its content.',
      inputSchema: {
        path: z.string().optional().describe('path to package-lock.json or npm-shrinkwrap.json'),
        content: z.string().optional().describe('the lockfile JSON, instead of a path'),
        limit: z.number().int().positive().optional().describe('check only the first N distinct packages; the result is then partial and never proceed'),
        details: z.boolean().default(false).describe('include the result for every package'),
      },
      annotations: readOnly,
    },
    async ({ path, content, limit, details }) => {
      try {
        return reply(await checkLockfile({ ...(path ? { path } : {}), ...(content !== undefined ? { content } : {}), ...(limit ? { limit } : {}), details }, options));
      } catch (error) {
        return failure(error);
      }
    }
  );

  return server;
}
