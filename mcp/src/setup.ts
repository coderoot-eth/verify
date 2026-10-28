/**
 * Setting up a package to release through CodeRoot, and finding the version to
 * deploy. An agent wires the workflows; a person links the repository, approves
 * and revokes. Nothing here can approve or revoke.
 */

import { checkPackage, CheckOptions, Action } from './tools';
import { Verdict } from '../../lib/verdict';

const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const GITHUB_REPO = /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/;
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

const CHECKOUT = 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1';
const SETUP_NODE = 'actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0';
const UPLOAD_ARTIFACT = 'actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2';
const DOWNLOAD_ARTIFACT = 'actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2';
const ACTION = 'coderoot-eth/action@v1';
const NPM = '12.2.0';

export interface SetupInput {
  /** The npm package name, e.g. @acme/widget. */
  package: string;
  /** The public GitHub repository, owner/name. */
  repository: string;
  /** Node version for the build (default 22). */
  node?: string;
}

export interface SetupResult {
  files: Array<{ path: string; content: string }>;
  /** What only a person (or a CodeRoot workspace admin) can do, in order. */
  humanSteps: string[];
  /** What the agent does after the files are in place, in order. */
  agentSteps: string[];
  /** Never done by an agent. */
  never: string[];
}

function releaseWorkflow(node: string): string {
  return `# Publishes this package when a version tag (v1.2.3) is pushed, then submits the
# release to CodeRoot, where a person approves it before anyone is told to trust it.
#
# \`pack\` builds and tests once and cannot publish. \`publish\` runs in the
# \`npm-publish\` environment, the only place npm's trusted publishing accepts, and
# publishes that exact tarball with provenance; no npm token exists. \`submit\` has
# no environment, so its identity token cannot publish, and hands the same
# tarball to CodeRoot.

name: release

on:
  push:
    tags:
      - "v[0-9]+.[0-9]+.[0-9]+"

permissions: {}

jobs:
  pack:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
    outputs:
      name: \${{ steps.pack.outputs.name }}
      version: \${{ steps.pack.outputs.version }}
      sha256: \${{ steps.pack.outputs.sha256 }}
    steps:
      - uses: ${CHECKOUT}
        with:
          persist-credentials: false
      - uses: ${SETUP_NODE}
        with:
          node-version: "${node}"
          cache: ""
      - run: npm ci --ignore-scripts
      - run: npm run test --if-present
      - run: npm run build --if-present
      - id: pack
        env:
          TAG: \${{ github.ref_name }}
        run: |
          set -euo pipefail
          name="$(node -p "require('./package.json').name")"
          version="$(node -p "require('./package.json').version")"
          [ "v$version" = "$TAG" ] || { echo "tag $TAG does not match $name $version"; exit 1; }
          npm pack --ignore-scripts >/dev/null && mv ./*.tgz package.tgz
          {
            echo "name=$name"
            echo "version=$version"
            echo "sha256=$(sha256sum package.tgz | cut -d' ' -f1)"
          } >> "$GITHUB_OUTPUT"
      - uses: ${UPLOAD_ARTIFACT}
        with:
          name: package
          path: package.tgz
          if-no-files-found: error
          retention-days: 7

  publish:
    needs: pack
    runs-on: ubuntu-latest
    timeout-minutes: 10
    environment: npm-publish
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: ${SETUP_NODE}
        with:
          node-version: "${node}"
          cache: ""
      - name: Exact npm
        run: npm install -g npm@${NPM} --ignore-scripts && npm --version
      - uses: ${DOWNLOAD_ARTIFACT}
        with:
          name: package
      - name: Check the tarball is the one pack built
        env:
          EXPECTED: \${{ needs.pack.outputs.sha256 }}
        run: '[ "$(sha256sum package.tgz | cut -d" " -f1)" = "$EXPECTED" ] || { echo "digest mismatch"; exit 1; }'
      - name: Publish with provenance
        run: npm publish package.tgz --registry https://registry.npmjs.org/ --access public --provenance --ignore-scripts

  submit:
    needs: [pack, publish]
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: ${DOWNLOAD_ARTIFACT}
        with:
          name: package
      - name: Check the tarball is the one pack built
        env:
          EXPECTED: \${{ needs.pack.outputs.sha256 }}
        run: '[ "$(sha256sum package.tgz | cut -d" " -f1)" = "$EXPECTED" ] || { echo "digest mismatch"; exit 1; }'
      - name: Submit to CodeRoot
        uses: ${ACTION}
        with:
          mode: submit
          flow: published
          artifact: package.tgz
          name: \${{ needs.pack.outputs.name }}
          version: \${{ needs.pack.outputs.version }}
`;
}

function deployWorkflow(pkg: string, node: string): string {
  return `# Deploys one published version of ${pkg}, only when CodeRoot answers verified
# for the exact bytes npm serves. Run it with the version to deploy; to move
# back, run it with the previous good version.

name: deploy

on:
  workflow_dispatch:
    inputs:
      version:
        description: "Version to deploy, e.g. 1.2.3"
        required: true

permissions: {}

jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - uses: ${SETUP_NODE}
        with:
          node-version: "${node}"
          cache: ""
      - name: Fetch the published tarball
        id: tarball
        env:
          PACKAGE: "${pkg}"
          VERSION: \${{ inputs.version }}
        run: |
          set -euo pipefail
          mkdir -p "$RUNNER_TEMP/release"
          npm pack "$PACKAGE@$VERSION" --pack-destination "$RUNNER_TEMP/release" --silent >/dev/null
          file="$(ls "$RUNNER_TEMP"/release/*.tgz)"
          echo "file=$file" >> "$GITHUB_OUTPUT"
          echo "hash=sha256:$(sha256sum "$file" | cut -d' ' -f1)" >> "$GITHUB_OUTPUT"
      - name: CodeRoot verify
        uses: ${ACTION}
        with:
          mode: verify
          hash: \${{ steps.tarball.outputs.hash }}
      # Runs only when the step above answered verified. Replace with the real deploy.
      - name: Deploy
        env:
          PACKAGE: "${pkg}"
          VERSION: \${{ inputs.version }}
          FILE: \${{ steps.tarball.outputs.file }}
          HASH: \${{ steps.tarball.outputs.hash }}
        run: echo "deploying $PACKAGE@$VERSION ($HASH)"
`;
}

/** The files and steps that set a package up to release through CodeRoot. */
export function setupRelease(input: SetupInput): SetupResult {
  const pkg = input.package.trim();
  const repo = input.repository.trim().replace(/^https:\/\/github\.com\//, '').replace(/\.git$/, '');
  const node = (input.node ?? '22').trim();
  if (!NPM_NAME.test(pkg)) throw new Error(`not a valid npm package name: ${pkg}`);
  if (!GITHUB_REPO.test(repo)) throw new Error(`repository must be owner/name on GitHub: ${input.repository}`);
  if (!/^\d+$/.test(node)) throw new Error(`node must be a major version, e.g. 22: ${node}`);

  return {
    files: [
      { path: '.github/workflows/release.yml', content: releaseWorkflow(node) },
      { path: '.github/workflows/deploy.yml', content: deployWorkflow(pkg, node) },
    ],
    humanSteps: [
      `GitHub (repository admin): create the environment \`npm-publish\` in ${repo} (Settings → Environments), limited to tags matching \`v*\`.`,
      `npm (package owner): if ${pkg} does not exist yet, publish a code-free 0.0.0 placeholder by hand to reserve it. Then add a trusted publisher on npmjs.com: GitHub Actions, repository ${repo}, workflow \`release.yml\`, environment \`npm-publish\`. Publish the first real version within 48 hours, or npm drops the setting.`,
      `CodeRoot (workspace admin): link repository ${repo}, workflow \`.github/workflows/release.yml\` and package ${pkg} to the workspace. Give them the repository id and owner id: \`gh api repos/${repo} --jq '.id, .owner.id'\`.`,
      'CodeRoot (a person in the queue): approve each release at its review link, and revoke a release that must no longer be trusted.',
    ],
    agentSteps: [
      'Write the two files, commit package.json and package-lock.json with them, and push to the default branch.',
      'When the person confirms the steps above, set the version in package.json, commit, and push a tag v<version> on that commit.',
      'Watch the release run. The submit job ends with the review link; the release now waits for a person. Until they approve, verify_package answers unregistered.',
      'After the approval, verify_package answers verified. Deploy with: gh workflow run deploy.yml -f version=<version>.',
      'If a release is revoked, verify_package answers revoked and the deploy refuses it. Call release_history, and deploy its latestVerified version instead.',
    ],
    never: [
      'Approve or revoke a release. Only a person in the CodeRoot queue can, and the gate refuses anyone else.',
      'Add an npm token, a CodeRoot credential or any other secret to the repository or the workflows.',
      'Add continue-on-error or || true to the CodeRoot steps, or deploy a version that does not answer verified.',
    ],
  };
}

export interface HistoryEntry {
  version: string;
  publishedAt: string | null;
  verdict: Verdict;
  action: Action;
  deprecated: string | null;
}

export interface HistoryResult {
  package: string;
  /** npm's \`latest\` dist-tag. */
  npmLatest: string | null;
  /** The newest checked version whose bytes answer verified: the one to deploy or move back to. */
  latestVerified: string | null;
  advice: string;
  versions: HistoryEntry[];
}

/** The newest published versions of a package, each checked by its bytes. */
export async function releaseHistory(name: string, limit = 10, options: CheckOptions = {}): Promise<HistoryResult> {
  if (!NPM_NAME.test(name)) throw new Error(`not a valid npm package name: ${name}`);
  const registry = (options.registryUrl ?? 'https://registry.npmjs.org').replace(/\/+$/, '');
  const res = await fetch(`${registry}/${name.replace('/', '%2f')}`, { headers: { Accept: 'application/json' } });
  if (res.status === 404) throw new Error(`${name} is not on npm`);
  if (!res.ok) throw new Error(`could not read ${name} from npm (HTTP ${res.status})`);
  const packument = (await res.json()) as {
    'dist-tags'?: Record<string, string>;
    time?: Record<string, string>;
    versions?: Record<string, { deprecated?: string }>;
  };

  const published = Object.keys(packument.versions ?? {}).filter((v) => SEMVER.test(v));
  const when = (v: string) => packument.time?.[v] ?? '';
  published.sort((a, b) => (when(b) < when(a) ? -1 : when(b) > when(a) ? 1 : 0));
  const newest = published.slice(0, Math.max(1, Math.min(limit, 50)));

  const versions: HistoryEntry[] = [];
  for (const version of newest) {
    const result = await checkPackage(name, version, options);
    versions.push({
      version,
      publishedAt: when(version) || null,
      verdict: result.verdict,
      action: result.action,
      deprecated: packument.versions?.[version]?.deprecated ?? null,
    });
  }

  const npmLatest = packument['dist-tags']?.['latest'] ?? null;
  const latestVerified = versions.find((v) => v.action === 'proceed')?.version ?? null;
  const latestEntry = versions.find((v) => v.version === npmLatest);
  let advice: string;
  if (!latestVerified) advice = `No checked version of ${name} answers verified. Deploy none of them; ask a person to approve a release.`;
  else if (latestVerified === npmLatest) advice = `npm's latest, ${npmLatest}, answers verified. Deploy it.`;
  else
    advice =
      `npm's latest, ${npmLatest ?? 'none'}, answers ${latestEntry?.verdict ?? 'nothing among the versions checked'}. ` +
      `Deploy ${latestVerified}, the newest version that answers verified.`;

  return { package: name, npmLatest, latestVerified, advice, versions };
}
