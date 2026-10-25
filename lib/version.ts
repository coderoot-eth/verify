import * as fs from 'fs';
import * as path from 'path';

/** This package's version, read from package.json in the source tree or the installed build. */
export function packageVersion(): string {
  for (const candidate of [path.join(__dirname, '..', 'package.json'), path.join(__dirname, '..', '..', 'package.json')]) {
    try {
      const pkg = JSON.parse(fs.readFileSync(candidate, 'utf8')) as { name?: string; version?: string };
      if (pkg.name === '@coderoot-eth/verify' && pkg.version) return pkg.version;
    } catch {
      // try the next location
    }
  }
  return '0.0.0';
}
