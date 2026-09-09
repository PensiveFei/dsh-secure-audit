import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));

/**
 * Install-hygiene contract.
 *
 * npm 7+ auto-installs peerDependencies. With a bare peer on
 * @deepseek-ai/dsh-tools, a clean `npm install dsh-secure-audit` pulled in 21
 * packages — a complete parallel @deepseek-ai core tree, including a second
 * copy of @deepseek-ai/dsh-scope. Installed next to a host that already runs
 * its own core, two dsh-scope copies mean the scope symbols no longer match
 * and the harness refuses to compose a context.
 *
 * Declaring the peer optional keeps the documentation value (this plugin needs
 * a host that provides dsh-tools) while telling npm not to go install one.
 */
test('manifest: the DSH peer is optional, so installing never clones the core tree', () => {
  const peers = Object.keys(pkg.peerDependencies || {});
  assert.ok(peers.length > 0, 'expected at least one declared peer');
  assert.ok(pkg.peerDependenciesMeta, 'peerDependenciesMeta must exist');
  for (const name of peers) {
    const meta = pkg.peerDependenciesMeta[name];
    assert.ok(meta && meta.optional === true, name + ' must be declared an OPTIONAL peer');
  }
});

/**
 * semver admits prereleases ONLY for the exact major.minor.patch tuple named
 * in the range. So ">=0.1.0-rc.7" matches no 0.1.2-alpha.x, and
 * ">=0.1.2-alpha.2" matches no 0.1.0-rc.x. Both harness lines are in active
 * use, so the range has to name both or one group of users gets a permanent
 * unmet-peer warning. (0.2.8 fixed one direction and broke the other.)
 */
test('manifest: the peer range covers every shipped prerelease line', () => {
  const range = pkg.peerDependencies['@deepseek-ai/dsh-tools'];
  // 0.1.1-rc.x, 0.1.3-alpha.x and 0.1.5-alpha.x hosts are all in the wild;
  // each tuple must be named explicitly or those users get a permanent
  // unmet-peer warning.
  for (const line of ['0\.1\.0-rc', '0\.1\.1-rc', '0\.1\.2-alpha', '0\.1\.3-alpha', '0\.1\.5-alpha']) {
    assert.ok(new RegExp(line).test(range), 'range must admit the ' + line.replace(/\\/g, '') + ' line: ' + range);
  }
});

test('manifest: the test dependency tracks the current host line', () => {
  // Pinned to 0.1.2-alpha.2 the smoke test validated an outdated dsh-tools
  // contract while users ran the 0.1.2-rc line.
  const dev = pkg.devDependencies['@deepseek-ai/dsh-tools'];
  assert.ok(!/alpha/.test(dev), 'dev dependency must not pin a superseded alpha line: ' + dev);
});

test('manifest: version and changelog agree', () => {
  const changelog = readFileSync(join(ROOT, 'CHANGELOG.md'), 'utf8');
  assert.ok(
    changelog.includes('## [' + pkg.version + ']'),
    'CHANGELOG.md has no section for ' + pkg.version,
  );
});
