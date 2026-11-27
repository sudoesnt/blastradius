// The inventory scan: what it reads, and above all how it reports a scan that fell short.
// A wrong "you do not have this package" lowers a verdict, so absence is only claimed from a complete scan.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';

const { parseManifest, scanInventory, matchInventory, inventoryIsComplete } = await import('../src/inventory.mjs');
const { validateAnalysis } = await import('../src/analyze.mjs');

const names = (pairs, eco) => pairs.filter(([e]) => e === eco).map(([, n]) => n).sort();

async function tree(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'blastradius-inv-'));
  for (const [rel, text] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(root, rel)), { recursive: true });
    await fs.writeFile(path.join(root, rel), text);
  }
  return root;
}

// ---------- parsers ----------

test('pnpm-lock.yaml: current, scoped, peer-suffixed and old-style keys', () => {
  const text = `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      express:
        specifier: ^4.19.0
        version: 4.19.2
      '@scope/tool':
        specifier: ^1.0.0
        version: 1.2.0

packages:

  '@babel/core@7.24.0':
    resolution: {integrity: sha512-x}

  lodash@4.17.21:
    resolution: {integrity: sha512-y}

  /left-pad/1.3.0:
    resolution: {integrity: sha512-z}

  'react-dom@18.3.1(react@18.3.1)':
    resolution: {integrity: sha512-w}
`;
  assert.deepEqual(names(parseManifest('pnpm-lock.yaml', text), 'npm'), ['@babel/core', '@scope/tool', 'express', 'left-pad', 'lodash', 'react-dom']);
});

test('yarn.lock: classic and berry entries, several ranges on one line', () => {
  const text = `# yarn lockfile v1

"@babel/core@^7.0.0", "@babel/core@^7.1.0":
  version "7.24.0"

lodash@^4.17.0:
  version "4.17.21"

"chalk@npm:^5.3.0":
  version: 5.3.0

__metadata:
  version: 8
`;
  assert.deepEqual([...new Set(names(parseManifest('yarn.lock', text), 'npm'))], ['@babel/core', 'chalk', 'lodash']);
});

test('pyproject.toml: PEP 621, optional groups, dependency groups, uv and Poetry', () => {
  const text = `[build-system]
requires = ["hatchling>=1.0"]

[project]
name = "demo"
keywords = ["not-a-dependency"]
dependencies = [
  "requests[socks]>=2.31",   # comment
  "Pydantic_Core ; python_version < '3.13'",
]

[project.optional-dependencies]
dev = ["pytest>=8", "ruff"]

[dependency-groups]
docs = ["mkdocs"]

[tool.uv]
dev-dependencies = ["ipython"]

[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27"

[tool.poetry.group.test.dependencies]
coverage = { version = "^7" }
`;
  const got = names(parseManifest('pyproject.toml', text), 'pip');
  assert.deepEqual(got, ['Pydantic_Core', 'coverage', 'hatchling', 'httpx', 'ipython', 'mkdocs', 'pytest', 'requests', 'ruff']);
  assert.ok(!got.includes('not-a-dependency') && !got.includes('python') && !got.includes('demo'));
});

test('uv.lock, poetry.lock and Cargo files', () => {
  const lock = `version = 1

[[package]]
name = "anyio"
version = "4.4.0"
dependencies = [
    { name = "idna" },
]

[[package]]
name = "idna"
version = "3.7"

[metadata]
name = "not-a-package"
`;
  assert.deepEqual(names(parseManifest('uv.lock', lock), 'pip'), ['anyio', 'idna']);
  assert.deepEqual(names(parseManifest('poetry.lock', lock), 'pip'), ['anyio', 'idna']);
  assert.deepEqual(names(parseManifest('Cargo.lock', lock), 'cargo'), ['anyio', 'idna']);

  const cargo = `[package]
name = "mycrate"

[dependencies]
serde = { version = "1", features = ["derive"] }
tokio = "1"

[dev-dependencies]
proptest = "1"

[target.'cfg(windows)'.dependencies]
windows-sys = "0.59"

[dependencies.serde_json]
version = "1"
`;
  assert.deepEqual(names(parseManifest('Cargo.toml', cargo), 'cargo'), ['proptest', 'serde', 'serde_json', 'tokio', 'windows-sys']);
  assert.equal(parseManifest('README.md', 'x'), null);
});

// ---------- scanning ----------

test('a full scan reads every supported manifest and says it is complete', async () => {
  const root = await tree({
    'web/package.json': JSON.stringify({ dependencies: { express: '^4' }, devDependencies: { vitest: '^2' } }),
    'web/pnpm-lock.yaml': "packages:\n\n  lodash@4.17.21:\n    resolution: {}\n",
    'api/pyproject.toml': '[project]\ndependencies = ["fastapi"]\n',
    'api/uv.lock': '[[package]]\nname = "Starlette"\n',
    'tool/Cargo.toml': '[dependencies]\nserde_json = "1"\n',
    'svc/go.mod': 'module x\n\nrequire github.com/gin-gonic/gin v1.10.0\n',
    'web/node_modules/evil/package.json': JSON.stringify({ dependencies: { 'should-not-be-read': '1' } })
  });
  const inv = await scanInventory([root]);
  assert.equal(inv.complete, true);
  assert.deepEqual(inv.problems, []);
  assert.equal(inventoryIsComplete(inv), true);
  assert.deepEqual(inv.packages.npm, ['express', 'lodash', 'vitest']);
  assert.deepEqual(inv.packages.pip, ['fastapi', 'starlette']);
  assert.deepEqual(inv.packages.cargo, ['serde-json'], 'crate names are normalised so serde_json matches serde-json');
  assert.deepEqual(inv.packages.go, ['github.com/gin-gonic/gin']);
  assert.equal(inv.manifestCount, 6);
});

test('more than 4,000 files is no longer a silent cut-off', async () => {
  const files = { 'deep/in/the/tree/package.json': JSON.stringify({ dependencies: { 'found-after-many-files': '1' } }) };
  for (let i = 0; i < 4500; i++) files[`aaa-bulk/f${i}.txt`] = '';
  const inv = await scanInventory([await tree(files)]);
  assert.equal(inv.complete, true);
  assert.ok(inv.entriesWalked > 4500);
  assert.ok(inv.packages.npm.includes('found-after-many-files'));
});

test('every way a scan can fall short is recorded and makes it incomplete', async () => {
  const root = await tree({
    'a/package.json': JSON.stringify({ dependencies: { early: '1' } }),
    'a/b/c/d/package.json': JSON.stringify({ dependencies: { 'too-deep': '1' } }),
    'broken/package.json': '{ not json',
    'z/1.txt': '', 'z/2.txt': '', 'z/3.txt': ''
  });

  const deep = await scanInventory([root], { maxDepth: 2 });
  assert.equal(deep.complete, false);
  assert.ok(deep.problems.some((p) => /deeper than 2 levels/.test(p)));
  assert.equal(deep.gaps.tooDeep.length, 1);
  assert.ok(!deep.packages.npm.includes('too-deep'));
  assert.ok(deep.problems.some((p) => /could not be parsed/.test(p)), 'a manifest that fails to parse is a gap too');

  const capped = await scanInventory([root], { maxEntries: 3 });
  assert.equal(capped.complete, false);
  assert.equal(capped.gaps.entryLimitReached, true);
  assert.ok(capped.problems.some((p) => /stopped after 3 files and folders/.test(p)));

  const missing = await scanInventory([path.join(root, 'does-not-exist')]);
  assert.equal(missing.complete, false);
  assert.ok(missing.problems.some((p) => /could not be opened/.test(p)));
});

// ---------- what a miss is allowed to mean ----------

const cluster = (packages) => ({ id: 'inc-x', leadTitle: 'x', evidence: 'A stolen token was used by the attacker.', packages, kevProducts: [] });
const raw = { clusterId: 'inc-x', verdict: 'ACT_NOW', tldrRootCause: 'x.', couldThisHappenToMe: 'Yes.', rootCauseBucket: 'Unknown / Not Disclosed', rootCauseBasis: 'UNKNOWN' };
const complete = { schema: 2, complete: true, problems: [], roots: ['/code'], packages: { npm: ['left-pad'], pip: [], go: [], cargo: ['serde-json'] } };

test('only a complete scan can say you do not have a package', () => {
  const miss = matchInventory(cluster([{ ecosystem: 'npm', name: 'ruflo' }]), complete);
  assert.deepEqual([miss.checked, miss.matches.length, miss.conclusive], [true, 0, true]);
  assert.equal(validateAnalysis(raw, cluster([]), miss).verdict, 'WATCH_HARDEN', 'a conclusive miss lowers Act Now');

  for (const partial of [
    { ...complete, complete: false, problems: ['stopped after 750,000 files and folders'] },
    { roots: ['/code'], packages: complete.packages } // written by the old scanner: no schema, no completeness
  ]) {
    assert.equal(inventoryIsComplete(partial), false);
    const m = matchInventory(cluster([{ ecosystem: 'npm', name: 'ruflo' }]), partial);
    assert.deepEqual([m.checked, m.matches.length, m.conclusive], [true, 0, false]);
    assert.equal(validateAnalysis(raw, cluster([]), m).verdict, 'ACT_NOW', 'an inconclusive miss never lowers a verdict');

    const hit = matchInventory(cluster([{ ecosystem: 'npm', name: 'left-pad' }]), partial);
    assert.deepEqual([hit.matches, hit.conclusive], [['npm:left-pad'], true], 'a match in a partial scan is still a match');
  }
});

test('ecosystems the scanner cannot read never produce a "not found"', () => {
  const maven = matchInventory(cluster([{ ecosystem: 'maven', name: 'org.apache:log4j-core' }]), complete);
  assert.equal(maven.checked, false, 'nothing was looked up, so nothing is claimed');

  const mixed = matchInventory(cluster([{ ecosystem: 'npm', name: 'ruflo' }, { ecosystem: 'maven', name: 'x:y' }]), complete);
  assert.deepEqual([mixed.checked, mixed.conclusive], [true, false], 'a miss on npm proves nothing about the maven half');

  const rust = matchInventory(cluster([{ ecosystem: 'rust', name: 'serde_json' }]), complete);
  assert.deepEqual(rust.matches, ['cargo:serde_json']);
  const pip = matchInventory(cluster([{ ecosystem: 'pip', name: 'Some.Package' }]), { ...complete, packages: { ...complete.packages, pip: ['some-package'] } });
  assert.deepEqual(pip.matches, ['pip:Some.Package']);
});
