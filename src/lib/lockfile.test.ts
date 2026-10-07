import { describe, it, expect } from 'vitest';
import { LockfileError, pickLockfiles, readNpmLock, readPnpmLock } from './lockfile';

const PNPM_V9 = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      react:
        specifier: ^18.3.1
        version: 18.3.1

packages:

  '@babel/core@7.29.0':
    resolution: {integrity: sha512-x}

  ansi-regex@5.0.1:
    resolution: {integrity: sha512-y}

  react-dom@18.3.1:
    resolution: {integrity: sha512-z}
    peerDependencies:
      react: ^18.3.1

  'gitdep@https://codeload.github.com/a/b/tar.gz/abc':
    resolution: {tarball: https://codeload.github.com/a/b/tar.gz/abc}

  semver@7.8.5-beta.1:
    resolution: {integrity: sha512-w}

snapshots:

  react-dom@18.3.1(react@18.3.1):
    dependencies:
      react: 18.3.1

  ansi-regex@5.0.1: {}
`;

describe('readPnpmLock', () => {
  it('reads v9 keys, scoped and quoted, and counts what has no registry version', () => {
    const r = readPnpmLock(PNPM_V9);
    expect(r.kind).toBe('pnpm');
    expect(r.packages).toEqual([
      { ecosystem: 'npm', name: '@babel/core', version: '7.29.0' },
      { ecosystem: 'npm', name: 'ansi-regex', version: '5.0.1' },
      { ecosystem: 'npm', name: 'react-dom', version: '18.3.1' },
      { ecosystem: 'npm', name: 'semver', version: '7.8.5-beta.1' },
    ]);
    expect(r.skipped).toEqual([{ ecosystem: 'npm', name: 'gitdep', spec: 'https://codeload.github.com/a/b/tar.gz/abc' }]);
  });

  it('reads only the packages block, never the snapshots below it', () => {
    // The peer-suffixed snapshot key would add a duplicate if it were read.
    expect(readPnpmLock(PNPM_V9).packages.filter((p) => p.name === 'react-dom')).toHaveLength(1);
  });

  it('reads v6 keys with their leading slash and peer suffix', () => {
    const v6 = "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: x}\n\n  /react-dom@18.2.0(react@18.2.0):\n    dev: false\n";
    expect(readPnpmLock(v6).packages).toEqual([
      { ecosystem: 'npm', name: 'lodash', version: '4.17.21' },
      { ecosystem: 'npm', name: 'react-dom', version: '18.2.0' },
    ]);
  });

  it('refuses a text with no lockfileVersion, and a version it does not know', () => {
    expect(() => readPnpmLock('hello: world')).toThrow(LockfileError);
    expect(() => readPnpmLock("lockfileVersion: 5.4\npackages:\n  /a/1.0.0:\n")).toThrow(/UNSUPPORTED_VERSION/);
  });

  it('reads a project with no dependency as an empty list, not an error', () => {
    expect(readPnpmLock("lockfileVersion: '9.0'\n\nimporters:\n  .: {}\n")).toEqual({ kind: 'pnpm', ecosystem: 'npm', packages: [], skipped: [] });
  });
});

describe('readNpmLock', () => {
  it('reads v3 packages, nested ones included, and counts link and git entries', () => {
    const lock = {
      lockfileVersion: 3,
      packages: {
        '': { ecosystem: 'npm', name: 'app', version: '1.0.0' },
        'node_modules/lodash': { version: '4.17.20' },
        'node_modules/a/node_modules/lodash': { version: '4.17.21' },
        'node_modules/@scope/x': { version: '2.0.0' },
        'node_modules/local': { link: true, resolved: 'packages/local' },
        'node_modules/fromgit': { version: '1.0.0', resolved: 'git+ssh://git@github.com/a/b.git#abc' },
        'packages/local': { ecosystem: 'npm', name: 'local', version: '0.0.1' },
      },
    };
    const r = readNpmLock(JSON.stringify(lock));
    expect(r.packages).toMatchObject([
      { ecosystem: 'npm', name: '@scope/x', version: '2.0.0' },
      { ecosystem: 'npm', name: 'lodash', version: '4.17.20' },
      { ecosystem: 'npm', name: 'lodash', version: '4.17.21' },
    ]);
    expect(r.skipped.map((s) => s.name)).toEqual(['fromgit', 'local']);
  });

  it('reads a v1 nested dependencies tree', () => {
    const v1 = { lockfileVersion: 1, dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } } } };
    expect(readNpmLock(JSON.stringify(v1)).packages).toMatchObject([{ ecosystem: 'npm', name: 'a', version: '1.0.0' }, { ecosystem: 'npm', name: 'b', version: '2.0.0' }]);
  });

  it('refuses text that is not JSON, and JSON that is not a lockfile', () => {
    expect(() => readNpmLock('{nope')).toThrow(/NOT_JSON/);
    expect(() => readNpmLock('{"hello":1}')).toThrow(/NOT_A_LOCKFILE/);
  });
});

describe('pickLockfiles', () => {
  it('picks the preferred lockfile of EACH ecosystem present, and none when there is none', () => {
    expect(pickLockfiles(['package-lock.json', 'pnpm-lock.yaml']).map((l) => l.file)).toEqual(['pnpm-lock.yaml']);
    expect(pickLockfiles(['yarn.lock', 'requirements.txt', 'poetry.lock', 'Cargo.lock']).map((l) => l.file)).toEqual(['yarn.lock', 'poetry.lock', 'Cargo.lock']);
    expect(pickLockfiles(['README.md'])).toEqual([]);
  });
});
