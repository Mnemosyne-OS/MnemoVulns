import { describe, it, expect } from 'vitest';
import { pnpmDevFlags, readNpmLock, readPipfileLock, readPnpmLock, readPoetryLock } from './lockfile';

const PNPM = `lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      vitest:
        specifier: ^1.6.1
        version: 1.6.1
      shared:
        specifier: ^1.0.0
        version: 1.0.0

  apps/web:
    dependencies:
      react-dom:
        specifier: ^18.3.1
        version: 18.3.1(react@18.3.1)
      local:
        specifier: workspace:*
        version: link:../../packages/local

packages:

  vitest@1.6.1:
    resolution: {integrity: a}

  tinypool@1.0.0:
    resolution: {integrity: b}

  shared@1.0.0:
    resolution: {integrity: c}

  react-dom@18.3.1:
    resolution: {integrity: d}

  react@18.3.1:
    resolution: {integrity: e}

  orphan@0.1.0:
    resolution: {integrity: f}

snapshots:

  vitest@1.6.1:
    dependencies:
      tinypool: 1.0.0
      shared: 1.0.0

  tinypool@1.0.0: {}

  shared@1.0.0: {}

  react-dom@18.3.1(react@18.3.1):
    dependencies:
      react: 18.3.1
      shared: 1.0.0

  react@18.3.1: {}

  orphan@0.1.0: {}
`;

describe('pnpm dev flags', () => {
  it('marks what only devDependencies reach, and production wins when both reach it', () => {
    const f = pnpmDevFlags(PNPM);
    expect(f.get('vitest@1.6.1')).toBe(true);
    expect(f.get('tinypool@1.0.0')).toBe(true);
    expect(f.get('react-dom@18.3.1')).toBe(false);
    expect(f.get('react@18.3.1')).toBe(false);
    expect(f.get('shared@1.0.0')).toBe(false); // dev at the root, but also under react-dom
  });

  it('leaves a version reached from nowhere UNKNOWN, never production', () => {
    const r = readPnpmLock(PNPM);
    expect(r.packages.find((p) => p.name === 'orphan')).not.toHaveProperty('dev');
    expect(r.packages.find((p) => p.name === 'vitest')?.dev).toBe(true);
  });
});

describe('other lockfiles', () => {
  it('reads the dev flag package-lock writes, devOptional included', () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: {
      '': {}, 'node_modules/a': { version: '1.0.0', dev: true }, 'node_modules/b': { version: '1.0.0' }, 'node_modules/c': { version: '1.0.0', devOptional: true },
    } });
    const r = readNpmLock(lock);
    expect(r.packages.map((p) => [p.name, p.dev])).toEqual([['a', true], ['b', false], ['c', true]]);
  });

  it('reads Pipfile develop as development', () => {
    const r = readPipfileLock(JSON.stringify({ default: { django: { version: '==3.2.0' } }, develop: { pytest: { version: '==7.0.0' } } }));
    expect(r.packages.map((p) => [p.name, p.dev])).toEqual([['django', false], ['pytest', true]]);
  });

  it('reads poetry 1.x categories and 2.x groups, and nothing when neither is written', () => {
    const r = readPoetryLock(`[[package]]
name = "a"
version = "1.0.0"
category = "dev"

[[package]]
name = "b"
version = "1.0.0"
groups = ["main"]

[[package]]
name = "c"
version = "1.0.0"
`);
    expect(r.packages.map((p) => [p.name, p.dev])).toEqual([['a', true], ['b', false], ['c', undefined]]);
  });
});
