import { describe, it, expect } from 'vitest';
import type { OsvRecord } from './advisory';
import { pnpmGraph, readPnpmLock, viaOf, type DepGraph } from './lockfile';
import { apiSource, type Fetcher } from './osv';
import { runScan, VIA_CAP } from './scan';
import { reportText } from './texts';

const PNPM = `lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      builder:
        specifier: ^1.0.0
        version: 1.0.0

  apps/desktop:
    dependencies:
      llama:
        specifier: ^3.0.0
        version: 3.0.0(react@18.3.1)
    devDependencies:
      llama:
        specifier: ^3.0.0
        version: 3.0.0(react@18.3.1)

  apps/site:
    dependencies:
      local:
        specifier: workspace:*
        version: link:../../packages/local
      tar:
        specifier: ^7.5.0
        version: 7.5.13

packages:

  builder@1.0.0:
    resolution: {integrity: a}

  llama@3.0.0:
    resolution: {integrity: b}

  tar@7.5.13:
    resolution: {integrity: c}

  tar@6.2.1:
    resolution: {integrity: d}

  react@18.3.1:
    resolution: {integrity: e}

  lonely@1.0.0:
    resolution: {integrity: f}

snapshots:

  builder@1.0.0:
    dependencies:
      tar: 6.2.1

  llama@3.0.0(react@18.3.1):
    dependencies:
      tar: 7.5.13
      react: 18.3.1

  tar@7.5.13: {}

  tar@6.2.1: {}

  react@18.3.1: {}

  lonely@1.0.0: {}
`;

describe('who pulls a version (pnpm v9)', () => {
  it('names the workspace package and the direct dependency each path starts from, production first', () => {
    const via = viaOf(pnpmGraph(PNPM), new Set(['tar@7.5.13', 'tar@6.2.1']));
    expect(via.get('tar@7.5.13')).toEqual([
      { importer: 'apps/desktop', through: 'llama', dev: false },
      { importer: 'apps/site', through: 'tar', dev: false },
    ]);
    expect(via.get('tar@6.2.1')).toEqual([{ importer: '.', through: 'builder', dev: true }]);
  });

  it('a dependency declared both ways is production, once', () => {
    const via = viaOf(pnpmGraph(PNPM), new Set(['react@18.3.1']));
    expect(via.get('react@18.3.1')).toEqual([{ importer: 'apps/desktop', through: 'llama', dev: false }]);
  });

  it('production sorts first and wins over a dev root met BEFORE it, whatever the lockfile order', () => {
    const graph: DepGraph = {
      roots: [
        { importer: '.', through: 'a', id: 'a@1.0.0', dev: true },
        { importer: 'apps/z', through: 'b', id: 'b@1.0.0', dev: false },
        { importer: 'apps/z', through: 'b', id: 'b@1.0.0', dev: true },
        { importer: '.', through: 'a', id: 'a@1.0.0', dev: false },
      ],
      edges: new Map([['a@1.0.0', ['t@1.0.0']], ['b@1.0.0', ['t@1.0.0']]]),
    };
    expect(viaOf(graph, new Set(['t@1.0.0'])).get('t@1.0.0')).toEqual([
      { importer: '.', through: 'a', dev: false },
      { importer: 'apps/z', through: 'b', dev: false },
    ]);
    const devFirst: DepGraph = {
      roots: [{ importer: '.', through: 'a', id: 'a@1.0.0', dev: true }, { importer: 'apps/z', through: 'b', id: 'b@1.0.0', dev: false }],
      edges: graph.edges,
    };
    expect(viaOf(devFirst, new Set(['t@1.0.0'])).get('t@1.0.0')!.map((w) => w.importer)).toEqual(['apps/z', '.']);
  });

  it('a target reached from no importer is left out, never guessed', () => {
    const via = viaOf(pnpmGraph(PNPM), new Set(['lonely@1.0.0']));
    expect(via.has('lonely@1.0.0')).toBe(false);
  });

  it('a workspace link is not a path (the linked package is its own importer)', () => {
    const roots = pnpmGraph(PNPM).roots;
    expect(roots.some((r) => r.through === 'local')).toBe(false);
  });

  it('only pnpm v9 carries a graph; v6 shows no "pulled by" at all', () => {
    expect(readPnpmLock(PNPM).graph).toBeDefined();
    const v6 = `lockfileVersion: '6.0'\n\npackages:\n\n  /tar@7.5.13:\n    resolution: {integrity: c}\n`;
    expect(readPnpmLock(v6).graph).toBeUndefined();
  });
});

const ELECTRON = (packager: string | null) => `lockfileVersion: '9.0'

importers:

  apps/desktop:
    devDependencies:
      electron:
        specifier: ^31.7.7
        version: 31.7.7
${packager ? `      ${packager}:
        specifier: ^24.0.0
        version: 24.13.3
` : ''}
packages:

  electron@31.7.7:
    resolution: {integrity: a}

  extract-zip@2.0.1:
    resolution: {integrity: b}

  ${packager ?? 'unused'}@24.13.3:
    resolution: {integrity: c}

snapshots:

  electron@31.7.7:
    dependencies:
      extract-zip: 2.0.1

  extract-zip@2.0.1: {}

  ${packager ?? 'unused'}@24.13.3: {}
`;

const ALIAS = `lockfileVersion: '9.0'

importers:

  apps/wiki:
    dependencies:
      core:
        specifier: ^3.0.0
        version: 3.0.0

packages:

  core@3.0.0:
    resolution: {integrity: a}

  '@docusaurus/react-loadable@6.0.0':
    resolution: {integrity: b}

snapshots:

  core@3.0.0:
    dependencies:
      react-loadable: '@docusaurus/react-loadable@6.0.0(react@18.3.1)'

  '@docusaurus/react-loadable@6.0.0(react@18.3.1)': {}
`;

describe('an npm alias', () => {
  it('follows the real package an alias names, so it is pulled by someone and its place is known', () => {
    const read = readPnpmLock(ALIAS);
    expect(read.packages.find((p) => p.name === '@docusaurus/react-loadable')?.dev).toBe(false);
    expect(viaOf(read.graph!, new Set(['@docusaurus/react-loadable@6.0.0'])).get('@docusaurus/react-loadable@6.0.0'))
      .toEqual([{ importer: 'apps/wiki', through: 'core', dev: false }]);
  });
});

const ROOT_PACKAGER = `lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      electron-builder:
        specifier: ^24.0.0
        version: 24.13.3

  apps/desktop:
    devDependencies:
      electron:
        specifier: ^31.7.7
        version: 31.7.7

packages:

  electron@31.7.7:
    resolution: {integrity: a}

  electron-builder@24.13.3:
    resolution: {integrity: c}

snapshots:

  electron@31.7.7: {}

  electron-builder@24.13.3: {}
`;

describe('the Electron runtime', () => {
  it('ships when the packager is declared at the workspace root', () => {
    expect(readPnpmLock(ROOT_PACKAGER).packages.find((p) => p.name === 'electron')?.dev).toBe(false);
  });

  it('ships when the importer also declares a packager: electron itself, not what downloads it', () => {
    const read = readPnpmLock(ELECTRON('electron-builder'));
    expect(read.packages.find((p) => p.name === 'electron')?.dev).toBe(false);
    expect(read.packages.find((p) => p.name === 'extract-zip')?.dev).toBe(true);
    const via = viaOf(read.graph!, new Set(['electron@31.7.7', 'extract-zip@2.0.1']));
    expect(via.get('electron@31.7.7')).toEqual([{ importer: 'apps/desktop', through: 'electron', dev: false, runtime: true }]);
    expect(via.get('extract-zip@2.0.1')).toEqual([{ importer: 'apps/desktop', through: 'electron', dev: true }]);
  });

  it('every packager of the list counts', () => {
    for (const p of ['@electron-forge/cli', 'electron-packager']) {
      expect(readPnpmLock(ELECTRON(p)).packages.find((x) => x.name === 'electron')?.dev).toBe(false);
    }
  });

  it('stays as declared with no packager (a project that only runs electron in tests)', () => {
    const read = readPnpmLock(ELECTRON(null));
    expect(read.packages.find((p) => p.name === 'electron')?.dev).toBe(true);
    expect(viaOf(read.graph!, new Set(['electron@31.7.7'])).get('electron@31.7.7')).toEqual([{ importer: 'apps/desktop', through: 'electron', dev: true }]);
  });
});

describe('the finding carries who pulls it', () => {
  const tarRecord: OsvRecord = {
    id: 'GHSA-1', modified: 'm1', summary: 'tar bug', database_specific: { severity: 'HIGH' },
    affected: [{ package: { ecosystem: 'npm', name: 'tar' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '7.5.21' }] }] }],
  };
  const fetcher: Fetcher = async (url, init) => {
    const body = url.endsWith('/querybatch')
      ? { results: (JSON.parse(String(init?.body)) as { queries: { package: { name: string } }[] }).queries.map((q) => (q.package.name === 'tar' ? { vulns: [{ id: 'GHSA-1', modified: 'm1' }] } : {})) }
      : tarRecord;
    return new Response(JSON.stringify(body), { status: 200 });
  };
  const cache = { read: async () => null, write: async () => {} };

  it('puts the ways on the finding and in the report', async () => {
    const res = await runScan({ sourceFor: () => apiSource(fetcher), cache, locks: [{ file: 'pnpm-lock.yaml', read: readPnpmLock(PNPM) }] });
    const f = res.findings.find((x) => x.version === '6.2.1')!;
    expect(f.via).toEqual([{ importer: '.', through: 'builder', dev: true }]);
    expect(f).not.toHaveProperty('viaTotal');
    expect(reportText('p', res, { entries: [] })).toContain('[via . <- builder (dev)]');
  });

  it('cuts at VIA_CAP and says how many there were', async () => {
    const roots: DepGraph['roots'] = Array.from({ length: VIA_CAP + 3 }, (_, i) => ({ importer: `apps/a${String(i).padStart(2, '0')}`, through: 'tar', id: 'tar@7.5.13', dev: false }));
    const read = { kind: 'pnpm' as const, ecosystem: 'npm' as const, packages: [{ ecosystem: 'npm' as const, name: 'tar', version: '7.5.13' }], skipped: [], graph: { roots, edges: new Map() } };
    const res = await runScan({ sourceFor: () => apiSource(fetcher), cache, locks: [{ file: 'pnpm-lock.yaml', read }] });
    expect(res.findings[0]!.via).toHaveLength(VIA_CAP);
    expect(res.findings[0]!.viaTotal).toBe(VIA_CAP + 3);
  });

  it('a lockfile with no graph leaves the finding without any via field', async () => {
    const read = { kind: 'npm' as const, ecosystem: 'npm' as const, packages: [{ ecosystem: 'npm' as const, name: 'tar', version: '7.5.13' }], skipped: [] };
    const res = await runScan({ sourceFor: () => apiSource(fetcher), cache, locks: [{ file: 'package-lock.json', read }] });
    expect(res.findings[0]).not.toHaveProperty('via');
  });
});
