import { describe, it, expect, vi } from 'vitest';
import type { OsvRecord } from './advisory';
import { EMPTY_LIBRARY } from './library';
import { apiSource, type Fetcher } from './osv';
import { LAST_SCAN_FILE, loadSavedScan, scanProject, TRACKING_FILE, type HostPort } from './project';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const LOCK = "lockfileVersion: '9.0'\n\npackages:\n\n  tar@7.5.13:\n    resolution: {integrity: x}\n";
const REC: OsvRecord = {
  id: 'GHSA-1', modified: 'm1', summary: 's', database_specific: { severity: 'HIGH' },
  affected: [{ package: { ecosystem: 'npm', name: 'tar' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '7.5.21' }] }] }],
};
const fetcher: Fetcher = async (url, init) => {
  if (url.endsWith('/querybatch')) {
    const { queries } = JSON.parse(String(init?.body)) as { queries: unknown[] };
    return json({ results: queries.map(() => ({ vulns: [{ id: 'GHSA-1', modified: 'm1' }] })) });
  }
  return json(REC);
};

/** An in-memory disk: path → content, directories implied by the paths. */
function disk(files: Record<string, string>) {
  const fs = { ...files };
  const ingest = vi.fn(async () => undefined);
  const port: HostPort = {
    readDir: async (dir) => {
      const prefix = dir.replace(/\/+$/, '') + '/';
      const names = new Set(Object.keys(fs).filter((p) => p.startsWith(prefix)).map((p) => p.slice(prefix.length).split('/')[0]!));
      return { success: true, files: [...names].map((name) => ({ name, isDirectory: !((prefix + name) in fs) })) };
    },
    readFile: async (p) => (p in fs ? { success: true, content: fs[p]! } : { success: false, error: 'ENOENT' }),
    writeFile: async (p, c) => { fs[p] = c; return { success: true }; },
    mkdir: async () => ({ success: true }),
    ingest,
  };
  return { fs, port, ingest };
}

const project = { root: '/code/app', name: 'app', slug: 'app-1' };

describe('scanProject', () => {
  // Tony 07/10: the library moved to the pack folder; a project's accepted
  // risks follow it at its first scan there, and the old file is never written.
  it('takes the tracking from the former folder when the new one has none yet', async () => {
    const accepted = { version: 1, project: '/code/app', entries: [{ id: 'GHSA-1', name: 'tar', versions: ['7.5.13'], state: 'accepted', since: '2026-09-01', firstSeen: '2026-08-01', reason: 'not reachable' }] };
    const oldFile = `/old/projects/app-1/${TRACKING_FILE}`;
    const d = disk({ '/code/app/pnpm-lock.yaml': LOCK, [oldFile]: JSON.stringify(accepted) });
    const res = await scanProject({ port: d.port, sourceFor: () => apiSource(fetcher), lib: { ...EMPTY_LIBRARY, formerFolder: '/old' }, folder: '/kn', vault: null, project });
    if (!res.ok) throw new Error(res.failure.code);
    expect(JSON.parse(d.fs[`/kn/projects/app-1/${TRACKING_FILE}`]!).entries[0]).toMatchObject({ id: 'GHSA-1', state: 'accepted', reason: 'not reachable' });
    expect(JSON.parse(d.fs[oldFile]!)).toEqual(accepted);
  });

  it('a tracking already in the new folder wins over the former one', async () => {
    const mk = (state: string) => JSON.stringify({ version: 1, project: '/code/app', entries: [{ id: 'GHSA-1', name: 'tar', versions: ['7.5.13'], state, since: '2026-09-01', firstSeen: '2026-08-01', ...(state === 'accepted' ? { reason: 'old' } : {}) }] });
    const d = disk({ '/code/app/pnpm-lock.yaml': LOCK, [`/old/projects/app-1/${TRACKING_FILE}`]: mk('accepted'), [`/kn/projects/app-1/${TRACKING_FILE}`]: mk('open') });
    const res = await scanProject({ port: d.port, sourceFor: () => apiSource(fetcher), lib: { ...EMPTY_LIBRARY, formerFolder: '/old' }, folder: '/kn', vault: null, project });
    if (!res.ok) throw new Error(res.failure.code);
    expect(res.outcome.tracking.entries[0]).toMatchObject({ state: 'open' });
  });

  it('scans, writes the tracker and the report, and puts each record in the vault once', async () => {
    const d = disk({ '/code/app/pnpm-lock.yaml': LOCK });
    const res = await scanProject({ port: d.port, sourceFor: () => apiSource(fetcher), lib: EMPTY_LIBRARY, folder: '/lib', vault: 'app-mnemo-vulns', project });
    if (!res.ok) throw new Error(res.failure.code);
    expect(res.outcome.scan.findings).toHaveLength(1);
    expect(JSON.parse(d.fs[`/lib/projects/app-1/${TRACKING_FILE}`]!).entries[0]).toMatchObject({ id: 'GHSA-1', state: 'open' });
    expect(d.fs['/lib/projects/app-1/report.md']).toContain('GHSA-1');
    expect(d.ingest).toHaveBeenCalledTimes(1);
    expect(res.outcome.ingested).toEqual({ 'GHSA-1': 'm1' });

    // Second scan: same record date, nothing written to the vault again.
    const again = await scanProject({ port: d.port, sourceFor: () => apiSource(fetcher), lib: { ...EMPTY_LIBRARY, ingested: res.outcome.ingested }, folder: '/lib', vault: 'app-mnemo-vulns', project });
    expect(d.ingest).toHaveBeenCalledTimes(1);
    expect(again.ok && again.outcome.vault).toEqual({ written: 0, failed: 0, already: 1 });
  });

  it('reads the last scan back with its tracker, so a project opens on its list', async () => {
    const d = disk({ '/code/app/pnpm-lock.yaml': LOCK });
    const res = await scanProject({ port: d.port, sourceFor: () => apiSource(fetcher), lib: EMPTY_LIBRARY, folder: '/lib', vault: null, project });
    if (!res.ok) throw new Error(res.failure.code);
    expect(JSON.parse(d.fs[`/lib/projects/app-1/${LAST_SCAN_FILE}`]!).scan.records).toEqual([]);
    const back = await loadSavedScan(d.port, '/lib', res.outcome.project);
    expect(back).toMatchObject({ fromDisk: true, trackingWritten: true });
    expect(back!.scan.findings.map((f) => f.id)).toEqual(['GHSA-1']);
    expect(back!.tracking.entries[0]).toMatchObject({ id: 'GHSA-1', state: 'open' });
  });

  it('never shows an older saved scan as the last one, and locks editing over an unreadable tracker', async () => {
    const d = disk({ '/code/app/pnpm-lock.yaml': LOCK });
    const res = await scanProject({ port: d.port, sourceFor: () => apiSource(fetcher), lib: EMPTY_LIBRARY, folder: '/lib', vault: null, project });
    if (!res.ok) throw new Error(res.failure.code);
    const newer = { ...res.outcome.project, lastScan: { ...res.outcome.project.lastScan!, at: '2099-01-01T00:00:00Z' } };
    expect(await loadSavedScan(d.port, '/lib', newer)).toBeNull();
    d.fs[`/lib/projects/app-1/${TRACKING_FILE}`] = '{ broken';
    const locked = await loadSavedScan(d.port, '/lib', res.outcome.project);
    expect(locked).toMatchObject({ trackingWritten: false });
    expect(locked!.trackingError).toBeTruthy();
  });

  it('never overwrites a tracker it could not read', async () => {
    const broken = '{ this is not json';
    const d = disk({ '/code/app/pnpm-lock.yaml': LOCK, [`/lib/projects/app-1/${TRACKING_FILE}`]: broken });
    const res = await scanProject({ port: d.port, sourceFor: () => apiSource(fetcher), lib: EMPTY_LIBRARY, folder: '/lib', vault: null, project });
    if (!res.ok) throw new Error(res.failure.code);
    expect(res.outcome.trackingWritten).toBe(false);
    expect(res.outcome.trackingError).toBeTruthy();
    expect(d.fs[`/lib/projects/app-1/${TRACKING_FILE}`]).toBe(broken);
  });

  it('makes the scan PARTIAL when one of the lockfiles is found but cannot be read', async () => {
    const d = disk({ '/code/app/pnpm-lock.yaml': LOCK, '/code/app/Cargo.lock': 'not a cargo lockfile' });
    const res = await scanProject({ port: d.port, sourceFor: () => apiSource(fetcher), lib: EMPTY_LIBRARY, folder: '/lib', vault: null, project });
    if (!res.ok) throw new Error(res.failure.code);
    expect(res.outcome.lockFailures.length).toBeGreaterThan(0);
    expect(res.outcome.scan.complete).toBe(false);
  });

  it('keeps a finding on a package declared for development, labelled, never filtered out', async () => {
    const npm = JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/tar': { version: '7.5.13', dev: true } } });
    const res = await scanProject({ port: disk({ '/code/app/package-lock.json': npm }).port, sourceFor: () => apiSource(fetcher), lib: EMPTY_LIBRARY, folder: '/lib', vault: null, project });
    if (!res.ok) throw new Error(res.failure.code);
    expect(res.outcome.scan.findings).toHaveLength(1);
    expect(res.outcome.scan.findings[0]!.dev).toBe(true);
  });

  it('names the reason when there is nothing to scan', async () => {
    const none = await scanProject({ port: disk({ '/code/app/README.md': '' }).port, sourceFor: () => apiSource(fetcher), lib: EMPTY_LIBRARY, folder: '/lib', vault: null, project });
    expect(none).toEqual({ ok: false, failure: { code: 'NO_LOCKFILE' } });
    const yarn = await scanProject({ port: disk({ '/code/app/yarn.lock': 'not a yarn lockfile' }).port, sourceFor: () => apiSource(fetcher), lib: EMPTY_LIBRARY, folder: '/lib', vault: null, project });
    expect(yarn.ok === false && yarn.failure.code).toBe('LOCKFILE_INVALID');
    const bad = await scanProject({ port: disk({ '/code/app/pnpm-lock.yaml': 'nope' }).port, sourceFor: () => apiSource(fetcher), lib: EMPTY_LIBRARY, folder: '/lib', vault: null, project });
    expect(bad.ok === false && bad.failure.code).toBe('LOCKFILE_INVALID');
  });
});
