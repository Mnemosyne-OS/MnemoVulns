/**
 * The agent's moves in MnemoVulns (doc 149): each reaches the App's own
 * function, a risk is only accepted with a reason and only when open, a scan
 * answers « started », and every refusal names what to call instead.
 */
import { describe, expect, it, vi } from 'vitest';
import { findEntry, findingsLimit, findProject, projectArg, SCREEN_WAIT_MS, STOP_WAIT_MS, vulnsAgentHandlers, type VulnsAgentContext } from './agent';
import type { PlanFilter } from './packagePlan';
import type { AgentScreen } from '../ui/agentScreen';
import { EMPTY_LIBRARY, type ProjectRecord } from './library';
import type { ProjectOutcome } from './project';
import type { Finding } from './scan';
import { accept, type Tracking } from './tracking';
import type { MirrorView, ScanView } from '../ui/types';

const finding = (id: string, name: string, over: Partial<Finding> = {}): Finding => ({
  id, ecosystem: 'npm', name, version: '1.0.0', severity: 'HIGH', fix: { kind: 'fixed', version: '1.0.1' },
  malicious: false, summary: 'x'.repeat(500), aliases: [], modified: 'm', source: { name: 'OSV', licence: 'CC-BY-4.0', licenceUrl: 'https://x' } as Finding['source'], recordRead: true, ...over,
});
const tracking: Tracking = { entries: [
  { id: 'GHSA-1', name: 'tar', versions: ['1.0.0'], state: 'open', since: 's', firstSeen: 'f' },
  { id: 'GHSA-2', name: 'lodash', versions: ['1.0.0'], state: 'accepted', since: 's', firstSeen: 'f', reason: 'dev only' },
  { id: 'GHSA-3', name: 'req', versions: ['1.0.0'], state: 'open', since: 's', firstSeen: 'f' },
  { id: 'GHSA-3', name: 'req', ecosystem: 'PyPI', versions: ['1.0.0'], state: 'open', since: 's', firstSeen: 'f' },
] };
const app: ProjectRecord = { root: '/code/app', name: 'app', slug: 'app-1', lastScan: { at: 'a', complete: true, findings: 2, open: 1, unasked: 0 } };
const fresh: ProjectRecord = { root: '/code/new', name: 'new', slug: 'new-1' };
const twinA: ProjectRecord = { root: '/a/site', name: 'site', slug: 's1', lastScan: app.lastScan };
const twinB: ProjectRecord = { root: '/b/site', name: 'site', slug: 's2' };
const outcome = { project: app, scan: { at: '2026-10-12T10:00:00Z', complete: true, findings: [finding('GHSA-1', 'tar'), finding('GHSA-2', 'lodash', { severity: 'LOW' })] }, tracking, trackingWritten: true } as unknown as ProjectOutcome;

/**
 * The project page's chips and tiles, as ui/agentScreen reads them. A filter
 * other than « all » hides the tiles outside it, as the page does.
 */
function fakeScreen(opts: { chips?: PlanFilter[]; filter?: PlanFilter; places?: Record<string, PlanFilter>; deaf?: boolean } = {}) {
  const chips = opts.chips ?? ['all', 'shipped', 'dev'];
  const places = opts.places ?? { 'npm:tar': 'shipped', 'npm:lodash': 'shipped' };
  const state = { filter: (opts.filter ?? 'all') as PlanFilter | null, revealed: [] as string[] };
  const screen: AgentScreen = {
    planFilter: () => state.filter,
    hasPlanFilter: (f) => chips.includes(f),
    pressPlanFilter: vi.fn((f: PlanFilter) => {
      if (!chips.includes(f)) return false;
      // A chip that does not answer: the press lands nowhere.
      if (!opts.deaf) state.filter = f;
      return true;
    }),
    hasTile: (k) => k in places && (state.filter === 'all' || places[k] === state.filter),
    revealTile: vi.fn((k: string) => { if (!screen.hasTile(k)) return false; state.revealed.push(k); return true; }),
  };
  return { screen, state };
}

const installed = { npm: { kind: 'ready', state: { installed: { records: 1, asOf: 'a', newestModified: 'm', sizeBytes: 1 } } } } as unknown as Record<string, MirrorView>;

function setup(over: Partial<VulnsAgentContext> = {}) {
  const ctx: VulnsAgentContext = {
    lib: { ...EMPTY_LIBRARY, folder: '/kn', projects: [app, fresh, twinA, twinB] },
    libStatus: { kind: 'ready' },
    view: { kind: 'home' },
    scans: { [app.root]: { kind: 'done', outcome } },
    job: null,
    openProject: vi.fn(),
    goHome: vi.fn(),
    scan: vi.fn(async () => true),
    changeTracking: vi.fn(async () => true),
    stopScan: vi.fn(),
    useSource: vi.fn(async () => true),
    mirrors: {},
    screen: fakeScreen().screen,
    ...over,
  };
  return { ctx, h: vulnsAgentHandlers(() => ctx) };
}

describe('what an agent reads', () => {
  it('projects lists them with the last summary, null when never scanned', () => {
    const r = setup({ job: { root: '/code/new', startedAt: 0, progress: null } }).h.projects();
    expect(r.projects[0]).toMatchObject({ name: 'app', lastScan: { open: 1 }, scanning: false });
    expect(r.projects[1]).toMatchObject({ name: 'new', lastScan: null, scanning: true });
  });

  it('a library not read yet, or unreadable, is refused by name', () => {
    expect(() => setup({ libStatus: { kind: 'loading' } }).h.projects()).toThrow(/^NOT_READY/);
    expect(() => setup({ libStatus: { kind: 'error', why: 'boom' } }).h.projects()).toThrow(/^NOT_READY.*boom/);
  });

  it('vulnerabilities gives the open ones by default, with their tracking state, summaries cut', () => {
    const { h } = setup();
    const r = h.vulnerabilities({ project: 'app' });
    expect(r.vulnerabilities.map((v) => v.id)).toEqual(['GHSA-1']);
    expect(r.vulnerabilities[0]!.summary!.length).toBe(301);
    const all = h.vulnerabilities({ project: '/code/app', state: 'all' });
    expect(all.vulnerabilities.find((v) => v.id === 'GHSA-2')).toMatchObject({ state: 'accepted', reason: 'dev only' });
    expect(h.vulnerabilities({ project: 'app', state: 'all', limit: -2 }).vulnerabilities).toHaveLength(1);
    expect(() => h.vulnerabilities({ project: 'app', state: 'weird' })).toThrow(/^BAD_ARG/);
    expect(findingsLimit(-2)).toBe(1);
    expect(findingsLimit(10_000)).toBe(500);
  });

  it('a scan not loaded, never run, or failed says what to call', () => {
    const { h } = setup({ scans: { '/a/site': { kind: 'failed', failure: { code: 'NO_LOCKFILE' } } as ScanView } });
    expect(() => h.vulnerabilities({ project: 'app' })).toThrow(/^NOT_LOADED.*openProject/);
    expect(() => h.vulnerabilities({ project: 'new' })).toThrow(/^NEVER_SCANNED.*scan/);
    expect(() => h.vulnerabilities({ project: '/a/site' })).toThrow(/^SCAN_FAILED.*NO_LOCKFILE/);
  });

  it('a project by its folder or by the words a person says', () => {
    expect(findProject([app, fresh], 'le projet App')).toBe(app);
    expect(findProject([twinA, twinB], '/b/site')).toBe(twinB);
  });

  it('a name naming two projects is AMBIGUOUS with their folders, never the first; an unknown one lists them', () => {
    expect(() => findProject([twinA, twinB], 'site')).toThrow('AMBIGUOUS: "site" names several projects: site (/a/site), site (/b/site); say which');
    expect(() => findProject([app, fresh], 'nope')).toThrow('NO_PROJECT: no project named "nope"; projects: app, new');
  });

  it('no project named is the one on screen; none on screen is said with the names', () => {
    const { ctx } = setup({ view: { kind: 'project', root: '/code/new' } });
    expect(projectArg(ctx, undefined)).toBe(fresh);
    expect(() => projectArg(setup().ctx, '')).toThrow(/^NO_PROJECT_SHOWN.*app, new, site/);
  });

  it('vulnerabilities narrows by severity and by a package said in words', () => {
    const { h } = setup({ view: { kind: 'project', root: '/code/app' } });
    expect(h.vulnerabilities({ state: 'all', severity: 'low' }).vulnerabilities.map((v) => v.id)).toEqual(['GHSA-2']);
    expect(h.vulnerabilities({ state: 'all', package: 'le paquet Lodash' }).vulnerabilities.map((v) => v.id)).toEqual(['GHSA-2']);
    expect(() => h.vulnerabilities({ package: 'react' })).toThrow('NO_PACKAGE: no package named "react" among the vulnerabilities of "app"; packages: tar, lodash');
    expect(() => h.vulnerabilities({ severity: 'scary' })).toThrow(/^BAD_ARG: severity/);
  });
});

describe('what an agent changes', () => {
  it('openProject and home are the screen moves', () => {
    const { ctx, h } = setup();
    expect(h.openProject({ project: 'app' })).toEqual({ project: 'app', shown: true });
    expect(ctx.openProject).toHaveBeenCalledWith('/code/app');
    h.home();
    expect(ctx.goHome).toHaveBeenCalledTimes(1);
  });

  it('scan opens the project and starts the scan without waiting for it', () => {
    let finish: (v: boolean) => void = () => undefined;
    const { ctx, h } = setup({ scan: vi.fn(() => new Promise<boolean>((r) => { finish = r; })) });
    expect(h.scan({ project: 'new' })).toEqual({ project: 'new', started: true, followWith: 'projects' });
    expect(ctx.openProject).toHaveBeenCalledWith('/code/new');
    expect(ctx.scan).toHaveBeenCalledWith('/code/new');
    finish(true);
  });

  it('a second scan while one runs is BUSY', () => {
    const { ctx, h } = setup({ job: { root: '/code/app', startedAt: 0, progress: null } });
    expect(() => h.scan({ project: 'new' })).toThrow(/^BUSY/);
    expect(ctx.scan).not.toHaveBeenCalled();
  });

  it('acceptRisk goes through changeTracking with tracking.accept and the reason', async () => {
    const { ctx, h } = setup();
    expect(await h.acceptRisk({ project: 'app', id: 'GHSA-1', package: 'tar', reason: 'not reachable' })).toMatchObject({ state: 'accepted' });
    const change = vi.mocked(ctx.changeTracking).mock.calls[0]![1];
    expect(change(tracking, 'now')).toEqual(accept(tracking, 'GHSA-1', 'tar', 'not reachable', 'now'));
  });

  it('a risk is never accepted without a reason, nor when it is not open', async () => {
    const { ctx, h } = setup();
    await expect(h.acceptRisk({ project: 'app', id: 'GHSA-1', package: 'tar', reason: '  ' })).rejects.toThrow(/^BAD_ARG/);
    await expect(h.acceptRisk({ project: 'app', id: 'GHSA-2', package: 'lodash', reason: 'x' })).rejects.toThrow(/^NOT_OPEN/);
    expect(ctx.changeTracking).not.toHaveBeenCalled();
  });

  it('reopenRisk only takes back an accepted one', async () => {
    const { ctx, h } = setup();
    expect(await h.reopenRisk({ project: 'app', id: 'GHSA-2', package: 'lodash' })).toMatchObject({ state: 'open' });
    await expect(h.reopenRisk({ project: 'app', id: 'GHSA-1', package: 'tar' })).rejects.toThrow(/^NOT_ACCEPTED/);
    expect(ctx.changeTracking).toHaveBeenCalledTimes(1);
  });

  it('a tracker change that did not land is said; one during a scan or on an unreadable tracker is refused', async () => {
    await expect(setup({ changeTracking: async () => false }).h.acceptRisk({ project: 'app', id: 'GHSA-1', package: 'tar', reason: 'x' })).rejects.toThrow(/^WRITE_FAILED/);
    await expect(setup({ job: { root: '/code/app', startedAt: 0, progress: null } }).h.acceptRisk({ project: 'app', id: 'GHSA-1', package: 'tar', reason: 'x' })).rejects.toThrow(/^BUSY/);
    const unreadable = { [app.root]: { kind: 'done', outcome: { ...outcome, trackingWritten: false } } as ScanView };
    await expect(setup({ scans: unreadable }).h.acceptRisk({ project: 'app', id: 'GHSA-1', package: 'tar', reason: 'x' })).rejects.toThrow(/^TRACKING_UNREADABLE/);
  });

  it('the same advisory on one package name in two ecosystems needs the ecosystem', () => {
    expect(() => findEntry(tracking, { id: 'GHSA-3', pkg: 'req' }, 'open')).toThrow('AMBIGUOUS: GHSA-3 on "req" names several open vulnerabilities: GHSA-3 on req, GHSA-3 on req (PyPI); say which (its id, or the ecosystem)');
    expect(findEntry(tracking, { id: 'GHSA-3', pkg: 'req', ecosystem: 'pypi' }, 'open').ecosystem).toBe('PyPI');
    expect(() => findEntry(tracking, { id: 'GHSA-9', pkg: 'tar' }, 'open')).toThrow('NO_VULNERABILITY: no vulnerability GHSA-9 on "tar" in this project; open ones: GHSA-1 on tar, GHSA-3 on req, GHSA-3 on req (PyPI)');
  });

  it('a risk by its package alone, or by a CVE said aloud; nothing named is refused', () => {
    const findings = [finding('GHSA-1', 'tar', { aliases: ['CVE-2024-1234'] })];
    expect(findEntry(tracking, { pkg: 'Tar' }, 'open', findings).id).toBe('GHSA-1');
    expect(findEntry(tracking, { id: 'cve 2024 1234' }, 'open', findings).name).toBe('tar');
    expect(() => findEntry(tracking, { pkg: 'req' }, 'open', findings)).toThrow(/^AMBIGUOUS: "req" names several open/);
    expect(() => findEntry(tracking, {}, 'open')).toThrow(/^BAD_ARG/);
  });

  it('acceptRisk and reopenRisk take the package alone, the project on screen', async () => {
    const { ctx, h } = setup({ view: { kind: 'project', root: '/code/app' } });
    expect(await h.acceptRisk({ package: 'tar', reason: 'not reachable' })).toMatchObject({ project: 'app', id: 'GHSA-1', state: 'accepted' });
    expect(await h.reopenRisk({ package: 'lodash' })).toMatchObject({ id: 'GHSA-2', state: 'open' });
    expect(ctx.changeTracking).toHaveBeenCalledTimes(2);
    await expect(h.acceptRisk({ package: 'lodash', reason: 'x' })).rejects.toThrow(/^NOT_OPEN/);
  });
});

describe('the screen moves a voice asks for', () => {
  const babel = {
    ...outcome,
    scan: { ...outcome.scan, findings: [finding('GHSA-7', '@babel/core'), finding('GHSA-8', '@babel/traverse'), finding('GHSA-1', 'tar')] },
  } as unknown as ProjectOutcome;

  it('showPackage opens the tile of a package said in words, with what fixes it', async () => {
    const { screen, state } = fakeScreen();
    const { ctx, h } = setup({ view: { kind: 'project', root: '/code/app' }, screen });
    expect(await h.showPackage({ package: 'le paquet tar' })).toMatchObject({ project: 'app', package: 'tar', shown: true, open: 1, fixVersion: '1.0.1' });
    expect(state.revealed).toEqual(['npm:tar']);
    expect(ctx.openProject).not.toHaveBeenCalled();
  });

  it('showPackage opens the project first, and sets a hiding filter back to all', async () => {
    const { screen, state } = fakeScreen({ filter: 'dev' });
    const { ctx, h } = setup({ screen });
    await h.showPackage({ project: 'app', package: 'tar' });
    expect(ctx.openProject).toHaveBeenCalledWith('/code/app');
    expect(screen.pressPlanFilter).toHaveBeenCalledWith('all');
    expect(state.revealed).toEqual(['npm:tar']);
  });

  it('showPackage refuses several packages with their names, and an unknown one with the list', async () => {
    const { h } = setup({ view: { kind: 'project', root: '/code/app' }, scans: { [app.root]: { kind: 'done', outcome: babel } } });
    await expect(h.showPackage({ package: 'babel' })).rejects.toThrow('AMBIGUOUS: "babel" names several packages: @babel/core, @babel/traverse; say which');
    await expect(h.showPackage({ package: 'react' })).rejects.toThrow('NO_PACKAGE: no package named "react"; packages: @babel/core, @babel/traverse, tar');
  });

  it('a project never scanned is said at once; a last scan never read is said after the wait', async () => {
    await expect(setup().h.showPackage({ project: 'new', package: 'tar' })).rejects.toThrow(/^NEVER_SCANNED/);
    vi.useFakeTimers();
    try {
      const pending = setup({ scans: {} }).h.showPackage({ project: 'app', package: 'tar' });
      const seen = expect(pending).rejects.toThrow(/^NOT_LOADED/);
      await vi.advanceTimersByTimeAsync(SCREEN_WAIT_MS + 100);
      await seen;
    } finally {
      vi.useRealTimers();
    }
  });

  it('filterPackages presses the chip and answers once it took', async () => {
    const { screen, state } = fakeScreen();
    const { h } = setup({ view: { kind: 'project', root: '/code/app' }, screen });
    expect(await h.filterPackages({ show: 'dev' })).toEqual({ project: 'app', showing: 'dev', packages: 0 });
    expect(state.filter).toBe('dev');
    await expect(h.filterPackages({ show: 'unknown' })).rejects.toThrow(/^NO_FILTER.*filters: all, shipped, dev/);
    await expect(h.filterPackages({ show: 'weird' })).rejects.toThrow(/^BAD_ARG/);
  });

  it('a chip that does not take is WRITE_FAILED, never reported done', async () => {
    vi.useFakeTimers();
    try {
      const { screen } = fakeScreen({ deaf: true });
      const pending = setup({ view: { kind: 'project', root: '/code/app' }, screen }).h.filterPackages({ show: 'shipped' });
      const seen = expect(pending).rejects.toThrow(/^WRITE_FAILED/);
      await vi.advanceTimersByTimeAsync(SCREEN_WAIT_MS + 100);
      await seen;
    } finally {
      vi.useRealTimers();
    }
  });

  it('stopScan presses Stop and says stopped once the scan is gone', async () => {
    await expect(setup().h.stopScan()).rejects.toThrow(/^NOT_SCANNING/);
    const { ctx, h } = setup({ job: { root: '/code/app', startedAt: 0, progress: null } });
    vi.mocked(ctx.stopScan).mockImplementation(() => { ctx.job = null; });
    expect(await h.stopScan()).toEqual({ project: 'app', stopped: true });
  });

  it('a scan that does not end in time is said stopping, not stopped', async () => {
    vi.useFakeTimers();
    try {
      const pending = setup({ job: { root: '/code/app', startedAt: 0, progress: null } }).h.stopScan();
      await vi.advanceTimersByTimeAsync(STOP_WAIT_MS + 100);
      expect(await pending).toEqual({ project: 'app', stopping: true, followWith: 'projects' });
    } finally {
      vi.useRealTimers();
    }
  });

  it('setScanSource is the base buttons: only with a local database, refused when not saved', async () => {
    await expect(setup().h.setScanSource({ source: 'local' })).rejects.toThrow(/^NO_LOCAL_DATABASE/);
    const { ctx, h } = setup({ mirrors: installed });
    expect(await h.setScanSource({ source: 'local' })).toEqual({ source: 'local', changed: true });
    expect(ctx.useSource).toHaveBeenCalledWith('mirror');
    expect(await h.setScanSource({ source: 'online' })).toEqual({ source: 'online', changed: false });
    await expect(setup({ mirrors: installed, useSource: async () => false }).h.setScanSource({ source: 'local' })).rejects.toThrow(/^WRITE_FAILED/);
    await expect(setup({ mirrors: installed, job: { root: '/code/app', startedAt: 0, progress: null } }).h.setScanSource({ source: 'local' })).rejects.toThrow(/^BUSY/);
  });
});
