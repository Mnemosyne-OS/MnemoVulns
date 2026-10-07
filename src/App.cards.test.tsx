/**
 * Verification (session 9747aa5d, T1): mounts the real App on a mocked SDK
 * and counts how many times it publishes its cards while one is pinned.
 *
 * Rule attacked: a module publishes its snapshot when its data CHANGES, never
 * in a loop (doc 110 lot 0, "boucle de publication sans scan"). Expected: one
 * publication for one pinned card and one library.
 */
import { describe, it, expect, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

const { invoke, readDir, readFile, selectFolder } = vi.hoisted(() => ({
  invoke: vi.fn(),
  readDir: vi.fn(async (..._args: unknown[]) => ({ success: true, files: [] as { name: string; isDirectory: boolean }[] })),
  readFile: vi.fn(async (..._args: unknown[]) => ({ success: false } as { success: boolean; content?: string })),
  selectFolder: vi.fn(async (..._args: unknown[]) => null as string | null),
}));
const lib = {
  state: { library: {
    folder: '/lib', scanSource: 'api', ingested: {},
    projects: [{ root: '/code/app', name: 'app', slug: 'app-1', lastScan: { at: '2026-10-05T00:00:00Z', complete: true, findings: 3, open: 2, unasked: 0, openBySeverity: { CRITICAL: 1, HIGH: 0, MODERATE: 1, LOW: 0, UNKNOWN: 0 }, accepted: 0, fixed: 1 } }],
  } },
};

vi.mock('./sdk/mnemo-sdk', () => ({
  MnemoCartridgeSDK: class {
    invoke = invoke;
    readDir = (...a: unknown[]) => readDir(...(a as []));
    readFile = (...a: unknown[]) => readFile(...(a as []));
    writeFile = () => Promise.resolve({ success: true });
    selectFolder = (...a: unknown[]) => selectFolder(...(a as []));
    openInOS = () => Promise.resolve({ success: true });
  },
  onHostConfig: () => () => {},
}));

import App from './App';
import { translate } from './i18n/strings';

describe('App: cards publication while one is pinned', () => {
  it('publishes ONCE for one pinned card and one library (no loop)', async () => {
    invoke.mockImplementation(async (action: string) => {
      switch (action) {
        case 'state.get': return lib;
        case 'cockpit.state': return { success: true, pinned: ['vulns:app-1'] };
        case 'cockpit.publish': return { success: true, accepted: 1, dropped: 0, pinned: ['vulns:app-1'] };
        case 'vulns.mirrorStatus': return { ecosystem: 'npm', phase: 'idle', startedAt: null, done: null, total: null, error: null, last: null, installed: null, unreadable: null };
        default: return undefined;
      }
    });
    render(<App />);
    // Let the boot settle and give any loop room to show itself.
    await new Promise((r) => setTimeout(r, 400));
    await new Promise((r) => setTimeout(r, 400));
    const publishes = invoke.mock.calls.filter((c) => c[0] === 'cockpit.publish').length;
    expect(publishes).toBe(1);
  }, 20_000);
});

const BACK = translate('en', 'nav.back');

describe('App: opened from a card on the canvas', () => {
  const answer = (opened: object | null) => async (action: string) => {
    switch (action) {
      case 'state.get': return lib;
      case 'cockpit.state': return { success: true, pinned: [], opened };
      case 'vulns.mirrorStatus': return { ecosystem: 'npm', phase: 'idle', startedAt: null, done: null, total: null, error: null, last: null, installed: null, unreadable: null };
      default: return undefined;
    }
  };

  it('opens on the project of the card that launched it', async () => {
    invoke.mockImplementation(answer({ id: 'vulns:app-1', at: new Date().toISOString() }));
    render(<App />);
    expect(await screen.findByText(BACK)).toBeTruthy();
  });

  it('stays on the home when the press is old (a later mount, not that press)', async () => {
    invoke.mockImplementation(answer({ id: 'vulns:app-1', at: new Date(Date.now() - 10 * 60_000).toISOString() }));
    render(<App />);
    await new Promise((r) => setTimeout(r, 300));
    expect(screen.getAllByText(translate('en', 'home.open')).length).toBeGreaterThan(0);
    expect(screen.queryByText(BACK)).toBeNull();
  });
});

describe('App: a local database update rescans the projects', () => {
  it('rescans each scanned project once the update lands with changed records', async () => {
    const mirrorLib = { state: { library: { ...lib.state.library, scanSource: 'mirror' } } };
    let calls = 0;
    const idle = { ecosystem: 'npm', phase: 'idle', startedAt: null, done: null, total: null, error: null, unreadable: null, installed: { records: 10, asOf: '2026-10-05T00:00:00Z', newestModified: 'x', sizeBytes: 1 } };
    invoke.mockImplementation(async (action: string, payload?: { ecosystem?: string }) => {
      switch (action) {
        case 'state.get': return mirrorLib;
        case 'cockpit.state': return { success: true, pinned: [] };
        case 'vault.pack.ensure': return { vault: 'KP-MNEMO-VULNS-OSV', folder: '/kn/mnemo-vulns', created: false };
        case 'vulns.mirrorStatus':
          if (payload?.ecosystem !== 'npm') return { ...idle, ecosystem: payload?.ecosystem, installed: null, last: null };
          calls += 1;
          return calls === 1 ? { ...idle, phase: 'updating', last: null } : { ...idle, last: { kind: 'updated', count: 3, at: 'now' } };
        default: return undefined;
      }
    });
    readDir.mockClear();
    render(<App />);
    await new Promise((r) => setTimeout(r, 1_800));
    expect(readDir.mock.calls.some((c) => c[0] === '/code/app')).toBe(true);
  }, 20_000);
});

describe('App: a scan keeps its files in the knowledge folder', () => {
  const idle = { ecosystem: 'npm', phase: 'idle', startedAt: null, done: null, total: null, error: null, last: null, installed: null, unreadable: null };
  const LOCKFILE = JSON.stringify({ lockfileVersion: 3, packages: { '': {} } });

  it('never asks for a storage folder and writes under the folder vault.pack.ensure answers', async () => {
    invoke.mockReset();
    selectFolder.mockClear();
    invoke.mockImplementation(async (action: string) => {
      switch (action) {
        case 'state.get': return lib;
        case 'cockpit.state': return { success: true, pinned: [] };
        case 'vulns.mirrorStatus': return idle;
        case 'vault.pack.ensure': return { vault: 'KP-MNEMO-VULNS-OSV', folder: '/kn/mnemo-vulns', created: true };
        case 'dialog.mkdir': return { success: true };
        default: return undefined;
      }
    });
    readDir.mockImplementation(async (dir: unknown) => ({ success: true, files: dir === '/code/app' ? [{ name: 'package-lock.json', isDirectory: false }] : [] }));
    readFile.mockImplementation(async (path: unknown) => (path === '/code/app/package-lock.json' ? { success: true, content: LOCKFILE } : { success: false }));
    render(<App />);
    fireEvent.click(await screen.findByText(translate('en', 'scan.rescan')));
    await waitFor(() => expect(invoke.mock.calls.some((c) => c[0] === 'dialog.mkdir')).toBe(true));
    expect(selectFolder).not.toHaveBeenCalled();
    expect(invoke.mock.calls.find((c) => c[0] === 'vault.pack.ensure')?.[1]).toEqual({ pack: 'osv', lexicalOnly: true });
    const made = invoke.mock.calls.filter((c) => c[0] === 'dialog.mkdir').map((c) => (c[1] as { dirPath: string }).dirPath);
    expect(made.length).toBeGreaterThan(0);
    for (const dir of made) expect(dir.startsWith('/kn/mnemo-vulns/')).toBe(true);
    // The library follows the pack folder, and the old vault's dates are not carried over.
    const saved = invoke.mock.calls.filter((c) => c[0] === 'state.set').map((c) => (c[1] as { state: { library: { folder: string; ingestedIn?: string } } }).state.library);
    expect(saved.some((l) => l.folder === '/kn/mnemo-vulns' && l.ingestedIn === 'KP-MNEMO-VULNS-OSV')).toBe(true);
  }, 20_000);

  it('says to choose the knowledge folder in the Hub when there is none, and asks for no folder', async () => {
    invoke.mockReset();
    selectFolder.mockClear();
    invoke.mockImplementation(async (action: string) => {
      switch (action) {
        case 'state.get': return lib;
        case 'cockpit.state': return { success: true, pinned: [] };
        case 'vulns.mirrorStatus': return idle;
        case 'vault.pack.ensure': throw new Error('NO_KNOWLEDGE_ROOT');
        default: return undefined;
      }
    });
    render(<App />);
    fireEvent.click(await screen.findByText(translate('en', 'scan.rescan')));
    expect(await screen.findByText(translate('en', 'run.noKnowledgeRoot'))).toBeTruthy();
    expect(selectFolder).not.toHaveBeenCalled();
    expect(invoke.mock.calls.some((c) => c[0] === 'dialog.mkdir')).toBe(false);
  }, 20_000);
});
