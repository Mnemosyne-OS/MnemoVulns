import { describe, it, expect } from 'vitest';
import { vi } from 'vitest';
import { EMPTY_LIBRARY, parseLibrary, persistLibrary } from './library';
import { openBySeverity } from './project';

describe('parseLibrary', () => {
  it('reads the host answer shape and keeps a summary without per-severity counts ABSENT', () => {
    const raw = { state: { library: { folder: '/lib', ingested: { 'GHSA-1': 'm' }, projects: [
      { root: '/a', name: 'a', slug: 'a-1', lastScan: { at: 'x', complete: true, findings: 3, open: 2, unasked: 0 } },
      { root: '', name: 'bad', slug: 'b' },
    ] } } };
    const lib = parseLibrary(raw);
    expect(lib.folder).toBe('/lib');
    expect(lib.projects).toHaveLength(1);
    expect(lib.projects[0]!.lastScan).not.toHaveProperty('openBySeverity');
    expect(lib.projects[0]!.lastScan).not.toHaveProperty('accepted');
  });

  it('drops per-severity counts that are not all readable', () => {
    const lastScan = { at: 'x', complete: true, findings: 1, open: 1, unasked: 0, openBySeverity: { CRITICAL: 1, HIGH: 'x' } };
    const lib = parseLibrary({ library: { projects: [{ root: '/a', name: 'a', slug: 'a', lastScan }] } });
    expect(lib.projects[0]!.lastScan).not.toHaveProperty('openBySeverity');
  });
});

describe('parseLibrary keeps what the card shows', () => {
  it('reads back the malicious count and the packages to fix, and drops an unreadable one', () => {
    const toFix = [{ ecosystem: 'npm', name: 'tar', version: '7.5.13', severity: 'HIGH', count: 6, action: { kind: 'to', version: '7.5.21' } }, { name: 'bad' }];
    const lastScan = { at: 'x', complete: true, findings: 7, open: 7, unasked: 0, openMalicious: 1, toFix };
    const p = parseLibrary({ library: { projects: [{ root: '/a', name: 'a', slug: 'a', lastScan }] } }).projects[0]!.lastScan!;
    expect(p.openMalicious).toBe(1);
    expect(p.toFix).toEqual([toFix[0]]);
  });
});

describe('persistLibrary', () => {
  it('refuses to write before the library was read (an unread library would be overwritten)', async () => {
    const setState = vi.fn(async () => undefined);
    expect(await persistLibrary({ kind: 'loading' } as never, EMPTY_LIBRARY, setState)).toBe('refused');
    expect(setState).not.toHaveBeenCalled();
    expect(await persistLibrary({ kind: 'ready' } as never, EMPTY_LIBRARY, setState)).toBe('saved');
    expect(setState).toHaveBeenCalledTimes(1);
  });
});

describe('openBySeverity', () => {
  it('counts each OPEN tracked vulnerability once, at its worst severity', () => {
    const findings = [
      { id: 'G1', name: 'tar', severity: 'HIGH' as const },
      { id: 'G1', name: 'tar', severity: 'CRITICAL' as const },
      { id: 'G2', name: 'tar', severity: 'LOW' as const },
    ];
    const tracking = { entries: [
      { id: 'G1', name: 'tar', versions: [], state: 'open' as const, since: 'x', firstSeen: 'x' },
      { id: 'G2', name: 'tar', versions: [], state: 'accepted' as const, since: 'x', firstSeen: 'x', reason: 'r' },
    ] };
    expect(openBySeverity(findings, tracking)).toEqual({ CRITICAL: 1, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 });
  });
});
