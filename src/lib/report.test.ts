import { describe, it, expect } from 'vitest';
import { EMPTY_TRACKING, accept, reconcile } from './tracking';
import { reportText } from './texts';
import { openMalicious } from './project';
import type { ScanResult } from './scan';

const T1 = '2026-10-01T00:00:00Z';
const finding = (name: string, malicious = false) => ({
  id: malicious ? 'MAL-1' : 'PYSEC-1', ecosystem: 'PyPI' as const, name, version: '3.2.0', severity: 'HIGH' as const, fix: { kind: 'none' as const },
  malicious, summary: 's', aliases: [], modified: T1, source: { name: 'x', licence: 'y', licenceUrl: 'z' }, recordRead: true,
});
const scanOf = (findings: ReturnType<typeof finding>[]): ScanResult => ({
  at: T1, lockfiles: ['poetry.lock'], packages: 1, asked: 1, unasked: 0, skipped: 0, recordsUnread: 0, recordsFromCache: 0, complete: true, error: null, records: [],
  installed: findings.map((f) => ({ ecosystem: 'PyPI' as const, name: f.name, version: f.version, asked: true })), sources: [{ ecosystem: 'PyPI', kind: 'api', asOf: null }],
  findings,
});

describe('reportText', () => {
  it('keeps the tracked state of a PyPI package whose lockfile changed the spelling', () => {
    const first = reconcile(EMPTY_TRACKING, { at: T1, lockfileComplete: true, findings: [finding('Django')], installed: [{ ecosystem: 'PyPI', name: 'Django', version: '3.2.0', asked: true }] });
    const accepted = accept(first, 'PYSEC-1', 'Django', 'why', T1, 'PyPI')!;
    const next = reconcile(accepted, { at: T1, lockfileComplete: true, findings: [finding('django')], installed: [{ ecosystem: 'PyPI', name: 'django', version: '3.2.0', asked: true }] });
    const line = reportText('p', scanOf([finding('django')]), next).split('\n').find((l) => l.startsWith('- ') && l.includes('PYSEC-1'))!;
    expect(line).toContain('[accepted: why]');
  });
});

describe('openMalicious', () => {
  it('counts open malicious packages only', () => {
    const findings = [finding('evil', true), finding('django')];
    const tracking = reconcile(EMPTY_TRACKING, { at: T1, lockfileComplete: true, findings, installed: findings.map((f) => ({ ecosystem: 'PyPI', name: f.name, version: f.version, asked: true })) });
    expect(openMalicious(findings, tracking)).toBe(1);
    const acceptedMal = accept(tracking, 'MAL-1', 'evil', 'test fixture', T1, 'PyPI')!;
    expect(openMalicious(findings, acceptedMal)).toBe(0);
  });
});

import { toFixFirst } from './project';

describe('toFixFirst', () => {
  const f = (id: string, name: string, version: string, severity: 'CRITICAL' | 'HIGH' | 'LOW', fix: { kind: 'fixed'; version: string } | { kind: 'none' } | { kind: 'see' }, malicious = false) => ({
    id, ecosystem: 'npm' as const, name, version, severity, fix, malicious, summary: 's', aliases: [], modified: T1, source: { name: 'x', licence: 'y', licenceUrl: 'z' }, recordRead: true,
  });
  const open = (fs: ReturnType<typeof f>[]) => reconcile(EMPTY_TRACKING, { at: T1, lockfileComplete: true, findings: fs, installed: fs.map((x) => ({ ecosystem: 'npm', name: x.name, version: x.version, asked: true })) });

  it('asks for the HIGHEST fixed version a package needs, malicious first, then by severity and count', () => {
    const fs = [
      f('G1', 'tar', '7.5.13', 'HIGH', { kind: 'fixed', version: '7.5.16' }),
      f('G2', 'tar', '7.5.13', 'LOW', { kind: 'fixed', version: '7.5.21' }),
      f('G3', 'qs', '6.0.0', 'CRITICAL', { kind: 'fixed', version: '6.2.0' }),
      f('MAL-1', 'evil', '1.0.0', 'LOW', { kind: 'none' }, true),
      f('G4', 'xlsx', '0.18.5', 'HIGH', { kind: 'none' }),
    ];
    const out = toFixFirst(fs, open(fs), 10);
    expect(out.map((x) => [x.name, x.action])).toEqual([
      ['evil', { kind: 'remove' }],
      ['qs', { kind: 'to', version: '6.2.0' }],
      ['tar', { kind: 'to', version: '7.5.21' }],
      ['xlsx', { kind: 'none' }],
    ]);
    expect(out.find((x) => x.name === 'tar')).toMatchObject({ severity: 'HIGH', count: 2 });
  });

  it('orders gem versions as gems, like the tile: a four-segment Rails fix is a version, not "see the record"', () => {
    const gem = (id: string, fixed: string) => ({ ...f(id, 'actionpack', '6.1.0', 'HIGH', { kind: 'fixed', version: fixed }), ecosystem: 'RubyGems' as const });
    const fs = [gem('G1', '6.1.7.3'), gem('G2', '6.1.7.5')];
    const tr = reconcile(EMPTY_TRACKING, { at: T1, lockfileComplete: true, findings: fs, installed: [{ ecosystem: 'RubyGems', name: 'actionpack', version: '6.1.0', asked: true }] });
    expect(toFixFirst(fs, tr)[0]!.action).toEqual({ kind: 'to', version: '6.1.7.5' });
  });

  it('puts what ships before a dev tool, even a worse one, and marks the dev tool', () => {
    const fs = [
      { ...f('G1', 'tar', '6.2.1', 'CRITICAL', { kind: 'fixed', version: '7.5.21' }), dev: true },
      { ...f('G2', 'protobufjs', '6.11.6', 'HIGH', { kind: 'fixed', version: '7.6.3' }), dev: false },
      f('G3', 'unsaid', '1.0.0', 'LOW', { kind: 'fixed', version: '1.0.1' }),
    ];
    const out = toFixFirst(fs, open(fs), 10);
    expect(out.map((x) => x.name)).toEqual(['protobufjs', 'unsaid', 'tar']);
    expect(out.map((x) => x.dev)).toEqual([undefined, undefined, true]);
  });

  it('never names a version for a package where one vulnerability cannot be ordered, and skips what is not open', () => {
    const fs = [f('G1', 'a', '1.0.0', 'HIGH', { kind: 'fixed', version: '1.2.0' }), f('G2', 'a', '1.0.0', 'HIGH', { kind: 'see' }), f('G3', 'b', '1.0.0', 'HIGH', { kind: 'fixed', version: '2.0.0' })];
    const tr = accept(open(fs), 'G3', 'b', 'kept', T1)!;
    expect(toFixFirst(fs, tr)).toEqual([{ ecosystem: 'npm', name: 'a', version: '1.0.0', severity: 'HIGH', count: 2, action: { kind: 'see' } }]);
  });
});

import { newUrgent } from './project';

describe('newUrgent', () => {
  const f = (id: string, severity: 'CRITICAL' | 'HIGH' | 'LOW', malicious = false) => ({
    id, ecosystem: 'npm' as const, name: 'tar', version: '1.0.0', severity, fix: { kind: 'none' as const }, malicious, summary: 's', aliases: [], modified: 'm', source: { name: 'x', licence: 'y', licenceUrl: 'z' }, recordRead: true,
  });
  const inst = [{ ecosystem: 'npm' as const, name: 'tar', version: '1.0.0', asked: true }];

  it('counts the critical, high and malicious ones a LATER scan sees for the first time', () => {
    const first = reconcile(EMPTY_TRACKING, { at: 'T1', lockfileComplete: true, findings: [f('G1', 'HIGH')], installed: inst });
    expect(newUrgent({ at: 'T1', findings: [f('G1', 'HIGH')] }, first)).toBe(0);
    const later = [f('G1', 'HIGH'), f('G2', 'CRITICAL'), f('G3', 'LOW'), f('MAL-1', 'LOW', true)];
    const second = reconcile(first, { at: 'T2', lockfileComplete: true, findings: later, installed: inst });
    expect(newUrgent({ at: 'T2', findings: later }, second)).toBe(2);
    const accepted = accept(second, 'G2', 'tar', 'kept', 'T2')!;
    expect(newUrgent({ at: 'T2', findings: later }, accepted)).toBe(1);
  });
});
