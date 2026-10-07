import { describe, it, expect } from 'vitest';
import { EMPTY_TRACKING, accept, parseTracking, reconcile, reopen, type Measurement } from './tracking';

const T1 = '2026-10-01T00:00:00Z';
const T2 = '2026-10-02T00:00:00Z';

const m = (at: string, findings: Measurement['findings'], installed: Measurement['installed']): Measurement =>
  ({ at, findings, installed, lockfileComplete: true });

const first = reconcile(EMPTY_TRACKING, m(T1, [{ id: 'GHSA-1', name: 'tar', version: '7.5.13' }], [{ name: 'tar', version: '7.5.13', asked: true }]));

describe('reconcile', () => {
  it('opens what a scan measures for the first time', () => {
    expect(first.entries).toEqual([{ id: 'GHSA-1', name: 'tar', versions: ['7.5.13'], state: 'open', since: T1, firstSeen: T1 }]);
  });

  it('marks FIXED only when the installed version moved out of the range', () => {
    const next = reconcile(first, m(T2, [], [{ name: 'tar', version: '7.5.21', asked: true }]));
    expect(next.entries[0]).toMatchObject({ state: 'fixed', since: T2, fixedBy: 'upgraded', fixedWith: ['7.5.21'] });
  });

  it('never calls FIXED a vulnerability that disappears while the version stayed the same', () => {
    const next = reconcile(first, m(T2, [], [{ name: 'tar', version: '7.5.13', asked: true }]));
    expect(next.entries[0]).toMatchObject({ state: 'withdrawn', since: T2 });
  });

  it('marks a package that left the lockfile as fixed by removal', () => {
    expect(reconcile(first, m(T2, [], [])).entries[0]).toMatchObject({ state: 'fixed', fixedBy: 'removed' });
  });

  it('does not call a removal from a lockfile read in part', () => {
    const next = reconcile(first, { at: T2, findings: [], installed: [], lockfileComplete: false });
    expect(next.entries[0]!.state).toBe('open');
  });

  it('changes nothing for a package that was not asked', () => {
    const next = reconcile(first, m(T2, [], [{ name: 'tar', version: '7.5.21', asked: false }]));
    expect(next.entries[0]).toEqual(first.entries[0]);
  });

  it('keeps an accepted risk accepted, with its reason, while it is still measured', () => {
    const acc = accept(first, 'GHSA-1', 'tar', 'build tool only', T1)!;
    const next = reconcile(acc, m(T2, [{ id: 'GHSA-1', name: 'tar', version: '7.5.13' }], [{ name: 'tar', version: '7.5.13', asked: true }]));
    expect(next.entries[0]).toMatchObject({ state: 'accepted', reason: 'build tool only' });
  });

  it('reopens a fixed vulnerability that comes back', () => {
    const fixed = reconcile(first, m(T2, [], [{ name: 'tar', version: '7.5.21', asked: true }]));
    const back = reconcile(fixed, m('2026-10-03T00:00:00Z', [{ id: 'GHSA-1', name: 'tar', version: '7.5.13' }], [{ name: 'tar', version: '7.5.13', asked: true }]));
    expect(back.entries[0]).toMatchObject({ state: 'open', since: '2026-10-03T00:00:00Z', firstSeen: T1 });
    expect(back.entries[0]).not.toHaveProperty('fixedBy');
  });
});

describe('accept and reopen', () => {
  it('refuses to accept a risk without a written reason', () => {
    expect(accept(first, 'GHSA-1', 'tar', '   ', T2)).toBeNull();
  });
  it('takes an accepted risk back to open, without its reason', () => {
    const acc = accept(first, 'GHSA-1', 'tar', 'why', T1)!;
    const back = reopen(acc, 'GHSA-1', 'tar', T2)!;
    expect(back.entries[0]).toMatchObject({ state: 'open', since: T2 });
    expect(back.entries[0]).not.toHaveProperty('reason');
  });
});

describe('parseTracking', () => {
  it('drops entries it cannot trust, an accepted one without its reason included', () => {
    const raw = {
      entries: [
        first.entries[0]!,
        { id: 'GHSA-2', name: 'x', versions: [], state: 'accepted', since: T1, firstSeen: T1 },
        { id: 'GHSA-3', name: 'x', state: 'gone', since: T1, firstSeen: T1 },
        'garbage',
      ],
    };
    expect(parseTracking(raw).entries).toEqual([first.entries[0]]);
  });
});
