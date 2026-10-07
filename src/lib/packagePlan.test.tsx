import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { filterPlans, overviewOf, planAll, planPackage } from './packagePlan';
import type { Finding } from './scan';
import { trackKey, type TrackEntry } from './tracking';
import { translate, type Key } from '../i18n/strings';
import { ProjectView } from '../ui/ProjectView';
import type { ProjectOutcome } from './project';

const f = (over: Partial<Finding>): Finding => ({
  id: 'GHSA-1', ecosystem: 'npm', name: 'tar', version: '7.5.13', severity: 'HIGH', fix: { kind: 'fixed', version: '7.5.8' },
  malicious: false, summary: 's', aliases: [], modified: 'm', source: { name: 'x', licence: 'y', licenceUrl: 'z' }, recordRead: true, ...over,
});
const none = new Map<string, TrackEntry>();

// The case of the field report: one CRITICAL record touches both tar versions; 6.2.1 is dev, 7.5.13 ships.
const TAR: Finding[] = [
  f({ id: 'GHSA-crit', version: '6.2.1', severity: 'CRITICAL', fix: { kind: 'fixed', version: '7.5.19' }, dev: true }),
  f({ id: 'GHSA-crit', version: '7.5.13', severity: 'CRITICAL', fix: { kind: 'fixed', version: '7.5.19' }, dev: false, via: [{ importer: 'apps/desktop', through: 'llama', dev: false }] }),
  f({ id: 'GHSA-high', version: '7.5.13', severity: 'HIGH', fix: { kind: 'fixed', version: '7.5.8' }, dev: false }),
];

describe('planPackage', () => {
  it('counts a record once, and targets the highest fixed version by version order, not text order', () => {
    const p = planPackage(TAR, none);
    expect(p.records).toBe(2);
    expect(p.bySeverity).toMatchObject({ CRITICAL: 1, HIGH: 1 });
    expect(p.target).toBe('7.5.19'); // as text, '7.5.8' > '7.5.19'
    expect(p.closes).toBe(2);
    expect(p.open).toBe(2);
  });

  it('lists the shipped version first even when the dev version is higher', () => {
    const p = planPackage([
      f({ id: 'A', version: '9.0.0', dev: true, fix: { kind: 'fixed', version: '9.0.1' } }),
      f({ id: 'A', version: '1.0.0', dev: false, fix: { kind: 'fixed', version: '1.0.1' } }),
    ], none);
    expect(p.versions.map((v) => v.version)).toEqual(['1.0.0', '9.0.0']);
  });

  it('orders gem versions as gems: a four-segment Rails fix has a target', () => {
    const p = planPackage([
      f({ id: 'A', ecosystem: 'RubyGems', name: 'actionpack', version: '6.1.0', fix: { kind: 'fixed', version: '6.1.7.3' } }),
      f({ id: 'B', ecosystem: 'RubyGems', name: 'actionpack', version: '6.1.0', fix: { kind: 'fixed', version: '6.1.7.5' } }),
    ], none);
    expect(p.target).toBe('6.1.7.5');
  });

  it('says the package ships when ANY version ships, and lists the shipped version first', () => {
    const p = planPackage(TAR, none);
    expect(p.place).toBe('shipped');
    expect(p.versions.map((v) => [v.version, v.place])).toEqual([['7.5.13', 'shipped'], ['6.2.1', 'dev']]);
    expect(p.versions[0]!.target).toBe('7.5.19');
    expect(p.versions[0]!.via).toEqual([{ importer: 'apps/desktop', through: 'llama', dev: false }]);
  });

  it('never folds a record with no fix, or an unstated fix, into "closes"', () => {
    const p = planPackage([
      f({ id: 'A', fix: { kind: 'fixed', version: '7.6.0' } }),
      f({ id: 'B', fix: { kind: 'none' } }),
      f({ id: 'C', fix: { kind: 'unknown' } }),
      f({ id: 'D', fix: { kind: 'see' } }),
    ], none);
    expect([p.closes, p.noFix, p.unknownFix, p.target]).toEqual([1, 1, 2, '7.6.0']);
  });

  it('a record fixed on one version and unfixed on another is NOT closed', () => {
    const p = planPackage([f({ id: 'A', version: '1.0.0', fix: { kind: 'fixed', version: '1.0.1' } }), f({ id: 'A', version: '2.0.0', fix: { kind: 'none' } })], none);
    expect([p.closes, p.noFix, p.target]).toEqual([0, 1, null]);
    const q = planPackage([f({ id: 'A', version: '1.0.0', fix: { kind: 'fixed', version: '1.0.1' } }), f({ id: 'A', version: '2.0.0', fix: { kind: 'unknown' } })], none);
    expect([q.closes, q.unknownFix, q.target]).toEqual([0, 1, null]);
  });

  it('gives no target when two fixed versions cannot be ordered', () => {
    const p = planPackage([f({ id: 'A', fix: { kind: 'fixed', version: '1.2.3' } }), f({ id: 'B', fix: { kind: 'fixed', version: 'banana' } })], none);
    expect(p.target).toBeNull();
    expect(p.closes).toBe(2);
  });

  it('reads accepted and open from the tracker; a record with no entry is open', () => {
    const entry: TrackEntry = { id: 'GHSA-crit', name: 'tar', versions: ['7.5.13'], state: 'accepted', since: 'x', firstSeen: 'x', reason: 'r' };
    const p = planPackage(TAR, new Map([[trackKey('GHSA-crit', 'tar'), entry]]));
    expect([p.open, p.accepted]).toEqual([1, 1]);
  });
});

describe('planAll and filterPlans', () => {
  const ALL: Finding[] = [
    f({ id: 'X1', name: 'devonly', version: '1.0.0', severity: 'CRITICAL', dev: true }),
    ...TAR,
    f({ id: 'X2', name: 'quiet', version: '1.0.0', severity: 'LOW', dev: false }),
    f({ id: 'MAL-1', name: 'evil', version: '1.0.0', malicious: true }),
  ];

  it('puts shipped packages before dev-only ones even when the dev one is worse, and leaves malicious ones out', () => {
    expect(planAll(ALL, none).map((p) => p.name)).toEqual(['tar', 'quiet', 'devonly']);
  });

  it('filters each place on its own: an unknown place is never "in the product"', () => {
    const plans = planAll([...ALL, f({ id: 'U', name: 'unsaid', version: '1.0.0' })], none);
    expect(filterPlans(plans, 'shipped').map((p) => p.name).sort()).toEqual(['quiet', 'tar']);
    expect(filterPlans(plans, 'dev').map((p) => p.name)).toEqual(['devonly']);
    expect(filterPlans(plans, 'unknown').map((p) => p.name)).toEqual(['unsaid']);
    expect(filterPlans(plans, 'all')).toHaveLength(4);
  });
});

describe('overviewOf', () => {
  it('sums the OPEN records by severity and by place, and starts with shipped packages that have a target', () => {
    const accepted: TrackEntry = { id: 'X1', name: 'devonly', versions: ['1.0.0'], state: 'accepted', since: 'x', firstSeen: 'x', reason: 'r' };
    const plans = planAll([
      ...TAR,
      f({ id: 'X1', name: 'devonly', version: '1.0.0', severity: 'CRITICAL', dev: true }),
      f({ id: 'X3', name: 'devtoo', version: '1.0.0', severity: 'LOW', dev: true }),
      f({ id: 'N', name: 'nofix', version: '1.0.0', severity: 'HIGH', dev: false, fix: { kind: 'none' } }),
    ], new Map([[trackKey('X1', 'devonly'), accepted]]));
    const o = overviewOf(plans);
    expect(o.openBySeverity).toMatchObject({ CRITICAL: 1, HIGH: 2, LOW: 1 });
    expect([o.openShipped, o.openDev]).toEqual([3, 1]);
    expect(o.start.map((p) => p.name)).toEqual(['tar']);
  });

  it('keeps at most the asked number of starting points', () => {
    const plans = planAll(['a', 'b', 'c', 'd'].map((name) => f({ id: name, name, dev: false })), none);
    expect(overviewOf(plans).start).toHaveLength(3);
    expect(overviewOf(plans, { startCount: 2 }).start).toHaveLength(2);
  });

  it('counts an unknown place apart, never in the product (a Cargo.lock says nothing about dev)', () => {
    const o = overviewOf(planAll([f({ id: 'A', name: 'a' }), f({ id: 'B', name: 'b' }), f({ id: 'C', name: 'c', dev: false })], none));
    expect([o.openShipped, o.openDev, o.openUnknown]).toEqual([1, 0, 2]);
  });

  it('carries the open malicious packages it is given', () => {
    expect(overviewOf([], { openMalicious: 2 }).openMalicious).toBe(2);
    expect(overviewOf([]).openMalicious).toBe(0);
  });
});

describe('the package card', () => {
  const t = (key: Key, vars?: Record<string, string | number>) => translate('en', key, vars);
  const outcome: ProjectOutcome = {
    project: { root: '/a', name: 'a', slug: 'a' },
    scan: { at: 'x', lockfiles: ['pnpm-lock.yaml'], packages: 2, asked: 2, unasked: 0, skipped: 0, findings: TAR, recordsUnread: 0, recordsFromCache: 0, complete: true, error: null, installed: [], records: [], sources: [] },
    tracking: { entries: [] }, trackingWritten: true, trackingError: null, reportWritten: true, reportError: null, vault: null, ingested: {}, lockFailures: [],
  };
  const draw = () => render(<ProjectView t={t} lang="en" project={outcome.project} view={{ kind: 'done', outcome }} job={null} now={0}
    onScan={() => {}} onStop={() => {}} onBack={() => {}} onAccept={() => {}} onReopen={() => {}} onOpenUrl={() => {}} />);

  it('leads with the version to move to, and marks each installed version where it goes', () => {
    draw();
    expect(screen.getByTestId('plan-action').textContent).toContain(t('plan.upgrade', { version: '7.5.19' }));
    const lines = screen.getAllByTestId('plan-version').map((el) => el.textContent);
    expect(lines[0]).toContain('7.5.13');
    expect(lines[0]).toContain(t('plan.shipped'));
    expect(lines[1]).toContain('6.2.1');
    expect(lines[1]).toContain(t('plan.dev'));
  });

  it('keeps the records folded until asked, then shows each once with the versions it touches', () => {
    draw();
    expect(screen.queryByText('GHSA-crit')).toBeNull();
    fireEvent.click(screen.getByText(new RegExp(t('plan.show', { n: 2 }))));
    expect(screen.getAllByText('GHSA-crit')).toHaveLength(1);
    expect(screen.getByText(new RegExp(t('plan.versionsOf', { versions: '6.2.1, 7.5.13' })))).toBeTruthy();
  });

  it('draws the packages as tiles, and an opened tile takes the whole row', () => {
    draw();
    expect(screen.getByTestId('package-grid').style.display).toBe('grid');
    const card = screen.getByTestId('package-card');
    expect(card.style.gridColumn).toBe('');
    fireEvent.click(screen.getByText(new RegExp(t('plan.show', { n: 2 }))));
    expect(card.style.gridColumn).toBe('1 / -1');
  });

  it('puts the overview in the header, and a starting point brings back a tile the filter hid', () => {
    draw();
    const o = screen.getByTestId('overview');
    expect(o.textContent).toContain(t('over.shipped', { n: 2 }));
    fireEvent.click(screen.getByText(t('plan.filterDev', { n: 0 })));
    expect(screen.queryByTestId('package-card')).toBeNull();
    fireEvent.click(screen.getByText('tar'));
    expect(screen.getByTestId('package-card').id).toBe('pkg-npm_tar');
  });

  it('says 1 in the singular', () => {
    const one = { ...outcome, scan: { ...outcome.scan, findings: [f({ id: 'ONE', name: 'solo', version: '1.0.0', dev: false })] } };
    render(<ProjectView t={t} lang="en" project={one.project} view={{ kind: 'done', outcome: one }} job={null} now={0}
      onScan={() => {}} onStop={() => {}} onBack={() => {}} onAccept={() => {}} onReopen={() => {}} onOpenUrl={() => {}} />);
    const card = screen.getByTestId('package-card').textContent!;
    expect(card).toContain(t('plan.open1'));
    expect(card).toContain(t('plan.records1'));
    expect(card).toContain(t('plan.show1'));
  });

  it('filters to dev only and says when nothing is left', () => {
    draw();
    fireEvent.click(screen.getByText(t('plan.filterDev', { n: 0 })));
    expect(screen.getByText(t('plan.empty'))).toBeTruthy();
  });
});

describe('the header and the sections tell the same story', () => {
  const t = (key: Key, vars?: Record<string, string | number>) => translate('en', key, vars);
  const show = (findings: Finding[]) => {
    const o: ProjectOutcome = {
      project: { root: '/a', name: 'a', slug: 'a' },
      scan: { at: 'x', lockfiles: ['Cargo.lock'], packages: 3, asked: 3, unasked: 0, skipped: 0, findings, recordsUnread: 0, recordsFromCache: 0, complete: true, error: null, installed: [], records: [], sources: [] },
      tracking: { entries: [] }, trackingWritten: true, trackingError: null, reportWritten: true, reportError: null, vault: null, ingested: {}, lockFailures: [],
    };
    return render(<ProjectView t={t} lang="en" project={o.project} view={{ kind: 'done', outcome: o }} job={null} now={0}
      onScan={() => {}} onStop={() => {}} onBack={() => {}} onAccept={() => {}} onReopen={() => {}} onOpenUrl={() => {}} />);
  };

  it('counts a malicious package in the header, and its row says who pulls it', () => {
    show([
      f({ id: 'MAL-1', name: 'evil', version: '1.0.0', malicious: true, dev: false, via: [{ importer: 'apps/x', through: 'evil', dev: false }] }),
      f({ id: 'L', name: 'low', version: '1.0.0', severity: 'LOW', dev: false }),
    ]);
    expect(screen.getByTestId('overview').textContent).toContain(t('over.malicious', { n: 1 }));
    expect(screen.getByText(t('plan.lead', { n: 2 }))).toBeTruthy();
    expect(screen.getByTestId('via').textContent).toBe(`${t('via.label')} apps/x ← evil`);
  });

  it('never says "in the product" for a lockfile that does not say: its own count and filter', () => {
    show([f({ id: 'A', name: 'a', version: '1.0.0' }), f({ id: 'B', name: 'b', version: '1.0.0' })]);
    const o = screen.getByTestId('overview').textContent!;
    expect(o).toContain(t('over.shipped', { n: 0 }));
    expect(o).toContain(t('over.unknown', { n: 2 }));
    expect(screen.getByText(t('plan.filterShipped', { n: 0 }))).toBeTruthy();
    expect(screen.getByText(t('plan.filterUnknown', { n: 2 }))).toBeTruthy();
  });

  it('offers no "place not known" filter when every place is known', () => {
    show([f({ id: 'A', name: 'a', version: '1.0.0', dev: false })]);
    expect(screen.queryByText(t('plan.filterUnknown', { n: 0 }))).toBeNull();
  });
});
