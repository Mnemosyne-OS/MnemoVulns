import { describe, it, expect } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { vi } from 'vitest';
import { EMPTY_TRACKING, reconcile } from '../lib/tracking';
import { translate, type Key } from '../i18n/strings';
import type { ProjectOutcome } from '../lib/project';
import type { ScanResult } from '../lib/scan';
import { ProjectView } from './ProjectView';
import { Home } from './Home';
import { MirrorCard } from './MirrorCard';

const t = (key: Key, vars?: Record<string, string | number>) => translate('en', key, vars);
const project = { root: '/code/app', name: 'app', slug: 'app-1' };

function outcome(scan: Partial<ScanResult>, trackingWritten = true): ProjectOutcome {
  return {
    project,
    scan: {
      at: '2026-10-04T00:00:00Z', lockfiles: ['pnpm-lock.yaml'], packages: 10, asked: 10, unasked: 0, skipped: 0,
      findings: [], recordsUnread: 0, recordsFromCache: 0, complete: true, error: null, installed: [], records: [], sources: [{ ecosystem: 'npm', kind: 'api', asOf: null }], ...scan,
    },
    tracking: { entries: [] }, trackingWritten, trackingError: trackingWritten ? null : 'NOT_JSON', reportWritten: true, reportError: null, vault: null, ingested: {}, lockFailures: [],
  };
}

const view = (o: ProjectOutcome) => render(
  <ProjectView t={t} lang="en" project={project} view={{ kind: 'done', outcome: o }} job={null} now={0}
    onScan={() => {}} onStop={() => {}} onBack={() => {}} onAccept={() => {}} onReopen={() => {}} onOpenUrl={() => {}} />,
);

describe('ProjectView', () => {
  it('says the project is clean only after a COMPLETE scan', () => {
    view(outcome({}));
    expect(screen.getByText(t('sum.clean', { asked: 10 }))).toBeTruthy();
  });

  it('never turns a partial scan with no finding into a clean project', () => {
    view(outcome({ complete: false, unasked: 4, asked: 6, error: 'HTTP_503' }));
    expect(screen.queryByText(t('sum.clean', { asked: 6 }))).toBeNull();
    expect(screen.getByRole('alert').textContent).toContain(t('sum.partial', { unasked: 4, unread: 0 }));
  });

  it('says when the stored tracker was unreadable and left as it was', () => {
    view(outcome({}, false));
    expect(screen.getByText(t('track.unreadable', { why: 'NOT_JSON' }))).toBeTruthy();
  });

  it('accepts a PyPI risk with its ecosystem (a missing one matched no tracker entry)', () => {
    const finding = { id: 'PYSEC-1', ecosystem: 'PyPI' as const, name: 'Django', version: '3.2.0', severity: 'HIGH' as const, fix: { kind: 'none' as const }, malicious: false, summary: 's', aliases: [], modified: 'x', source: { name: 'x', licence: 'y', licenceUrl: 'z' }, recordRead: true };
    const tracking = reconcile(EMPTY_TRACKING, { at: 'x', lockfileComplete: true, findings: [finding], installed: [{ ecosystem: 'PyPI', name: 'Django', version: '3.2.0', asked: true }] });
    const onAccept = vi.fn();
    render(<ProjectView t={t} lang="en" project={project} view={{ kind: 'done', outcome: { ...outcome({ findings: [finding] }), tracking } }} job={null} now={0}
      onScan={() => {}} onStop={() => {}} onBack={() => {}} onAccept={onAccept} onReopen={() => {}} onOpenUrl={() => {}} />);
    fireEvent.click(screen.getByText(new RegExp(t('plan.show1'))));
    fireEvent.click(screen.getByText(t('track.accept')));
    fireEvent.change(screen.getByLabelText(t('track.reason')), { target: { value: 'patched' } });
    fireEvent.click(screen.getByText(t('track.confirm')));
    expect(onAccept).toHaveBeenCalledWith('PYSEC-1', 'Django', 'PyPI', 'patched');
  });

  it('labels a finding declared for development, and names the local database date', () => {
    const asOf = '2026-10-04T12:00:00Z';
    const finding = { id: 'GHSA-1', ecosystem: 'npm' as const, name: 'electron', version: '31.7.7', severity: 'HIGH' as const, fix: { kind: 'none' as const }, malicious: false, summary: 's', aliases: [], modified: 'x', source: { name: 'x', licence: 'y', licenceUrl: 'z' }, recordRead: true, dev: true };
    const { container } = view(outcome({ findings: [finding], sources: [{ ecosystem: 'npm', kind: 'mirror', asOf }] }));
    expect(container.textContent).toContain(t('plan.dev'));
    expect(container.textContent).toContain(t('sum.mirror', { date: new Date(asOf).toLocaleString('en') }));
  });

  it('says who pulls a finding, marks the dev ways, and counts the ways it cut', () => {
    const base = { id: 'GHSA-1', ecosystem: 'npm' as const, name: 'tar', version: '7.5.13', severity: 'HIGH' as const, fix: { kind: 'none' as const }, malicious: false, summary: 's', aliases: [], modified: 'x', source: { name: 'x', licence: 'y', licenceUrl: 'z' }, recordRead: true };
    const finding = { ...base, via: [{ importer: 'apps/desktop', through: 'llama', dev: false }, { importer: '.', through: 'builder', dev: true }], viaTotal: 5 };
    const { getByTestId } = view(outcome({ findings: [finding] }));
    expect(getByTestId('via').textContent).toBe(`${t('via.label')} apps/desktop ← llama · . ← builder (${t('via.dev')}) · ${t('via.more', { n: 3 })}`);
  });

  it('shows no "pulled by" line when the lockfile gave no graph', () => {
    const finding = { id: 'GHSA-1', ecosystem: 'npm' as const, name: 'tar', version: '7.5.13', severity: 'HIGH' as const, fix: { kind: 'none' as const }, malicious: false, summary: 's', aliases: [], modified: 'x', source: { name: 'x', licence: 'y', licenceUrl: 'z' }, recordRead: true };
    const { queryByTestId } = view(outcome({ findings: [finding] }));
    expect(queryByTestId('via')).toBeNull();
  });

  it('says when the report could not be saved', () => {
    view({ ...outcome({}), reportWritten: false, reportError: 'EACCES' });
    expect(screen.getByText(t('report.notWritten', { why: 'EACCES' }))).toBeTruthy();
  });
});

describe('MirrorCard', () => {
  const idle = (eco: string, installed: object | null = null) => ({ kind: 'ready' as const, state: { ecosystem: eco, phase: 'idle' as const, startedAt: null, done: null, total: null, error: null, last: null, installed: installed as never, unreadable: null } });
  const card = (confirm: { bytes: number | null | undefined; error: string | null } | null, mirrors?: Partial<Record<'npm' | 'PyPI' | 'crates.io', ReturnType<typeof idle>>>, onDownload = vi.fn()) => render(
    <MirrorCard t={t} lang="en" mirrors={{ npm: idle('npm'), PyPI: idle('PyPI'), 'crates.io': idle('crates.io'), ...mirrors }}
      confirm={confirm ? { ecosystem: 'PyPI', ...confirm } : null} scanSource="api" now={0} busy={false}
      onDownload={onDownload} onConfirm={() => {}} onDismiss={() => {}} onUpdate={() => {}} onCancel={() => {}} onUseSource={() => {}} />,
  );

  it('names a failed size read instead of saying the server does not give it', () => {
    card({ bytes: null, error: 'TIMEOUT' });
    expect(screen.getByText(t('base.sizeFailed', { why: 'TIMEOUT' }))).toBeTruthy();
    expect(screen.queryByText(t('base.sizeUnknown'))).toBeNull();
    expect((screen.getByText(t('base.confirm')) as HTMLButtonElement).disabled).toBe(true);
  });

  it('says the server does not give the size only when it answered without one, and offers no download the host would refuse', () => {
    card({ bytes: null, error: null });
    expect(screen.getByText(t('base.sizeUnknown'))).toBeTruthy();
    expect((screen.getByText(t('base.confirm')) as HTMLButtonElement).disabled).toBe(true);
  });

  it('offers each ecosystem its own database, and says one that is absent is scanned online', () => {
    const onDownload = vi.fn();
    const { container } = card(null, { PyPI: idle('PyPI', { records: 17_000, asOf: '2026-10-05T00:00:00Z', newestModified: 'x', sizeBytes: 70_000_000 }) }, onDownload);
    expect(container.textContent!.split(t('base.absent')).length - 1).toBe(2);
    expect(screen.getByText(t('base.useLocal'))).toBeTruthy();
    fireEvent.click(screen.getByText(t('base.download', { ecosystem: 'crates.io' })));
    expect(onDownload).toHaveBeenCalledWith('crates.io');
    expect(screen.queryByText(t('base.download', { ecosystem: 'PyPI' }))).toBeNull();
  });
});

describe('Home', () => {
  const onRemove = vi.fn();
  const lib = (lastScan?: object) => ({ folder: '/lib', ingested: {}, projects: [{ root: '/a', name: 'a', slug: 'a', ...(lastScan ? { lastScan } : {}) }] }) as Parameters<typeof Home>[0]['lib'];
  const home = (l: Parameters<typeof Home>[0]['lib']) => render(
    <Home t={t} lang="en" lib={l} libStatus={{ kind: 'ready' }} job={null} now={0} onAdd={() => {}} onOpen={() => {}} onScan={() => {}} pinned={new Set()} onTogglePin={() => {}} onRemove={onRemove} />,
  );

  it('shows a dash, never a zero, for counts an old summary does not carry', () => {
    home(lib({ at: '2026-10-04T00:00:00Z', complete: true, findings: 3, open: 2, unasked: 0 }));
    expect(screen.getByText(`${t('sev.CRITICAL')} ${t('home.dash')}`)).toBeTruthy();
    expect(screen.queryByText(`${t('sev.CRITICAL')} 0`)).toBeNull();
  });

  it('says "1 project" in the singular', () => {
    home(lib({ at: '2026-10-04T00:00:00Z', complete: true, findings: 3, open: 2, unasked: 0 }));
    expect(screen.getByText(t('home.totalOne', { open: 2 }))).toBeTruthy();
  });

  it('opens the project when the tile itself is clicked, and a tile button keeps its own action', () => {
    const onOpen = vi.fn();
    const onScan = vi.fn();
    render(<Home t={t} lang="en" lib={lib()} libStatus={{ kind: 'ready' }} job={null} now={0} onAdd={() => {}} onOpen={onOpen} onScan={onScan} pinned={new Set()} onTogglePin={() => {}} onRemove={() => {}} />);
    fireEvent.click(screen.getByText('a'));
    expect(onOpen).toHaveBeenCalledWith('/a');
    onOpen.mockClear();
    fireEvent.click(screen.getByText(t('scan.run')));
    expect(onScan).toHaveBeenCalledWith('/a');
    expect(onOpen).not.toHaveBeenCalled();
  });

  it('removes a project only on the second press, after saying what stays on disk', () => {
    onRemove.mockClear();
    home(lib());
    fireEvent.click(screen.getByLabelText(t('home.remove')));
    expect(onRemove).not.toHaveBeenCalled();
    expect(screen.getByText(t('home.removeWhy'))).toBeTruthy();
    fireEvent.click(screen.getByText(t('home.removeConfirm')));
    expect(onRemove).toHaveBeenCalledWith('/a');
  });

  it('never adds a partial scan into the total', () => {
    home(lib({ at: '2026-10-04T00:00:00Z', complete: false, findings: 9, open: 9, unasked: 4 }));
    expect(screen.queryByText(t('home.total', { projects: 1, open: 9 }))).toBeNull();
    expect(screen.getByText(t('home.notCounted', { partial: 1, never: 0 }))).toBeTruthy();
  });
});
