/**
 * ProjectView — one project: the scan button, what the scan measured, and each
 * vulnerability with its fix and its tracked state.
 *
 * The summary line says the MEASURE (versions asked, records read) before any
 * count, and a partial scan says it is partial above the list: a short list
 * from a partial scan must never read as a clean project.
 */
import { useMemo, useState } from 'react';
import type { Lang } from '../i18n/strings';
import { SEVERITY_ORDER, osvUrl } from '../lib/advisory';
import { filterPlans, overviewOf, planAll, type PackagePlan, type PlanOverview, type Place, type PlanFilter } from '../lib/packagePlan';
import type { ProjectRecord } from '../lib/library';
import type { Finding } from '../lib/scan';
import { tally, trackKey, type TrackEntry } from '../lib/tracking';
import { progressOf } from '../lib/progress';
import { Gauge } from './Gauge';
import { S } from './styles';
import { SEVERITY_KEY, SEVERITY_TOKEN, groupFindings, viaLine, type Job, type PackageGroup, type ScanView, type T } from './types';

/** One project's screen. */
export function ProjectView({ t, lang, project, view, job, now, onScan, onStop, onBack, onAccept, onReopen, onOpenUrl }: {
  t: T;
  lang: Lang;
  project: ProjectRecord;
  view: ScanView | undefined;
  job: Job | null;
  now: number;
  onScan: () => void;
  onStop: () => void;
  onBack: () => void;
  onAccept: (id: string, name: string, ecosystem: string, reason: string) => void;
  onReopen: (id: string, name: string, ecosystem: string) => void;
  onOpenUrl: (url: string) => void;
}) {
  const running = job?.root === project.root;
  const outcome = view?.kind === 'done' ? view.outcome : null;
  const date = (iso: string) => new Date(iso).toLocaleString(lang);
  const states = useMemo(() => new Map((outcome?.tracking.entries ?? []).map((e) => [trackKey(e.id, e.name, e.ecosystem), e])), [outcome]);
  const editable = !!outcome && outcome.trackingWritten;
  const grouped = outcome ? groupFindings(outcome.scan.findings) : null;
  const counts = outcome ? tally(outcome.tracking) : null;
  const devCount = outcome ? outcome.scan.findings.filter((f) => f.dev === true).length : 0;
  const [filter, setFilter] = useState<PlanFilter>('all');
  const plans = useMemo(() => (outcome ? planAll(outcome.scan.findings, states) : []), [outcome, states]);
  const shown = filterPlans(plans, filter);
  // Malicious packages with an open record: their own section, but counted in the header too.
  const openMalicious = (grouped?.malicious ?? []).filter((g) => g.findings.some((f) => {
    const st = states.get(trackKey(f.id, f.name, f.ecosystem))?.state;
    return st === undefined || st === 'open';
  })).length;
  /** Brings a package's tile into view; the filter goes back to "all" when it hides that tile. */
  const pickPlan = (p: PackagePlan) => {
    if (!filterPlans(plans, filter).includes(p)) setFilter('all');
    requestAnimationFrame(() => document.getElementById(tileId(p.key))?.scrollIntoView?.({ behavior: 'smooth', block: 'center' }));
  };
  const filters: { id: PlanFilter; key: 'plan.filterAll' | 'plan.filterShipped' | 'plan.filterDev' | 'plan.filterUnknown' }[] = [
    { id: 'all', key: 'plan.filterAll' }, { id: 'shipped', key: 'plan.filterShipped' }, { id: 'dev', key: 'plan.filterDev' },
    // Offered only when some package's place is not stated: an empty chip is noise.
    ...(plans.some((p) => p.place === 'unknown') ? [{ id: 'unknown' as const, key: 'plan.filterUnknown' as const }] : []),
  ];

  return (
    <>
      <button style={S.link} onClick={onBack}>{t('nav.back')}</button>
      <section style={S.card}>
        <div style={S.row}>
          <div style={{ minWidth: 0 }}>
            <h2 style={S.h2}>{project.name}</h2>
            <div style={{ ...S.small, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={project.root}>{project.root}</div>
          </div>
          {running
            ? <button style={S.ghost} onClick={onStop}>{t('scan.stop')}</button>
            : <button style={S.button} disabled={!!job} onClick={onScan}>{outcome || project.lastScan ? t('scan.again') : t('scan.run')}</button>}
        </div>

        {running && (
          <div style={S.small} role="status">
            {job!.progress
              ? t(job!.progress.phase === 'asking' ? 'scan.asking' : 'scan.records', { done: job!.progress.done, total: job!.progress.total })
              : '…'}
            {' · '}{t('scan.elapsed', { s: Math.max(0, Math.round((now - job!.startedAt) / 1000)) })}
          </div>
        )}

        {!view && !running && project.lastScan && (
          <div style={S.small}>
            {project.lastScan.complete
              ? t('proj.last', { date: date(project.lastScan.at), n: project.lastScan.findings, open: project.lastScan.open })
              : t('home.lastPartial', { date: date(project.lastScan.at), n: project.lastScan.findings })}
          </div>
        )}

        {outcome?.fromDisk && <div style={S.small}>{t('proj.saved', { date: date(outcome.scan.at) })}</div>}

        {view?.kind === 'failed' && (
          <div style={S.error} role="alert">
            {t(`fail.${view.failure.code}`, {
              why: 'why' in view.failure ? view.failure.why : '',
              file: 'file' in view.failure ? view.failure.file : '',
            })}
          </div>
        )}

        {outcome && (
          <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', alignItems: 'flex-start' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: '1 1 420px', minWidth: 0 }}>
            <div style={S.small}>{t('sum.lockfile', { file: outcome.scan.lockfiles.join(', '), date: date(outcome.scan.at) })}</div>
            {outcome.scan.sources.map((s) => (
              <div key={s.ecosystem} style={S.small}>
                {s.ecosystem} · {s.kind === 'mirror' && s.asOf ? t('sum.mirror', { date: date(s.asOf) }) : t('sum.online')}
              </div>
            ))}
            {outcome.lockFailures.map((f) => (
              <div key={'file' in f ? f.file : f.code} style={S.error}>
                {t(`fail.${f.code}`, { why: 'why' in f ? f.why : '', file: 'file' in f ? f.file : '' })}
              </div>
            ))}
            {!outcome.scan.complete && (
              <div style={S.error} role="alert">
                {t('sum.partial', { unasked: outcome.scan.unasked, unread: outcome.scan.recordsUnread })}
                {outcome.scan.error ? ` ${t('sum.error', { why: outcome.scan.error })}` : ''}
              </div>
            )}
            <div style={{ fontWeight: 600 }}>
              {outcome.scan.findings.length === 0 && outcome.scan.complete
                ? t('sum.clean', { asked: outcome.scan.asked })
                : t('sum.found', { n: outcome.scan.findings.length, asked: outcome.scan.asked })}
            </div>
            {outcome.scan.skipped > 0 && <div style={S.small}>{t('sum.skipped', { n: outcome.scan.skipped })}</div>}
            {devCount > 0 && <div style={S.small}>{t('sum.dev', { n: devCount })}</div>}
            {outcome.scan.recordsFromCache > 0 && <div style={S.small}>{t('sum.cache', { n: outcome.scan.recordsFromCache })}</div>}
            {outcome.vault && <div style={S.small}>{t('vault.result', outcome.vault)}</div>}
            {outcome.trackingError && (
              <div style={S.error}>
                {outcome.trackingWritten ? t('track.notWritten', { why: outcome.trackingError }) : t('track.unreadable', { why: outcome.trackingError })}
              </div>
            )}
            {outcome.reportError && <div style={S.error}>{t('report.notWritten', { why: outcome.reportError })}</div>}
            {counts && <Gauge t={t} progress={progressOf(counts)} />}
            {counts && (counts.fixed > 0 || counts.withdrawn > 0) && (
              <div style={S.small}>{t('track.history', { fixed: counts.fixed, withdrawn: counts.withdrawn })}</div>
            )}
          </div>
          {(plans.length > 0 || openMalicious > 0) && <Overview t={t} o={overviewOf(plans, { openMalicious })} onPick={pickPlan} />}
          </div>
        )}
      </section>

      {grouped && grouped.malicious.length > 0 && (
        <section style={{ ...S.card, borderColor: 'var(--danger, var(--accent))' }}>
          <h2 style={S.h2}>{t('group.malicious')}</h2>
          {grouped.malicious.map((g) => <Group key={g.key} {...{ t, g, states, editable, onAccept, onReopen, onOpenUrl }} />)}
        </section>
      )}
      {plans.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={S.p}>{t('plan.lead', { n: plans.filter((p) => p.open > 0).length + openMalicious })}</div>
          <div role="group" aria-label={t('plan.filterLabel')} style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {filters.map((f) => (
              <button key={f.id} style={{ ...S.ghost, ...(filter === f.id ? S.iconOn : {}) }} aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>
                {t(f.key, { n: filterPlans(plans, f.id).length })}
              </button>
            ))}
          </div>
        </div>
      )}
      {plans.length > 0 && shown.length === 0 && <div style={S.small}>{t('plan.empty')}</div>}
      {shown.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 12, alignItems: 'start' }} data-testid="package-grid">
          {shown.map((p) => (
            <PackageCard key={p.key} {...{ t, p, findings: grouped?.packages.find((g) => g.key === p.key)?.findings ?? [], states, editable, onAccept, onReopen, onOpenUrl }} />
          ))}
        </div>
      )}
    </>
  );
}

function Group({ t, g, states, editable, onAccept, onReopen, onOpenUrl }: {
  t: T;
  g: PackageGroup;
  states: Map<string, TrackEntry>;
  editable: boolean;
  onAccept: (id: string, name: string, ecosystem: string, reason: string) => void;
  onReopen: (id: string, name: string, ecosystem: string) => void;
  onOpenUrl: (url: string) => void;
}) {
  // One row per record: the same record on two versions is shown once, with both versions.
  const seen = new Set<string>();
  const rows = g.findings.filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)));
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ fontWeight: 600 }}>{t('group.versions', { name: g.ecosystem === 'npm' ? g.name : `${g.name} (${g.ecosystem})`, versions: g.versions.join(', ') })}</div>
      <ul style={{ ...S.list, gap: 10 }}>
        {rows.map((f) => (
          <Row key={f.id} {...{ t, f, entry: states.get(trackKey(f.id, f.name, f.ecosystem)), editable, onAccept, onReopen, onOpenUrl }} />
        ))}
      </ul>
    </div>
  );
}

function Row({ t, f, versions, entry, editable, onAccept, onReopen, onOpenUrl }: {
  t: T;
  f: Finding;
  /** In a package card: the versions this record touches; the card already says where each one is. */
  versions?: string[];
  entry: TrackEntry | undefined;
  editable: boolean;
  onAccept: (id: string, name: string, ecosystem: string, reason: string) => void;
  onReopen: (id: string, name: string, ecosystem: string) => void;
  onOpenUrl: (url: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [reason, setReason] = useState('');
  const fix = f.fix.kind === 'fixed' ? t('fix.fixed', { version: f.fix.version })
    : f.fix.kind === 'none' ? t('fix.none')
      : f.fix.kind === 'see' ? t('fix.see')
        : t('fix.unknown');
  return (
    <li style={{ display: 'flex', flexDirection: 'column', gap: 3, borderTop: '1px solid var(--border-subtle)', paddingTop: 6 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'baseline' }}>
        <span style={{ color: SEVERITY_TOKEN[f.severity], fontWeight: 600 }}>{t(SEVERITY_KEY[f.severity])}</span>
        <button style={S.link} onClick={() => onOpenUrl(osvUrl(f.id))}>{f.id}</button>
        {f.aliases.length > 0 && <span style={S.small}>{f.aliases.join(', ')}</span>}
        {entry && <span style={S.small}>· {t(`state.${entry.state}`)}</span>}
        {versions
          ? <span style={S.small}>· {t('plan.versionsOf', { versions: versions.join(', ') })}</span>
          : f.dev === true && <span style={S.small} title={t('dev.why')}>· {t('dev.label')}</span>}
      </div>
      <div style={S.p}>{f.recordRead ? (f.summary ?? '') : t('record.unread')}</div>
      <div style={S.small}>{fix} · {t('record.source', { source: f.source.name, licence: f.source.licence })}</div>
      {!versions && f.via && f.via.length > 0 && (
        <div style={S.small} title={t('via.why')} data-testid="via">
          {viaLine(t, f.via, f.viaTotal)}
        </div>
      )}
      {entry?.state === 'accepted' && entry.reason && <div style={S.small}>{t('track.because', { reason: entry.reason })}</div>}
      {entry?.state === 'open' && !editing && (
        <button style={S.link} disabled={!editable} title={editable ? undefined : t('track.locked')} onClick={() => setEditing(true)}>{t('track.accept')}</button>
      )}
      {entry?.state === 'accepted' && (
        <button style={S.link} disabled={!editable} title={editable ? undefined : t('track.locked')} onClick={() => onReopen(f.id, f.name, f.ecosystem)}>{t('track.reopen')}</button>
      )}
      {editing && (
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <input style={{ ...S.input, flex: 1, minWidth: 200 }} placeholder={t('track.reason')} aria-label={t('track.reason')} value={reason} onChange={(e) => setReason(e.target.value)} />
          <button style={S.ghost} disabled={!reason.trim()} onClick={() => { onAccept(f.id, f.name, f.ecosystem, reason); setEditing(false); setReason(''); }}>{t('track.confirm')}</button>
          <button style={S.link} onClick={() => { setEditing(false); setReason(''); }}>{t('track.cancel')}</button>
        </div>
      )}
    </li>
  );
}

/** The DOM id of a package tile, for the header's shortcuts. */
const tileId = (key: string) => `pkg-${key.replace(/[^A-Za-z0-9_-]/g, '_')}`;

const PLACE: Record<Place, { label: 'plan.shipped' | 'plan.dev' | 'plan.unknown'; why: 'plan.shippedWhy' | 'plan.devWhy' | 'plan.unknownWhy'; color: string }> = {
  shipped: { label: 'plan.shipped', why: 'plan.shippedWhy', color: 'var(--danger, var(--accent))' },
  dev: { label: 'plan.dev', why: 'plan.devWhy', color: 'var(--text-muted)' },
  unknown: { label: 'plan.unknown', why: 'plan.unknownWhy', color: 'var(--text-muted)' },
};

/** Where a version goes: shipped, development only, or not stated. */
function PlaceBadge({ t, place }: { t: T; place: Place }) {
  const p = PLACE[place];
  return (
    <span title={t(p.why)} style={{ fontSize: 11, fontWeight: 600, color: p.color, border: `1px solid color-mix(in srgb, ${p.color} 45%, transparent)`, borderRadius: 999, padding: '1px 8px', whiteSpace: 'nowrap' }}>
      {t(p.label)}
    </span>
  );
}

/** One package: what to do first (the version to move to), where each installed version is, then the records. */
function PackageCard({ t, p, findings, states, editable, onAccept, onReopen, onOpenUrl }: {
  t: T;
  p: PackagePlan;
  findings: Finding[];
  states: Map<string, TrackEntry>;
  editable: boolean;
  onAccept: (id: string, name: string, ecosystem: string, reason: string) => void;
  onReopen: (id: string, name: string, ecosystem: string) => void;
  onOpenUrl: (url: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const seen = new Set<string>();
  const rows = findings.filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)));
  const versionsOf = (id: string) => [...new Set(findings.filter((f) => f.id === id).map((f) => f.version))].sort();
  const settled = p.open === 0;
  return (
    <section
      style={{ ...S.card, padding: 12, gap: 7, borderLeft: `3px solid ${settled ? 'var(--border-subtle)' : SEVERITY_TOKEN[p.worst]}`, opacity: settled ? 0.75 : 1, minWidth: 0, ...(open ? { gridColumn: '1 / -1' } : {}) }}
      data-testid="package-card"
      id={tileId(p.key)}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'baseline' }}>
        <div style={{ display: 'flex', gap: 6, alignItems: 'baseline', minWidth: 0 }}>
          <span style={{ fontSize: 15, fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={p.name}>
            {p.ecosystem === 'npm' ? p.name : `${p.name} (${p.ecosystem})`}
          </span>
          <PlaceBadge t={t} place={p.place} />
        </div>
        <span style={{ ...S.small, whiteSpace: 'nowrap' }} title={t('plan.records', { n: p.records })}>
          {p.open === 1 ? t('plan.open1') : t('plan.open', { n: p.open })}{p.accepted > 0 ? ` · ${t('plan.accepted', { n: p.accepted })}` : ''}
        </span>
      </div>

      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
        {SEVERITY_ORDER.filter((s) => p.bySeverity[s] > 0).map((s) => (
          <span key={s} style={{ fontSize: 11, color: SEVERITY_TOKEN[s], background: `color-mix(in srgb, ${SEVERITY_TOKEN[s]} 12%, transparent)`, borderRadius: 5, padding: '1px 6px' }}>
            {p.bySeverity[s]} {t(SEVERITY_KEY[s])}
          </span>
        ))}
      </div>

      {(p.target || p.closes > 0 || p.noFix > 0 || p.unknownFix > 0) && (
        <div style={{ background: 'color-mix(in srgb, var(--accent) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--accent) 30%, transparent)', borderRadius: 8, padding: '5px 9px', display: 'flex', flexDirection: 'column', gap: 1 }} data-testid="plan-action">
          {p.target
            ? <div><strong>⬆ {t('plan.upgrade', { version: p.target })}</strong> <span style={S.small}>{t('plan.closes', { n: p.closes, total: p.records })}</span></div>
            : p.closes > 0 && <div style={S.small}>{t('plan.unordered')}</div>}
          {p.noFix > 0 && <div style={S.small}>{t('plan.noFix', { n: p.noFix })}</div>}
          {p.unknownFix > 0 && <div style={S.small}>{t('plan.unknownFix', { n: p.unknownFix })}</div>}
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }} aria-label={t('plan.versions')}>
        {p.versions.map((v) => {
          const via = v.via && v.via.length > 0
            ? viaLine(t, v.via, v.viaTotal)
            : null;
          return (
            <div key={v.version} style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }} data-testid="plan-version">
              <div style={{ display: 'flex', gap: 6, alignItems: 'baseline', flexWrap: 'wrap', fontSize: 13 }}>
                <span style={{ fontFamily: 'var(--font-mono, monospace)', fontWeight: 600 }}>{v.version}</span>
                {v.target && <span style={S.small}>→ {v.target}</span>}
                <PlaceBadge t={t} place={v.place} />
                <span style={S.small}>{v.records === 1 ? t('plan.records1') : t('plan.records', { n: v.records })}</span>
              </div>
              {via && (
                <div style={{ ...S.small, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: open ? 'normal' : 'nowrap' }} title={`${via}\n\n${t('via.why')}`} data-testid="via">
                  {via}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <button style={{ ...S.link, fontSize: 12 }} aria-expanded={open} onClick={() => setOpen(!open)}>
        {open ? `▾ ${t('plan.hide')}` : `▸ ${rows.length === 1 ? t('plan.show1') : t('plan.show', { n: rows.length })}`}
      </button>
      {open && (
        <ul style={{ ...S.list, gap: 10 }}>
          {rows.map((f) => (
            <Row key={f.id} {...{ t, f, versions: versionsOf(f.id), entry: states.get(trackKey(f.id, f.name, f.ecosystem)), editable, onAccept, onReopen, onOpenUrl }} />
          ))}
        </ul>
      )}
    </section>
  );
}

/** The header's right column: open records by severity, where they are, and the first upgrades to make. */
function Overview({ t, o, onPick }: { t: T; o: PlanOverview; onPick: (p: PackagePlan) => void }) {
  return (
    <div
      style={{ flex: '1 1 300px', minWidth: 0, display: 'flex', flexDirection: 'column', gap: 10, padding: 12, borderRadius: 12, background: 'color-mix(in srgb, var(--text-primary) 4%, transparent)', border: '1px solid color-mix(in srgb, var(--text-primary) 10%, transparent)' }}
      data-testid="overview"
    >
      {o.openMalicious > 0 && (
        <div style={{ ...S.error, fontWeight: 600 }}>{t('over.malicious', { n: o.openMalicious })}</div>
      )}
      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        {SEVERITY_ORDER.filter((s) => o.openBySeverity[s] > 0).map((s) => (
          <div key={s} style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.1 }}>
            <span style={{ fontSize: 24, fontWeight: 700, color: SEVERITY_TOKEN[s] }}>{o.openBySeverity[s]}</span>
            <span style={S.small}>{t(SEVERITY_KEY[s])}</span>
          </div>
        ))}
      </div>
      <div style={S.small}>
        <span style={{ color: 'var(--danger, var(--accent))' }}>{t('over.shipped', { n: o.openShipped })}</span> · {t('over.dev', { n: o.openDev })}
        {o.openUnknown > 0 && <> · {t('over.unknown', { n: o.openUnknown })}</>}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <div style={{ ...S.small, textTransform: 'uppercase', letterSpacing: 0.6 }}>{t('over.title')}</div>
        {o.start.length === 0 && <div style={S.small}>{t('over.none')}</div>}
        {o.start.map((p, i) => (
          <button
            key={p.key}
            onClick={() => onPick(p)}
            style={{ ...S.ghost, display: 'flex', alignItems: 'baseline', gap: 8, textAlign: 'left', padding: '5px 10px', borderLeft: `3px solid ${SEVERITY_TOKEN[p.worst]}` }}
          >
            <span style={S.small}>{i + 1}.</span>
            <strong style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.name}</strong>
            <span style={{ fontFamily: 'var(--font-mono, monospace)' }}>→ {p.target}</span>
            <span style={{ ...S.small, marginLeft: 'auto', whiteSpace: 'nowrap' }}>{t('over.closes', { n: p.closes })}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
