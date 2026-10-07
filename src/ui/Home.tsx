/**
 * Home — every project the person added, as a tile with what its last scan
 * measured, and one strip that sums the last COMPLETE scans.
 *
 * A partial scan is never added into the total: it would make the total look
 * smaller than it is. A summary written before the per-severity counts existed
 * shows dashes, never zeros nobody measured.
 */
import { useState } from 'react';
import type { Lang } from '../i18n/strings';
import { SEVERITY_ORDER } from '../lib/advisory';
import type { LibraryState, LibStatus, ProjectRecord } from '../lib/library';
import { progressOf } from '../lib/progress';
import { cardId } from '../lib/cards';
import { Gauge } from './Gauge';
import { S } from './styles';
import { SEVERITY_KEY, SEVERITY_TOKEN, homeTotals, type Job, type T } from './types';

/** The home: totals, the add button, and one tile per project. */
export function Home({ t, lang, lib, libStatus, job, now, onAdd, onOpen, onScan, pinned, onTogglePin, onRemove }: {
  t: T;
  lang: Lang;
  lib: LibraryState;
  libStatus: LibStatus;
  job: Job | null;
  now: number;
  onAdd: () => void;
  onOpen: (root: string) => void;
  onScan: (root: string) => void;
  /** Card ids the host keeps pinned on the canvas. */
  pinned: ReadonlySet<string>;
  onTogglePin: (root: string) => void;
  onRemove: (root: string) => void;
}) {
  const projects = [...lib.projects].sort((a, b) => a.name.localeCompare(b.name));
  const totals = homeTotals(projects);
  return (
    <>
      <section style={S.card}>
        <p style={S.p}>{t('home.lead')}</p>
        {totals.counted > 0 && <div style={{ fontWeight: 600 }}>{totals.counted === 1 ? t('home.totalOne', { open: totals.open }) : t('home.total', { projects: totals.counted, open: totals.open })}</div>}
        {(totals.partial > 0 || totals.never > 0) && projects.length > 0 && (
          <div style={S.small}>{t('home.notCounted', { partial: totals.partial, never: totals.never })}</div>
        )}
        <button style={S.button} disabled={!!job || libStatus.kind !== 'ready'} onClick={onAdd}>{t('home.add')}</button>
        {libStatus.kind === 'ready' && projects.length === 0 && <div style={S.small}>{t('home.none')}</div>}
      </section>

      {projects.length > 0 && (
        <div style={S.grid}>
          {projects.map((p) => <Tile key={p.root} {...{ t, lang, p, job, now, onOpen, onScan }} pinnedCard={pinned.has(cardId(p))} onTogglePin={onTogglePin} onRemove={onRemove} />)}
        </div>
      )}
    </>
  );
}

function Tile({ t, lang, p, job, now, onOpen, onScan, pinnedCard, onTogglePin, onRemove }: {
  t: T;
  lang: Lang;
  p: ProjectRecord;
  job: Job | null;
  now: number;
  onOpen: (root: string) => void;
  onScan: (root: string) => void;
  pinnedCard: boolean;
  onTogglePin: (root: string) => void;
  onRemove: (root: string) => void;
}) {
  // Removing takes two presses: the first only arms it and says what stays on disk.
  const [arming, setArming] = useState(false);
  const running = job?.root === p.root;
  const s = p.lastScan;
  const date = (iso: string) => new Date(iso).toLocaleString(lang);
  const stop = (e: { stopPropagation: () => void }) => e.stopPropagation();
  // The worst open severity colours the tile's edge; nothing measured, no colour.
  const worst = s?.openBySeverity ? SEVERITY_ORDER.find((k) => (s.openBySeverity![k] ?? 0) > 0) : undefined;
  const stripe = worst ? SEVERITY_TOKEN[worst] : 'var(--border-subtle)';
  return (
    <div className="mv-tile" style={{ ...S.tile, borderLeft: `3px solid ${stripe}` }} onClick={() => { if (!arming) onOpen(p.root); }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
        <div style={{ ...S.tileName, flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>{p.name}</div>
        {!arming && (
          <button style={S.icon} disabled={running} title={t('home.remove')} aria-label={t('home.remove')} onClick={(e) => { stop(e); setArming(true); }}>
            <TrashIcon />
          </button>
        )}
      </div>
      <div style={{ ...S.small, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={p.root}>{p.root}</div>
      <div style={S.small}>{!s ? t('home.never') : s.complete ? t('home.tileDate', { date: date(s.at) }) : t('home.tilePartial', { date: date(s.at) })}</div>

      {s && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {SEVERITY_ORDER.filter((k) => k !== 'UNKNOWN' || (s.openBySeverity?.UNKNOWN ?? 0) > 0).map((k) => (
            <span key={k} style={{ fontSize: 12, color: SEVERITY_TOKEN[k] }}>
              {t(SEVERITY_KEY[k])} {s.openBySeverity ? s.openBySeverity[k] : t('home.dash')}
            </span>
          ))}
        </div>
      )}
      {s && (
        <div style={S.small}>
          {[
            t('home.tileOpen', { n: s.open }),
            t('home.tileAccepted', { n: s.accepted ?? t('home.dash') }),
            t('home.tileFixed', { n: s.fixed ?? t('home.dash') }),
          ].join(' · ')}
        </div>
      )}

      {s && (s.newUrgent ?? 0) > 0 && <div style={{ ...S.small, color: SEVERITY_TOKEN.CRITICAL, fontWeight: 600 }}>{t('home.fresh', { n: s.newUrgent! })}</div>}
      {s && <Gauge t={t} progress={progressOf(s)} />}

      {running && (
        <div style={S.small} role="status">
          {job!.progress
            ? t(job!.progress.phase === 'asking' ? 'scan.asking' : 'scan.records', { done: job!.progress.done, total: job!.progress.total })
            : '…'}
          {' · '}{t('scan.elapsed', { s: Math.max(0, Math.round((now - job!.startedAt) / 1000)) })}
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, marginTop: 'auto', alignItems: 'center' }}>
        <button style={{ ...S.ghost, whiteSpace: 'nowrap' }} onClick={(e) => { stop(e); onOpen(p.root); }}>{t('home.open')}</button>
        <button style={{ ...S.ghost, whiteSpace: 'nowrap' }} disabled={!!job} onClick={(e) => { stop(e); onScan(p.root); }}>{s ? t('scan.rescan') : t('scan.run')}</button>
        {s && (
          <button
            style={{ ...S.icon, marginLeft: 'auto', ...(pinnedCard ? S.iconOn : null) }}
            aria-pressed={pinnedCard}
            title={pinnedCard ? t('card.unpin') : t('card.pin')}
            aria-label={pinnedCard ? t('card.unpin') : t('card.pin')}
            onClick={(e) => { stop(e); onTogglePin(p.root); }}
          >
            <PinIcon />
          </button>
        )}
      </div>
      {arming && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }} role="alertdialog" aria-label={t('home.remove')}>
          <div style={S.small}>{t('home.removeWhy')}</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button style={S.ghost} disabled={running} onClick={(e) => { stop(e); setArming(false); onRemove(p.root); }}>{t('home.removeConfirm')}</button>
            <button style={S.ghost} onClick={(e) => { stop(e); setArming(false); }}>{t('track.cancel')}</button>
          </div>
        </div>
      )}
    </div>
  );
}

/** A pin, drawn inline (the cartridge carries no icon library). */
function PinIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 17v5" />
      <path d="M9 10.8V4h6v6.8l2.6 3.2a1 1 0 0 1-.8 1.6H7.2a1 1 0 0 1-.8-1.6z" />
    </svg>
  );
}

/** A bin, drawn inline. */
function TrashIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M3 6h18" />
      <path d="M8 6V4h8v2" />
      <path d="M19 6l-1 14H6L5 6" />
    </svg>
  );
}
