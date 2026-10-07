/**
 * MirrorCard — the local databases, one row per ecosystem (npm, PyPI,
 * crates.io): download one, update it by delta, replace it, and choose whether
 * scans read them or OSV.dev online.
 *
 * The size of a download is shown BEFORE the gesture, read from the server.
 * A job shows what it measured (bytes, records) and a clock, never a
 * percentage of a total it does not have. An ecosystem without its database
 * is still scanned, online: the project view says which source answered each
 * ecosystem.
 */
import type { Lang } from '../i18n/strings';
import { MIRROR_ECOSYSTEMS as ECOSYSTEMS, type MirrorEcosystem as Ecosystem } from '../lib/lockfile';
import { S } from './styles';
import { formatMb, type MirrorState, type MirrorView, type T } from './types';

/** A download waiting for its confirm: the size read from the server, or why it could not be read. */
export interface MirrorConfirm {
  ecosystem: Ecosystem;
  /** Undefined while asking, null when the server does not say. */
  bytes: number | null | undefined;
  /** Why the size could not be read (the server was not reached); null otherwise. */
  error: string | null;
}

interface RowProps {
  t: T;
  lang: Lang;
  now: number;
  busy: boolean;
  onDownload: (e: Ecosystem) => void;
  onConfirm: (e: Ecosystem) => void;
  onDismiss: () => void;
  onUpdate: (e: Ecosystem) => void;
  onCancel: (e: Ecosystem) => void;
}

/** The local database card on the home. */
export function MirrorCard({ t, lang, mirrors, confirm, scanSource, now, busy, onUseSource, ...actions }: Omit<RowProps, 'busy'> & {
  mirrors: Record<Ecosystem, MirrorView>;
  confirm: MirrorConfirm | null;
  scanSource: 'api' | 'mirror';
  busy: boolean;
  onUseSource: (s: 'api' | 'mirror') => void;
}) {
  const views = ECOSYSTEMS.map((e) => mirrors[e]);
  if (views.some((v) => v.kind === 'loading')) return null;
  const denied = views.find((v): v is Extract<MirrorView, { kind: 'error' }> => v.kind === 'error');
  if (denied && views.every((v) => v.kind === 'error')) {
    return (
      <section style={S.card}>
        <h2 style={S.h2}>{t('base.title')}</h2>
        <div style={S.small}>{t('base.denied', { why: denied.why })}</div>
      </section>
    );
  }
  const anyInstalled = views.some((v) => v.kind === 'ready' && v.state.installed);

  return (
    <section style={S.card}>
      <h2 style={S.h2}>{t('base.title')}</h2>
      {anyInstalled ? (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }} role="radiogroup">
          <button style={scanSource === 'mirror' ? S.button : S.ghost} aria-pressed={scanSource === 'mirror'} disabled={busy} onClick={() => onUseSource('mirror')}>{t('base.useLocal')}</button>
          <button style={scanSource === 'api' ? S.button : S.ghost} aria-pressed={scanSource === 'api'} disabled={busy} onClick={() => onUseSource('api')}>{t('base.useOnline')}</button>
        </div>
      ) : (
        <div style={S.p}>{t('base.none')}</div>
      )}
      {ECOSYSTEMS.map((e) => {
        const v = mirrors[e];
        return (
          <div key={e} style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
            {v.kind === 'error'
              ? <div style={S.small}><strong>{e}</strong> · {t('base.denied', { why: v.why })}</div>
              : v.kind === 'ready' && <Row {...actions} t={t} lang={lang} now={now} busy={busy} st={v.state} ecosystem={e} confirm={confirm?.ecosystem === e ? confirm : null} />}
          </div>
        );
      })}
    </section>
  );
}

function Row({ t, lang, now, busy, st, ecosystem, confirm, onDownload, onConfirm, onDismiss, onUpdate, onCancel }: RowProps & {
  st: MirrorState;
  ecosystem: Ecosystem;
  confirm: MirrorConfirm | null;
}) {
  const running = st.phase !== 'idle';
  const date = (iso: string) => new Date(iso).toLocaleString(lang);
  const n = (x: number) => x.toLocaleString(lang);
  const clock = st.startedAt ? ` · ${t('scan.elapsed', { s: Math.max(0, Math.round((now - st.startedAt) / 1000)) })}` : '';

  let progress: string | null = null;
  if (st.phase === 'downloading') {
    progress = st.done !== null && st.total !== null ? t('base.downloading', { done: formatMb(st.done, lang), total: formatMb(st.total, lang) }) : '…';
  } else if (st.phase === 'building') {
    progress = st.done !== null && st.total !== null ? t('base.building', { done: n(st.done), total: n(st.total) }) : t('base.buildingStart');
  } else if (st.phase === 'updating') {
    progress = st.done !== null && st.total !== null ? t('base.updating', { done: n(st.done), total: n(st.total) }) : t('base.updatingStart');
  }

  const tooLarge = st.error?.startsWith('DELTA_TOO_LARGE:') ? st.error.split(':')[1] : null;
  const errorLine = !st.error ? null
    : st.error === 'CANCELLED' ? t('base.cancelled')
      : tooLarge ? t('base.tooLarge', { n: tooLarge })
        : t('base.failed', { why: st.error });
  const lastLine = !st.last || st.error ? null
    : st.last.kind === 'built' ? t('base.lastBuilt', { n: n(st.last.count) })
      : st.last.kind === 'updated' ? t('base.lastUpdated', { n: n(st.last.count) })
        : t('base.lastUpToDate');

  return (
    <>
      {st.unreadable && <div style={S.error}>{t('base.unreadable', { why: st.unreadable })}</div>}

      {st.installed ? (
        <>
          <div style={S.p}>
            <strong>{ecosystem}</strong>{' · '}
            {t('base.installed', {
              records: n(st.installed.records),
              date: date(st.installed.asOf),
              size: st.installed.sizeBytes !== null ? formatMb(st.installed.sizeBytes, lang) : t('home.dash'),
            })}
          </div>
          {!running && (
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <button style={S.link} disabled={busy} onClick={() => onUpdate(ecosystem)}>{t('base.update', { date: date(st.installed.asOf) })}</button>
              <button style={S.link} disabled={busy} onClick={() => onDownload(ecosystem)}>{t('base.replace')}</button>
            </div>
          )}
        </>
      ) : (
        <div style={{ ...S.row, justifyContent: 'flex-start', gap: 12 }}>
          <span style={S.p}><strong>{ecosystem}</strong>{' · '}{t('base.absent')}</span>
          {!running && !confirm && <button style={S.ghost} disabled={busy} onClick={() => onDownload(ecosystem)}>{t('base.download', { ecosystem })}</button>}
        </div>
      )}

      {confirm && !running && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }} role="dialog" aria-label={t('base.download', { ecosystem })}>
          <div style={S.small}>
            {confirm.error ? t('base.sizeFailed', { why: confirm.error }) : confirm.bytes === undefined ? '…' : confirm.bytes !== null ? t('base.size', { size: formatMb(confirm.bytes, lang) }) : t('base.sizeUnknown')}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button style={S.button} disabled={busy || confirm.bytes == null || !!confirm.error} onClick={() => onConfirm(ecosystem)}>{t('base.confirm')}</button>
            <button style={S.ghost} onClick={onDismiss}>{t('track.cancel')}</button>
          </div>
        </div>
      )}

      {running && (
        <div style={{ ...S.row, justifyContent: 'flex-start', gap: 12 }} role="status">
          <span style={S.small}>{progress}{clock}</span>
          <button style={S.ghost} onClick={() => onCancel(ecosystem)}>{t('base.cancel')}</button>
        </div>
      )}
      {!running && errorLine && <div style={S.error}>{errorLine}</div>}
      {!running && lastLine && <div style={S.small}>{lastLine}</div>}
    </>
  );
}
