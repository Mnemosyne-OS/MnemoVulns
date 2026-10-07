/**
 * MnemoVulns (doc 135 §3sexies, lot 1): the known vulnerabilities of a
 * project, from its lockfile and OSV.dev, kept in memory and tracked from one
 * scan to the next.
 *
 * Built on MnemoHealth's shape: the host calls live here, the screens only
 * draw and call back. Nothing is fetched before a gesture.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { MnemoCartridgeSDK } from './sdk/mnemo-sdk';
import { useI18n } from './i18n/useI18n';
import { translate } from './i18n/strings';
import {
  EMPTY_LIBRARY, capIngested, parseLibrary, persistLibrary, projectFor, withProject, withoutProject,
  type LibStatus, type LibraryState,
} from './lib/library';
import { loadSavedScan, saveTracking, scanProject, summaryOf, type HostPort } from './lib/project';
import { apiSource } from './lib/osv';
import { MIRROR_ECOSYSTEMS, type Ecosystem, type MirrorEcosystem } from './lib/lockfile';
import { mirrorSource } from './lib/mirror';
import { MirrorCard, type MirrorConfirm } from './ui/MirrorCard';
import { cardId, OPENED_RECENT_MS, projectCard, projectOfCard, sameMembers, type CardWords } from './lib/cards';
import { accept, reopen, type Tracking } from './lib/tracking';
import { useClock } from './lib/useClock';
import { S } from './ui/styles';
import { Home } from './ui/Home';
import { ProjectView } from './ui/ProjectView';
import { Footer } from './ui/Footer';
import type { Job, MirrorState, MirrorView, ScanView, View } from './ui/types';

// Must match "name" in mnemo-plugin.json: the host keys the Memory Pack and its folder on it.
const sdk = new MnemoCartridgeSDK('@mnemosyne-plugins/mnemo-vulns');

/** A chronicle write is a local IPC; 15 s is the house default (rule 9). */
const INGEST_TIMEOUT_MS = 15_000;
const HOST_TIMEOUT_MS = 15_000;

/**
 * The one Memory Pack MnemoVulns writes to (host doc 135 §6.6). One pack, not
 * one per ecosystem: the records come from one source (OSV.dev), sit in one
 * `records/` folder, and a record can name packages of several ecosystems.
 * Lexical only: people look records up by id, package name and version.
 */
const PACK = 'osv';

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

const port: HostPort = {
  readDir: (dir) => sdk.readDir(dir),
  readFile: (path) => sdk.readFile(path),
  writeFile: (path, content) => sdk.writeFile(path, content),
  // Read like MnemoHealth: only an explicit `success: false` is a failure.
  mkdir: async (dirPath) => {
    const made = await sdk.invoke<{ success?: boolean; error?: string }>('dialog.mkdir', { dirPath }, HOST_TIMEOUT_MS);
    return { success: made?.success !== false, ...(made?.error ? { error: made.error } : {}) };
  },
  ingest: async (entry) => {
    await sdk.invoke('mnemosyne.ingest', entry, INGEST_TIMEOUT_MS);
  },
};

const fetcher = (url: string, init?: RequestInit) => fetch(url, init);

/** A host query of the local mirror. 60 s: the first call reads the 20 MB index from disk. */
const MIRROR_QUERY_TIMEOUT_MS = 60_000;
/** How often the home asks the host where a download, build or update stands. */
const MIRROR_POLL_MS = 1_000;

/** The host mirror of one ecosystem, as the scan asks it. */
const mirrorPortFor = (ecosystem: Ecosystem) => ({
  query: (names: string[]) => sdk.invoke<{ asOf: string; records: unknown[] }>('vulns.mirrorQuery', { names, ecosystem }, MIRROR_QUERY_TIMEOUT_MS),
});

const eachEcosystem = <V,>(v: V): Record<MirrorEcosystem, V> => Object.fromEntries(MIRROR_ECOSYSTEMS.map((e) => [e, v])) as Record<MirrorEcosystem, V>;

export default function App() {
  const { t, lang } = useI18n();
  const [view, setView] = useState<View>({ kind: 'home' });
  const [lib, setLib] = useState<LibraryState>(EMPTY_LIBRARY);
  const [libStatus, setLibStatus] = useState<LibStatus>({ kind: 'loading' });
  const [scans, setScans] = useState<Record<string, ScanView>>({});
  const [job, setJob] = useState<Job | null>(null);
  const [notice, setNotice] = useState<string[]>([]);
  const [mirrors, setMirrors] = useState<Record<MirrorEcosystem, MirrorView>>(() => eachEcosystem<MirrorView>({ kind: 'loading' }));
  const [confirm, setConfirm] = useState<MirrorConfirm | null>(null);
  // The host owns which cards are pinned; this is its last answer, never a copy kept apart.
  const [pinned, setPinned] = useState<ReadonlySet<string>>(new Set());
  // A refused publish pauses publishing until the next gesture: a loop that
  // re-asks after a Deny is a storm of permission dialogs (doc 110).
  const [cardsPaused, setCardsPaused] = useState(false);
  // A local database just changed: rescan the projects once it is safe (no scan running).
  const [rescanPending, setRescanPending] = useState(false);
  // A card opened from the canvas, waiting for the library to be read.
  const openedCardRef = useRef<string | null>(null);
  const [openedTick, setOpenedTick] = useState(0);
  // The publish effect depends on `pinned`: replacing it with an EQUAL set on every
  // answer re-ran the effect, which published again, in a loop (doc 110 lot 0).
  const adoptPinned = (ids: readonly string[]) => setPinned((cur) => (sameMembers(cur, ids) ? cur : new Set(ids)));
  const mirrorPhaseRef = useRef<Record<MirrorEcosystem, MirrorState['phase']>>(eachEcosystem<MirrorState['phase']>('idle'));
  const abortRef = useRef<AbortController | null>(null);
  const libRef = useRef(lib);
  libRef.current = lib;
  const libStatusRef = useRef(libStatus);
  libStatusRef.current = libStatus;
  const langRef = useRef(lang);
  langRef.current = lang;
  const mountedRef = useRef(true);
  // The pack's vault and folder, for this window's life (the host answers the same).
  const packRef = useRef<{ vault: string; folder: string | null } | null>(null);
  const libGenRef = useRef(0);

  // ── Boot: the durable library. The pack is asked for at the first scan,
  // never here: a missing knowledge folder opens the Hub, and a boot is
  // nobody's gesture.
  const bootLibrary = useCallback(() => {
    const gen = ++libGenRef.current;
    const current = () => mountedRef.current && gen === libGenRef.current;
    setLibStatus({ kind: 'loading' });
    sdk.invoke('state.get', undefined, HOST_TIMEOUT_MS)
      .then((raw) => {
        if (!current()) return;
        setLib(parseLibrary(raw));
        setLibStatus({ kind: 'ready' });
      })
      .catch((err) => {
        console.error('[mnemo-vulns] state.get failed', err);
        if (current()) setLibStatus({ kind: 'error', why: errText(err) });
      });
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    bootLibrary();
    void refreshMirror();
    // Ungated: what the host kept pinned for us, without a dialog on nobody's gesture.
    sdk.invoke<{ pinned?: string[]; opened?: { id?: unknown; at?: unknown } | null }>('cockpit.state', undefined, HOST_TIMEOUT_MS)
      .then((res) => {
        if (!mountedRef.current) return;
        if (Array.isArray(res?.pinned)) adoptPinned(res.pinned);
        // Launched by a card's "open" press: show that card's project.
        const o = res?.opened;
        if (o && typeof o.id === 'string' && typeof o.at === 'string' && Date.now() - Date.parse(o.at) < OPENED_RECENT_MS) { openedCardRef.current = o.id; setOpenedTick((n) => n + 1); }
      })
      .catch((err) => console.warn('[mnemo-vulns] cockpit.state unavailable', err));
    return () => { mountedRef.current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- boot once; refreshMirror reads refs only
  }, [bootLibrary]);

  // While the host downloads, builds or updates, ask where it stands once a second.
  const mirrorRunning = MIRROR_ECOSYSTEMS.some((e) => { const m = mirrors[e]; return m.kind === 'ready' && m.state.phase !== 'idle'; });
  useEffect(() => {
    if (!mirrorRunning) return;
    const id = window.setInterval(() => { void refreshMirror(); }, MIRROR_POLL_MS);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the interval only depends on running
  }, [mirrorRunning]);

  // Cancel a running scan when the window goes away.
  useEffect(() => () => abortRef.current?.abort(), []);

  const saveLib = useCallback(async (next: LibraryState): Promise<boolean> => {
    try {
      const done = await persistLibrary(libStatusRef.current, next, (payload) => sdk.invoke('state.set', payload, HOST_TIMEOUT_MS));
      if (done === 'refused') {
        setNotice((n) => [...n, translate(langRef.current, 'lib.notSaved')]);
        return false;
      }
      setLib(next);
      libRef.current = next;
      return true;
    } catch (err) {
      console.error('[mnemo-vulns] state.set failed', err);
      setNotice((n) => [...n, translate(langRef.current, 'run.failed', { why: errText(err) })]);
      return false;
    }
  }, []);

  const now = useClock(job !== null || mirrorRunning);

  const openExternal = (url: string) => {
    sdk.invoke('shell.openExternal', { url }, HOST_TIMEOUT_MS)
      .catch((err) => setNotice([t('run.failed', { why: errText(err) })]));
  };

  /**
   * The vault and folder of the pack. `folder` is `<knowledge root>/<app>/`:
   * the records, the tracking and the reports go there, and the person is
   * never asked for a folder to keep them in (Tony, 07/10). Throws
   * NO_KNOWLEDGE_ROOT when no knowledge folder is chosen yet; the host has
   * then opened the Hub, which asks.
   */
  const packVault = useCallback(async (): Promise<{ vault: string; folder: string | null }> => {
    if (packRef.current) return packRef.current;
    const res = await sdk.invoke<{ vault?: string; folder?: string }>('vault.pack.ensure', { pack: PACK, lexicalOnly: true }, HOST_TIMEOUT_MS * 2);
    if (!res?.vault) throw new Error('ENSURE_PACK_FAILED');
    const found = { vault: res.vault, folder: typeof res.folder === 'string' && res.folder ? res.folder : null };
    packRef.current = found;
    return found;
  }, []);

  /** A failure, worded when it is one the person can act on. */
  const failureText = (err: unknown): string => {
    const why = errText(err);
    return why.includes('NO_KNOWLEDGE_ROOT') ? t('run.noKnowledgeRoot') : t('run.failed', { why });
  };

  // ── Alert cards on the canvas (doc 110) ───────────────────────────────
  // A card opened from the canvas while this window is open: show its project.
  useEffect(() => {
    const onMessage = (ev: MessageEvent) => {
      if (ev.source !== window.parent) return;
      const d = ev.data as { type?: unknown; event?: unknown; data?: { id?: unknown } } | null;
      if (d?.type !== 'MNEMO_PLUGIN_EVENT' || d.event !== 'cockpit:card-opened' || typeof d.data?.id !== 'string') return;
      openedCardRef.current = d.data.id;
      setOpenedTick((n) => n + 1);
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, []);

  // The card's project is known once the library is read; a card of a removed project opens nothing.
  useEffect(() => {
    const id = openedCardRef.current;
    if (!id || libStatus.kind !== 'ready') return;
    openedCardRef.current = null;
    const p = projectOfCard(lib.projects, id);
    if (p) { setNotice([]); setView({ kind: 'project', root: p.root }); }
  }, [openedTick, libStatus.kind, lib.projects]);

  const cardWords = (): CardWords => ({
    open: translate(langRef.current, 'card.open'),
    partial: translate(langRef.current, 'card.partial'),
    malicious: translate(langRef.current, 'card.malicious'),
    fixTo: translate(langRef.current, 'card.fixTo'),
    fixRemove: translate(langRef.current, 'card.fixRemove'),
    fixNone: translate(langRef.current, 'card.fixNone'),
    fixSee: translate(langRef.current, 'card.fixSee'),
    dev: translate(langRef.current, 'via.dev'),
    gauge: translate(langRef.current, 'card.gauge'),
    fresh: translate(langRef.current, 'card.fresh'),
    sev: { CRITICAL: translate(langRef.current, 'sev.CRITICAL'), HIGH: translate(langRef.current, 'sev.HIGH'), MODERATE: translate(langRef.current, 'sev.MODERATE'), LOW: translate(langRef.current, 'sev.LOW') },
  });

  // While something is pinned, every change of a project's summary refreshes its card.
  useEffect(() => {
    if (pinned.size === 0 || cardsPaused) return;
    const cards = lib.projects.filter((p) => pinned.has(cardId(p))).map((p) => projectCard(p, cardWords())).filter(Boolean);
    if (cards.length === 0) return;
    let alive = true;
    sdk.invoke<{ success?: boolean; pinned?: string[]; dropped?: number }>('cockpit.publish', { cards }, HOST_TIMEOUT_MS)
      .then((res) => {
        if (!alive) return;
        if (Array.isArray(res?.pinned)) adoptPinned(res.pinned);
        if (typeof res?.dropped === 'number' && res.dropped > 0) console.warn('[mnemo-vulns] cockpit.publish dropped cards', res.dropped);
        if (res?.success === false) setCardsPaused(true);
      })
      .catch((err) => {
        console.warn('[mnemo-vulns] cockpit.publish refused', err);
        if (alive) setCardsPaused(true);
      });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- cardWords reads a ref
  }, [lib.projects, pinned, cardsPaused]);

  // Removing a project takes it off the list and its card off the canvas; its
  // tracking and report stay in the library folder (history is never deleted here).
  const removeProject = async (root: string) => {
    const p = projectFor(libRef.current, root);
    const id = cardId(p);
    if (pinned.has(id)) {
      try {
        const res = await sdk.invoke<{ pinned?: string[] }>('cockpit.unpin', { id }, HOST_TIMEOUT_MS);
        if (Array.isArray(res?.pinned)) adoptPinned(res.pinned);
      } catch (err) {
        setNotice([t('card.failed', { why: errText(err) })]);
      }
    }
    if (!(await saveLib(withoutProject(libRef.current, root)))) {
      setNotice([t('home.removeFailed')]);
      return;
    }
    setScans((m) => { const { [root]: _gone, ...rest } = m; return rest; });
  };

  const togglePin = (root: string) => {
    const p = projectFor(libRef.current, root);
    const id = cardId(p);
    const card = projectCard(p, cardWords());
    const unpin = pinned.has(id);
    if (!unpin && !card) return;
    setCardsPaused(false);
    sdk.invoke<{ success?: boolean; pinned?: string[]; error?: string }>(unpin ? 'cockpit.unpin' : 'cockpit.pin', unpin ? { id } : { id, card, level: 'hud' }, HOST_TIMEOUT_MS)
      .then((res) => {
        if (Array.isArray(res?.pinned)) adoptPinned(res.pinned);
        if (res?.success === false) setNotice([t('card.failed', { why: res.error ?? '' })]);
      })
      .catch((err) => setNotice([t('card.failed', { why: errText(err) })]));
  };

  // ── The local database (host mirror) ──────────────────────────────────
  async function refreshMirror(): Promise<void> {
    await Promise.all(MIRROR_ECOSYSTEMS.map((e) => refreshMirrorOf(e)));
  }

  async function refreshMirrorOf(ecosystem: MirrorEcosystem): Promise<void> {
    try {
      const st = await sdk.invoke<MirrorState>('vulns.mirrorStatus', { ecosystem }, HOST_TIMEOUT_MS);
      if (!mountedRef.current) return;
      const was = mirrorPhaseRef.current[ecosystem];
      mirrorPhaseRef.current = { ...mirrorPhaseRef.current, [ecosystem]: st.phase };
      setMirrors((m) => ({ ...m, [ecosystem]: { kind: 'ready', state: st } }));
      // A database just built is the one the person asked for: scans read it from now on.
      if (was === 'building' && st.phase === 'idle' && st.installed && !st.error && libRef.current.scanSource !== 'mirror') {
        await saveLib({ ...libRef.current, scanSource: 'mirror' });
      }
      // A base that just changed (built, or updated with records) is measured against at once:
      // the projects are rescanned, so a vulnerability published since the last scan is seen now.
      const changed = st.phase === 'idle' && !st.error && st.last !== null && (st.last.kind === 'built' || (st.last.kind === 'updated' && st.last.count > 0));
      if ((was === 'building' || was === 'updating') && changed && libRef.current.projects.some((p) => p.lastScan)) setRescanPending(true);
    } catch (err) {
      console.error('[mnemo-vulns] mirror status failed', ecosystem, err);
      if (mountedRef.current) setMirrors((m) => ({ ...m, [ecosystem]: { kind: 'error', why: errText(err) } }));
    }
  }

  /** First press: read the size from the server and ask to confirm. The download starts on the confirm. */
  const askDownload = async (ecosystem: MirrorEcosystem) => {
    setConfirm({ ecosystem, bytes: undefined, error: null });
    // Only the answer for the download still asked about lands (another press may have replaced it).
    const land = (next: MirrorConfirm) => setConfirm((c) => (c?.ecosystem === ecosystem ? next : c));
    try {
      const d = await sdk.invoke<{ bytes: number | null }>('vulns.mirrorDumpSize', { ecosystem }, HOST_TIMEOUT_MS);
      if (mountedRef.current) land({ ecosystem, bytes: d?.bytes ?? null, error: null });
    } catch (err) {
      // Not reaching the server is not "the server does not say": the screen names the failure.
      console.warn('[mnemo-vulns] dump size not read', ecosystem, err);
      if (mountedRef.current) land({ ecosystem, bytes: null, error: errText(err) });
    }
  };

  const mirrorAction = async (action: 'vulns.mirrorDownload' | 'vulns.mirrorUpdate' | 'vulns.mirrorCancel', ecosystem: MirrorEcosystem) => {
    try {
      await sdk.invoke(action, { ecosystem }, HOST_TIMEOUT_MS);
    } catch (err) {
      setNotice([t('run.failed', { why: errText(err) })]);
    }
    await refreshMirror();
  };

  // ── Add a project ─────────────────────────────────────────────────────
  const addProject = async () => {
    if (libStatusRef.current.kind !== 'ready') return;
    setNotice([]);
    const root = await sdk.selectFolder({ startIn: 'Documents' });
    if (!root) return;
    const p = projectFor(libRef.current, root);
    if (await saveLib(withProject(libRef.current, p))) setView({ kind: 'project', root });
  };

  // ── Scan one project ──────────────────────────────────────────────────
  /** Scans one project. Resolves false when the knowledge folder is missing (the Hub just opened). */
  const scan = async (root: string, opts: { quiet?: boolean } = {}): Promise<boolean> => {
    if (job || libStatusRef.current.kind !== 'ready') return true;
    if (!opts.quiet) setNotice([]);
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    const startedAt = Date.now();
    setJob({ root, startedAt, progress: null });
    try {
      // The pack first: a missing knowledge folder is said before a download, not after it.
      const { vault: target, folder } = await packVault();
      // An older host answers no folder: said, never a guessed path.
      if (!folder) throw new Error('NO_PACK_FOLDER');
      // New files go to the pack folder; a library that pointed elsewhere follows it.
      // Dates kept for another vault say nothing about this one: the delta starts over.
      const moved = libRef.current.folder !== folder || libRef.current.ingestedIn !== target;
      // The folder left behind is kept, so each project's tracking can follow
      // it at its first scan here (an earlier former folder is not overwritten
      // by the pack folder itself).
      const former = libRef.current.folder && libRef.current.folder !== folder
        ? libRef.current.folder : libRef.current.formerFolder;
      if (moved && !(await saveLib({
        ...libRef.current, folder, ingestedIn: target,
        ...(former ? { formerFolder: former } : {}),
        ingested: libRef.current.ingestedIn === target ? libRef.current.ingested : {},
      }))) return true;
      const res = await scanProject({
        port, lib: libRef.current, folder,
        // The local database of an ecosystem when the person chose it and it is installed; online otherwise.
        sourceFor: (eco) => { const m = (mirrors as Partial<Record<Ecosystem, MirrorView>>)[eco]; return libRef.current.scanSource === 'mirror' && m?.kind === 'ready' && m.state.installed
          ? mirrorSource(mirrorPortFor(eco), eco) : apiSource(fetcher); },
        vault: target,
        project: projectFor(libRef.current, root),
        signal: ctrl.signal,
        onProgress: (progress) => { if (mountedRef.current) setJob({ root, startedAt, progress }); },
      });
      if (!mountedRef.current) return true;
      if (!res.ok) {
        setScans((m) => ({ ...m, [root]: { kind: 'failed', failure: res.failure } }));
        return true;
      }
      setScans((m) => ({ ...m, [root]: { kind: 'done', outcome: res.outcome } }));
      await saveLib({ ...withProject(libRef.current, res.outcome.project), ingested: capIngested(res.outcome.ingested) });
      return true;
    } catch (err) {
      console.error('[mnemo-vulns] scan failed', err);
      if (mountedRef.current) setNotice([failureText(err)]);
      return !errText(err).includes('NO_KNOWLEDGE_ROOT');
    } finally {
      if (mountedRef.current) setJob(null);
    }
  };

  // The rescan after a database update: one project after the other, with the
  // sources of THIS render (the database the update just changed), then one
  // notice naming the projects where something urgent is new.
  useEffect(() => {
    if (!rescanPending || job || libStatus.kind !== 'ready' || libRef.current.scanSource !== 'mirror') return;
    setRescanPending(false);
    void (async () => {
      const roots = libRef.current.projects.filter((p) => p.lastScan).map((p) => p.root);
      for (const root of roots) {
        if (!mountedRef.current) return;
        // No knowledge folder: the Hub opened once, and the notice says so. Asking
        // again for every project would open it once per project.
        if (!(await scan(root, { quiet: true }))) return;
      }
      if (!mountedRef.current) return;
      const news = libRef.current.projects.filter((p) => (p.lastScan?.newUrgent ?? 0) > 0);
      setNotice(news.length
        ? news.map((p) => t('fresh.notice', { project: p.name, n: p.lastScan!.newUrgent! }))
        : [t('fresh.none', { n: roots.length })]);
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- runs once per pending rescan; scan reads refs
  }, [rescanPending, job, libStatus.kind]);

  // ── Accept a risk / take it back: the person's own change of the tracker ─
  const changeTracking = async (root: string, change: (tracking: Tracking, at: string) => Tracking | null) => {
    const current = scans[root];
    const folder = libRef.current.folder;
    if (current?.kind !== 'done' || !current.outcome.trackingWritten || !folder) return;
    const next = change(current.outcome.tracking, new Date().toISOString());
    if (!next) {
      // The tracker has no such entry: the gesture changed nothing, and the screen says it.
      setNotice([t('track.notFound')]);
      return;
    }
    try {
      const w = await saveTracking(port, folder, current.outcome.project, next);
      if (!w.success) {
        setNotice([t('track.notWritten', { why: w.error ?? 'WRITE_FAILED' })]);
        return;
      }
      const project = { ...current.outcome.project, lastScan: summaryOf(current.outcome.scan, next) };
      setScans((m) => ({ ...m, [root]: { kind: 'done', outcome: { ...current.outcome, tracking: next, project } } }));
      // The home tiles read the stored summary: an accepted risk is no longer counted as open there.
      await saveLib(withProject(libRef.current, project));
    } catch (err) {
      setNotice([t('track.notWritten', { why: errText(err) })]);
    }
  };

  // Opening a project with no scan in memory reads its last saved scan, so its list is there at once.
  useEffect(() => {
    if (view.kind !== 'project') return;
    const root = view.root;
    const folder = lib.folder;
    if (scans[root] || !folder || job?.root === root) return;
    let alive = true;
    loadSavedScan(port, folder, projectFor(lib, root))
      .then((outcome) => { if (alive && outcome) setScans((m) => (m[root] ? m : { ...m, [root]: { kind: 'done', outcome } })); })
      .catch((err) => console.warn('[mnemo-vulns] last scan not read', err));
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- port is stable; read once per opened project
  }, [view, lib.folder]);

  const project = view.kind === 'project' ? projectFor(lib, view.root) : null;

  return (
    <div style={S.page}>
      <header style={S.header}>
        <div style={S.title}>🛡️ MnemoVulns</div>
        <div style={S.muted}>{t('app.subtitle')}</div>
      </header>

      {libStatus.kind === 'error' && (
        <section style={S.card} role="alert">
          <div style={S.error}>{t('lib.unreadable', { why: libStatus.why })}</div>
          <button style={S.link} onClick={bootLibrary}>{t('vault.retry')}</button>
        </section>
      )}

      {notice.length > 0 && (
        <section style={S.card} role="status">
          {notice.map((n, i) => <div key={i} style={S.small}>{n}</div>)}
        </section>
      )}

      {view.kind === 'home' && (
        <MirrorCard t={t} lang={lang} mirrors={mirrors} confirm={confirm} scanSource={lib.scanSource} now={now} busy={!!job}
          onDownload={(e) => { void askDownload(e); }}
          onConfirm={(e) => { setConfirm(null); void mirrorAction('vulns.mirrorDownload', e); }}
          onDismiss={() => setConfirm(null)}
          onUpdate={(e) => { void mirrorAction('vulns.mirrorUpdate', e); }}
          onCancel={(e) => { void mirrorAction('vulns.mirrorCancel', e); }}
          onUseSource={(s) => { void saveLib({ ...libRef.current, scanSource: s }); }} />
      )}

      {view.kind === 'home' && (
        <Home t={t} lang={lang} lib={lib} libStatus={libStatus} job={job} now={now}
          onAdd={() => { void addProject(); }}
          onOpen={(root) => { setNotice([]); setView({ kind: 'project', root }); }}
          onScan={(root) => { void scan(root); }}
          pinned={pinned}
          onTogglePin={togglePin}
          onRemove={(root) => { void removeProject(root); }} />
      )}

      {project && (
        <ProjectView
          t={t}
          lang={lang}
          project={project}
          view={scans[project.root]}
          job={job}
          now={now}
          onScan={() => { void scan(project.root); }}
          onStop={() => abortRef.current?.abort()}
          onBack={() => { setNotice([]); setView({ kind: 'home' }); }}
          onAccept={(id, name, ecosystem, reason) => { void changeTracking(project.root, (tr, at) => accept(tr, id, name, reason, at, ecosystem)); }}
          onReopen={(id, name, ecosystem) => { void changeTracking(project.root, (tr, at) => reopen(tr, id, name, at, ecosystem)); }}
          onOpenUrl={openExternal}
        />
      )}

      <Footer
        t={t}
        folder={lib.folder}
        onOpenFolder={() => {
          if (!lib.folder) return;
          sdk.openInOS(lib.folder).then((r) => { if (!r?.success) console.error('[mnemo-vulns] open folder refused', r?.error); })
            .catch((err) => console.error('[mnemo-vulns] open folder failed', err));
        }}
      />
    </div>
  );
}
