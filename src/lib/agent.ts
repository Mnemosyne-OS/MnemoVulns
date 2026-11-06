/**
 * agent.ts — what an agent may do in MnemoVulns (doc 149), declared in
 * `mnemo-plugin.json` › agentActions and served by VulnsAgentActions while the
 * window is open.
 *
 * Each move is the App's own function behind a button: open a project, scan
 * it, stop the scan, pick the base, accept a risk with a reason or take it
 * back (the same `accept` / `reopen` of lib/tracking through the App's
 * `changeTracking`), filter the package grid or open a package's tile (the
 * page's own chips and tiles, ui/agentScreen), so the person sees the screen
 * change. Adding a project is NOT exposed: it is an OS folder picker, a
 * gesture of the person. Removing one is not exposed either, nor the local
 * database's download (hundreds of MB, the person confirms a size).
 *
 * 🗣️ By voice (doc 149 §19) the orb plans a sentence in ONE call and never
 *    reads MnemoVulns first: a project and a package are taken by the words
 *    the person says (lib/agentFind), a risk by its package alone when the
 *    package has one in the right state, and the project defaults to the one
 *    on screen. Several matches are refused with their names (AMBIGUOUS),
 *    never the first taken.
 */
import { findNamed, fold, nameWords } from './agentFind';
import { SEVERITY_ORDER } from './advisory';
import type { LibraryState, LibStatus, ProjectRecord } from './library';
import { filterPlans, planAll, type PlanFilter } from './packagePlan';
import type { Finding } from './scan';
import { accept, reopen, trackKey, type TrackEntry, type Tracking } from './tracking';
import { groupFindings, type Job, type MirrorView, type ScanView, type View } from '../ui/types';
import type { AgentScreen } from '../ui/agentScreen';

export interface VulnsAgentContext {
  lib: LibraryState;
  libStatus: LibStatus;
  view: View;
  scans: Record<string, ScanView>;
  job: Job | null;
  openProject: (root: string) => void;
  goHome: () => void;
  /** The App's scan (the Scan button). Runs for as long as the lockfile takes. */
  scan: (root: string) => Promise<boolean>;
  /** The App's changeTracking: true once the tracker is written and the summary saved. */
  changeTracking: (root: string, change: (tracking: Tracking, at: string) => Tracking | null) => Promise<boolean>;
  /** The Stop button of a running scan. */
  stopScan: () => void;
  /** The base picker's buttons: true once the library is saved with that source. */
  useSource: (source: LibraryState['scanSource']) => Promise<boolean>;
  /** The local database per ecosystem, as the home's base card draws it. */
  mirrors: Readonly<Record<string, MirrorView>>;
  /** The project page's own chips and tiles (ui/agentScreen). */
  screen: AgentScreen;
}

export const FINDING_STATES = ['open', 'accepted', 'fixed', 'withdrawn', 'all'] as const;
/** The package grid's chips, in the order the screen draws them. */
export const PLAN_FILTERS: readonly PlanFilter[] = ['all', 'shipped', 'dev', 'unknown'];
/** The base picker, in the words an agent says (local = the host's mirror, online = OSV.dev). */
export const SCAN_SOURCES = ['local', 'online'] as const;
/** Characters of an advisory summary carried per line; the record has the rest. */
export const SUMMARY_MAX = 300;
/** How long a screen move waits for the project page (its last scan is read from disk) and for a chip to answer. */
export const SCREEN_WAIT_MS = 8_000;
/** How long stopScan waits for the scan to end before saying it is still stopping. */
export const STOP_WAIT_MS = 10_000;
const POLL_MS = 50;
const LIST_MAX = 12;

export const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

/** A whole number inside the manifest's bounds, or the default. Clamped, never trusted. */
export function boundedInt(v: unknown, fallback: number, min: number, max: number): number {
  if (typeof v !== 'number' || !Number.isFinite(v)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(v)));
}

/** `vulnerabilities` › limit: 1..500, default 100 (mnemo-plugin.json). */
export const findingsLimit = (v: unknown): number => boundedInt(v, 100, 1, 500);

const listed = (labels: readonly string[]) => {
  const unique = [...new Set(labels)];
  return unique.length > LIST_MAX ? `${unique.slice(0, LIST_MAX).join(', ')} (+${unique.length - LIST_MAX})` : unique.join(', ');
};

function requireLibrary(ctx: VulnsAgentContext): void {
  if (ctx.libStatus.kind === 'loading') throw new Error('NOT_READY: MnemoVulns is still reading its library; try again in a moment');
  if (ctx.libStatus.kind === 'error') throw new Error(`NOT_READY: the library could not be read (${ctx.libStatus.why}); the person sees it in MnemoVulns`);
}

/**
 * The project an agent named: its folder path, or the words of its name
 * (« le projet site »). Two projects of the same name are labelled with
 * their folder, so the refusal lets the repair call pick one.
 */
export function findProject(projects: readonly ProjectRecord[], ref: string): ProjectRecord {
  const count = new Map<string, number>();
  for (const p of projects) count.set(p.name.toLowerCase(), (count.get(p.name.toLowerCase()) ?? 0) + 1);
  return findNamed(
    projects.map((p) => ({ item: p, id: p.root, names: [p.name], label: (count.get(p.name.toLowerCase()) ?? 0) > 1 ? `${p.name} (${p.root})` : p.name })),
    ref,
    { code: 'NO_PROJECT', noun: 'project' },
  );
}

/** The project named, else the one on screen: « montre le paquet lodash » while a project is open. */
export function projectArg(ctx: VulnsAgentContext, raw: unknown): ProjectRecord {
  const ref = str(raw);
  if (ref) return findProject(ctx.lib.projects, ref);
  const view = ctx.view;
  const shown = view.kind === 'project' ? ctx.lib.projects.find((p) => p.root === view.root) : undefined;
  if (shown) return shown;
  throw new Error(`NO_PROJECT_SHOWN: no project is open; name one. projects: ${listed(ctx.lib.projects.map((p) => p.name)) || 'none (the person adds one with Add a project)'}`);
}

/** An advisory id as said or written: « CVE 2024 1234 » is CVE-2024-1234. */
const idKey = (s: string) => fold(s).replace(/[^a-z0-9]/g, '');

/**
 * The package names that hold every word asked; the whole name said wins over
 * a partial one (« core » against « core » and « babel core »).
 */
export function namesMatching(names: readonly string[], ref: string): Set<string> {
  const asked = nameWords(ref);
  if (!asked.length) return new Set();
  const whole = names.filter((n) => nameWords(n).join(' ') === asked.join(' '));
  if (whole.length) return new Set(whole);
  return new Set(names.filter((n) => { const have = new Set(nameWords(n)); return asked.every((w) => have.has(w)); }));
}

export function projectLine(p: ProjectRecord, ctx: Pick<VulnsAgentContext, 'job' | 'view'>) {
  return {
    name: p.name,
    root: p.root,
    lastScan: p.lastScan ?? null,
    scanning: ctx.job?.root === p.root,
    shown: ctx.view.kind === 'project' && ctx.view.root === p.root,
  };
}

export function findingLine(f: Finding, entry: TrackEntry | undefined) {
  return {
    id: f.id,
    ecosystem: f.ecosystem,
    package: f.name,
    version: f.version,
    severity: f.severity,
    fix: f.fix,
    ...(f.malicious ? { malicious: true } : {}),
    ...(f.dev ? { dev: true } : {}),
    ...(f.summary ? { summary: f.summary.length > SUMMARY_MAX ? `${f.summary.slice(0, SUMMARY_MAX)}…` : f.summary } : {}),
    state: entry?.state ?? 'open',
    ...(entry?.reason ? { reason: entry.reason } : {}),
  };
}

/** The scan of a project as the screen holds it, or a refusal that says what to call. */
function outcomeOf(ctx: VulnsAgentContext, p: ProjectRecord) {
  const view = ctx.scans[p.root];
  if (!view) {
    if (!p.lastScan) throw new Error(`NEVER_SCANNED: "${p.name}" has never been scanned; call scan`);
    throw new Error(`NOT_LOADED: the last scan of "${p.name}" is read when the project is open; call openProject, then this again`);
  }
  if (view.kind === 'failed') throw new Error(`SCAN_FAILED: the last scan of "${p.name}" failed (${view.failure.code}); the person sees why on its page`);
  return view.outcome;
}

/**
 * The tracker entry an agent named, among those in the state the move needs:
 * by its package's words, its advisory id (or a CVE alias), or both; the
 * ecosystem only when the pair is in two. One entry in that state is taken;
 * several are refused with their ids; one in another state says which.
 */
export function findEntry(
  tracking: Tracking,
  ref: { id?: string; pkg?: string; ecosystem?: string },
  want: 'open' | 'accepted',
  findings: readonly Finding[] = [],
): TrackEntry {
  const id = (ref.id ?? '').trim();
  const pkg = (ref.pkg ?? '').trim();
  const eco = (ref.ecosystem ?? '').trim();
  if (!id && !pkg) throw new Error('BAD_ARG: name the package (and the advisory id when the package has several)');
  const ecoOf = (e: TrackEntry) => e.ecosystem ?? 'npm';
  const byKey = new Map(findings.map((f) => [trackKey(f.id, f.name, f.ecosystem), f]));
  const label = (e: TrackEntry) => {
    const sev = byKey.get(trackKey(e.id, e.name, e.ecosystem))?.severity;
    return `${e.id} on ${e.name}${ecoOf(e) !== 'npm' ? ` (${ecoOf(e)})` : ''}${sev ? ` [${sev}]` : ''}`;
  };
  let hits = tracking.entries;
  if (id) {
    hits = hits.filter((e) => idKey(e.id) === idKey(id)
      || (byKey.get(trackKey(e.id, e.name, e.ecosystem))?.aliases ?? []).some((a) => idKey(a) === idKey(id)));
  }
  if (pkg) {
    const names = namesMatching([...new Set(hits.map((e) => e.name))], pkg);
    hits = hits.filter((e) => names.has(e.name));
  }
  if (eco) hits = hits.filter((e) => ecoOf(e).toLowerCase() === eco.toLowerCase());
  const said = [id, pkg && `"${pkg}"`, eco].filter(Boolean).join(' on ');
  if (!hits.length) {
    const ready = tracking.entries.filter((e) => e.state === want).map(label);
    throw new Error(`NO_VULNERABILITY: no vulnerability ${said} in this project; ${want} ones: ${listed(ready) || 'none'}`);
  }
  const inState = hits.filter((e) => e.state === want);
  if (inState.length === 1) return inState[0]!;
  if (inState.length > 1) throw new Error(`AMBIGUOUS: ${said} names several ${want} vulnerabilities: ${listed(inState.map(label))}; say which (its id, or the ecosystem)`);
  const e = hits[0]!;
  throw new Error(want === 'open'
    ? `NOT_OPEN: ${e.id} on ${e.name} is ${e.state}; only an open one can be accepted`
    : `NOT_ACCEPTED: ${e.id} on ${e.name} is ${e.state}; only an accepted one can be taken back`);
}

/** Polls the App's latest view until `ok` holds, or the time is up. */
async function waitFor(ok: () => boolean, ms: number): Promise<boolean> {
  const until = Date.now() + ms;
  while (!ok()) {
    if (Date.now() >= until) return false;
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
  return true;
}

/**
 * Puts a project on screen and waits for its last scan: the page reads it from
 * disk when it opens. Never scanned is said at once, a failed scan too.
 */
async function showLoaded(get: () => VulnsAgentContext, p: ProjectRecord) {
  const ctx = get();
  if (!(ctx.view.kind === 'project' && ctx.view.root === p.root)) ctx.openProject(p.root);
  if (!ctx.scans[p.root] && !p.lastScan) throw new Error(`NEVER_SCANNED: "${p.name}" has never been scanned; call scan`);
  if (!(await waitFor(() => !!get().scans[p.root], SCREEN_WAIT_MS))) {
    throw new Error(`NOT_LOADED: the last scan of "${p.name}" was not read in ${SCREEN_WAIT_MS / 1000} s; the person sees why on its page`);
  }
  return outcomeOf(get(), p);
}

async function track(ctx: VulnsAgentContext, p: ProjectRecord, change: (t: Tracking, at: string) => Tracking | null): Promise<void> {
  const outcome = outcomeOf(ctx, p);
  if (!outcome.trackingWritten) throw new Error(`TRACKING_UNREADABLE: the tracker of "${p.name}" could not be read, so it is left as it is; the person sees why on its page`);
  if (ctx.job?.root === p.root) throw new Error(`BUSY: "${p.name}" is being scanned; try again when scanning is false in projects`);
  if (!(await ctx.changeTracking(p.root, change))) throw new Error('WRITE_FAILED: the tracker was not changed; the reason is on the person\'s screen');
}

export function vulnsAgentHandlers(get: () => VulnsAgentContext) {
  return {
    // agent-actions:begin
    projects: () => {
      const ctx = get();
      requireLibrary(ctx);
      return { scanSource: ctx.lib.scanSource, projects: ctx.lib.projects.map((p) => projectLine(p, ctx)) };
    },

    vulnerabilities: (args: Record<string, unknown>) => {
      const ctx = get();
      requireLibrary(ctx);
      const p = projectArg(ctx, args.project);
      const outcome = outcomeOf(ctx, p);
      const state = str(args.state) || 'open';
      if (!(FINDING_STATES as readonly string[]).includes(state)) throw new Error(`BAD_ARG: state is one of ${FINDING_STATES.join(', ')}`);
      const severity = str(args.severity).toUpperCase();
      if (severity && !(SEVERITY_ORDER as readonly string[]).includes(severity)) throw new Error(`BAD_ARG: severity is one of ${SEVERITY_ORDER.join(', ')}`);
      const pkg = str(args.package);
      const names = pkg ? namesMatching([...new Set(outcome.scan.findings.map((f) => f.name))], pkg) : null;
      if (names && !names.size) {
        throw new Error(`NO_PACKAGE: no package named "${pkg}" among the vulnerabilities of "${p.name}"; packages: ${listed(outcome.scan.findings.map((f) => f.name)) || 'none'}`);
      }
      const entries = new Map(outcome.tracking.entries.map((e) => [trackKey(e.id, e.name, e.ecosystem), e]));
      const lines = outcome.scan.findings
        .filter((f) => (!names || names.has(f.name)) && (!severity || f.severity === severity))
        .map((f) => findingLine(f, entries.get(trackKey(f.id, f.name, f.ecosystem))))
        .filter((l) => state === 'all' || l.state === state);
      const limit = findingsLimit(args.limit);
      return {
        project: p.name,
        scannedAt: outcome.scan.at,
        complete: outcome.scan.complete,
        ...(outcome.fromDisk ? { fromLastSavedScan: true } : {}),
        matching: lines.length,
        vulnerabilities: lines.slice(0, limit),
      };
    },

    openProject: (args: Record<string, unknown>) => {
      const ctx = get();
      requireLibrary(ctx);
      const p = findProject(ctx.lib.projects, str(args.project));
      ctx.openProject(p.root);
      return { project: p.name, shown: true };
    },

    home: () => {
      const ctx = get();
      ctx.goHome();
      return { shown: 'home' };
    },

    showPackage: async (args: Record<string, unknown>) => {
      const ctx = get();
      requireLibrary(ctx);
      const p = projectArg(ctx, args.project);
      const outcome = await showLoaded(get, p);
      const { malicious, packages } = groupFindings(outcome.scan.findings);
      const all = [...malicious, ...packages];
      const sameName = (n: string) => all.filter((g) => g.name === n).length > 1;
      const g = findNamed(
        all.map((x) => ({ item: x, id: x.key, names: [x.name, x.ecosystem], label: sameName(x.name) ? `${x.name} (${x.ecosystem})` : x.name })),
        str(args.package),
        { code: 'NO_PACKAGE', noun: 'package' },
      );
      // A malicious package has no tile: it heads the page in its own section, already in view.
      if (malicious.includes(g)) return { project: p.name, package: g.name, ecosystem: g.ecosystem, malicious: true, shown: true };
      const states = new Map(outcome.tracking.entries.map((e) => [trackKey(e.id, e.name, e.ecosystem), e]));
      const plan = planAll(outcome.scan.findings, states).find((x) => x.key === g.key);
      const screen = get().screen;
      if (!(await waitFor(() => screen.planFilter() !== null, SCREEN_WAIT_MS))) throw new Error(`WRITE_FAILED: the packages of "${p.name}" are not drawn on the page`);
      // A tile the person's filter hides: the « all » chip, as the header's own links do.
      if (!screen.hasTile(g.key)) screen.pressPlanFilter('all');
      if (!(await waitFor(() => screen.hasTile(g.key), SCREEN_WAIT_MS)) || !screen.revealTile(g.key)) {
        throw new Error(`WRITE_FAILED: the tile of ${g.name} is not on the page`);
      }
      return {
        project: p.name,
        package: g.name,
        ecosystem: g.ecosystem,
        shown: true,
        ...(plan ? { open: plan.open, accepted: plan.accepted, worst: plan.worst, fixVersion: plan.target, place: plan.place } : {}),
      };
    },

    filterPackages: async (args: Record<string, unknown>) => {
      const ctx = get();
      requireLibrary(ctx);
      const show = str(args.show) as PlanFilter;
      if (!PLAN_FILTERS.includes(show)) throw new Error(`BAD_ARG: show is one of ${PLAN_FILTERS.join(', ')}`);
      const p = projectArg(ctx, args.project);
      const outcome = await showLoaded(get, p);
      const states = new Map(outcome.tracking.entries.map((e) => [trackKey(e.id, e.name, e.ecosystem), e]));
      const plans = planAll(outcome.scan.findings, states);
      if (!plans.length) throw new Error(`NO_PACKAGES: "${p.name}" has no vulnerable package to filter`);
      const screen = get().screen;
      if (!(await waitFor(() => screen.planFilter() !== null, SCREEN_WAIT_MS))) throw new Error(`WRITE_FAILED: the filter of "${p.name}" is not drawn on the page`);
      if (!screen.hasPlanFilter(show)) {
        throw new Error(`NO_FILTER: every package of "${p.name}" says where it is, so there is no ${show} filter; filters: ${PLAN_FILTERS.filter((f) => screen.hasPlanFilter(f)).join(', ')}`);
      }
      if (screen.planFilter() !== show) {
        screen.pressPlanFilter(show);
        if (!(await waitFor(() => screen.planFilter() === show, SCREEN_WAIT_MS))) throw new Error(`WRITE_FAILED: the ${show} filter did not take`);
      }
      return { project: p.name, showing: show, packages: filterPlans(plans, show).length };
    },

    scan: (args: Record<string, unknown>) => {
      const ctx = get();
      requireLibrary(ctx);
      const p = projectArg(ctx, args.project);
      if (ctx.job) throw new Error(`BUSY: a scan is running (${ctx.job.root}); call projects to see it finish`);
      ctx.openProject(p.root);
      // A scan reads a lockfile and asks OSV for every package: started, never awaited.
      void ctx.scan(p.root).catch((err: unknown) => console.warn('[mnemo-vulns] agent scan failed', err));
      return { project: p.name, started: true, followWith: 'projects' };
    },

    stopScan: async () => {
      const ctx = get();
      const job = ctx.job;
      if (!job) throw new Error('NOT_SCANNING: no scan is running');
      const name = ctx.lib.projects.find((p) => p.root === job.root)?.name ?? job.root;
      ctx.stopScan();
      // The request in flight ends first: said stopped only once the job is gone.
      if (await waitFor(() => get().job === null, STOP_WAIT_MS)) return { project: name, stopped: true };
      return { project: name, stopping: true, followWith: 'projects' };
    },

    setScanSource: async (args: Record<string, unknown>) => {
      const ctx = get();
      requireLibrary(ctx);
      const said = str(args.source);
      if (!(SCAN_SOURCES as readonly string[]).includes(said)) throw new Error(`BAD_ARG: source is one of ${SCAN_SOURCES.join(', ')}`);
      const source: LibraryState['scanSource'] = said === 'local' ? 'mirror' : 'api';
      // The picker is drawn only once a local database is installed: without one, scans are online already.
      const installed = Object.values(ctx.mirrors).some((m) => m.kind === 'ready' && !!m.state.installed);
      if (!installed) throw new Error('NO_LOCAL_DATABASE: no local database is installed, so scans ask OSV.dev online; the person downloads one on the home page');
      if (ctx.job) throw new Error(`BUSY: a scan is running (${ctx.job.root}); the base changes once it ends`);
      if (ctx.lib.scanSource === source) return { source: said, changed: false };
      if (!(await ctx.useSource(source))) throw new Error('WRITE_FAILED: the base was not changed; the reason is on the person\'s screen');
      return { source: said, changed: true };
    },

    acceptRisk: async (args: Record<string, unknown>) => {
      const ctx = get();
      requireLibrary(ctx);
      const p = projectArg(ctx, args.project);
      const reason = str(args.reason);
      if (!reason) throw new Error('BAD_ARG: reason is empty; an accepted risk always says why');
      const outcome = outcomeOf(ctx, p);
      const entry = findEntry(outcome.tracking, { id: str(args.id), pkg: str(args.package), ecosystem: str(args.ecosystem) }, 'open', outcome.scan.findings);
      await track(ctx, p, (t, at) => accept(t, entry.id, entry.name, reason, at, entry.ecosystem));
      return { project: p.name, id: entry.id, package: entry.name, state: 'accepted' };
    },

    reopenRisk: async (args: Record<string, unknown>) => {
      const ctx = get();
      requireLibrary(ctx);
      const p = projectArg(ctx, args.project);
      const outcome = outcomeOf(ctx, p);
      const entry = findEntry(outcome.tracking, { id: str(args.id), pkg: str(args.package), ecosystem: str(args.ecosystem) }, 'accepted', outcome.scan.findings);
      await track(ctx, p, (t, at) => reopen(t, entry.id, entry.name, at, entry.ecosystem));
      return { project: p.name, id: entry.id, package: entry.name, state: 'open' };
    },
    // agent-actions:end
  };
}
