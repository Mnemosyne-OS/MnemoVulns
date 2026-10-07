/**
 * library — where MnemoVulns keeps things, and the durable state that points at them.
 *
 * Two places, two jobs (same contract as MnemoHealth and MnemoLaw):
 *  - the FOLDER the host gives the cartridge next to its Memory Pack
 *    (`vault.pack.ensure`, `<knowledge root>/<app>/`; never asked of the
 *    person) holds what agents and people can read: one
 *    JSON per OSV record (`records/`), and per project its `tracking.json`
 *    and the `report.md` of the last scan. DocWatch can watch it, an agent
 *    can open it, a reinstall does not lose it.
 *  - the durable state (doc 73, 256 KB cap) holds the folder, the list of
 *    projects with the summary of their last scan, and which record dates
 *    already reached the vault (the delta of the chronicles).
 *
 * 🚨 The durable state is written only once it has been READ: a library saved
 * over an unread one would erase the person's projects (MnemoLaw's gap).
 */
import { SEVERITY_ORDER, type Severity } from './advisory';

export interface ScanSummary {
  at: string;
  complete: boolean;
  findings: number;
  open: number;
  unasked: number;
  /**
   * Open vulnerabilities by severity. ABSENT on summaries written before it
   * existed: the screen shows a dash, never a zero nobody measured.
   */
  openBySeverity?: Record<Severity, number>;
  accepted?: number;
  fixed?: number;
  /** Open malicious packages (OSV `MAL-` records carry no severity). ABSENT on older summaries. */
  openMalicious?: number;
  /** The packages to fix first (at most TO_FIX_MAX), what to do with each. ABSENT on older summaries. */
  toFix?: ToFix[];
  /**
   * Open critical, high or malicious vulnerabilities this scan saw for the
   * FIRST time on this project (0 on a project's first scan: everything is
   * new there, so nothing is news). ABSENT on older summaries.
   */
  newUrgent?: number;
}

/** One installed package with open vulnerabilities, and the gesture that closes them. */
export interface ToFix {
  ecosystem: string;
  name: string;
  version: string;
  /** Its worst open severity. */
  severity: Severity;
  /** Open vulnerabilities on this package. */
  count: number;
  /** `to`: upgrade to this version (the highest any of them needs); `remove`: a malicious package; `none`: no fixed release; `see`: read the record. */
  action: { kind: 'to'; version: string } | { kind: 'remove' } | { kind: 'none' } | { kind: 'see' };
  /** The lockfile declares this version for development only. ABSENT = it ships, or the lockfile does not say. */
  dev?: true;
}

/** How many packages a summary keeps to fix first: the lines a card can show. */
export const TO_FIX_MAX = 3;

export interface ProjectRecord {
  /** Absolute path of the project folder, as the person picked it. */
  root: string;
  /** Folder name, for the screen. */
  name: string;
  /** Sub-folder of the library that holds this project's files. */
  slug: string;
  lastScan?: ScanSummary;
}

export interface LibraryState {
  /**
   * Where the files are written: the pack folder once a scan asked for it. A
   * library saved before the packs may still name a folder the person chose;
   * its files are read from there until the next scan moves the library.
   */
  folder: string | null;
  projects: ProjectRecord[];
  /** Record id → the `modified` date whose chronicle reached the vault. */
  ingested: Record<string, string>;
  /**
   * The vault `ingested` describes. ABSENT on libraries saved before the packs,
   * whose dates describe the old app vault: a pack vault never inherits them,
   * or the records already there would never reach the pack.
   */
  ingestedIn?: string;
  /**
   * The folder the library used before it moved to the pack folder. A project
   * scanned there for the first time takes its tracking (accepted risks,
   * measured fixes) from here when the new folder has none yet (Tony, 07/10).
   * Never written to.
   */
  formerFolder?: string;
  /** Where scans read: the local mirror once the person chose it, the API otherwise. */
  scanSource: 'api' | 'mirror';
}

/** The library before its folder is chosen. */
export const EMPTY_LIBRARY: LibraryState = { folder: null, projects: [], ingested: {}, scanSource: 'api' };
/** Record dates remembered for the vault delta. Past it the oldest are forgotten (and written again once). */
export const INGESTED_CAP = 5_000;

export type LibStatus = { kind: 'loading' } | { kind: 'ready' } | { kind: 'error'; why: string };

const isCount = (v: unknown) => typeof v === 'number' && Number.isFinite(v) && v >= 0;

const ACTIONS = ['to', 'remove', 'none', 'see'];
function isToFix(v: unknown): v is ToFix {
  const o = v as Partial<ToFix> | null;
  const a = o?.action as { kind?: unknown; version?: unknown } | undefined;
  return !!o && typeof o.ecosystem === 'string' && typeof o.name === 'string' && typeof o.version === 'string'
    && (SEVERITY_ORDER as readonly unknown[]).includes(o.severity) && isCount(o.count)
    && !!a && ACTIONS.includes(a.kind as string) && (a.kind !== 'to' || typeof a.version === 'string')
    && (o.dev === undefined || o.dev === true);
}

function parseSummary(v: unknown): ScanSummary | undefined {
  if (!v || typeof v !== 'object') return undefined;
  const s = v as Record<string, unknown>;
  if (typeof s.at !== 'string' || typeof s.complete !== 'boolean') return undefined;
  if (!isCount(s.findings) || !isCount(s.open) || !isCount(s.unasked)) return undefined;
  const out: ScanSummary = { at: s.at, complete: s.complete, findings: s.findings as number, open: s.open as number, unasked: s.unasked as number };
  const sev = s.openBySeverity as Record<string, unknown> | undefined;
  if (sev && typeof sev === 'object' && SEVERITY_ORDER.every((k) => isCount(sev[k]))) {
    out.openBySeverity = Object.fromEntries(SEVERITY_ORDER.map((k) => [k, sev[k] as number])) as Record<Severity, number>;
  }
  if (isCount(s.accepted)) out.accepted = s.accepted as number;
  if (isCount(s.fixed)) out.fixed = s.fixed as number;
  if (isCount(s.openMalicious)) out.openMalicious = s.openMalicious as number;
  if (isCount(s.newUrgent)) out.newUrgent = s.newUrgent as number;
  if (Array.isArray(s.toFix)) {
    const list = s.toFix.filter(isToFix).slice(0, TO_FIX_MAX);
    if (list.length === s.toFix.length || list.length > 0) out.toFix = list;
  }
  return out;
}

/** Reads a stored library defensively: anything unreadable is dropped, never invented. */
export function parseLibrary(raw: unknown): LibraryState {
  const r = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  // 🪤 `state.get` answers `{ state: { library }, updatedAt }` (host cartridgeState.ts).
  const holder = (r.state && typeof r.state === 'object' ? r.state : r) as Record<string, unknown>;
  const lib = (holder.library && typeof holder.library === 'object' ? holder.library : {}) as Record<string, unknown>;
  const projects: ProjectRecord[] = [];
  for (const v of Array.isArray(lib.projects) ? lib.projects : []) {
    if (!v || typeof v !== 'object') continue;
    const p = v as Record<string, unknown>;
    if (typeof p.root !== 'string' || !p.root || typeof p.name !== 'string' || typeof p.slug !== 'string' || !p.slug) continue;
    const lastScan = parseSummary(p.lastScan);
    projects.push({ root: p.root, name: p.name, slug: p.slug, ...(lastScan ? { lastScan } : {}) });
  }
  const ingested: Record<string, string> = {};
  if (lib.ingested && typeof lib.ingested === 'object') {
    for (const [id, m] of Object.entries(lib.ingested as Record<string, unknown>)) if (typeof m === 'string') ingested[id] = m;
  }
  return {
    folder: typeof lib.folder === 'string' && lib.folder ? lib.folder : null, projects, ingested,
    ...(typeof lib.ingestedIn === 'string' && lib.ingestedIn ? { ingestedIn: lib.ingestedIn } : {}),
    ...(typeof lib.formerFolder === 'string' && lib.formerFolder ? { formerFolder: lib.formerFolder } : {}),
    scanSource: lib.scanSource === 'mirror' ? 'mirror' : 'api',
  };
}

/** Writes the library ONLY once it was read; otherwise refuses. */
export async function persistLibrary(
  status: LibStatus,
  next: LibraryState,
  setState: (payload: { state: { library: LibraryState } }) => Promise<unknown>,
): Promise<'saved' | 'refused'> {
  if (status.kind !== 'ready') return 'refused';
  await setState({ state: { library: next } });
  return 'saved';
}

/** Keeps the newest `INGESTED_CAP` entries (by insertion order). */
export function capIngested(map: Record<string, string>): Record<string, string> {
  const entries = Object.entries(map);
  return entries.length <= INGESTED_CAP ? map : Object.fromEntries(entries.slice(-INGESTED_CAP));
}

/** Joins a folder and a name with the folder's own separator (Windows or POSIX). */
export function joinPath(folder: string, file: string): string {
  const sep = folder.includes('\\') && !folder.includes('/') ? '\\' : '/';
  return folder.replace(/[\\/]+$/, '') + sep + file;
}

/** Last segment of a path. */
export function baseName(p: string): string {
  return p.replace(/[\\/]+$/, '').split(/[\\/]/).pop() ?? p;
}

/** A stable, short, file-safe name for a project: its folder name plus a hash of its full path. */
export function projectSlug(root: string): string {
  let h = 5381;
  const key = root.replace(/[\\/]+$/, '').toLowerCase();
  for (let i = 0; i < key.length; i++) h = ((h * 33) ^ key.charCodeAt(i)) >>> 0;
  const name = baseName(root).toLowerCase().replace(/[^a-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '') || 'project';
  return `${name}-${h.toString(16).padStart(8, '0')}`;
}

/** File name of a kept record. */
export function recordFile(id: string): string {
  return `${id.replace(/[^A-Za-z0-9_.-]+/g, '-')}.json`;
}

/** The project record of a root, or a new one. */
export function projectFor(lib: LibraryState, root: string): ProjectRecord {
  return lib.projects.find((p) => p.root === root) ?? { root, name: baseName(root), slug: projectSlug(root) };
}

/** Replaces the project with the same root, or adds it. */
/** The library without one project. Its files in the library folder are left on disk. */
export function withoutProject(lib: LibraryState, root: string): LibraryState {
  return { ...lib, projects: lib.projects.filter((x) => x.root !== root) };
}

export function withProject(lib: LibraryState, p: ProjectRecord): LibraryState {
  return { ...lib, projects: [...lib.projects.filter((x) => x.root !== p.root), p] };
}
