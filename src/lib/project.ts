/**
 * project — one project, scanned from its folder to the vault.
 *
 *  1. find the lockfile in the project folder (pnpm first, then npm);
 *  2. read and parse it;
 *  3. ask OSV (`runScan`), reading kept records from the library folder;
 *  4. reconcile the project's tracker and write `tracking.json` + `report.md`;
 *  5. write the chronicle of every record whose date is not in the vault yet.
 *
 * 🚨 A tracker that exists but cannot be read is NEVER overwritten: the scan
 * still shows its findings, and the screen says the tracking was not updated.
 * Writing a fresh tracker over it would erase every accepted risk and every
 * measured fix the person had.
 */
import { LockfileError, pickLockfiles, readLockfile, type Ecosystem, type LockfileRead } from './lockfile';
import { baseName, joinPath, recordFile, TO_FIX_MAX, type LibraryState, type ProjectRecord, type ScanSummary, type ToFix } from './library';
import type { VulnSource } from './osv';
import { runScan, type Finding, type ScanProgress, type ScanResult } from './scan';
import { attributionText, recordChronicle, recordRef, reportText, SPINE } from './texts';
import { EMPTY_TRACKING, parseTracking, reconcile, tally, trackKey, type Tracking } from './tracking';
import { SEVERITY_ORDER, versionOrder, type OsvRecord, type Severity } from './advisory';

/** Files written per project (tracking, report) and once per library (attribution). */
export const TRACKING_FILE = 'tracking.json';
/** The last scan's findings, so a project opens on its list without scanning again. */
export const LAST_SCAN_FILE = 'last-scan.json';
export const REPORT_FILE = 'report.md';
export const ATTRIBUTION_FILE = 'ATTRIBUTION.md';

/** The host operations a scan needs, injected so the run is testable without a bridge. */
export interface HostPort {
  readDir(dir: string): Promise<{ success: boolean; files?: { name: string; isDirectory: boolean }[]; error?: string }>;
  readFile(path: string): Promise<{ success: boolean; content?: string; isBinary?: boolean; error?: string }>;
  writeFile(path: string, content: string): Promise<{ success: boolean; error?: string }>;
  mkdir(path: string): Promise<{ success: boolean; error?: string }>;
  ingest(entry: { vault: string; content: string; sourceRef: string; spineType: string }): Promise<void>;
}

/** Why a project could not be scanned at all. */
export type ScanFailure =
  | { code: 'FOLDER_UNREADABLE'; why: string }
  | { code: 'NO_LOCKFILE' }
  | { code: 'LOCKFILE_UNREADABLE'; file: string; why: string }
  | { code: 'LOCKFILE_INVALID'; file: string; why: string }
  | { code: 'WRITE_FAILED'; why: string };

export interface ProjectOutcome {
  project: ProjectRecord;
  scan: ScanResult;
  tracking: Tracking;
  /** False when the stored tracker was unreadable and left as it was. */
  trackingWritten: boolean;
  trackingError: string | null;
  reportWritten: boolean;
  /** Why report.md was not written, said on screen; null when it was. */
  reportError: string | null;
  /** Chronicles written in this scan, refused, and already in the vault. */
  vault: { written: number; failed: number; already: number } | null;
  ingested: Record<string, string>;
  /** Lockfiles found but not read: their ecosystems were not measured. */
  lockFailures: ScanFailure[];
  /** True when this outcome was read back from the last saved scan, not measured now. */
  fromDisk?: boolean;
}

const dirOf = (folder: string, ...parts: string[]) => parts.reduce(joinPath, folder);

async function ensureDir(port: HostPort, dir: string): Promise<void> {
  const made = await port.mkdir(dir);
  if (!made.success) throw Object.assign(new Error(made.error ?? 'MKDIR_FAILED'), { scanCode: 'WRITE_FAILED' });
}

/**
 * Reads the stored tracker: absent = empty, present but unreadable = an error, never empty.
 * `formerDir` is the same project in the folder the library used before the
 * packs: read only when this folder has no tracker yet, so the accepted risks
 * follow the move. The next write puts the copy in the new folder.
 */
async function readTracking(port: HostPort, projectDir: string, formerDir?: string): Promise<{ tracking: Tracking } | { error: string }> {
  const listing = await port.readDir(projectDir);
  if (!listing.success) return { error: listing.error ?? 'READDIR_FAILED' };
  if (!(listing.files ?? []).some((f) => f.name === TRACKING_FILE && !f.isDirectory)) {
    if (!formerDir || formerDir === projectDir) return { tracking: EMPTY_TRACKING };
    const former = await port.readDir(formerDir);
    // The old folder gone or unreadable: nothing to carry, the tracking starts empty.
    if (!former.success) {
      console.warn('[mnemo-vulns] former tracking folder unreadable, starting empty', formerDir, former.error);
      return { tracking: EMPTY_TRACKING };
    }
    return readTracking(port, formerDir);
  }
  const file = await port.readFile(joinPath(projectDir, TRACKING_FILE));
  if (!file.success || typeof file.content !== 'string') return { error: file.error ?? 'READ_FAILED' };
  try {
    const raw = JSON.parse(file.content) as unknown;
    if (!raw || typeof raw !== 'object' || !Array.isArray((raw as { entries?: unknown }).entries)) return { error: 'NOT_A_TRACKING_FILE' };
    return { tracking: parseTracking(raw) };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

/** Open vulnerabilities by severity: one per tracked (record, package), at its worst severity. */
export function openBySeverity(findings: readonly { id: string; name: string; ecosystem?: string; severity: Severity }[], tracking: Tracking): Record<Severity, number> {
  const open = new Set(tracking.entries.filter((e) => e.state === 'open').map((e) => trackKey(e.id, e.name, e.ecosystem)));
  const worst = new Map<string, Severity>();
  for (const f of findings) {
    const k = trackKey(f.id, f.name, f.ecosystem);
    if (!open.has(k)) continue;
    const cur = worst.get(k);
    if (!cur || SEVERITY_ORDER.indexOf(f.severity) < SEVERITY_ORDER.indexOf(cur)) worst.set(k, f.severity);
  }
  const out = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>;
  for (const s of worst.values()) out[s]++;
  return out;
}

/**
 * The packages to fix first: each installed package with open vulnerabilities,
 * malicious ones first, then what ships before dev tools (a dev-only version
 * first on the card sent the person to the wrong place), then by worst
 * severity, then by how many. The gesture
 * is the HIGHEST fixed version any of them needs (upgrading to less leaves one
 * open); one vulnerability with no fixed release makes it "no fix", and one we
 * cannot order makes it "read the record", never a version we guessed.
 */
export function toFixFirst(findings: readonly Finding[], tracking: Tracking, max = TO_FIX_MAX): ToFix[] {
  const open = new Set(tracking.entries.filter((e) => e.state === 'open').map((e) => trackKey(e.id, e.name, e.ecosystem)));
  const byPkg = new Map<string, { f: Finding[] }>();
  for (const f of findings) {
    if (!open.has(trackKey(f.id, f.name, f.ecosystem))) continue;
    const k = `${f.ecosystem}:${f.name}@${f.version}`;
    const g = byPkg.get(k) ?? { f: [] };
    if (!g.f.some((x) => x.id === f.id)) g.f.push(f);
    byPkg.set(k, g);
  }
  const out: ToFix[] = [];
  for (const { f } of byPkg.values()) {
    const first = f[0]!;
    const severity = f.map((x) => x.severity).sort((a, b) => SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b))[0]!;
    const cmp = versionOrder(first.ecosystem);
    let action: ToFix['action'];
    if (f.some((x) => x.malicious)) action = { kind: 'remove' };
    else if (f.some((x) => x.fix.kind === 'none')) action = { kind: 'none' };
    else if (f.some((x) => x.fix.kind !== 'fixed')) action = { kind: 'see' };
    else {
      let best: string | null = null;
      let orderable = true;
      for (const x of f) {
        const v = (x.fix as { version: string }).version;
        if (best === null) { best = v; continue; }
        const c = cmp(v, best);
        if (c === null) { orderable = false; break; }
        if (c > 0) best = v;
      }
      action = orderable && best !== null ? { kind: 'to', version: best } : { kind: 'see' };
    }
    out.push({ ecosystem: first.ecosystem, name: first.name, version: first.version, severity, count: f.length, action, ...(first.dev === true ? { dev: true as const } : {}) });
  }
  const malicious = (t: ToFix) => (t.action.kind === 'remove' ? 0 : 1);
  const dev = (t: ToFix) => (t.dev ? 1 : 0);
  return out.sort((a, b) => malicious(a) - malicious(b) || dev(a) - dev(b) || SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.count - a.count || a.name.localeCompare(b.name)).slice(0, max);
}

/** Open vulnerabilities that are malicious packages, each counted once. */
export function openMalicious(findings: readonly { id: string; name: string; ecosystem?: string; malicious: boolean }[], tracking: Tracking): number {
  const open = new Set(tracking.entries.filter((e) => e.state === 'open').map((e) => trackKey(e.id, e.name, e.ecosystem)));
  return new Set(findings.filter((f) => f.malicious).map((f) => trackKey(f.id, f.name, f.ecosystem)).filter((k) => open.has(k))).size;
}

/** The summary of a scan kept in the durable state, recomputed when the person changes the tracker. */
export function summaryOf(scan: ScanResult, tracking: Tracking): ScanSummary {
  const counts = tally(tracking);
  return {
    at: scan.at, complete: scan.complete, findings: scan.findings.length, open: counts.open, unasked: scan.unasked,
    openBySeverity: openBySeverity(scan.findings, tracking), accepted: counts.accepted, fixed: counts.fixed,
    openMalicious: openMalicious(scan.findings, tracking),
    toFix: toFixFirst(scan.findings, tracking),
    newUrgent: newUrgent(scan, tracking),
  };
}

/**
 * Open critical, high or malicious vulnerabilities first seen by THIS scan.
 * A project's first scan answers 0: every entry is first seen there, and
 * calling all of them news would ring on the day the project is added.
 */
export function newUrgent(scan: Pick<ScanResult, 'at' | 'findings'>, tracking: Tracking): number {
  if (!tracking.entries.some((e) => e.firstSeen !== scan.at)) return 0;
  const fresh = new Set(tracking.entries.filter((e) => e.state === 'open' && e.firstSeen === scan.at).map((e) => trackKey(e.id, e.name, e.ecosystem)));
  const urgent = new Set<string>();
  for (const f of scan.findings) {
    const k = trackKey(f.id, f.name, f.ecosystem);
    if (fresh.has(k) && (f.malicious || f.severity === 'CRITICAL' || f.severity === 'HIGH')) urgent.add(k);
  }
  return urgent.size;
}

/** Writes a tracker changed by the person (an accepted risk, a risk taken back). */
export async function saveTracking(port: HostPort, folder: string, project: ProjectRecord, tracking: Tracking): Promise<{ success: boolean; error?: string }> {
  const projectDir = dirOf(folder, 'projects', project.slug);
  return port.writeFile(joinPath(projectDir, TRACKING_FILE), JSON.stringify({ version: 1, project: project.root, entries: tracking.entries }, null, 1));
}

/**
 * The last scan of a project, read back from its folder with its tracker, or
 * null when there is none, it cannot be read, or it is not the scan the
 * library's summary describes (an older file is never shown as the last scan).
 */
export async function loadSavedScan(port: HostPort, folder: string, project: ProjectRecord): Promise<ProjectOutcome | null> {
  const projectDir = dirOf(folder, 'projects', project.slug);
  const file = await port.readFile(joinPath(projectDir, LAST_SCAN_FILE));
  if (!file.success || typeof file.content !== 'string') return null;
  let scan: ScanResult;
  try {
    const raw = JSON.parse(file.content) as { scan?: Partial<ScanResult> };
    const s = raw?.scan;
    if (!s || typeof s.at !== 'string' || !Array.isArray(s.findings) || !Array.isArray(s.installed) || !Array.isArray(s.sources) || !Array.isArray(s.lockfiles)) return null;
    scan = { ...(s as ScanResult), records: [] };
  } catch (err) {
    console.warn('[mnemo-vulns] last scan unreadable', projectDir, err);
    return null;
  }
  if (project.lastScan && project.lastScan.at !== scan.at) return null;
  const stored = await readTracking(port, projectDir);
  const tracking = 'tracking' in stored
    ? stored.tracking
    : reconcile(EMPTY_TRACKING, { at: scan.at, findings: scan.findings, installed: scan.installed, lockfileComplete: scan.complete });
  return {
    project, scan, tracking,
    // Editable only when the tracker on disk was read: nothing is written over a file we could not read.
    trackingWritten: 'tracking' in stored,
    trackingError: 'tracking' in stored ? null : stored.error,
    reportWritten: true, reportError: null, vault: null, ingested: {}, lockFailures: [], fromDisk: true,
  };
}

/** Scans one project. Returns a failure when nothing could be measured. */
export async function scanProject(deps: {
  port: HostPort;
  /** The source for one ecosystem (npm goes to the local database when chosen). */
  sourceFor: (ecosystem: Ecosystem) => VulnSource;
  lib: LibraryState;
  folder: string;
  vault: string | null;
  project: ProjectRecord;
  signal?: AbortSignal;
  onProgress?: (p: ScanProgress) => void;
  now?: () => Date;
}): Promise<{ ok: true; outcome: ProjectOutcome } | { ok: false; failure: ScanFailure }> {
  const { port, project, folder } = deps;

  const listing = await port.readDir(project.root);
  if (!listing.success) return { ok: false, failure: { code: 'FOLDER_UNREADABLE', why: listing.error ?? 'READDIR_FAILED' } };
  const picked = pickLockfiles((listing.files ?? []).filter((f) => !f.isDirectory).map((f) => f.name));
  if (picked.length === 0) return { ok: false, failure: { code: 'NO_LOCKFILE' } };

  // One lockfile per ecosystem. One that cannot be read does not stop the
  // others: it is named on the screen, and the scan is partial.
  const locks: { file: string; read: LockfileRead }[] = [];
  const lockFailures: ScanFailure[] = [];
  for (const p of picked) {
    const file = await port.readFile(joinPath(project.root, p.file));
    if (!file.success || typeof file.content !== 'string' || file.isBinary) {
      lockFailures.push({ code: 'LOCKFILE_UNREADABLE', file: p.file, why: file.error ?? (file.isBinary ? 'BINARY' : 'NO_CONTENT') });
      continue;
    }
    try {
      locks.push({ file: p.file, read: readLockfile(p.kind, file.content) });
    } catch (err) {
      if (!(err instanceof LockfileError)) throw err;
      lockFailures.push({ code: 'LOCKFILE_INVALID', file: p.file, why: err.message });
    }
  }
  if (locks.length === 0) return { ok: false, failure: lockFailures[0]! };

  const recordsDir = dirOf(folder, 'records');
  const projectDir = dirOf(folder, 'projects', project.slug);
  try {
    await ensureDir(port, recordsDir);
    await ensureDir(port, projectDir);
  } catch (err) {
    return { ok: false, failure: { code: 'WRITE_FAILED', why: err instanceof Error ? err.message : String(err) } };
  }

  const formerDir = deps.lib.formerFolder ? dirOf(deps.lib.formerFolder, 'projects', project.slug) : undefined;
  const stored = await readTracking(port, projectDir, formerDir);

  const measured = await runScan({
    sourceFor: deps.sourceFor,
    locks,
    ...(deps.signal ? { signal: deps.signal } : {}),
    ...(deps.onProgress ? { onProgress: deps.onProgress } : {}),
    ...(deps.now ? { now: deps.now } : {}),
    cache: {
      read: async (id) => {
        const r = await port.readFile(joinPath(recordsDir, recordFile(id)));
        // Absent is the common case (first scan): no error, just no copy.
        if (!r.success || typeof r.content !== 'string') return null;
        return JSON.parse(r.content) as OsvRecord;
      },
      write: async (rec) => {
        const w = await port.writeFile(joinPath(recordsDir, recordFile(rec.id)), JSON.stringify(rec, null, 1));
        if (!w.success) throw new Error(w.error ?? 'WRITE_FAILED');
      },
    },
  });
  // A lockfile found but not read leaves its ecosystem unmeasured: the scan is partial before anything is written.
  const scan: ScanResult = lockFailures.length ? { ...measured, complete: false, error: measured.error ?? 'LOCKFILE_UNREAD' } : measured;

  let tracking: Tracking;
  let trackingWritten = false;
  let trackingError: string | null = null;
  if ('tracking' in stored) {
    tracking = reconcile(stored.tracking, { at: scan.at, findings: scan.findings, installed: scan.installed, lockfileComplete: lockFailures.length === 0 });
    const w = await port.writeFile(joinPath(projectDir, TRACKING_FILE), JSON.stringify({ version: 1, project: project.root, entries: tracking.entries }, null, 1));
    trackingWritten = w.success;
    if (!w.success) trackingError = w.error ?? 'WRITE_FAILED';
  } else {
    // Shown with the findings, but nothing is reconciled over a file we could not read.
    tracking = reconcile(EMPTY_TRACKING, { at: scan.at, findings: scan.findings, installed: scan.installed, lockfileComplete: lockFailures.length === 0 });
    trackingError = stored.error;
    console.error('[mnemo-vulns] tracking unreadable, left untouched', projectDir, stored.error);
  }

  // The records live in records/, so the saved scan keeps the findings without them.
  const saved = await port.writeFile(joinPath(projectDir, LAST_SCAN_FILE), JSON.stringify({ version: 1, project: project.root, scan: { ...scan, records: [] } }));
  if (!saved.success) console.error('[mnemo-vulns] last scan not saved', saved.error);
  const report = await port.writeFile(joinPath(projectDir, REPORT_FILE), reportText(baseName(project.root), scan, tracking));
  if (!report.success) console.error('[mnemo-vulns] report not written', report.error);
  const attribution = await port.writeFile(joinPath(folder, ATTRIBUTION_FILE), attributionText());
  if (!attribution.success) console.error('[mnemo-vulns] attribution not written', attribution.error);

  const ingested = { ...deps.lib.ingested };
  let vault: ProjectOutcome['vault'] = null;
  if (deps.vault) {
    vault = { written: 0, failed: 0, already: 0 };
    for (const rec of scan.records) {
      if (deps.signal?.aborted) break;
      if (ingested[rec.id] === rec.modified) { vault.already++; continue; }
      try {
        await port.ingest({ vault: deps.vault, content: recordChronicle(rec), sourceRef: recordRef(rec), spineType: SPINE });
        // Re-inserted at the end, so the cap forgets the oldest first.
        delete ingested[rec.id];
        ingested[rec.id] = rec.modified;
        vault.written++;
      } catch (err) {
        vault.failed++;
        console.error('[mnemo-vulns] chronicle refused', rec.id, err);
      }
    }
  }

  return {
    ok: true,
    outcome: {
      project: { ...project, lastScan: summaryOf(scan, tracking) },
      scan, tracking, trackingWritten, trackingError, reportWritten: report.success, reportError: report.success ? null : (report.error ?? 'UNKNOWN'), vault, ingested, lockFailures,
    },
  };
}
