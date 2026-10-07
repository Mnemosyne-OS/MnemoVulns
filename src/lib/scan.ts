/**
 * scan — a lockfile, asked to OSV, turned into findings.
 *
 * The delta (doc 135, MnemoVulns lot 1): `querybatch` gives each record's
 * `modified` date. A record already kept with the SAME date is read from the
 * person's folder, not fetched again; a newer date is fetched and replaces it.
 *
 * Honesty of the result:
 *  - `complete` is true only when EVERY readable package was asked AND every
 *    record touching them could be read. Anything else is partial, and the
 *    screen never turns a partial scan into "no vulnerability".
 *  - a record that could not be read still makes a finding (OSV said the
 *    version is affected): it shows its id with an UNKNOWN severity and fix,
 *    never disappears.
 */
import { cveAliases, fixFor, isMalicious, severityOf, sourceOf, type Fix, type OsvRecord, type Severity, type Source } from './advisory';
import { viaOf, type Ecosystem, type LockfileRead, type Via } from './lockfile';
import { mapLimited, pkgKey, RECORD_CONCURRENCY, type BatchOutcome, type VulnSource } from './osv';

export interface Finding {
  id: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  severity: Severity;
  fix: Fix;
  malicious: boolean;
  summary: string | null;
  aliases: string[];
  modified: string;
  source: Source;
  /** False when OSV named the record but it could not be read. */
  recordRead: boolean;
  /** The lockfile declares the package for development only. ABSENT when it does not say. A label, never a filter. */
  dev?: boolean;
  /**
   * Who pulls this version: the workspace packages and the direct dependency
   * each path starts from, production first, at most VIA_CAP of them.
   * ABSENT when the lockfile records no graph (only pnpm v9 does today).
   */
  via?: Via[];
  /** How many ways there are in all, when `via` was cut at VIA_CAP. */
  viaTotal?: number;
}

/** Ways kept per finding: enough to see who pulls it, without a per-finding wall. */
export const VIA_CAP = 12;

export interface ScanResult {
  at: string;
  /** The lockfiles read, one per ecosystem. */
  lockfiles: string[];
  /** Readable packages in the lockfiles. */
  packages: number;
  asked: number;
  unasked: number;
  /** Entries with no registry version (link, file, git), counted. */
  skipped: number;
  findings: Finding[];
  /** Records OSV named that could not be read. */
  recordsUnread: number;
  /** Records read from the folder instead of the network (the delta). */
  recordsFromCache: number;
  complete: boolean;
  error: string | null;
  /** Every name@version of the lockfile, for the tracker (who was measured). */
  installed: { ecosystem: Ecosystem; name: string; version: string; asked: boolean }[];
  /** The records read during this scan, newest copy, for the folder and the vault. */
  records: OsvRecord[];
  /**
   * Which source answered EACH ecosystem, and the date of its data (null =
   * live API). The local mirror holds npm only: a Python project is always
   * asked online, even when the person chose the local database, and the
   * screen says so per ecosystem instead of reading an empty mirror as clean.
   */
  sources: { ecosystem: Ecosystem; kind: VulnSource['kind']; asOf: string | null }[];
}

/** Where kept records are read and written (the person's folder). */
export interface RecordCache {
  read(id: string): Promise<OsvRecord | null>;
  write(rec: OsvRecord): Promise<void>;
}

export interface ScanProgress {
  phase: 'asking' | 'records';
  done: number;
  total: number;
}

/** The `via` fields of a finding: the ways, cut at VIA_CAP, and the full count when cut. */
function viaFields(ways: Via[] | undefined): Pick<Finding, 'via' | 'viaTotal'> {
  if (!ways || ways.length === 0) return {};
  return ways.length > VIA_CAP ? { via: ways.slice(0, VIA_CAP), viaTotal: ways.length } : { via: ways };
}

/** Runs one scan. Never throws for a network failure: the result says what was not measured. */
export async function runScan(deps: {
  /** The source for one ecosystem (the caller routes npm to the mirror when chosen). */
  sourceFor: (ecosystem: Ecosystem) => VulnSource;
  cache: RecordCache;
  locks: { file: string; read: LockfileRead }[];
  now?: () => Date;
  signal?: AbortSignal;
  onProgress?: (p: ScanProgress) => void;
}): Promise<ScanResult> {
  const now = deps.now ?? (() => new Date());
  const { signal } = deps;
  const packages = deps.locks.flatMap((l) => l.read.packages);
  const outcome: BatchOutcome = { hits: new Map(), unasked: [], error: null };
  const sources: ScanResult['sources'] = [];
  /** Which source to read each record from: the one whose ecosystem named it first. */
  const recordSource = new Map<string, VulnSource>();
  let askedBefore = 0;
  for (const lock of deps.locks) {
    const source = deps.sourceFor(lock.read.ecosystem);
    const out = await source.hits(lock.read.packages, {
      ...(signal ? { signal } : {}),
      onProgress: (done) => deps.onProgress?.({ phase: 'asking', done: askedBefore + done, total: packages.length }),
    });
    askedBefore += lock.read.packages.length;
    for (const [k, v] of out.hits) {
      outcome.hits.set(k, v);
      for (const h of v) if (!recordSource.has(h.id)) recordSource.set(h.id, source);
    }
    outcome.unasked.push(...out.unasked);
    outcome.error ??= out.error;
    sources.push({ ecosystem: lock.read.ecosystem, kind: source.kind, asOf: source.asOf });
  }

  // Every record id touched, with the newest `modified` OSV gave for it.
  const wanted = new Map<string, string>();
  for (const list of outcome.hits.values()) {
    for (const h of list) {
      const prev = wanted.get(h.id);
      if (prev === undefined || h.modified > prev) wanted.set(h.id, h.modified);
    }
  }

  const ids = [...wanted.keys()].sort();
  let fromCache = 0;
  let done = 0;
  const settled = await mapLimited(ids, RECORD_CONCURRENCY, async (id) => {
    if (signal?.aborted) throw new Error('ABORTED');
    const want = wanted.get(id)!;
    let cached: OsvRecord | null = null;
    try {
      cached = await deps.cache.read(id);
    } catch (err) {
      // An unreadable copy is fetched again, never trusted.
      console.warn('[mnemo-vulns] cached record unreadable', id, err);
    }
    let rec: OsvRecord;
    if (cached && cached.id === id && want !== '' && cached.modified === want) {
      fromCache++;
      rec = cached;
    } else {
      rec = await recordSource.get(id)!.record(id, signal);
      try {
        await deps.cache.write(rec);
      } catch (err) {
        // The finding is still right; only the next scan's delta is lost.
        console.error('[mnemo-vulns] record copy not written', id, err);
      }
    }
    deps.onProgress?.({ phase: 'records', done: ++done, total: ids.length });
    return rec;
  });

  const records = new Map<string, OsvRecord>();
  let unread = 0;
  settled.forEach((s, i) => {
    if (s.status === 'fulfilled') records.set(ids[i]!, s.value);
    else { unread++; console.error('[mnemo-vulns] record not read', ids[i], s.reason); }
  });

  // Who pulls each affected version, read from the lockfile that holds it.
  const viaByLock = deps.locks.map((l) => {
    if (!l.read.graph) return null;
    const targets = new Set(l.read.packages.filter((p) => outcome.hits.has(pkgKey(p))).map((p) => `${p.name}@${p.version}`));
    return viaOf(l.read.graph, targets);
  });
  const viaFor = (pkg: { ecosystem: Ecosystem; name: string; version: string }): Via[] | undefined => {
    for (const [i, l] of deps.locks.entries()) {
      if (l.read.ecosystem !== pkg.ecosystem) continue;
      const ways = viaByLock[i]?.get(`${pkg.name}@${pkg.version}`);
      if (ways) return ways;
    }
    return undefined;
  };

  const findings: Finding[] = [];
  for (const pkg of packages) {
    const list = outcome.hits.get(pkgKey(pkg));
    if (!list) continue;
    for (const h of list) {
      const rec = records.get(h.id);
      if (rec?.withdrawn) continue; // OSV keeps withdrawn records; they are no longer advisories
      findings.push({
        id: h.id,
        ecosystem: pkg.ecosystem,
        name: pkg.name,
        version: pkg.version,
        severity: rec ? severityOf(rec) : 'UNKNOWN',
        fix: rec ? fixFor(rec, pkg.name, pkg.version, pkg.ecosystem) : { kind: 'unknown' },
        malicious: isMalicious(h.id),
        summary: rec?.summary?.trim() || null,
        aliases: rec ? cveAliases(rec) : [],
        modified: rec?.modified ?? h.modified,
        source: sourceOf(h.id),
        recordRead: !!rec,
        ...(pkg.dev === undefined ? {} : { dev: pkg.dev }),
        ...viaFields(viaFor(pkg)),
      });
    }
  }

  const unaskedKeys = new Set(outcome.unasked.map(pkgKey));
  const error = outcome.error ?? (unread > 0 ? 'RECORDS_UNREAD' : null);
  return {
    at: now().toISOString(),
    lockfiles: deps.locks.map((l) => l.file),
    packages: packages.length,
    asked: packages.length - outcome.unasked.length,
    unasked: outcome.unasked.length,
    skipped: deps.locks.reduce((n, l) => n + l.read.skipped.length, 0),
    findings,
    recordsUnread: unread,
    recordsFromCache: fromCache,
    complete: outcome.unasked.length === 0 && unread === 0 && !signal?.aborted,
    error: signal?.aborted ? 'ABORTED' : error,
    installed: packages.map((p) => ({ ecosystem: p.ecosystem, name: p.name, version: p.version, asked: !unaskedKeys.has(pkgKey(p)) })),
    records: [...records.values()],
    sources,
  };
}
