/**
 * packagePlan — what to DO about one package, read from its findings.
 *
 * The list of records says what is wrong; this says where to act: which
 * version to move to, how many records that closes, which installed version
 * is where (shipped or development, and who pulls it).
 *
 * 🚨 Honesty rules:
 *  - the target is the HIGHEST fixed version among the records, compared the
 *    way the ecosystem orders versions; a record with no published fix or an
 *    unstated fix is COUNTED apart, never folded into "closes";
 *  - two fixed versions that cannot be ordered give NO target (null), never
 *    the first one met;
 *  - the place of a version is "shipped" only when the lockfile says a
 *    production dependency reaches it, "dev" only when it says development
 *    only, and "unknown" when it does not say.
 */
import { SEVERITY_ORDER, versionOrder, type Compare, type Severity } from './advisory';
import type { Ecosystem, Via } from './lockfile';
import type { Finding } from './scan';
import { trackKey, type TrackEntry } from './tracking';

export type Place = 'shipped' | 'dev' | 'unknown';

/** One installed version of the package. */
export interface VersionPlan {
  version: string;
  place: Place;
  via?: Via[];
  viaTotal?: number;
  /** Records touching this version. */
  records: number;
  /** The version that closes every record of THIS version that has a fix; null when none or unorderable. */
  target: string | null;
}

/** The plan of one package. */
export interface PackagePlan {
  key: string;
  ecosystem: Ecosystem;
  name: string;
  worst: Severity;
  /** Records per severity, each record counted once even when it touches two versions. */
  bySeverity: Record<Severity, number>;
  /** The same, for the records still open only. */
  openBySeverity: Record<Severity, number>;
  /** Distinct records. */
  records: number;
  /** Distinct records still open, and accepted, per the tracker (a record with no entry is open). */
  open: number;
  accepted: number;
  /** The highest fixed version over all records, or null (none, or not orderable). */
  target: string | null;
  /** Distinct records that state a fixed version (all closed by `target`). */
  closes: number;
  /** Distinct records with no published fix. */
  noFix: number;
  /** Distinct records whose fix is not stated or not readable here. */
  unknownFix: number;
  /** Shipped when any version is shipped, dev when all are dev, unknown otherwise. */
  place: Place;
  versions: VersionPlan[];
}

const rank = (s: Severity) => SEVERITY_ORDER.indexOf(s);

/** The highest of the versions, or null when two of them cannot be ordered. */
function highest(versions: string[], cmp: Compare): string | null {
  let best: string | null = null;
  for (const v of versions) {
    if (best === null) { best = v; continue; }
    const c = cmp(v, best);
    if (c === null) return null;
    if (c === 1) best = v;
  }
  return best;
}

const placeOf = (dev: boolean | undefined): Place => (dev === false ? 'shipped' : dev === true ? 'dev' : 'unknown');

/** The plan of one package's findings (all with the same ecosystem and name). */
export function planPackage(findings: readonly Finding[], states: ReadonlyMap<string, TrackEntry>): PackagePlan {
  const first = findings[0]!;
  const cmp = versionOrder(first.ecosystem);
  const byId = new Map<string, Finding[]>();
  for (const f of findings) byId.set(f.id, [...(byId.get(f.id) ?? []), f]);

  const bySeverity: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 };
  const openBySeverity: Record<Severity, number> = { ...bySeverity };
  let open = 0, accepted = 0, closes = 0, noFix = 0, unknownFix = 0;
  const fixedVersions: string[] = [];
  for (const [id, list] of byId) {
    const worst = list.reduce((w, f) => (rank(f.severity) < rank(w) ? f.severity : w), list[0]!.severity);
    bySeverity[worst]++;
    const state = states.get(trackKey(id, first.name, first.ecosystem))?.state;
    if (state === 'accepted') accepted++;
    else if (state === undefined || state === 'open') { open++; openBySeverity[worst]++; }
    // A record is closed by a version only when EVERY version it touches has a stated fix.
    if (list.some((f) => f.fix.kind === 'none')) noFix++;
    else if (list.every((f) => f.fix.kind === 'fixed')) { closes++; for (const f of list) if (f.fix.kind === 'fixed') fixedVersions.push(f.fix.version); }
    else unknownFix++;
  }

  const byVersion = new Map<string, Finding[]>();
  for (const f of findings) byVersion.set(f.version, [...(byVersion.get(f.version) ?? []), f]);
  const versions: VersionPlan[] = [...byVersion.entries()].map(([version, list]) => {
    const f = list[0]!;
    const fixes = list.flatMap((x) => (x.fix.kind === 'fixed' ? [x.fix.version] : []));
    return {
      version,
      place: placeOf(f.dev),
      ...(f.via ? { via: f.via } : {}),
      ...(f.viaTotal ? { viaTotal: f.viaTotal } : {}),
      records: new Set(list.map((x) => x.id)).size,
      target: fixes.length ? highest(fixes, cmp) : null,
    };
  });
  // Shipped versions first: they are the ones to fix first.
  const placeRank: Record<Place, number> = { shipped: 0, unknown: 1, dev: 2 };
  versions.sort((a, b) => placeRank[a.place] - placeRank[b.place] || (cmp(b.version, a.version) ?? 0));

  const place: Place = versions.some((v) => v.place === 'shipped') ? 'shipped'
    : versions.every((v) => v.place === 'dev') ? 'dev' : 'unknown';
  const worst = SEVERITY_ORDER.find((s) => bySeverity[s] > 0) ?? 'UNKNOWN';

  return {
    key: `${first.ecosystem}:${first.name}`,
    ecosystem: first.ecosystem,
    name: first.name,
    worst,
    bySeverity,
    openBySeverity,
    records: byId.size,
    open,
    accepted,
    target: fixedVersions.length ? highest(fixedVersions, cmp) : null,
    closes,
    noFix,
    unknownFix,
    place,
    versions,
  };
}

export type PlanFilter = 'all' | 'shipped' | 'dev' | 'unknown';

/**
 * Plans every package, the ones to act on first at the top: open records
 * before settled ones, shipped before dev, then the worst severity, then the
 * most records.
 */
export function planAll(findings: readonly Finding[], states: ReadonlyMap<string, TrackEntry>): PackagePlan[] {
  const byPkg = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.malicious) continue;
    const k = `${f.ecosystem}:${f.name}`;
    byPkg.set(k, [...(byPkg.get(k) ?? []), f]);
  }
  const placeRank: Record<Place, number> = { shipped: 0, unknown: 1, dev: 2 };
  return [...byPkg.values()].map((list) => planPackage(list, states)).sort((a, b) =>
    Number(a.open === 0) - Number(b.open === 0)
    || placeRank[a.place] - placeRank[b.place]
    || rank(a.worst) - rank(b.worst)
    || b.records - a.records
    || a.name.localeCompare(b.name));
}

/**
 * The plans a filter keeps. Each place is its own filter: a package whose
 * lockfile says nothing (Cargo.lock, uv.lock, yarn) is NOT "in the product",
 * or the filter and the header would claim what every tile says is unknown.
 */
export function filterPlans(plans: readonly PackagePlan[], filter: PlanFilter): PackagePlan[] {
  if (filter === 'all') return [...plans];
  return plans.filter((p) => p.place === filter);
}

/** What the project header shows next to the measure: open records by severity, where they are, where to start. */
export interface PlanOverview {
  openBySeverity: Record<Severity, number>;
  /** Open records in packages that ship, in dev-only packages, and where the lockfile does not say. */
  openShipped: number;
  openDev: number;
  openUnknown: number;
  /**
   * Malicious packages with an open record. They are not plans (they have
   * their own section), but a header that counts everything else would read
   * as complete above a section that lists one more.
   */
  openMalicious: number;
  /** The first packages to act on: open, shipped, with a version that fixes them, in tile order. */
  start: PackagePlan[];
}

/** Sums the plans (already in planAll order) for the header. */
export function overviewOf(plans: readonly PackagePlan[], opts: { openMalicious?: number; startCount?: number } = {}): PlanOverview {
  const openBySeverity: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MODERATE: 0, LOW: 0, UNKNOWN: 0 };
  let openShipped = 0;
  let openDev = 0;
  let openUnknown = 0;
  for (const p of plans) {
    for (const s of SEVERITY_ORDER) openBySeverity[s] += p.openBySeverity[s];
    if (p.place === 'dev') openDev += p.open;
    else if (p.place === 'shipped') openShipped += p.open;
    else openUnknown += p.open;
  }
  // Starting points: not known to be dev only, in tile order (shipped first).
  const start = plans.filter((p) => p.open > 0 && p.place !== 'dev' && p.target !== null).slice(0, opts.startCount ?? 3);
  return { openBySeverity, openShipped, openDev, openUnknown, openMalicious: opts.openMalicious ?? 0, start };
}
