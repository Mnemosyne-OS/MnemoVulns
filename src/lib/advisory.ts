/**
 * advisory — what one OSV record says about one installed version.
 *
 * OSV (`api.osv.dev`) already decides WHICH records touch a name@version: its
 * `querybatch` answer is the authority for "affected". What this module adds
 * is read from the record itself:
 *
 *  - the version that fixes it, in THREE states, never a boolean:
 *      `fixed`   a `fixed` event closes the range the version sits in;
 *      `none`    the range is open, or closed by `last_affected`: no fixed
 *                release is published (measured on 2026-10-04: `braces`
 *                3.0.3, `adm-zip` up to 0.6.0);
 *      `unknown` the version matched another way (an explicit `versions`
 *                list, an ECOSYSTEM or GIT range): the record does not say.
 *  - the severity, as the record labels it, or UNKNOWN (no score is computed
 *    from a CVSS vector here: the label is the source's, not ours);
 *  - where the record comes from, and the licence of THAT source: OSV has no
 *    single licence, each database keeps its own (doc 135 §3sexies).
 */
import { compareVersions } from './semver';

export type Severity = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'UNKNOWN';
/** Severities from the most to the least urgent; the order every list is sorted by. */
export const SEVERITY_ORDER: readonly Severity[] = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'];

export type Fix =
  | { kind: 'fixed'; version: string }
  | { kind: 'none' }
  | { kind: 'unknown' }
  /** The record states its ranges in a form this module cannot order (a PEP 440 pre-release, say): open it. */
  | { kind: 'see' };

/** The fields of an OSV record this cartridge reads (OSV schema 1.x). */
export interface OsvRecord {
  id: string;
  modified: string;
  published?: string;
  withdrawn?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: { type: string; score: string }[];
  affected?: {
    package?: { ecosystem?: string; name?: string };
    ranges?: { type: string; events: Record<string, string>[] }[];
    versions?: string[];
    database_specific?: Record<string, unknown>;
  }[];
  references?: { type?: string; url?: string }[];
  database_specific?: Record<string, unknown>;
}

export interface Source {
  name: string;
  licence: string;
  licenceUrl: string;
}

/**
 * The page where OSV.dev lists each source with its licence (read on
 * 2026-10-04). Only the GitHub licence file was opened itself; the others
 * point here rather than at an address nobody checked.
 */
export const OSV_SOURCES_URL = 'https://google.github.io/osv.dev/data/';

/** Sources by id prefix, licences as OSV.dev lists them (read on 2026-10-04). */
const SOURCES: readonly [string, Source][] = [
  ['GHSA-', { name: 'GitHub Advisory Database', licence: 'CC-BY 4.0', licenceUrl: 'https://github.com/github/advisory-database/blob/main/LICENSE.md' }],
  ['MAL-', { name: 'OpenSSF Malicious Packages', licence: 'Apache 2.0', licenceUrl: OSV_SOURCES_URL }],
  ['PYSEC-', { name: 'PyPI Advisory Database', licence: 'CC-BY 4.0', licenceUrl: OSV_SOURCES_URL }],
  ['GO-', { name: 'Go Vulnerability Database', licence: 'CC-BY 4.0', licenceUrl: OSV_SOURCES_URL }],
  ['RUSTSEC-', { name: 'Rust Advisory Database', licence: 'CC0 1.0', licenceUrl: OSV_SOURCES_URL }],
  ['OSV-', { name: 'OSS-Fuzz', licence: 'CC-BY 4.0', licenceUrl: OSV_SOURCES_URL }],
];
const UNKNOWN_SOURCE: Source = { name: 'OSV.dev', licence: 'not stated for this source', licenceUrl: OSV_SOURCES_URL };

/** The database a record comes from, by its id prefix. */
export function sourceOf(id: string): Source {
  return SOURCES.find(([p]) => id.startsWith(p))?.[1] ?? UNKNOWN_SOURCE;
}

/** A record from the OpenSSF malicious-packages feed: the package itself is the threat. */
export function isMalicious(id: string): boolean {
  return id.startsWith('MAL-');
}

/** The record's own label, normalised (GitHub writes MODERATE, others MEDIUM). */
export function severityOf(rec: OsvRecord): Severity {
  const raw = rec.database_specific?.severity;
  if (typeof raw !== 'string') return 'UNKNOWN';
  const s = raw.toUpperCase();
  if (s === 'MEDIUM') return 'MODERATE';
  return (SEVERITY_ORDER as readonly string[]).includes(s) ? s as Severity : 'UNKNOWN';
}

export type Compare = (a: string, b: string) => -1 | 0 | 1 | null;

/**
 * How the versions of an ecosystem are ordered, for every door that compares
 * two fixed versions (the tile, the canvas card). One place: when the card
 * used semver for RubyGems and the tile compareGems, a Rails fix
 * (`6.1.7.5`, four segments) read "see the record" on the card and
 * "upgrade to 6.1.7.5" on the tile for the same package.
 */
export function versionOrder(ecosystem: string): Compare {
  if (ecosystem === 'PyPI') return compareReleases;
  if (ecosystem === 'RubyGems') return compareGems;
  return compareVersions;
}

/**
 * A package name as its registry compares it. PyPI names are case- and
 * separator-insensitive (PEP 503: `PyYAML`, `pyyaml`, `typing_extensions` and
 * `typing-extensions` are one project); OSV writes them lowercased while a
 * requirements file keeps the author's spelling. npm and crates.io compare as written.
 */
export function packageName(name: string, ecosystem: string): string {
  return ecosystem === 'PyPI' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name;
}

/**
 * PEP 440 versions (`3.2`, `3.2.0`, `3.2a1`, `1.0rc2`, `2.0.post1`,
 * `1.0.dev3`, `1!2.0`), compared the way pip orders them: epoch, release
 * (missing parts are zero, so `3.2` equals `3.2.0`), then a dev release
 * before its pre-releases, pre-releases (a < b < rc) before the release, and
 * post-releases after it. The spellings PEP 440 normalizes (`alpha`, `-rc.1`,
 * `c`) are accepted. A local version (`+cpu`) or anything else returns null:
 * not ordered here, never guessed.
 */
const PEP440 = /^(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?(?:(?:-(\d+))|(?:[-_.]?(?:post|rev|r)[-_.]?(\d*)))?(?:[-_.]?dev[-_.]?(\d*))?$/;
const PRE_RANK: Record<string, number> = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

function pep440Key(v: string): number[][] | null {
  const m = PEP440.exec(v.trim().toLowerCase().replace(/^v/, ''));
  if (!m) return null;
  const [, epoch, release, preL, preN, postImplicit, postN, devN] = m;
  const rel = release!.split('.').map(Number);
  const hasPost = postImplicit !== undefined || postN !== undefined;
  const dev = devN !== undefined ? Number(devN || 0) : null;
  // Phase: dev-only release < a < b < rc < release; post sorts after.
  const pre = preL !== undefined ? [PRE_RANK[preL]!, Number(preN || 0)] : dev !== null && !hasPost ? [-1, 0] : [3, 0];
  return [[Number(epoch ?? 0)], rel, pre, hasPost ? [1, Number(postImplicit ?? postN) || 0] : [0, 0], [dev === null ? 1 : 0, dev ?? 0]];
}

function cmpParts(x: number[], y: number[]): number {
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

export function compareReleases(a: string, b: string): -1 | 0 | 1 | null {
  if (a === '0' || b === '0') return a === b ? 0 : a === '0' ? -1 : 1;
  const x = pep440Key(a);
  const y = pep440Key(b);
  if (!x || !y) return null;
  for (let i = 0; i < x.length; i++) {
    const d = cmpParts(x[i]!, y[i]!);
    if (d !== 0) return d as -1 | 1;
  }
  return 0;
}

/**
 * Gem versions (`2.2.3`, `1.0.0.pre1`, `7.0.4.3`), compared the way
 * RubyGems does: segments split on dots and at letter/digit boundaries, a
 * number above any letters (`1.0.0` > `1.0.0.pre`), missing numbers as
 * zero. Anything else returns null.
 */
export function compareGems(a: string, b: string): -1 | 0 | 1 | null {
  if (a === '0' || b === '0') return a === b ? 0 : a === '0' ? -1 : 1;
  const parse = (v: string) => (/^\d+(?:\.[0-9A-Za-z]+)*$/.test(v) ? v.split('.').flatMap((s) => s.match(/\d+|[A-Za-z]+/g) ?? []).map((s) => (/^\d+$/.test(s) ? Number(s) : s)) : null);
  const x = parse(a);
  const y = parse(b);
  if (!x || !y) return null;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i] ?? 0;
    const q = y[i] ?? 0;
    if (p === q) continue;
    if (typeof p === 'number' && typeof q === 'number') return p < q ? -1 : 1;
    if (typeof p === 'number') return 1;
    if (typeof q === 'number') return -1;
    return p < q ? -1 : 1;
  }
  return 0;
}

/** How a range of this type is ordered for this ecosystem, or null when this module cannot order it. */
function comparatorFor(rangeType: string, ecosystem: string): Compare | null {
  if (rangeType === 'SEMVER') return compareVersions;
  if (rangeType === 'ECOSYSTEM' && ecosystem === 'PyPI') return compareReleases;
  if (rangeType === 'ECOSYSTEM' && (ecosystem === 'npm' || ecosystem === 'crates.io' || ecosystem === 'Go' || ecosystem === 'Packagist')) return compareVersions;
  if (rangeType === 'ECOSYSTEM' && ecosystem === 'RubyGems') return compareGems;
  return null;
}

const inRange = (cmp: Compare, v: string, lo: string, hi: string, inclusive: boolean): boolean | null => {
  const a = cmp(v, lo);
  const b = cmp(v, hi);
  if (a === null || b === null) return null;
  return a >= 0 && (inclusive ? b <= 0 : b < 0);
};

/**
 * The fix for `name@version` in this record. When several ranges contain the
 * version, the highest fixed version wins (all of them must be escaped), and
 * one range with no fix makes the whole answer `none`.
 */
export function fixFor(rec: OsvRecord, name: string, version: string, ecosystem = 'npm'): Fix {
  const fixes: { version: string; cmp: Compare }[] = [];
  let open = false;
  let matched = false;
  let unorderable = false;
  for (const a of rec.affected ?? []) {
    if (a.package?.ecosystem !== ecosystem || packageName(a.package?.name ?? '', ecosystem) !== packageName(name, ecosystem)) continue;
    for (const r of a.ranges ?? []) {
      const cmp = comparatorFor(r.type, ecosystem);
      if (!cmp) { if (r.type !== 'GIT') unorderable = true; continue; }
      let lo: string | null = null;
      for (const ev of r.events) {
        if (ev.introduced !== undefined) {
          lo = ev.introduced;
        } else if (lo !== null && ev.fixed !== undefined) {
          const hit = inRange(cmp, version, lo, ev.fixed, false);
          if (hit === null) unorderable = true;
          else if (hit) { matched = true; fixes.push({ version: ev.fixed, cmp }); }
          lo = null;
        } else if (lo !== null && ev.last_affected !== undefined) {
          const hit = inRange(cmp, version, lo, ev.last_affected, true);
          if (hit === null) unorderable = true;
          else if (hit) { matched = true; open = true; }
          lo = null;
        }
      }
      // An introduced event with nothing after it: affected from there on, no fix.
      if (lo !== null) {
        const c = cmp(version, lo);
        if (c === null) unorderable = true;
        else if (c >= 0) { matched = true; open = true; }
      }
    }
  }
  if (open) return { kind: 'none' };
  if (!matched) return unorderable ? { kind: 'see' } : { kind: 'unknown' };
  const highest = fixes.reduce((best, f) => (f.cmp(f.version, best.version) === 1 ? f : best));
  return { kind: 'fixed', version: highest.version };
}

/**
 * Whether this record touches `name@version`, decided here (the local mirror
 * serves records by package NAME; the API decides on its own side). A version
 * in the record's explicit `versions` list, or inside one of its SEMVER
 * ranges, is affected. A record with only ranges this module cannot read
 * (ECOSYSTEM, GIT) and no list touches nothing here: never a guess.
 */
export function affects(rec: OsvRecord, name: string, version: string, ecosystem = 'npm'): boolean {
  if (rec.withdrawn) return false;
  for (const a of rec.affected ?? []) {
    if (a.package?.ecosystem !== ecosystem || packageName(a.package?.name ?? '', ecosystem) !== packageName(name, ecosystem)) continue;
    if ((a.versions ?? []).some((v) => v === version || (ecosystem === 'PyPI' && compareReleases(v, version) === 0))) return true;
  }
  const k = fixFor(rec, name, version, ecosystem).kind;
  return k === 'fixed' || k === 'none';
}

/** The CVE ids this record is also known as. */
export function cveAliases(rec: OsvRecord): string[] {
  return (rec.aliases ?? []).filter((a) => a.startsWith('CVE-'));
}

/** The page where the record can be checked by anyone. */
export function osvUrl(id: string): string {
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}
