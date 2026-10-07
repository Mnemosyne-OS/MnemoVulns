/**
 * tracking — what happened to each vulnerability of a project, scan after scan
 * (doc 135, decisions of 2026-10-04).
 *
 * One entry per (record id, package name). Its state:
 *  - `open`      the last scan measured an affected version;
 *  - `accepted`  still affected, and the person wrote WHY they keep it;
 *  - `fixed`     MEASURED: the package is now at a version OSV no longer
 *                names (`upgraded`), or it left the lockfile (`removed`);
 *  - `withdrawn` the SAME version is installed and OSV no longer names the
 *                record (the database changed, the code did not).
 *
 * 🚨 The rules that keep the tracker honest (and the game built on it later):
 *  - `fixed` is never set by a click. Only a scan that measured the package
 *    can set it.
 *  - A vulnerability that disappears while the installed version did not
 *    change is `withdrawn`, NEVER `fixed`.
 *  - A package that was not asked (failed batch) changes NOTHING: no
 *    measurement, no transition.
 *  - A package missing from a lockfile that could not be read entirely does
 *    not count as removed: `removed` needs a complete lockfile read.
 *  - `accepted` needs a written reason; an empty one is refused.
 *  - A vulnerability that comes back after `fixed` or `withdrawn` reopens.
 */
import { packageName } from './advisory';
import type { Finding } from './scan';

export type TrackState = 'open' | 'accepted' | 'fixed' | 'withdrawn';

export interface TrackEntry {
  id: string;
  /**
   * Absent = npm. Every entry written before other ecosystems existed is npm:
   * the cartridge read nothing else then. A real default, not an invention.
   */
  ecosystem?: string;
  name: string;
  /** Versions measured as affected at the last scan that saw it. */
  versions: string[];
  state: TrackState;
  /** When the current state began. */
  since: string;
  firstSeen: string;
  fixedBy?: 'upgraded' | 'removed';
  /** The versions installed when it was measured fixed by an upgrade. */
  fixedWith?: string[];
  reason?: string;
}

export interface Tracking {
  entries: TrackEntry[];
}

/** A project's tracking before its first scan. */
export const EMPTY_TRACKING: Tracking = { entries: [] };

/** One key per (record, package), the ecosystem part of the package (npm keys stay as they were written). */
export const trackKey = (id: string, name: string, ecosystem = 'npm'): string =>
  ecosystem === 'npm' ? `${id}|${name}` : `${id}|${ecosystem}:${packageName(name, ecosystem)}`;

/**
 * The package part of a key. A PyPI name is compared as PyPI compares it, so
 * moving from requirements.txt (`Django`) to poetry.lock (`django`) keeps the
 * same entry instead of reading "removed" then "new".
 */
const pkgOf = (e: { name: string; ecosystem?: string }) =>
  (e.ecosystem && e.ecosystem !== 'npm' ? `${e.ecosystem}:${packageName(e.name, e.ecosystem)}` : e.name);

const STATES: readonly TrackState[] = ['open', 'accepted', 'fixed', 'withdrawn'];
const strs = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

/** Reads a stored tracking file defensively: an entry missing a field is dropped, never invented. */
export function parseTracking(raw: unknown): Tracking {
  const r = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const entries: TrackEntry[] = [];
  for (const v of Array.isArray(r.entries) ? r.entries : []) {
    if (!v || typeof v !== 'object') continue;
    const e = v as Record<string, unknown>;
    if (typeof e.id !== 'string' || typeof e.name !== 'string' || !STATES.includes(e.state as TrackState)) continue;
    if (typeof e.since !== 'string' || typeof e.firstSeen !== 'string') continue;
    if (e.state === 'accepted' && (typeof e.reason !== 'string' || !e.reason.trim())) continue;
    entries.push({
      id: e.id, ...(typeof e.ecosystem === 'string' && e.ecosystem !== 'npm' ? { ecosystem: e.ecosystem } : {}), name: e.name, versions: strs(e.versions), state: e.state as TrackState, since: e.since, firstSeen: e.firstSeen,
      ...(e.fixedBy === 'upgraded' || e.fixedBy === 'removed' ? { fixedBy: e.fixedBy } : {}),
      ...(Array.isArray(e.fixedWith) ? { fixedWith: strs(e.fixedWith) } : {}),
      ...(typeof e.reason === 'string' && e.reason.trim() ? { reason: e.reason } : {}),
    });
  }
  return { entries };
}

/** What a scan measured, as the tracker needs it. */
export interface Measurement {
  at: string;
  findings: readonly (Pick<Finding, 'id' | 'name' | 'version'> & { ecosystem?: string })[];
  installed: readonly { ecosystem?: string; name: string; version: string; asked: boolean }[];
  /** The lockfile was read in full (always true today; false would forbid `removed`). */
  lockfileComplete: boolean;
}

/** The tracker after one scan. Pure: same inputs, same output. */
export function reconcile(prev: Tracking, m: Measurement): Tracking {
  const byKey = new Map(prev.entries.map((e) => [trackKey(e.id, e.name, e.ecosystem), e]));
  const seen = new Map<string, { id: string; name: string; ecosystem: string; versions: string[] }>();
  for (const f of m.findings) {
    const eco = f.ecosystem ?? 'npm';
    const k = trackKey(f.id, f.name, eco);
    const cur = seen.get(k) ?? { id: f.id, name: f.name, ecosystem: eco, versions: [] };
    if (!cur.versions.includes(f.version)) cur.versions.push(f.version);
    seen.set(k, cur);
  }
  const installed = new Map<string, { versions: string[]; allAsked: boolean }>();
  for (const p of m.installed) {
    const key = pkgOf(p);
    const cur = installed.get(key) ?? { versions: [], allAsked: true };
    cur.versions.push(p.version);
    if (!p.asked) cur.allAsked = false;
    installed.set(key, cur);
  }

  const out: TrackEntry[] = [];
  const done = new Set<string>();

  for (const [k, s] of seen) {
    const old = byKey.get(k);
    const sorted = [...s.versions].sort();
    if (!old) {
      out.push({ id: s.id, ...(s.ecosystem !== 'npm' ? { ecosystem: s.ecosystem } : {}), name: s.name, versions: sorted, state: 'open', since: m.at, firstSeen: m.at });
    } else if (old.state === 'open' || old.state === 'accepted') {
      out.push({ ...old, versions: sorted });
    } else {
      // Fixed or withdrawn, and measured again: it came back.
      const { fixedBy: _b, fixedWith: _w, reason: _r, ...base } = old;
      out.push({ ...base, versions: sorted, state: 'open', since: m.at });
    }
    done.add(k);
  }

  for (const old of prev.entries) {
    const k = trackKey(old.id, old.name, old.ecosystem);
    if (done.has(k)) continue;
    done.add(k);
    if (old.state === 'fixed' || old.state === 'withdrawn') { out.push(old); continue; }
    const inst = installed.get(pkgOf(old));
    if (!inst) {
      out.push(m.lockfileComplete ? { ...old, state: 'fixed', since: m.at, fixedBy: 'removed' } : old);
      continue;
    }
    if (!inst.allAsked) { out.push(old); continue; } // not measured: nothing changes
    const stillThere = old.versions.some((v) => inst.versions.includes(v));
    if (stillThere) {
      out.push({ ...old, state: 'withdrawn', since: m.at });
    } else {
      out.push({ ...old, state: 'fixed', since: m.at, fixedBy: 'upgraded', fixedWith: [...inst.versions].sort() });
    }
  }

  const order = (e: TrackEntry) => `${e.id}|${pkgOf(e)}`;
  out.sort((a, b) => (order(a) < order(b) ? -1 : order(a) > order(b) ? 1 : 0));
  return { entries: out };
}

/** Accepts the risk of an open entry. A blank reason is refused (returns null). */
export function accept(t: Tracking, id: string, name: string, reason: string, at: string, ecosystem = 'npm'): Tracking | null {
  const why = reason.trim();
  if (!why) return null;
  let changed = false;
  const entries = t.entries.map((e) => {
    if (trackKey(e.id, e.name, e.ecosystem) !== trackKey(id, name, ecosystem) || e.state !== 'open') return e;
    changed = true;
    return { ...e, state: 'accepted' as const, since: at, reason: why };
  });
  return changed ? { entries } : null;
}

/** Takes an accepted risk back: the entry is open again. */
export function reopen(t: Tracking, id: string, name: string, at: string, ecosystem = 'npm'): Tracking | null {
  let changed = false;
  const entries = t.entries.map((e) => {
    if (trackKey(e.id, e.name, e.ecosystem) !== trackKey(id, name, ecosystem) || e.state !== 'accepted') return e;
    changed = true;
    const { reason: _r, ...rest } = e;
    return { ...rest, state: 'open' as const, since: at };
  });
  return changed ? { entries } : null;
}

/** Counts per state. */
export function tally(t: Tracking): Record<TrackState, number> {
  const c: Record<TrackState, number> = { open: 0, accepted: 0, fixed: 0, withdrawn: 0 };
  for (const e of t.entries) c[e.state]++;
  return c;
}
