/**
 * mirror — the host's local copy of OSV as a `VulnSource` (doc 135).
 *
 * The host answers by package NAME (every record that names the package);
 * which installed versions are affected is decided HERE, with `affects()`,
 * the same semver logic the API path was measured against (329 = 329).
 *
 * The answers are true for the mirror's date (`asOf`), which the scan carries
 * to the screen: a scan against a mirror is complete against THAT date only.
 */
import { affects, type OsvRecord } from './advisory';
import type { Ecosystem, InstalledPackage } from './lockfile';
import { pkgKey, type BatchOutcome, type Hit, type VulnSource } from './osv';

/** Names asked per host call: the host caps one query at 20 000. */
export const MIRROR_CHUNK = 2_000;

export interface MirrorPort {
  query(names: string[]): Promise<{ asOf: string; records: unknown[] }>;
}

/** The host mirror of one ecosystem as a source. */
export function mirrorSource(port: MirrorPort, ecosystem: Ecosystem = 'npm'): VulnSource {
  const seen = new Map<string, OsvRecord>();
  let asOf: string | null = null;
  return {
    kind: 'mirror',
    get asOf() { return asOf; },
    async hits(packages: readonly InstalledPackage[], opts = {}): Promise<BatchOutcome> {
      const byName = new Map<string, InstalledPackage[]>();
      const unasked: InstalledPackage[] = [];
      for (const p of packages) {
        // This mirror holds one ecosystem: anything else is unasked, never answered with nothing.
        if (p.ecosystem !== ecosystem) { unasked.push(p); continue; }
        byName.set(p.name, [...(byName.get(p.name) ?? []), p]);
      }
      const names = [...byName.keys()];
      const hits = new Map<string, Hit[]>();
      let error: string | null = unasked.length ? 'MIRROR_OTHER_ECOSYSTEM' : null;
      let asked = 0;
      for (let i = 0; i < names.length; i += MIRROR_CHUNK) {
        const chunk = names.slice(i, i + MIRROR_CHUNK);
        const pkgs = chunk.flatMap((n) => byName.get(n)!);
        if (opts.signal?.aborted) { unasked.push(...pkgs); error ??= 'ABORTED'; continue; }
        try {
          const res = await port.query(chunk);
          if (typeof res?.asOf !== 'string' || !Array.isArray(res.records)) throw new Error('MIRROR_BAD_ANSWER');
          // One mirror, one date: a date that changes mid-scan means a delta landed in between.
          if (asOf !== null && asOf !== res.asOf) throw new Error('MIRROR_CHANGED_DURING_SCAN');
          asOf = res.asOf;
          const recs = res.records.filter((r): r is OsvRecord => !!r && typeof (r as OsvRecord).id === 'string' && typeof (r as OsvRecord).modified === 'string');
          for (const r of recs) seen.set(r.id, r);
          for (const p of pkgs) {
            hits.set(pkgKey(p), recs.filter((r) => affects(r, p.name, p.version, ecosystem)).map((r) => ({ id: r.id, modified: r.modified })));
            asked++;
          }
        } catch (err) {
          unasked.push(...pkgs);
          error ??= err instanceof Error ? err.message : String(err);
          console.error('[mnemo-vulns] mirror query failed', err);
        }
        opts.onProgress?.(asked, packages.length);
      }
      return { hits, unasked, error };
    },
    async record(id: string): Promise<OsvRecord> {
      const r = seen.get(id);
      if (!r) throw new Error(`NOT_IN_MIRROR:${id}`);
      return r;
    },
  };
}
