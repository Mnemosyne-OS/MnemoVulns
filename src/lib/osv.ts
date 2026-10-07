/**
 * osv — the OSV.dev API, called straight from the cartridge.
 *
 * Measured on 2026-10-04: `api.osv.dev` answers with CORS (the origin echoed
 * back, `POST` allowed), so no host relay is needed. The full database dump
 * has no CORS and is 217 MB for npm alone: it is NOT read here (doc 135,
 * MnemoVulns lot 1).
 *
 * Two calls:
 *  - `POST /v1/querybatch` with name@version queries: which record ids touch
 *    each one, with their `modified` date. Documented pagination: a result
 *    carries a `next_page_token` when it has more than ~1 000 records or the
 *    whole batch more than ~3 000, and only THAT query is asked again with
 *    its token. Never assume one page.
 *  - `GET /v1/vulns/<id>`: the record itself (summary, ranges, severity).
 *
 * 🚨 A batch that fails leaves its packages UNASKED, and they are reported as
 * such. A scan with unasked packages is partial and never reads "0".
 */
import type { InstalledPackage } from './lockfile';
import type { OsvRecord } from './advisory';

/** OSV.dev's public API. */
export const OSV_API = 'https://api.osv.dev/v1';
/** Queries per batch request. The documented paging limits are per record count, not per query. */
export const BATCH_SIZE = 500;
/** Deadline of one request (rule 9). A batch of 500 answers in about a second; 30 s is generous. */
export const REQUEST_TIMEOUT_MS = 30_000;
/** Records fetched at once. */
export const RECORD_CONCURRENCY = 6;
/** Paging rounds for one batch before giving up on the rest (the documented case needs one or two). */
export const MAX_PAGE_ROUNDS = 20;

export type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;

function withDeadline(signal: AbortSignal | undefined, timeoutMs: number): AbortSignal {
  const deadline = AbortSignal.timeout(timeoutMs);
  return signal ? AbortSignal.any([signal, deadline]) : deadline;
}

export interface Hit {
  id: string;
  modified: string;
}

export interface BatchOutcome {
  /** Record ids per `name@version`, for every package that was asked. */
  hits: Map<string, Hit[]>;
  /** Packages that were never answered for (failed batch, paging cut short). */
  unasked: InstalledPackage[];
  /** The first error met, for the screen. */
  error: string | null;
}

/** One installed package as a key (`eco:name@version`). */
export const pkgKey = (p: InstalledPackage): string => `${p.ecosystem}:${p.name}@${p.version}`;

interface BatchResult {
  vulns?: { id?: unknown; modified?: unknown }[];
  next_page_token?: unknown;
}

async function postBatch(fetcher: Fetcher, queries: object[], signal?: AbortSignal): Promise<BatchResult[]> {
  const res = await fetcher(`${OSV_API}/querybatch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queries }),
    signal: withDeadline(signal, REQUEST_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`HTTP_${res.status}`);
  const json = (await res.json()) as { results?: unknown };
  if (!Array.isArray(json.results) || json.results.length !== queries.length) {
    // A short answer cannot be matched back to its queries: none of them count as asked.
    throw new Error('OSV_BAD_ANSWER');
  }
  return json.results as BatchResult[];
}

function readHits(r: BatchResult): Hit[] {
  const out: Hit[] = [];
  for (const v of r.vulns ?? []) {
    if (typeof v?.id === 'string' && v.id) out.push({ id: v.id, modified: typeof v.modified === 'string' ? v.modified : '' });
  }
  return out;
}

/** Asks OSV about every package, batch by batch, following each query's pages. */
export async function queryPackages(
  fetcher: Fetcher,
  packages: readonly InstalledPackage[],
  opts: { signal?: AbortSignal; onProgress?: (asked: number, total: number) => void } = {},
): Promise<BatchOutcome> {
  const hits = new Map<string, Hit[]>();
  const unasked: InstalledPackage[] = [];
  let error: string | null = null;
  let asked = 0;

  for (let i = 0; i < packages.length; i += BATCH_SIZE) {
    const chunk = packages.slice(i, i + BATCH_SIZE);
    if (opts.signal?.aborted) { unasked.push(...chunk); continue; }
    const query = (p: InstalledPackage, token?: string) => ({
      package: { name: p.name, ecosystem: p.ecosystem }, version: p.version, ...(token ? { page_token: token } : {}),
    });
    try {
      const first = await postBatch(fetcher, chunk.map((p) => query(p)), opts.signal);
      const found = new Map<string, Hit[]>();
      let pending: { pkg: InstalledPackage; token: string }[] = [];
      first.forEach((r, k) => {
        const pkg = chunk[k]!;
        found.set(pkgKey(pkg), readHits(r));
        if (typeof r.next_page_token === 'string' && r.next_page_token) pending.push({ pkg, token: r.next_page_token });
      });
      let rounds = 0;
      while (pending.length > 0 && rounds < MAX_PAGE_ROUNDS && !opts.signal?.aborted) {
        rounds++;
        const more = await postBatch(fetcher, pending.map((p) => query(p.pkg, p.token)), opts.signal);
        const next: typeof pending = [];
        more.forEach((r, k) => {
          const { pkg } = pending[k]!;
          found.get(pkgKey(pkg))!.push(...readHits(r));
          if (typeof r.next_page_token === 'string' && r.next_page_token) next.push({ pkg, token: r.next_page_token });
        });
        pending = next;
      }
      // A query whose pages were not all read has an incomplete answer: it is not "asked".
      const cut = new Set(pending.map((p) => pkgKey(p.pkg)));
      if (cut.size > 0) error ??= opts.signal?.aborted ? 'ABORTED' : 'OSV_PAGING_CUT';
      for (const pkg of chunk) {
        if (cut.has(pkgKey(pkg))) unasked.push(pkg);
        else { hits.set(pkgKey(pkg), found.get(pkgKey(pkg)) ?? []); asked++; }
      }
    } catch (err) {
      unasked.push(...chunk);
      error ??= opts.signal?.aborted ? 'ABORTED' : err instanceof Error ? err.message : String(err);
      console.error('[mnemo-vulns] OSV batch failed', i, err);
    }
    opts.onProgress?.(asked, packages.length);
  }
  return { hits, unasked, error };
}

/** One OSV record by id. */
export async function fetchRecord(fetcher: Fetcher, id: string, signal?: AbortSignal): Promise<OsvRecord> {
  const res = await fetcher(`${OSV_API}/vulns/${encodeURIComponent(id)}`, { signal: withDeadline(signal, REQUEST_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`HTTP_${res.status}`);
  const rec = (await res.json()) as OsvRecord;
  if (!rec || rec.id !== id || typeof rec.modified !== 'string') throw new Error('OSV_BAD_RECORD');
  return rec;
}

/**
 * Runs `task` over `items`, `limit` at a time. Each item settles on its own:
 * one failure never cancels the others.
 */
export async function mapLimited<T, R>(items: readonly T[], limit: number, task: (item: T) => Promise<R>): Promise<PromiseSettledResult<R>[]> {
  const out: PromiseSettledResult<R>[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      try { out[i] = { status: 'fulfilled', value: await task(items[i]!) }; }
      catch (reason) { out[i] = { status: 'rejected', reason }; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

/**
 * Where a scan reads its data. Two implementations: the OSV.dev API (`apiSource`)
 * and the local mirror kept by the host (`mirror.ts`). The scan, the tracker
 * and the vault are the same whichever answers.
 */
export interface VulnSource {
  kind: 'api' | 'mirror';
  /**
   * Date of the data the answers come from, `null` for the API (live). A
   * mirror always has one: a scan against a mirror is complete only against
   * THAT date, and the screen says so.
   */
  asOf: string | null;
  hits(packages: readonly InstalledPackage[], opts?: { signal?: AbortSignal; onProgress?: (asked: number, total: number) => void }): Promise<BatchOutcome>;
  record(id: string, signal?: AbortSignal): Promise<OsvRecord>;
}

/** The OSV.dev API as a source. */
export function apiSource(fetcher: Fetcher): VulnSource {
  return {
    kind: 'api',
    asOf: null,
    hits: (packages, opts) => queryPackages(fetcher, packages, opts ?? {}),
    record: (id, signal) => fetchRecord(fetcher, id, signal),
  };
}
