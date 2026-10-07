import { describe, it, expect, vi } from 'vitest';
import type { OsvRecord } from './advisory';
import { apiSource, type Fetcher } from './osv';
import { runScan, type RecordCache } from './scan';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const record = (id: string, modified: string, extra: Partial<OsvRecord> = {}): OsvRecord => ({
  id, modified, summary: `summary ${id}`, database_specific: { severity: 'HIGH' },
  affected: [{ package: { ecosystem: 'npm', name: 'tar' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '7.5.21' }] }] }],
  ...extra,
});

/** OSV says tar@7.5.13 is touched by the given ids; records are served from `served`. */
function osv(ids: { id: string; modified: string }[], served: Record<string, OsvRecord | number>) {
  return vi.fn<(...args: Parameters<Fetcher>) => ReturnType<Fetcher>>(async (url, init) => {
    if (url.endsWith('/querybatch')) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { name: string } }[] };
      return json({ results: queries.map((q) => (q.package.name === 'tar' ? { vulns: ids } : {})) });
    }
    const id = decodeURIComponent(url.split('/').pop()!);
    const r = served[id];
    return typeof r === 'number' ? json({}, r) : json(r);
  });
}

const lock = {
  kind: 'pnpm' as const, ecosystem: 'npm' as const,
  packages: [{ ecosystem: 'npm' as const, name: 'tar', version: '7.5.13' }, { ecosystem: 'npm' as const, name: 'ok', version: '1.0.0' }],
  skipped: [{ ecosystem: 'npm' as const, name: 'g', spec: 'git+x' }],
};
const locks = [{ file: 'pnpm-lock.yaml', read: lock }];

function memoryCache(start: Record<string, OsvRecord> = {}): RecordCache & { store: Record<string, OsvRecord> } {
  const store = { ...start };
  return { store, read: async (id) => store[id] ?? null, write: async (r) => { store[r.id] = r; } };
}

describe('runScan', () => {
  it('turns OSV hits into findings with severity and fix, and keeps the records', async () => {
    const cache = memoryCache();
    const res = await runScan({ sourceFor: () => apiSource(osv([{ id: 'GHSA-1', modified: 'm1' }], { 'GHSA-1': record('GHSA-1', 'm1') })), cache, locks });
    expect(res.complete).toBe(true);
    expect(res.asked).toBe(2);
    expect(res.skipped).toBe(1);
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0]).toMatchObject({ id: 'GHSA-1', name: 'tar', severity: 'HIGH', fix: { kind: 'fixed', version: '7.5.21' }, recordRead: true });
    expect(cache.store['GHSA-1']?.modified).toBe('m1');
  });

  it('reads a record from the folder when its date did not change (the delta)', async () => {
    const fetcher = osv([{ id: 'GHSA-1', modified: 'm1' }], {});
    const res = await runScan({ sourceFor: () => apiSource(fetcher), cache: memoryCache({ 'GHSA-1': record('GHSA-1', 'm1') }), locks });
    expect(fetcher.mock.calls.filter(([u]) => u.includes('/vulns/'))).toHaveLength(0);
    expect(res.recordsFromCache).toBe(1);
  });

  it('fetches again a record whose date changed', async () => {
    const cache = memoryCache({ 'GHSA-1': record('GHSA-1', 'old') });
    const res = await runScan({ sourceFor: () => apiSource(osv([{ id: 'GHSA-1', modified: 'new' }], { 'GHSA-1': record('GHSA-1', 'new') })), cache, locks });
    expect(res.recordsFromCache).toBe(0);
    expect(cache.store['GHSA-1']?.modified).toBe('new');
  });

  it('keeps a finding whose record could not be read, and calls the scan partial', async () => {
    const res = await runScan({ sourceFor: () => apiSource(osv([{ id: 'GHSA-1', modified: 'm1' }], { 'GHSA-1': 500 })), cache: memoryCache(), locks });
    expect(res.findings[0]).toMatchObject({ id: 'GHSA-1', severity: 'UNKNOWN', fix: { kind: 'unknown' }, recordRead: false });
    expect(res.complete).toBe(false);
    expect(res.error).toBe('RECORDS_UNREAD');
  });

  it('drops a record OSV marks withdrawn', async () => {
    const res = await runScan({ sourceFor: () => apiSource(osv([{ id: 'GHSA-1', modified: 'm1' }], { 'GHSA-1': record('GHSA-1', 'm1', { withdrawn: '2026-09-01' }) })), cache: memoryCache(), locks });
    expect(res.findings).toEqual([]);
  });

  it('never calls a scan with an unanswered batch complete', async () => {
    const fetcher: Fetcher = async () => json({}, 503);
    const res = await runScan({ sourceFor: () => apiSource(fetcher), cache: memoryCache(), locks });
    expect(res.findings).toEqual([]);
    expect(res.complete).toBe(false);
    expect(res.unasked).toBe(2);
    expect(res.installed.every((p) => !p.asked)).toBe(true);
  });
});
