import { describe, it, expect, vi } from 'vitest';
import { BATCH_SIZE, MAX_PAGE_ROUNDS, queryPackages, type Fetcher } from './osv';

type Q = { package: { name: string }; version: string; page_token?: string };

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const bodyOf = (init?: RequestInit) => JSON.parse(String(init?.body)) as { queries: Q[] };
const pkgs = (n: number) => Array.from({ length: n }, (_, i) => ({ ecosystem: 'npm' as const, name: `p${i}`, version: '1.0.0' }));

describe('queryPackages', () => {
  it('asks in batches and maps each answer back to its package', async () => {
    const fetcher = vi.fn<(...args: Parameters<Fetcher>) => ReturnType<Fetcher>>(async (_url, init) => {
      const { queries } = bodyOf(init);
      return json({ results: queries.map((q) => (q.package.name === 'p3' ? { vulns: [{ id: 'GHSA-a', modified: 'm1' }] } : {})) });
    });
    const out = await queryPackages(fetcher, pkgs(BATCH_SIZE * 2 + 1));
    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(out.unasked).toEqual([]);
    expect(out.error).toBeNull();
    expect(out.hits.get('npm:p3@1.0.0')).toEqual([{ id: 'GHSA-a', modified: 'm1' }]);
    expect(out.hits.get('npm:p4@1.0.0')).toEqual([]);
  });

  it('asks again ONLY the queries that returned a page token, with their token', async () => {
    const calls: Q[][] = [];
    const fetcher: Fetcher = async (_url, init) => {
      const { queries } = bodyOf(init);
      calls.push(queries);
      if (calls.length === 1) {
        return json({ results: queries.map((q) => (q.package.name === 'p1' ? { vulns: [{ id: 'A', modified: '' }], next_page_token: 'tok' } : {})) });
      }
      return json({ results: queries.map(() => ({ vulns: [{ id: 'B', modified: '' }] })) });
    };
    const out = await queryPackages(fetcher, pkgs(3));
    expect(calls[1]).toEqual([{ package: { name: 'p1', ecosystem: 'npm' }, version: '1.0.0', page_token: 'tok' }]);
    expect(out.hits.get('npm:p1@1.0.0')!.map((h) => h.id)).toEqual(['A', 'B']);
  });

  it('leaves a failed batch UNASKED, never answered with nothing', async () => {
    let n = 0;
    const fetcher: Fetcher = async (_url, init) => {
      n++;
      if (n === 2) return json({ error: 'busy' }, 503);
      return json({ results: bodyOf(init).queries.map(() => ({})) });
    };
    const out = await queryPackages(fetcher, pkgs(BATCH_SIZE + 2));
    expect(out.unasked).toHaveLength(2);
    expect(out.hits.has(`npm:p${BATCH_SIZE}@1.0.0`)).toBe(false);
    expect(out.error).toBe('HTTP_503');
  });

  it('refuses an answer whose length does not match the queries', async () => {
    const out = await queryPackages(async () => json({ results: [{}] }), pkgs(3));
    expect(out.unasked).toHaveLength(3);
    expect(out.error).toBe('OSV_BAD_ANSWER');
  });

  it('counts a query whose pages never end as unasked', async () => {
    const fetcher: Fetcher = async (_url, init) =>
      json({ results: bodyOf(init).queries.map(() => ({ vulns: [{ id: 'X', modified: '' }], next_page_token: 'again' })) });
    const out = await queryPackages(fetcher, pkgs(1));
    expect(out.unasked).toHaveLength(1);
    expect(out.error).toBe('OSV_PAGING_CUT');
    expect(MAX_PAGE_ROUNDS).toBeGreaterThan(1);
  });
});
