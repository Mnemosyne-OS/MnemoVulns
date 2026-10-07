import { describe, it, expect } from 'vitest';
import type { OsvRecord } from './advisory';
import { mirrorSource } from './mirror';

const tarRec: OsvRecord = {
  id: 'GHSA-1', modified: 'm1',
  affected: [{ package: { ecosystem: 'npm', name: 'tar' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '7.0.0' }, { fixed: '7.5.16' }] }] }],
};

describe('mirrorSource', () => {
  it('decides affected versions itself, from the records the host returns by name', async () => {
    const src = mirrorSource({ query: async () => ({ asOf: '2026-10-04T00:00:00Z', records: [tarRec] }) });
    const out = await src.hits([{ ecosystem: 'npm' as const, name: 'tar', version: '7.5.13' }, { ecosystem: 'npm' as const, name: 'tar', version: '7.5.21' }]);
    expect(out.hits.get('npm:tar@7.5.13')).toEqual([{ id: 'GHSA-1', modified: 'm1' }]);
    expect(out.hits.get('npm:tar@7.5.21')).toEqual([]);
    expect(src.asOf).toBe('2026-10-04T00:00:00Z');
    expect((await src.record('GHSA-1')).id).toBe('GHSA-1');
  });

  it('leaves the packages of a failed host call UNASKED', async () => {
    const src = mirrorSource({ query: async () => { throw new Error('NO_MIRROR'); } });
    const out = await src.hits([{ ecosystem: 'npm' as const, name: 'tar', version: '7.5.13' }]);
    expect(out.unasked).toHaveLength(1);
    expect(out.error).toBe('NO_MIRROR');
    expect(out.hits.size).toBe(0);
  });

  it('refuses a mirror whose date changes in the middle of a scan', async () => {
    let n = 0;
    const src = mirrorSource({ query: async () => ({ asOf: n++ === 0 ? 'a' : 'b', records: [] }) });
    const many = Array.from({ length: 2_001 }, (_, i) => ({ ecosystem: 'npm' as const, name: `p${i}`, version: '1.0.0' }));
    const out = await src.hits(many);
    expect(out.error).toBe('MIRROR_CHANGED_DURING_SCAN');
    expect(out.unasked).toHaveLength(1);
  });
});
