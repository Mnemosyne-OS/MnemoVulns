import { describe, it, expect } from 'vitest';
import { GAUGE_BLOCKS, litBlocks, progressOf, rankOf } from './progress';

describe('progress', () => {
  it('scores only measured fixes: an accepted risk stays on the remaining side', () => {
    const p = progressOf({ fixed: 1, open: 1, accepted: 2 })!;
    expect(p).toEqual({ fixed: 1, remaining: 3, ratio: 0.25 });
  });

  it('shows no gauge when nothing is measured, and none for a summary without the counts', () => {
    expect(progressOf({ fixed: 0, open: 0, accepted: 0 })!.ratio).toBeNull();
    expect(progressOf({ open: 3 })).toBeNull();
  });

  it('keeps honest ends: a little lights a block, almost done leaves one dark', () => {
    expect(litBlocks(0)).toBe(0);
    expect(litBlocks(0.01)).toBe(1);
    expect(litBlocks(0.99)).toBe(GAUGE_BLOCKS - 1);
    expect(litBlocks(1)).toBe(GAUGE_BLOCKS);
  });

  it('calls a project cleared only when nothing is left, accepted risks included', () => {
    expect(rankOf(progressOf({ fixed: 4, open: 0, accepted: 0 })!)).toBe('cleared');
    expect(rankOf(progressOf({ fixed: 4, open: 0, accepted: 1 })!)).toBe('three');
    expect(rankOf(progressOf({ fixed: 0, open: 5, accepted: 0 })!)).toBe('start');
  });
});
