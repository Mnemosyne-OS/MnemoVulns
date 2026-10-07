/**
 * progress — the game on top of the correction tracker (doc 135, Tony
 * 2026-10-04: "on fera un mode gamification").
 *
 * 🚨 Only a MEASURED fix scores: a scan saw the package at a version OSV no
 * longer names, or saw it leave the lockfile. An accepted risk scores nothing
 * (it is still there), and a vulnerability the database stopped naming scores
 * nothing (the code did not change). A game that paid for those would reward
 * hiding a vulnerability instead of fixing it.
 *
 * The gauge follows the To-do's arcade gauge (doc 96 §12.5): the measure
 * first, the theatre on top. Nothing measured = no gauge, never "100 %".
 */

/** Blocks in the gauge. */
export const GAUGE_BLOCKS = 16;

export interface Progress {
  /** Measured fixes. */
  fixed: number;
  /** Still affected: open plus accepted (an accepted risk is not a fix). */
  remaining: number;
  /** fixed / (fixed + remaining), or null when there is nothing to measure. */
  ratio: number | null;
}

/** The progress of one project from its tracker counts. Withdrawn entries are out of both sides. */
export function progressOf(counts: { fixed?: number; open: number; accepted?: number }): Progress | null {
  // A summary written before these counts existed carries no `fixed`: no gauge, never a zero.
  if (counts.fixed === undefined || counts.accepted === undefined) return null;
  const remaining = counts.open + counts.accepted;
  const total = counts.fixed + remaining;
  return { fixed: counts.fixed, remaining, ratio: total === 0 ? null : counts.fixed / total };
}

/**
 * Lit blocks for a ratio, with honest ends: anything above 0 lights at least
 * one block, anything below 1 leaves at least one dark. 3 % is not "nothing
 * done", 99 % is not "done".
 */
export function litBlocks(ratio: number, blocks = GAUGE_BLOCKS): number {
  if (!(ratio > 0)) return 0;
  if (ratio >= 1) return blocks;
  return Math.min(blocks - 1, Math.max(1, Math.round(ratio * blocks)));
}

export type Rank = 'start' | 'one' | 'two' | 'three' | 'cleared';

/** The rank shown next to the gauge. */
export function rankOf(p: Progress): Rank {
  if (p.ratio === null) return 'start';
  if (p.remaining === 0) return 'cleared';
  if (p.fixed === 0) return 'start';
  if (p.ratio < 1 / 3) return 'one';
  if (p.ratio < 2 / 3) return 'two';
  return 'three';
}
