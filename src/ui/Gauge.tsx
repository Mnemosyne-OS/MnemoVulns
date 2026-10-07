/**
 * Gauge — the arcade gauge of measured fixes (doc 135, gamification). Static:
 * nothing moves on its own, so there is nothing to switch off under
 * prefers-reduced-motion.
 */
import { GAUGE_BLOCKS, litBlocks, rankOf, type Progress } from '../lib/progress';
import { S } from './styles';
import type { T } from './types';

/** The gauge, its rank and the count behind it. Renders nothing without a measure. */
export function Gauge({ t, progress }: { t: T; progress: Progress | null }) {
  if (!progress || progress.ratio === null) return null;
  const lit = litBlocks(progress.ratio);
  const rank = rankOf(progress);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }} role="img" aria-label={t('game.aria', { fixed: progress.fixed, remaining: progress.remaining })}>
      <div style={{ display: 'flex', gap: 2 }}>
        {Array.from({ length: GAUGE_BLOCKS }, (_, i) => (
          <span key={i} style={{
            width: 10, height: 12, borderRadius: 2,
            background: i < lit ? 'var(--accent)' : 'var(--bg-void)',
            border: '1px solid var(--border-subtle)',
          }} />
        ))}
      </div>
      <div style={S.small}>
        <strong>{t(`game.rank.${rank}`)}</strong> · {t('game.count', { fixed: progress.fixed, remaining: progress.remaining })}
      </div>
    </div>
  );
}
