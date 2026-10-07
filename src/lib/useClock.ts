/**
 * useClock — the current time, refreshed once a second while `running`.
 *
 * 🪤 The first version keyed the interval on the JOB object. The job is
 * replaced on every progress event (one per article, ~0.1 s apart), so the
 * interval was torn down and rebuilt before its first tick: the screen read
 * "250 / 3398 · 0 s" for the whole import and the remaining time never
 * appeared (field report 2026-10-03). The clock now depends on a boolean
 * only, so progress events cannot reset it.
 */
import { useEffect, useState } from 'react';

/** The current time, refreshed every `periodMs` while `running`, frozen otherwise. */
export function useClock(running: boolean, periodMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!running) return;
    setNow(Date.now());
    const id = window.setInterval(() => setNow(Date.now()), periodMs);
    return () => window.clearInterval(id);
  }, [running, periodMs]);
  return now;
}
