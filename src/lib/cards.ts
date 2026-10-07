/**
 * cards — a project's alert card on the canvas (doc 110, the cockpit; doc 135,
 * "les tuiles d'alerte").
 *
 * The host owns which cards are pinned; the cartridge only PUBLISHES what it
 * measured, and the person pins a card from the project's tile. A card says
 * the open vulnerabilities by severity and when the scan ran ("seen" is the
 * scan date, so the host's "seen 3 days ago" is literally how old the measure
 * is). A partial scan says it is partial on the card too.
 *
 * Tone: 'alert' while a critical or high vulnerability is open, 'neutral'
 * while anything is open, 'idle' when the last complete scan left nothing
 * open. A summary without per-severity counts never claims "nothing critical":
 * it is 'neutral' at most.
 */
import type { ProjectRecord, ToFix } from './library';
import { GAUGE_BLOCKS, progressOf } from './progress';

/** Prefix of every card id this cartridge publishes. */
export const CARD_PREFIX = 'vulns:';

export interface CardWords {
  open: string;
  partial: string;
  /** "{n} malicious": a malicious package outranks every severity. */
  malicious: string;
  /** One package to fix ({pkg} is the NAME only): "{pkg} → {version}", "{pkg}: remove it", "{pkg}: no fix", "{pkg}: see the record". */
  fixTo: string;
  fixRemove: string;
  fixNone: string;
  fixSee: string;
  /** "dev" after a dev-only package. */
  dev: string;
  /** "{fixed}/{total} fixed". */
  gauge: string;
  /** "+{n} new critical/high" on the status line. */
  fresh: string;
  sev: Record<'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW', string>;
}

export interface CardOut {
  id: string;
  title: string;
  mark: { label: string; tint: string | null; svg: string | null };
  status: string | null;
  seenAt: string | null;
  lines: string[];
  tone: 'live' | 'idle' | 'alert' | 'neutral';
  /** A dated measure (the scan), not a live feed: the host draws no silence line when this window closes. */
  snapshot: true;
  /**
   * The gauge's COUNTS, drawn by the host as coloured squares on as many
   * blocks as the cartridge's own gauge, so both light the same squares.
   * ABSENT when nothing was measured.
   */
  meter?: { done: number; total: number; blocks: number };
}

/** True when a set holds exactly these ids (an equal answer must not replace the state). */
export function sameMembers(cur: ReadonlySet<string>, ids: readonly string[]): boolean {
  const next = new Set(ids);
  return next.size === cur.size && [...next].every((id) => cur.has(id));
}

/** How old a card's "open" press may be when the cartridge mounts and still act on it (the press launched it). */
export const OPENED_RECENT_MS = 60_000;

/** The project a card id names, or null (a removed project, or another module's card). */
export function projectOfCard<P extends { slug: string }>(projects: readonly P[], id: string): P | null {
  return projects.find((p) => `${CARD_PREFIX}${p.slug}` === id) ?? null;
}

/**
 * Lines the host draws on a card (its MAX_LINES, cockpitModel.ts). It drops
 * the rest without a word, so the card is cut HERE, where the order is chosen:
 * the count, the severities, then the fixes that fit.
 */
export const CARD_LINES = 4;

/** A project's card id, stable across scans (its slug). */
export const cardId = (p: ProjectRecord) => `${CARD_PREFIX}${p.slug}`;

/**
 * One line of the card: the package, the gesture, and how many it closes.
 * Short on purpose: a card line is about 38 characters wide, and the old
 * "tar 6.2.1 → 7.5.21 · Critical ×12" was cut before its count. The installed
 * version and the severity are on the cartridge's tile.
 */
export function fixLine(x: ToFix, w: CardWords): string {
  const what = x.action.kind === 'to' ? w.fixTo.replace('{pkg}', x.name).replace('{version}', x.action.version)
    : (x.action.kind === 'remove' ? w.fixRemove : x.action.kind === 'none' ? w.fixNone : w.fixSee).replace('{pkg}', x.name);
  return `${what}${x.count > 1 ? ` (${x.count})` : ''}${x.dev ? ` · ${w.dev}` : ''}`;
}

/** The card of one scanned project, or null before its first scan (nothing to say). */
export function projectCard(p: ProjectRecord, w: CardWords): CardOut | null {
  const s = p.lastScan;
  if (!s) return null;
  const sev = s.openBySeverity;
  // The two worst severities present, count first: four of them never fit on one card line.
  const bySev = sev
    ? (['CRITICAL', 'HIGH', 'MODERATE', 'LOW'] as const).filter((k) => sev[k] > 0).slice(0, 2).map((k) => `${sev[k]} ${w.sev[k]}`).join(' · ')
    : '';
  const mal = s.openMalicious ?? 0;
  // The gauge only when something was measured: no square drawn for a summary without the counts.
  const prog = progressOf(s);
  const game = prog && prog.ratio !== null ? prog : null;
  const urgent = mal > 0 || (sev ? sev.CRITICAL + sev.HIGH > 0 : false);
  const tone: CardOut['tone'] = urgent ? 'alert' : s.open > 0 || !s.complete || !sev ? 'neutral' : 'idle';
  return {
    id: cardId(p),
    title: p.name,
    mark: { label: 'VU', tint: null, svg: null },
    // "Partial" rides on the status line: the lines are kept for what to fix.
    // The rank name stays in the cartridge: on the card it pushed the scan time off the line.
    status: w.open.replace('{n}', String(s.open)) + ((s.newUrgent ?? 0) > 0 ? ` · ${w.fresh.replace('{n}', String(s.newUrgent))}` : '') + (s.complete ? '' : ` · ${w.partial}`),
    seenAt: s.at,
    lines: [
      // The squares are the host's to draw (meter): the line says the count in words.
      game ? w.gauge.replace('{fixed}', String(game.fixed)).replace('{total}', String(game.fixed + game.remaining)) : '',
      bySev,
      ...(s.toFix ? s.toFix.map((x) => fixLine(x, w)) : [mal > 0 ? w.malicious.replace('{n}', String(mal)) : '']),
    ].filter(Boolean).slice(0, CARD_LINES),
    tone,
    snapshot: true,
    ...(game ? { meter: { done: game.fixed, total: game.fixed + game.remaining, blocks: GAUGE_BLOCKS } } : {}),
  };
}
