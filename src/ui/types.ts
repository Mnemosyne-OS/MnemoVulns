/**
 * Shared types of the MnemoVulns screens, plus the pure helpers they draw
 * with. Kept out of the .tsx files so each of those exports a component and
 * nothing else (Fast Refresh).
 */
import type { Key } from '../i18n/strings';
import { SEVERITY_ORDER, type Severity } from '../lib/advisory';
import type { ScanFailure, ProjectOutcome } from '../lib/project';
import type { ScanProgress } from '../lib/scan';
import type { Finding } from '../lib/scan';
import type { Via } from '../lib/lockfile';

/**
 * The "pulled by" sentence, one formatting for every surface that draws it
 * (a record's row and a version line of a tile): two copies drift into two
 * screens that say the same path differently.
 */
export function viaLine(t: T, via: readonly Via[], total?: number): string {
  const ways = via.map((w) => `${w.importer} ← ${w.through}${w.dev ? ` (${t('via.dev')})` : w.runtime ? ` (${t('via.runtime')})` : ''}`).join(' · ');
  const more = total && total > via.length ? ` · ${t('via.more', { n: total - via.length })}` : '';
  return `${t('via.label')} ${ways}${more}`;
}

/** The translator handed down from App. */
export type T = (key: Key, vars?: Record<string, string | number>) => string;

export type View = { kind: 'home' } | { kind: 'project'; root: string };

/** A scan in progress: what it measured so far, never a percentage it did not measure. */
export interface Job {
  root: string;
  startedAt: number;
  progress: ScanProgress | null;
}

/** The last answer of a project scan in this session. */
export type ScanView =
  | { kind: 'failed'; failure: ScanFailure }
  | { kind: 'done'; outcome: ProjectOutcome };

/** Findings of one package, worst first. */
export interface PackageGroup {
  /** `<ecosystem>:<name>`: two ecosystems can have a package of the same name. */
  key: string;
  ecosystem: string;
  name: string;
  versions: string[];
  worst: Severity;
  findings: Finding[];
}

const rank = (s: Severity) => SEVERITY_ORDER.indexOf(s);

/**
 * Groups findings by package, worst package first, malicious packages apart.
 * The same record on two versions of a package stays two findings.
 */
export function groupFindings(findings: readonly Finding[]): { malicious: PackageGroup[]; packages: PackageGroup[] } {
  const byName = new Map<string, Finding[]>();
  for (const f of findings) byName.set(`${f.ecosystem}:${f.name}`, [...(byName.get(`${f.ecosystem}:${f.name}`) ?? []), f]);
  const groups: PackageGroup[] = [...byName.entries()].map(([key, list]) => {
    const { ecosystem, name } = list[0]!;
    const sorted = [...list].sort((a, b) => rank(a.severity) - rank(b.severity) || a.id.localeCompare(b.id));
    return { key, ecosystem, name, versions: [...new Set(list.map((f) => f.version))].sort(), worst: sorted[0]!.severity, findings: sorted };
  });
  groups.sort((a, b) => rank(a.worst) - rank(b.worst) || b.findings.length - a.findings.length || a.name.localeCompare(b.name));
  return {
    malicious: groups.filter((g) => g.findings.some((f) => f.malicious)),
    packages: groups.filter((g) => !g.findings.some((f) => f.malicious)),
  };
}

/** Severity colours on the host's tokens (rule 12). */
export const SEVERITY_TOKEN: Record<Severity, string> = {
  CRITICAL: 'var(--danger, var(--accent))',
  HIGH: 'var(--warning, var(--accent))',
  MODERATE: 'var(--text-primary)',
  LOW: 'var(--text-muted)',
  UNKNOWN: 'var(--text-muted)',
};

/** The locale key of each severity. */
export const SEVERITY_KEY: Record<Severity, Key> = {
  CRITICAL: 'sev.CRITICAL', HIGH: 'sev.HIGH', MODERATE: 'sev.MODERATE', LOW: 'sev.LOW', UNKNOWN: 'sev.UNKNOWN',
};

/** What the home strip counts: only projects whose LAST scan was complete. */
export interface HomeTotals {
  /** Projects whose last scan was complete: the only ones summed. */
  counted: number;
  open: number;
  partial: number;
  never: number;
}

/** Sums the last complete scans; partial and never-scanned projects are counted apart, never added in. */
export function homeTotals(projects: readonly { lastScan?: { complete: boolean; open: number } }[]): HomeTotals {
  const t: HomeTotals = { counted: 0, open: 0, partial: 0, never: 0 };
  for (const p of projects) {
    if (!p.lastScan) t.never++;
    else if (!p.lastScan.complete) t.partial++;
    else { t.counted++; t.open += p.lastScan.open; }
  }
  return t;
}

/** The host mirror's state, as `vulns.mirrorStatus` answers it (main/vulns/osvMirror.ts). */
export interface MirrorState {
  ecosystem: string;
  phase: 'idle' | 'downloading' | 'building' | 'updating';
  startedAt: number | null;
  done: number | null;
  total: number | null;
  error: string | null;
  last: { kind: 'built' | 'updated' | 'upToDate'; count: number; at: string } | null;
  installed: { records: number; asOf: string; newestModified: string; sizeBytes: number | null } | null;
  unreadable: string | null;
}

/** What the home knows about the mirror: asking, refused (no permission, older host), or its state. */
export type MirrorView =
  | { kind: 'loading' }
  | { kind: 'error'; why: string }
  | { kind: 'ready'; state: MirrorState };

/** Megabytes in the reader's language ("217 MB", "217 Mo"). */
export function formatMb(bytes: number, lang: string): string {
  return new Intl.NumberFormat(lang, { style: 'unit', unit: 'megabyte', maximumFractionDigits: 0 }).format(bytes / 1e6);
}
