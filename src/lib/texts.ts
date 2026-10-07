/**
 * texts — what MnemoVulns writes for a reader who is not looking at the screen:
 * the chronicle of one advisory in the vault, the report of one scan in the
 * person's folder, and the attribution file next to the kept records.
 *
 * These texts are written in English whatever the interface language: they
 * are read by agents and by the chat, and the advisories themselves are in
 * English. Every chronicle closes on its source, its licence, its date and
 * the address where anyone can check it.
 */
import { OSV_SOURCES_URL, SEVERITY_ORDER, cveAliases, osvUrl, severityOf, sourceOf, type OsvRecord } from './advisory';
import type { Finding, ScanResult } from './scan';
import { trackKey, type Tracking } from './tracking';

/** The report's "pulled by" note: `[via apps/web <- astro; . <- vitest (dev)]`, nothing when unknown. */
function viaText(f: Finding): string {
  if (!f.via?.length) return '';
  const ways = f.via.map((w) => `${w.importer} <- ${w.through}${w.dev ? ' (dev)' : w.runtime ? ' (app runtime)' : ''}`);
  const more = f.viaTotal && f.viaTotal > f.via.length ? `; +${f.viaTotal - f.via.length} more` : '';
  return ` [via ${ways.join('; ')}${more}]`;
}

/** Spine type of every MnemoVulns chronicle (free text for the host, `^[A-Z][A-Z0-9_]{2,39}$`). */
export const SPINE = 'VULNERABILITY';
/** Longest `details` kept in a chronicle: the chat cuts sources further anyway (doc 120). */
export const DETAILS_CAP = 3_000;

/** The source reference of a record's chronicle: one per id and per `modified` date (the delta). */
export function recordRef(rec: OsvRecord): string {
  return `osv:${rec.id}@${rec.modified}`;
}

/** The chronicle of one OSV record. */
export function recordChronicle(rec: OsvRecord): string {
  const src = sourceOf(rec.id);
  const affected = (rec.affected ?? [])
    .filter((a) => a.package?.name)
    .map((a) => {
      const ranges = (a.ranges ?? []).filter((r) => r.type === 'SEMVER').map((r) =>
        r.events.map((e) => Object.entries(e).map(([k, v]) => `${k} ${v}`).join('')).join(', '),
      );
      return `- ${a.package!.ecosystem ?? '?'} ${a.package!.name}${ranges.length ? `: ${ranges.join(' | ')}` : ''}`;
    });
  const details = (rec.details ?? '').trim();
  const cut = details.length > DETAILS_CAP;
  return [
    `# ${rec.id}${rec.summary ? `: ${rec.summary.trim()}` : ''}`,
    '',
    `Severity (as labelled by the source): ${severityOf(rec)}`,
    ...(cveAliases(rec).length ? [`Also known as: ${cveAliases(rec).join(', ')}`] : []),
    ...(rec.withdrawn ? [`Withdrawn by the source on ${rec.withdrawn}.`] : []),
    '',
    'Affected packages and ranges:',
    ...(affected.length ? affected : ['- not stated in the record']),
    ...(details ? ['', cut ? `${details.slice(0, DETAILS_CAP)}\n[details cut at ${DETAILS_CAP} characters, full text at the address below]` : details] : []),
    '',
    `Source: ${src.name}, via OSV.dev. Licence: ${src.licence} (${src.licenceUrl}).`,
    `Record modified: ${rec.modified}${rec.published ? `, published: ${rec.published}` : ''}.`,
    `Check it: ${osvUrl(rec.id)}`,
  ].join('\n');
}

/** The ATTRIBUTION.md next to the kept records. */
export function attributionText(): string {
  return [
    '# Vulnerability records in this folder',
    '',
    'MnemoVulns downloaded these records from the OSV.dev API (https://osv.dev). OSV.dev gathers several databases, and each keeps its own licence. Each record names its source in its id prefix; the licence of every source is listed by OSV.dev at:',
    '',
    OSV_SOURCES_URL,
    '',
    '- GHSA-…: GitHub Advisory Database, CC-BY 4.0 (https://github.com/github/advisory-database/blob/main/LICENSE.md)',
    '- MAL-…: OpenSSF Malicious Packages, Apache 2.0',
    '- other prefixes: see the page above.',
    '',
    'Each file is the record as OSV.dev served it, unchanged.',
    '',
  ].join('\n');
}

const fixText = (f: ScanResult['findings'][number]['fix']) =>
  f.kind === 'fixed' ? `fixed in ${f.version}` : f.kind === 'none' ? 'no fixed release published' : f.kind === 'see' ? 'fix stated in the record' : 'fix not stated';

/** The Markdown report of one scan, with the tracker's states. */
export function reportText(project: string, scan: ScanResult, tracking: Tracking): string {
  const state = new Map(tracking.entries.map((e) => [trackKey(e.id, e.name, e.ecosystem), e]));
  const head = [
    `# MnemoVulns report: ${project}`,
    '',
    `Scanned: ${scan.at}`,
    `Lockfiles: ${scan.lockfiles.join(', ')}`,
    ...scan.sources.map((s) => `${s.ecosystem}: ${s.kind === 'mirror' && s.asOf ? `local database of ${s.asOf}` : 'OSV.dev online'}`),
    `Packages asked: ${scan.asked} of ${scan.packages}${scan.skipped ? `, plus ${scan.skipped} with no pinned registry version (unpinned, link, file, git, workspace), not asked` : ''}`,
    scan.complete
      ? 'Scan: complete.'
      : `Scan: PARTIAL (${scan.unasked} packages not asked, ${scan.recordsUnread} records not read${scan.error ? `, ${scan.error}` : ''}). A partial scan does not show every vulnerability.`,
    `Known vulnerabilities: ${scan.findings.length}`,
    '',
  ];
  const rows = [...scan.findings].sort((a, b) =>
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id),
  ).map((f) => {
    const t = state.get(trackKey(f.id, f.name, f.ecosystem));
    const tracked = t ? ` [${t.state}${t.reason ? `: ${t.reason}` : ''}]` : '';
    return `- ${f.severity} ${f.ecosystem === 'npm' ? '' : `${f.ecosystem} `}${f.name}@${f.version} ${f.id}${f.aliases.length ? ` (${f.aliases.join(', ')})` : ''}: ${f.summary ?? 'record not read'}; ${fixText(f.fix)}${f.dev === true ? ' [declared dev dependency]' : ''}${viaText(f)}${tracked}`;
  });
  const fixed = tracking.entries.filter((e) => e.state === 'fixed').map((e) =>
    `- ${e.id} ${e.name}: fixed on ${e.since} (${e.fixedBy === 'removed' ? 'package removed' : `now ${(e.fixedWith ?? []).join(', ')}`})`,
  );
  const withdrawn = tracking.entries.filter((e) => e.state === 'withdrawn').map((e) =>
    `- ${e.id} ${e.name}: no longer named by OSV on ${e.since}, version unchanged (${e.versions.join(', ')})`,
  );
  return [
    ...head,
    ...(rows.length ? ['## Vulnerabilities', '', ...rows, ''] : []),
    ...(fixed.length ? ['## Fixed (measured)', '', ...fixed, ''] : []),
    ...(withdrawn.length ? ['## No longer named by the database (not a fix)', '', ...withdrawn, ''] : []),
    'Source: OSV.dev. Licences per source: see ATTRIBUTION.md.',
    '',
  ].join('\n');
}
