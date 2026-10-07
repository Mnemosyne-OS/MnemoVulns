import { describe, it, expect } from 'vitest';
import { CARD_LINES, projectCard, sameMembers } from './cards';

const w = { open: '{n} open', partial: 'partial scan', malicious: '{n} malicious', fixTo: '{pkg} → {version}', fixRemove: '{pkg}: remove', fixNone: '{pkg}: no fix', fixSee: '{pkg}: see', dev: 'dev', gauge: '{fixed}/{total} fixed', fresh: '+{n} new', sev: { CRITICAL: 'Critical', HIGH: 'High', MODERATE: 'Moderate', LOW: 'Low' } };
const project = { root: '/a', name: 'app', slug: 'app-1' };
const sev = (c: number, h: number, m = 0, l = 0) => ({ CRITICAL: c, HIGH: h, MODERATE: m, LOW: l, UNKNOWN: 0 });

describe('projectCard', () => {
  it('says nothing before the first scan', () => {
    expect(projectCard(project, w)).toBeNull();
  });

  it('is an alert while a critical or high vulnerability is open, dated by the scan', () => {
    const card = projectCard({ ...project, lastScan: { at: '2026-10-05T00:00:00Z', complete: true, findings: 9, open: 3, unasked: 0, openBySeverity: sev(1, 0, 2) } }, w)!;
    expect(card).toMatchObject({ id: 'vulns:app-1', snapshot: true, tone: 'alert', status: '3 open', seenAt: '2026-10-05T00:00:00Z', lines: ['1 Critical · 2 Moderate'] });
  });

  it('is idle only after a COMPLETE scan left nothing open', () => {
    const clean = { at: 'x', complete: true, findings: 0, open: 0, unasked: 0, openBySeverity: sev(0, 0) };
    expect(projectCard({ ...project, lastScan: clean }, w)!.tone).toBe('idle');
    expect(projectCard({ ...project, lastScan: { ...clean, complete: false, unasked: 4 } }, w)).toMatchObject({ tone: 'neutral', status: '0 open · partial scan' });
  });

  it('is an alert and says it when a malicious package is open (MAL- records carry no severity)', () => {
    const card = projectCard({ ...project, lastScan: { at: 'x', complete: true, findings: 1, open: 1, unasked: 0, openBySeverity: sev(0, 0), openMalicious: 1 } }, w)!;
    expect(card).toMatchObject({ tone: 'alert', lines: ['1 malicious'] });
  });

  it('says what to fix first, one package per line, after the severities', () => {
    const toFix = [
      { ecosystem: 'npm', name: 'evil', version: '1.0.0', severity: 'UNKNOWN' as const, count: 1, action: { kind: 'remove' as const } },
      { ecosystem: 'npm', name: 'tar', version: '7.5.13', severity: 'HIGH' as const, count: 6, action: { kind: 'to' as const, version: '7.5.21' } },
      { ecosystem: 'npm', name: 'xlsx', version: '0.18.5', severity: 'HIGH' as const, count: 2, action: { kind: 'none' as const }, dev: true as const },
    ];
    const card = projectCard({ ...project, lastScan: { at: 'x', complete: true, findings: 9, open: 9, unasked: 0, openBySeverity: sev(0, 8, 0, 0), toFix } }, w)!;
    expect(card.lines).toEqual(['8 High', 'evil: remove', 'tar → 7.5.21 (6)', 'xlsx: no fix (2) · dev']);
  });

  it('never claims "nothing urgent" from a summary without per-severity counts', () => {
    const old = { at: 'x', complete: true, findings: 2, open: 0, unasked: 0 };
    expect(projectCard({ ...project, lastScan: old }, w)!.tone).toBe('neutral');
  });
});

describe('sameMembers', () => {
  it('compares members, not identity or order', () => {
    expect(sameMembers(new Set(['a', 'b']), ['b', 'a'])).toBe(true);
    expect(sameMembers(new Set(['a']), ['a', 'b'])).toBe(false);
    expect(sameMembers(new Set(['a', 'b']), ['a', 'c'])).toBe(false);
  });
});

import { projectOfCard } from './cards';

describe('projectOfCard', () => {
  it('finds the project a card id names, and nothing for another module or a removed project', () => {
    const projects = [{ root: '/a', slug: 'a-1' }, { root: '/b', slug: 'b-2' }];
    expect(projectOfCard(projects, 'vulns:b-2')?.root).toBe('/b');
    expect(projectOfCard(projects, 'vulns:gone')).toBeNull();
    expect(projectOfCard(projects, 'agent:b-2')).toBeNull();
  });
});

describe('the gauge on the card', () => {
  it('hands the host the gauge counts on the cartridge own blocks, and the count in words; nothing without the counts', () => {
    const card = projectCard({ ...project, lastScan: { at: 'x', complete: true, findings: 4, open: 3, unasked: 0, openBySeverity: sev(0, 3), accepted: 0, fixed: 1 } }, w)!;
    expect(card.status).toBe('3 open');
    expect(card.lines[0]).toBe('1/4 fixed');
    expect(card.meter).toEqual({ done: 1, total: 4, blocks: 16 });
    const old = projectCard({ ...project, lastScan: { at: 'x', complete: true, findings: 4, open: 3, unasked: 0, openBySeverity: sev(0, 3) } }, w)!;
    expect(old.status).toBe('3 open');
    expect(old).not.toHaveProperty('meter');
    const clean = projectCard({ ...project, lastScan: { at: 'x', complete: true, findings: 0, open: 0, unasked: 0, openBySeverity: sev(0, 0), accepted: 0, fixed: 0 } }, w)!;
    expect(clean).not.toHaveProperty('meter');
  });
});

describe('a short card', () => {
  it('keeps the two worst severities only: four never fit on one line', () => {
    const card = projectCard({ ...project, lastScan: { at: 'x', complete: true, findings: 9, open: 9, unasked: 0, openBySeverity: sev(1, 2, 3, 4) } }, w)!;
    expect(card.lines).toEqual(['1 Critical · 2 High']);
  });
});

describe('the card fits the host', () => {
  it('sends at most CARD_LINES lines, the count and severities first, the fixes that fit after', () => {
    const fix = (name: string) => ({ ecosystem: 'npm', name, version: '1.0.0', severity: 'HIGH' as const, count: 2, action: { kind: 'to' as const, version: '2.0.0' } });
    const card = projectCard({ ...project, lastScan: { at: 'x', complete: true, findings: 9, open: 3, unasked: 0, openBySeverity: sev(0, 3), accepted: 0, fixed: 1, toFix: [fix('a'), fix('b'), fix('c')] } }, w)!;
    expect(card.lines).toEqual(['1/4 fixed', '3 High', 'a → 2.0.0 (2)', 'b → 2.0.0 (2)']);
    expect(card.lines).toHaveLength(CARD_LINES);
  });
});

describe('what is new on the card', () => {
  it('says how many urgent ones are new since the previous scan, and nothing when none', () => {
    const base = { at: 'x', complete: true, findings: 4, open: 4, unasked: 0, openBySeverity: sev(1, 3) };
    expect(projectCard({ ...project, lastScan: { ...base, newUrgent: 2 } }, w)!.status).toBe('4 open · +2 new');
    expect(projectCard({ ...project, lastScan: { ...base, newUrgent: 0 } }, w)!.status).toBe('4 open');
  });
});
