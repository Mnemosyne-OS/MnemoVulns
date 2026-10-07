import { describe, it, expect } from 'vitest';
import { affects, fixFor, severityOf, sourceOf, type OsvRecord } from './advisory';
import { compareVersions } from './semver';
import { compareReleases } from './advisory';

const rec = (affected: OsvRecord['affected'], extra: Partial<OsvRecord> = {}): OsvRecord => ({ id: 'GHSA-x', modified: '2026-10-01T00:00:00Z', affected, ...extra });
const semver = (events: Record<string, string>[]) => ({ type: 'SEMVER', events });

describe('compareVersions', () => {
  it('orders a pre-release before its release, numerically by part', () => {
    expect(compareVersions('1.0.0-beta.2', '1.0.0')).toBe(-1);
    expect(compareVersions('2.0.0', '2.0.0-rc.1')).toBe(1);
    expect(compareVersions('1.0.0-beta.2', '1.0.0-beta.10')).toBe(-1);
    expect(compareVersions('1.10.0', '1.9.9')).toBe(1);
    expect(compareVersions('0', '0.0.0-0')).toBe(-1);
  });
  it('refuses to order what is not a version', () => {
    expect(compareVersions('1.0', '1.0.0')).toBeNull();
  });
});

describe('fixFor', () => {
  it('gives the fixed version of the range the version sits in', () => {
    const r = rec([{ package: { ecosystem: 'npm', name: 'tar' }, ranges: [semver([{ introduced: '7.0.0' }, { fixed: '7.5.16' }])] }]);
    expect(fixFor(r, 'tar', '7.5.13')).toEqual({ kind: 'fixed', version: '7.5.16' });
  });

  it('takes the HIGHEST fix when several ranges contain the version', () => {
    const r = rec([
      { package: { ecosystem: 'npm', name: 'tar' }, ranges: [semver([{ introduced: '0' }, { fixed: '7.5.16' }])] },
      { package: { ecosystem: 'npm', name: 'tar' }, ranges: [semver([{ introduced: '7.0.0' }, { fixed: '7.5.21' }])] },
    ]);
    expect(fixFor(r, 'tar', '7.5.13')).toEqual({ kind: 'fixed', version: '7.5.21' });
  });

  it('says no fix is published when the range ends on last_affected or stays open', () => {
    const last = rec([{ package: { ecosystem: 'npm', name: 'braces' }, ranges: [semver([{ introduced: '0' }, { last_affected: '3.0.3' }])] }]);
    expect(fixFor(last, 'braces', '3.0.3')).toEqual({ kind: 'none' });
    const open = rec([{ package: { ecosystem: 'npm', name: 'xlsx' }, ranges: [semver([{ introduced: '0' }])] }]);
    expect(fixFor(open, 'xlsx', '0.18.5')).toEqual({ kind: 'none' });
  });

  it('says unknown when the version matched another way (a versions list)', () => {
    const r = rec([{ package: { ecosystem: 'npm', name: 'evil' }, versions: ['1.0.0'] }]);
    expect(fixFor(r, 'evil', '1.0.0')).toEqual({ kind: 'unknown' });
  });

  it('ignores ranges of another package or another ecosystem', () => {
    const r = rec([
      { package: { ecosystem: 'npm', name: 'other' }, ranges: [semver([{ introduced: '0' }, { fixed: '9.0.0' }])] },
      { package: { ecosystem: 'PyPI', name: 'tar' }, ranges: [semver([{ introduced: '0' }, { fixed: '9.0.0' }])] },
    ]);
    expect(fixFor(r, 'tar', '1.0.0')).toEqual({ kind: 'unknown' });
  });
});

describe('affects', () => {
  const tar = rec([{ package: { ecosystem: 'npm', name: 'tar' }, ranges: [semver([{ introduced: '7.0.0' }, { fixed: '7.5.16' }])] }]);
  it('is true inside a range and false on both sides of it', () => {
    expect(affects(tar, 'tar', '7.5.13')).toBe(true);
    expect(affects(tar, 'tar', '7.5.16')).toBe(false);
    expect(affects(tar, 'tar', '6.2.1')).toBe(false);
  });
  it('counts a pre-release of the fixed version as still affected', () => {
    expect(affects(tar, 'tar', '7.5.16-rc.1')).toBe(true);
  });
  it('reads last_affected as inclusive and an open range as everything after it', () => {
    const braces = rec([{ package: { ecosystem: 'npm', name: 'braces' }, ranges: [semver([{ introduced: '0' }, { last_affected: '3.0.3' }])] }]);
    expect(affects(braces, 'braces', '3.0.3')).toBe(true);
    expect(affects(braces, 'braces', '3.0.4')).toBe(false);
    const xlsx = rec([{ package: { ecosystem: 'npm', name: 'xlsx' }, ranges: [semver([{ introduced: '0.10.0' }])] }]);
    expect(affects(xlsx, 'xlsx', '0.18.5')).toBe(true);
    expect(affects(xlsx, 'xlsx', '0.9.0')).toBe(false);
  });
  it('matches an explicit versions list, and never a withdrawn record', () => {
    const evil = rec([{ package: { ecosystem: 'npm', name: 'evil' }, versions: ['1.0.0'] }]);
    expect(affects(evil, 'evil', '1.0.0')).toBe(true);
    expect(affects({ ...tar, withdrawn: '2026-01-01' }, 'tar', '7.5.13')).toBe(false);
  });
});

describe('severityOf and sourceOf', () => {
  it("reads the source's label, MEDIUM as MODERATE, anything else as UNKNOWN", () => {
    expect(severityOf(rec([], { database_specific: { severity: 'HIGH' } }))).toBe('HIGH');
    expect(severityOf(rec([], { database_specific: { severity: 'MEDIUM' } }))).toBe('MODERATE');
    expect(severityOf(rec([], { database_specific: { severity: 'whatever' } }))).toBe('UNKNOWN');
    expect(severityOf(rec([]))).toBe('UNKNOWN');
  });
  it('names the database of an id and its licence', () => {
    expect(sourceOf('GHSA-abcd').licence).toBe('CC-BY 4.0');
    expect(sourceOf('MAL-2026-1').licence).toBe('Apache 2.0');
    expect(sourceOf('XYZ-1').name).toBe('OSV.dev');
  });
});

describe('compareReleases (PEP 440)', () => {
  it('orders dev < pre-releases < release < post-release, and treats 3.2 as 3.2.0', () => {
    const order = ['1.0.dev1', '1.0a1.dev1', '1.0a1', '1.0b2', '1.0rc1', '1.0', '1.0.post1.dev1', '1.0.post1', '1.1'];
    for (let i = 0; i < order.length - 1; i++) expect(compareReleases(order[i]!, order[i + 1]!), order[i] + ' < ' + order[i + 1]).toBe(-1);
    expect(compareReleases('3.2', '3.2.0')).toBe(0);
    expect(compareReleases('3.2a1', '3.2.0')).toBe(-1);
    expect(compareReleases('1.0-rc.1', '1.0rc1')).toBe(0);
    expect(compareReleases('1!1.0', '2.0')).toBe(1);
  });
  it('never orders what it cannot read', () => {
    expect(compareReleases('1.0+cpu', '1.0')).toBeNull();
    expect(compareReleases('latest', '1.0')).toBeNull();
  });
});

describe('affects with a listed version', () => {
  it('matches a PyPI version listed as 3.2 when 3.2.0 is installed, and a name in another case', () => {
    const rec: OsvRecord = { id: 'PYSEC-9', modified: 'm', affected: [{ package: { ecosystem: 'PyPI', name: 'Django' }, versions: ['3.2'] }] };
    expect(affects(rec, 'django', '3.2.0', 'PyPI')).toBe(true);
    expect(affects(rec, 'django', '3.2.1', 'PyPI')).toBe(false);
  });
});
