import { describe, it, expect } from 'vitest';
import { LockfileError, pickLockfiles, readComposerLock, readGemfileLock, readGoMod } from './lockfile';
import { compareGems, fixFor, type OsvRecord } from './advisory';

describe('go.mod', () => {
  it('reads the selected module versions, and counts a replace to a local path apart', () => {
    const r = readGoMod(`module example.com/app

go 1.21

require (
\tgolang.org/x/net v0.7.0
\tgithub.com/pkg/errors v0.9.1 // indirect
\tgithub.com/me/local v1.0.0
)

require golang.org/x/text v0.3.7-0.20210101000000-abcdef123456

replace github.com/me/local => ../local
replace golang.org/x/net => golang.org/x/net v0.17.0
`);
    expect(r.ecosystem).toBe('Go');
    expect(r.packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      'github.com/pkg/errors@v0.9.1', 'golang.org/x/net@v0.7.0', 'golang.org/x/text@v0.3.7-0.20210101000000-abcdef123456',
    ]);
    expect(r.skipped).toEqual([{ ecosystem: 'Go', name: 'github.com/me/local', spec: 'replace => local path' }]);
  });

  it('refuses a file that is not a go.mod', () => {
    expect(() => readGoMod('hello')).toThrow(LockfileError);
  });
});

describe('composer.lock', () => {
  it('reads packages as shipped and packages-dev as declared for development, and counts a branch apart', () => {
    const r = readComposerLock(JSON.stringify({
      packages: [{ name: 'symfony/http-kernel', version: 'v4.4.0' }, { name: 'acme/thing', version: 'dev-main' }],
      'packages-dev': [{ name: 'phpunit/phpunit', version: '9.5.0' }],
    }));
    expect(r.packages).toEqual([
      { ecosystem: 'Packagist', name: 'phpunit/phpunit', version: '9.5.0', dev: true },
      { ecosystem: 'Packagist', name: 'symfony/http-kernel', version: 'v4.4.0', dev: false },
    ]);
    expect(r.skipped.map((s) => s.name)).toEqual(['acme/thing']);
    expect(() => readComposerLock('{}')).toThrow(LockfileError);
  });
});

describe('Gemfile.lock', () => {
  it('reads the GEM specs (not their dependency lines), drops the platform suffix, and counts PATH and GIT gems apart', () => {
    const r = readGemfileLock(`PATH
  remote: .
  specs:
    myapp (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.13.0-x86_64-linux)
      racc (~> 1.4)
    rack (2.2.3)
    rails (7.0.4.3)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  rails
`);
    expect(r.packages.map((p) => `${p.name}@${p.version}`)).toEqual(['nokogiri@1.13.0', 'rack@2.2.3', 'rails@7.0.4.3']);
    expect(r.packages.every((p) => !('dev' in p))).toBe(true);
    expect(r.skipped.map((s) => s.name)).toEqual(['myapp']);
    expect(() => readGemfileLock('nope')).toThrow(LockfileError);
  });
});

describe('compareGems', () => {
  it('orders gem versions the way RubyGems does', () => {
    expect(compareGems('1.0.0.pre1', '1.0.0')).toBe(-1);
    expect(compareGems('1.0.0', '1.0.0.pre1')).toBe(1);
    expect(compareGems('7.0.4.3', '7.0.4')).toBe(1);
    expect(compareGems('2.2', '2.2.0')).toBe(0);
    expect(compareGems('1.10.0', '1.9.9')).toBe(1);
    expect(compareGems('1.0.0.a', '1.0.0.b')).toBe(-1);
    expect(compareGems('1.0-x', '1.0')).toBeNull();
  });

  it('gives a RubyGems vulnerability its fixed version', () => {
    const rec: OsvRecord = { id: 'G-1', modified: 'm', affected: [{ package: { ecosystem: 'RubyGems', name: 'rack' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.2.6.4' }] }] }] };
    expect(fixFor(rec, 'rack', '2.2.3', 'RubyGems')).toEqual({ kind: 'fixed', version: '2.2.6.4' });
  });
});

describe('pickLockfiles', () => {
  it('reads every ecosystem a folder has, Go PHP and Ruby included', () => {
    expect(pickLockfiles(['go.mod', 'go.sum', 'composer.lock', 'Gemfile.lock', 'package-lock.json']).map((l) => l.ecosystem))
      .toEqual(['npm', 'Go', 'Packagist', 'RubyGems']);
  });
});
