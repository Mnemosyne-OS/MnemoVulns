/**
 * A project or a package named the way a person says it (doc 149 §19): the
 * words, folded, fillers out; several matches refused with their names.
 */
import { describe, expect, it } from 'vitest';
import { findNamed, nameWords, type Named } from './agentFind';

const pkg = (name: string): Named<string> => ({ item: name, id: `npm:${name}`, names: [name], label: name });
const PACKAGES = [pkg('@babel/core'), pkg('@babel/traverse'), pkg('core-js'), pkg('lodash')];
const kind = { code: 'NO_PACKAGE', noun: 'package' };

describe('a package named the way a person says it', () => {
  it('folds case, accents, the words of this domain and a plural', () => {
    expect(nameWords('le paquet Lodash')).toEqual(['lodash']);
    expect(nameWords('les failles du projet Éditions')).toEqual(['edition']);
    expect(nameWords('@babel/core')).toEqual(['babel', 'core']);
  });

  it('an id, the whole name, or every word of it', () => {
    expect(findNamed(PACKAGES, 'npm:lodash', kind)).toBe('lodash');
    expect(findNamed(PACKAGES, 'babel core', kind)).toBe('@babel/core');
    expect(findNamed(PACKAGES, 'babel traverse', kind)).toBe('@babel/traverse');
  });

  it('several matches are refused with their names, never the first taken', () => {
    expect(() => findNamed(PACKAGES, 'core', kind)).toThrow('AMBIGUOUS: "core" names several packages: @babel/core, core-js; say which');
  });

  it('no match is refused with the names that exist', () => {
    expect(() => findNamed(PACKAGES, 'react', kind)).toThrow('NO_PACKAGE: no package named "react"; packages: @babel/core, @babel/traverse, core-js, lodash');
    expect(() => findNamed(PACKAGES, 'le paquet', kind)).toThrow(/^NO_PACKAGE: "le paquet" names no package/);
    expect(() => findNamed(PACKAGES, '', kind)).toThrow(/^BAD_ARG/);
  });
});
