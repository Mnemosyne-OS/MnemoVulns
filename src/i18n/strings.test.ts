import { describe, it, expect } from 'vitest';
import { WRITTEN, translate } from './strings';

describe('strings', () => {
  const keys = Object.keys(WRITTEN.en);

  it('writes every key in fr and es', () => {
    for (const lang of ['fr', 'es'] as const) {
      expect(keys.filter((k) => !(k in WRITTEN[lang])), lang).toEqual([]);
    }
  });

  it('keeps every placeholder in every written language', () => {
    const vars = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort().join(',');
    for (const k of keys) {
      const en = vars((WRITTEN.en as Record<string, string>)[k]!);
      for (const lang of ['fr', 'es'] as const) {
        expect(vars((WRITTEN[lang] as Record<string, string>)[k]!), `${lang} ${k}`).toBe(en);
      }
    }
  });

  it('falls back to English and leaves an unknown placeholder visible', () => {
    expect(translate('de', 'home.add')).toBe('Choose a project');
    expect(translate('en', 'sum.found', {})).toContain('{asked}');
  });
});
