/**
 * useI18n — the cartridge follows the app's language, and never asks again.
 *
 * The host broadcasts its locale over the bridge on every config update
 * (`onHostConfig`, cartridge-sdk). Outside the shell nothing broadcasts, so the
 * viewer stays in English — which is the honest default, not a failure: there
 * is no user preference to read out there.
 *
 * 🪤 `onHostConfig` fires on UPDATES. A cartridge that only listens will sit in
 * English until the human happens to change something in Settings, which they
 * may never do. The host also puts the language in the frame's query string
 * when it opens the window (`?widget=…&theme=dark&lang=fr`), so that is read
 * once at mount as the starting value.
 */
import { useEffect, useState } from 'react';
import { onHostConfig } from '@mnemosyne_os/cartridge-sdk';
import { isLang, translate, type Key, type Lang } from './strings';

/** The language the frame was opened with, or English. */
function initialLang(): Lang {
  try {
    const q = new URLSearchParams(window.location.search).get('lang');
    // 'fr-CA' and 'fr' are the same language for a toolbar.
    const base = q?.split('-')[0]?.toLowerCase();
    if (isLang(base)) return base;
  } catch (err) {
    // No location in some test environments: English is the honest default.
    console.warn('[mnemo-vulns] frame language unreadable', err);
  }
  return 'en';
}

/** The interface language (from the frame URL, then the host's broadcasts) and the translator bound to it. */
export function useI18n() {
  const [lang, setLang] = useState<Lang>(initialLang);

  useEffect(() => onHostConfig((cfg) => {
    const base = cfg.lang?.split('-')[0]?.toLowerCase();
    if (isLang(base)) setLang(base);
  }, { apply: false }), []);

  return {
    lang,
    t: (key: Key, vars?: Record<string, string | number>) => translate(lang, key, vars),
  };
}
