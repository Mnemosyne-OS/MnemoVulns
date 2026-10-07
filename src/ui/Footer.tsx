/**
 * Footer — where MnemoVulns keeps things: the knowledge folder, how the chat
 * reaches the records, and the line that names where the data comes from.
 */
import { S } from './styles';
import type { T } from './types';

/** The footer: knowledge folder, chat hint, data source. */
export function Footer({ t, folder, onOpenFolder }: {
  t: T;
  folder: string | null;
  onOpenFolder: () => void;
}) {
  return (
    <footer style={S.footer}>
      <div style={{ ...S.small, display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <span>{folder ? t('footer.folder', { folder }) : t('footer.noFolder')}</span>
        {folder && <button style={S.link} onClick={onOpenFolder}>{t('footer.open')}</button>}
      </div>
      <div style={S.small}>{t('chat.hint')}</div>
      <div style={S.small}>{t('footer.source')}</div>
    </footer>
  );
}
