/**
 * styles — the cartridge's inline styles, on the host's design tokens only
 * (rule 12: `var(--…)`, never a hard colour). Kept out of the .tsx files so
 * each of those exports a component and nothing else (Fast Refresh).
 */
import type { CSSProperties } from 'react';

/** Inline styles of the cartridge, on the host's CSS variables. */
export const S: Record<string, CSSProperties> = {
  page: { height: '100%', overflow: 'auto', padding: 16, boxSizing: 'border-box', display: 'flex', flexDirection: 'column', gap: 12, background: 'var(--bg-void)', color: 'var(--text-primary)' },
  header: { display: 'flex', flexDirection: 'column', gap: 4 },
  title: { fontSize: 20, fontWeight: 600 },
  h2: { fontSize: 15, fontWeight: 600, margin: 0 },
  p: { margin: 0, lineHeight: 1.5 },
  muted: { color: 'var(--text-muted)' },
  small: { color: 'var(--text-muted)', fontSize: 12, lineHeight: 1.45 },
  error: { color: 'var(--danger, var(--accent))', fontSize: 13 },
  card: { background: 'linear-gradient(160deg, color-mix(in srgb, var(--text-primary) 4%, transparent), color-mix(in srgb, var(--text-primary) 1%, transparent)), var(--bg-panel)', border: '1px solid color-mix(in srgb, var(--text-primary) 10%, transparent)', borderRadius: 14, padding: 16, display: 'flex', flexDirection: 'column', gap: 10, boxShadow: 'inset 0 1px 0 color-mix(in srgb, var(--text-primary) 8%, transparent), 0 10px 30px color-mix(in srgb, var(--bg-void) 55%, transparent)' },
  button: { alignSelf: 'flex-start', background: 'linear-gradient(180deg, color-mix(in srgb, var(--accent) 78%, var(--text-primary) 22%), var(--accent))', color: 'var(--text-on-accent, var(--bg-void))', border: '1px solid color-mix(in srgb, var(--text-primary) 22%, transparent)', borderRadius: 10, padding: '7px 16px', cursor: 'pointer', fontWeight: 600, boxShadow: 'inset 0 1px 0 color-mix(in srgb, var(--text-primary) 35%, transparent), 0 4px 14px color-mix(in srgb, var(--accent) 30%, transparent)' },
  ghost: { background: 'linear-gradient(180deg, color-mix(in srgb, var(--text-primary) 10%, transparent), color-mix(in srgb, var(--text-primary) 3%, transparent))', backdropFilter: 'blur(10px)', WebkitBackdropFilter: 'blur(10px)', color: 'var(--text-primary)', border: '1px solid color-mix(in srgb, var(--text-primary) 16%, transparent)', borderRadius: 10, padding: '6px 12px', cursor: 'pointer', boxShadow: 'inset 0 1px 0 color-mix(in srgb, var(--text-primary) 14%, transparent)' },
  icon: { background: 'color-mix(in srgb, var(--text-primary) 5%, transparent)', color: 'var(--text-muted)', border: '1px solid color-mix(in srgb, var(--text-primary) 10%, transparent)', borderRadius: 9, padding: 6, cursor: 'pointer', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', lineHeight: 0 },
  iconOn: { color: 'var(--accent)', borderColor: 'var(--accent)', background: 'color-mix(in srgb, var(--accent) 14%, transparent)', boxShadow: '0 0 12px color-mix(in srgb, var(--accent) 35%, transparent)' },
  link: { background: 'transparent', color: 'var(--accent)', border: 'none', padding: 0, cursor: 'pointer', textAlign: 'left' },
  input: { background: 'var(--bg-void)', color: 'var(--text-primary)', border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '7px 9px' },
  list: { listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 4 },
  row: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(230px, 1fr))', gap: 14 },
  tile: { background: 'linear-gradient(165deg, color-mix(in srgb, var(--text-primary) 7%, transparent), color-mix(in srgb, var(--text-primary) 1%, transparent) 60%), var(--bg-panel)', border: '1px solid color-mix(in srgb, var(--text-primary) 12%, transparent)', borderRadius: 16, padding: 16, boxShadow: 'inset 0 1px 0 color-mix(in srgb, var(--text-primary) 10%, transparent), 0 12px 28px color-mix(in srgb, var(--bg-void) 60%, transparent)', transition: 'transform .15s ease, box-shadow .15s ease, border-color .15s ease', display: 'flex', flexDirection: 'column', gap: 8, cursor: 'pointer', textAlign: 'left', color: 'var(--text-primary)' },
  tileName: { fontSize: 16, fontWeight: 600 },
  licence: { background: 'var(--bg-void)', border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '8px 10px', fontSize: 12, lineHeight: 1.5, whiteSpace: 'pre-wrap' },
  select: { background: 'var(--bg-void)', color: 'var(--text-primary)', border: '1px solid var(--border-subtle)', borderRadius: 6, padding: '5px 8px' },
  footer: { marginTop: 'auto', paddingTop: 8, borderTop: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: 4 },
};
