/**
 * The agent presses the project page's own chips and tiles (ui/agentScreen):
 * read on the markup ProjectView draws, the same `data-*` hooks.
 */
import { useState } from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, describe, expect, it } from 'vitest';
import { domScreen } from './agentScreen';
import { tileId } from './types';

function Page() {
  const [filter, setFilter] = useState('all');
  const [open, setOpen] = useState(false);
  return (
    <div>
      {['all', 'dev'].map((f) => (
        <button key={f} aria-pressed={filter === f} data-plan-filter={f} onClick={() => setFilter(f)}>{f}</button>
      ))}
      {filter === 'all' && (
        <section id={tileId('npm:@babel/core')}>
          <button aria-expanded={open} data-tile-expand onClick={() => setOpen(!open)}>more</button>
        </section>
      )}
    </div>
  );
}

let host: HTMLDivElement | null = null;
afterEach(() => { host?.remove(); host = null; });

function mount() {
  host = document.createElement('div');
  document.body.appendChild(host);
  const root = createRoot(host);
  act(() => root.render(<Page />));
}

describe('the screen the agent presses', () => {
  it('reads and presses the filter chips', () => {
    mount();
    expect(domScreen.planFilter()).toBe('all');
    expect(domScreen.hasPlanFilter('unknown')).toBe(false);
    expect(domScreen.pressPlanFilter('unknown')).toBe(false);
    act(() => { domScreen.pressPlanFilter('dev'); });
    expect(domScreen.planFilter()).toBe('dev');
    expect(domScreen.hasTile('npm:@babel/core')).toBe(false);
  });

  it('opens a tile once, never closes one already open', () => {
    mount();
    const toggle = () => document.querySelector('[data-tile-expand]')!.getAttribute('aria-expanded');
    act(() => { expect(domScreen.revealTile('npm:@babel/core')).toBe(true); });
    expect(toggle()).toBe('true');
    act(() => { domScreen.revealTile('npm:@babel/core'); });
    expect(toggle()).toBe('true');
    expect(domScreen.revealTile('npm:lodash')).toBe(false);
  });

  it('reads nothing when no page is drawn', () => {
    expect(domScreen.planFilter()).toBeNull();
  });
});
