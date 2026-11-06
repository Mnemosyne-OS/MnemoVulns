/**
 * agentScreen — what the agent's screen moves touch on a project page that
 * lives in ProjectView's OWN state (the filter chips, a package tile opened
 * or not). Lifting that state into App would add hooks to a component that
 * stays mounted on the person's board, so the agent presses the very buttons
 * the person presses: the same setter runs, the person sees it happen.
 *
 * Kept apart from lib/agent.ts so the handlers stay testable with a fake
 * screen, and apart from the .tsx files (Fast Refresh: a component file
 * exports a component and nothing else).
 *
 * @module ui/agentScreen
 */
import type { PlanFilter } from '../lib/packagePlan';
import { tileId } from './types';

export interface AgentScreen {
  /** The pressed chip of the package filter, or null when the chips are not drawn. */
  planFilter(): PlanFilter | null;
  /** Whether that chip is drawn (« unknown » is drawn only when some package's place is unknown). */
  hasPlanFilter(filter: PlanFilter): boolean;
  /** Presses a filter chip; false when it is not on screen. */
  pressPlanFilter(filter: PlanFilter): boolean;
  /** Whether a package's tile is drawn (the filter may hide it). */
  hasTile(key: string): boolean;
  /** Scrolls a package's tile into view and opens it; false when it is not on screen. */
  revealTile(key: string): boolean;
}

const chip = (filter: PlanFilter) => document.querySelector<HTMLButtonElement>(`button[data-plan-filter="${filter}"]`);

/** The screen as the person sees it. */
export const domScreen: AgentScreen = {
  planFilter: () => {
    const on = document.querySelector<HTMLButtonElement>('button[data-plan-filter][aria-pressed="true"]');
    return on ? (on.dataset.planFilter as PlanFilter) : null;
  },
  hasPlanFilter: (filter) => !!chip(filter),
  pressPlanFilter: (filter) => {
    const b = chip(filter);
    if (!b) return false;
    b.click();
    return true;
  },
  hasTile: (key) => !!document.getElementById(tileId(key)),
  revealTile: (key) => {
    const tile = document.getElementById(tileId(key));
    if (!tile) return false;
    const toggle = tile.querySelector<HTMLButtonElement>('button[data-tile-expand]');
    // Opened once: a second press would close what the person asked to see.
    if (toggle?.getAttribute('aria-expanded') === 'false') toggle.click();
    tile.scrollIntoView?.({ behavior: 'smooth', block: 'center' });
    return true;
  },
};
