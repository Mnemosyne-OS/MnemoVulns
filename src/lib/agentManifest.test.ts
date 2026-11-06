/**
 * MnemoVulns's agent actions (doc 149): the manifest's declaration passes the
 * HOST's own check, and every declared action has its handler (a declared
 * action without one would be offered to agents and fail).
 *
 * Read through Vite (`?raw`, a JSON import), not node:fs: this cartridge's
 * test types carry no Node.
 */
import { describe, expect, it } from 'vitest';
import manifest from '../../mnemo-plugin.json';
import source from './agent.ts?raw';
import { agentActionsFromManifest } from '../../../infinity-edition/src/main/plugins/cartridgeAgentActions';
import { FINDING_STATES, vulnsAgentHandlers } from './agent';

const block = source.slice(source.indexOf('// agent-actions:begin'), source.indexOf('// agent-actions:end'));
const handlers = [...block.matchAll(/^ {4}(\w+): (?:async )?\(/gm)].map((m) => m[1]);

function declared() {
  const r = agentActionsFromManifest(manifest);
  if (!r.ok) throw new Error(r.error);
  return r.value;
}

describe("MnemoVulns's agent actions", () => {
  it("pass the host's check of the manifest", () => {
    const r = agentActionsFromManifest(manifest);
    expect(r.ok ? 'ok' : r.error).toBe('ok');
  });

  it('every declared action has its handler, and no handler is undeclared', () => {
    expect(handlers.length).toBeGreaterThan(5);
    expect([...handlers].sort()).toEqual(declared().map((a) => a.id).sort());
    expect(Object.keys(vulnsAgentHandlers(() => { throw new Error('unused'); })).sort()).toEqual([...handlers].sort());
  });

  it('nothing spends credits, and only the two lists are reads', () => {
    expect(declared().filter((a) => a.effect === 'spend')).toEqual([]);
    expect(declared().filter((a) => a.effect === 'read').map((a) => a.id).sort()).toEqual(['projects', 'vulnerabilities']);
  });

  it("the states it filters on are the tracker's own", () => {
    const p = declared().find((a) => a.id === 'vulnerabilities')!.params.state;
    expect(p?.type === 'string' ? p.enum : null).toEqual([...FINDING_STATES]);
  });
});
