/**
 * VulnsAgentActions — serves MnemoVulns's agent actions (doc 149) while the
 * window is open. A CHILD that renders nothing, never a hook in App: App stays
 * mounted on the person's board, and a hook added to it breaks its hook order
 * under hot reload. The handlers live in lib/agent.ts; this keeps their view of
 * the App fresh (a ref written every render) and subscribes ONCE.
 */
import { useEffect, useRef } from 'react';
import { MnemoCartridgeSDK } from '../sdk/mnemo-sdk';
import { vulnsAgentHandlers, type VulnsAgentContext } from '../lib/agent';
import { domScreen } from './agentScreen';

// Must match "name" in mnemo-plugin.json, as App's own instance does.
const sdk = new MnemoCartridgeSDK('@mnemosyne-plugins/mnemo-vulns');

export function VulnsAgentActions(props: Omit<VulnsAgentContext, 'screen'>) {
  const latest = useRef(props);
  latest.current = props;

  useEffect(() => {
    // Outside the shell nobody calls (a plain tab, the tests).
    if (typeof window === 'undefined' || window.parent === window) return undefined;
    if (typeof sdk.onAgentActions !== 'function') {
      // An iframe served an older SDK build: it must not take the window down.
      console.warn('[mnemo-vulns] this SDK build has no onAgentActions; reload the cartridge to serve agent actions');
      return undefined;
    }
    const sub = sdk.onAgentActions(vulnsAgentHandlers(() => ({ ...latest.current, screen: domScreen })));
    sub.ready.catch((err: unknown) => console.warn('[mnemo-vulns] agent actions not served:', err instanceof Error ? err.message : err));
    return () => sub.off();
  }, []);

  return null;
}
