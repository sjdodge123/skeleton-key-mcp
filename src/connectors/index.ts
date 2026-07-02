import type { Connector } from "./types.js";
import { sshConnector } from "./ssh.js";
import { httpConnector } from "./http.js";

/**
 * Registry of available connector *types*. Adding support for a new service
 * means adding a Connector here — targets of that type then become registrable.
 * The generic `ssh` and `http` connectors guarantee that any reachable service
 * is usable even before a bespoke adapter exists.
 */
const connectors = new Map<string, Connector>();

export function registerConnector(connector: Connector): void {
  connectors.set(connector.type, connector);
}

export function getConnector(type: string): Connector | undefined {
  return connectors.get(type);
}

export function listConnectors(): Connector[] {
  return [...connectors.values()];
}

// Built-in connectors. Bespoke adapters (synology, proxmox, unifi, ...) register
// here in later phases.
registerConnector(sshConnector);
registerConnector(httpConnector);
