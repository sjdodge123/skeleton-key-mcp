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

/**
 * Map a discovered service type to a connector that can actually register it.
 * Discovery labels services by product (synology, proxmox, …) but only `ssh`
 * and `http` connectors exist today, so bespoke detections fall back to `http`
 * (or `ssh` for port 22). Used by both the wizard and the MCP register flow so
 * they agree on the registerable type.
 */
export function registerableType(connectorType: string, port?: number): string {
  if (getConnector(connectorType)) return connectorType;
  return port === 22 ? "ssh" : "http";
}

// Built-in connectors. Bespoke adapters (synology, proxmox, unifi, ...) register
// here in later phases.
registerConnector(sshConnector);
registerConnector(httpConnector);
