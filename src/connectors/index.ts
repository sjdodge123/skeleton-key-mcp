import type { Connector } from "./types.js";
import { sshConnector } from "./ssh.js";
import { httpConnector } from "./http.js";
import { portainerConnector } from "./portainer.js";
import { unifiConnector } from "./unifi.js";
import { homeAssistantConnector } from "./home-assistant.js";
import { proxmoxConnector } from "./proxmox.js";

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
 * A bespoke connector is only suggested when the detection was **fingerprint-
 * confirmed**; a port-only guess (e.g. any HTTPS on 9443, which merely *hints*
 * Portainer) falls back to the generic `http`/`ssh` connector, so following the
 * suggestion never registers a non-Portainer service as a broken portainer
 * target. Types without a bespoke connector always fall back. Used by both the
 * wizard and the MCP register flow so they agree on the registerable type.
 */
export function registerableType(connectorType: string, port?: number, confidence?: string): string {
  // Only a fingerprint-confirmed detection routes to a bespoke connector; an
  // unconfirmed guess OR a missing confidence conservatively falls back, so we
  // never suggest registering a port-only hint as e.g. a broken portainer target.
  if (confidence === "confirmed" && getConnector(connectorType)) return connectorType;
  return port === 22 ? "ssh" : "http";
}

// Built-in connectors. Bespoke adapters (synology, proxmox, unifi, ...) register
// here in later phases.
registerConnector(sshConnector);
registerConnector(httpConnector);
registerConnector(portainerConnector);
registerConnector(unifiConnector);
registerConnector(homeAssistantConnector);
// Discovery fingerprints Home Assistant as `home-assistant` (its canonical type),
// but accept the no-hyphen `homeassistant` a human might type in register_target
// too — both resolve to the same connector.
connectors.set("homeassistant", homeAssistantConnector);
registerConnector(proxmoxConnector);
