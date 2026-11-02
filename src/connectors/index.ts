import { z } from "zod";
import type { Connector } from "./types.js";
import { UserFacingError } from "../lib/errors.js";
import { sshConnector } from "./ssh/index.js";
import { httpConnector } from "./http/index.js";
import { portainerConnector } from "./portainer/index.js";
import { unifiConnector } from "./unifi/index.js";
import { homeAssistantConnector } from "./home-assistant/index.js";
import { proxmoxConnector } from "./proxmox/index.js";
import { pelicanConnector } from "./pelican/index.js";
import { uptimeKumaConnector } from "./uptime-kuma/index.js";

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

/** Each connector once, even when it is registered under an alias too. */
export function listConnectors(): Connector[] {
  return [...new Set(connectors.values())];
}

/** Alternative type names that resolve to a connector (alias → canonical type). */
export function connectorAliases(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, c] of connectors) if (name !== c.type) out[name] = c.type;
  return out;
}

/**
 * The option keys a connector's `configSchema` declares, or null when the schema
 * isn't a plain object we can introspect.
 */
export function declaredOptionKeys(connector: Connector): string[] | null {
  const json = z.toJSONSchema(connector.configSchema, { io: "input", unrepresentable: "any" }) as { type?: string; properties?: Record<string, unknown> };
  if (json.type !== "object" || !json.properties) return null;
  return Object.keys(json.properties);
}

/**
 * Validate `options` for a target of this connector at the registration
 * boundary (register_target, update_target, the web form). Unknown keys are
 * refused here, so a typo such as `sudoPrefix` for `sudoPrefixes` fails loudly
 * instead of being silently dropped. Runtime parsing stays lenient on purpose:
 * a key an older version accepted must not break a target that is already
 * registered.
 */
export function validateTargetOptions(connector: Connector, options: Record<string, unknown> | undefined): void {
  assertKnownOptionKeys(connector, options);
  connector.configSchema.parse(options ?? {});
}

/** Refuse option keys the connector's `configSchema` doesn't declare. */
export function assertKnownOptionKeys(connector: Connector, options: Record<string, unknown> | undefined): void {
  const keys = declaredOptionKeys(connector);
  if (keys) {
    const unknown = Object.keys(options ?? {}).filter((k) => !keys.includes(k));
    if (unknown.length) {
      // Echo a key only when it looks like an option name: a pasted value in
      // the key position must never come back in an HTTP response.
      const named = unknown.filter((k) => /^[A-Za-z][A-Za-z0-9_]{0,40}$/.test(k)).map((k) => `'${k}'`);
      const unnamed = unknown.length - named.length;
      const list = [...named, ...(unnamed ? [`${unnamed} unrecognized key${unnamed > 1 ? "s" : ""}`] : [])].join(", ");
      throw new UserFacingError(
        `Unknown option${unknown.length > 1 ? "s" : ""} for a ${connector.type} target: ${list}. ` +
          `Valid options: ${keys.length ? keys.map((k) => `'${k}'`).join(", ") : "(none)"}.`,
      );
    }
  }
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
registerConnector(pelicanConnector);
registerConnector(uptimeKumaConnector);
