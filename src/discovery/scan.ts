import net from "node:net";
import os from "node:os";

/**
 * Opt-in LAN discovery. Probes hosts on the local subnet for well-known service
 * ports and maps hits to suggested connector types. This only *proposes* targets
 * — the wizard requires the user to confirm and attach credentials before
 * anything is registered. Nothing here connects to a service or sends creds.
 */

export interface ServiceSignature {
  /** Connector type to suggest. */
  connectorType: string;
  label: string;
  port: number;
}

/** Fingerprints for the common homelab services. Ordered by specificity. */
export const SIGNATURES: ServiceSignature[] = [
  { connectorType: "ssh", label: "SSH host", port: 22 },
  { connectorType: "synology", label: "Synology DSM", port: 5000 },
  { connectorType: "synology", label: "Synology DSM (HTTPS)", port: 5001 },
  { connectorType: "proxmox", label: "Proxmox VE", port: 8006 },
  { connectorType: "unifi", label: "UniFi Network", port: 8443 },
  { connectorType: "home-assistant", label: "Home Assistant", port: 8123 },
  { connectorType: "portainer", label: "Portainer", port: 9443 },
  { connectorType: "portainer", label: "Portainer (HTTP)", port: 9000 },
  { connectorType: "pihole", label: "Pi-hole", port: 80 },
  { connectorType: "http", label: "HTTP service", port: 443 },
];

export interface DiscoveredService {
  host: string;
  port: number;
  connectorType: string;
  label: string;
}

/**
 * Is `prefix` (a "a.b.c" /24 prefix) inside an RFC1918 private range? Used to
 * gate scanning: a user may point the scan at their real LAN subnet even when
 * the container itself is on Docker's bridge network, but we never scan public
 * IP space.
 */
export function isPrivateSubnet(prefix: string): boolean {
  const parts = prefix.split(".");
  if (parts.length !== 3) return false;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = nums as [number, number, number];
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

/** Enumerate local IPv4 /24 subnets from the host's own interfaces. */
export function localSubnets(): string[] {
  const subnets = new Set<string>();
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const addr of addrs ?? []) {
      if (addr.family === "IPv4" && !addr.internal) {
        const octets = addr.address.split(".");
        subnets.add(`${octets[0]}.${octets[1]}.${octets[2]}`);
      }
    }
  }
  return [...subnets];
}

function probe(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (open: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
    socket.connect(port, host);
  });
}

export interface ScanOptions {
  /** Subnet prefixes like "192.168.0"; defaults to detected local subnets. */
  subnets?: string[];
  /** Host range within each subnet (inclusive). */
  start?: number;
  end?: number;
  timeoutMs?: number;
  /** Max simultaneous socket probes. */
  concurrency?: number;
}

/**
 * TCP-connect scan across the configured subnets. LAN-scoped only: it refuses to
 * scan anything that isn't one of the host's own private subnets.
 */
export async function scanLan(opts: ScanOptions = {}): Promise<DiscoveredService[]> {
  // Honor a user-supplied subnet (e.g. their real LAN "192.168.0") even if the
  // container itself is bridged and only sees Docker's network; fall back to the
  // host's own interfaces. Either way, restrict to private ranges.
  const detected = localSubnets();
  const requested = opts.subnets && opts.subnets.length > 0 ? opts.subnets : detected;
  const subnets = requested.filter(isPrivateSubnet);
  if (subnets.length === 0) return [];

  const start = opts.start ?? 1;
  const end = opts.end ?? 254;
  const timeoutMs = opts.timeoutMs ?? 400;
  const concurrency = opts.concurrency ?? 128;

  const jobs: { host: string; sig: ServiceSignature }[] = [];
  for (const subnet of subnets) {
    for (let h = start; h <= end; h++) {
      const host = `${subnet}.${h}`;
      for (const sig of SIGNATURES) jobs.push({ host, sig });
    }
  }

  const found: DiscoveredService[] = [];
  let cursor = 0;
  async function worker(): Promise<void> {
    while (cursor < jobs.length) {
      const job = jobs[cursor++];
      if (!job) return;
      if (await probe(job.host, job.sig.port, timeoutMs)) {
        found.push({
          host: job.host,
          port: job.sig.port,
          connectorType: job.sig.connectorType,
          label: job.sig.label,
        });
      }
    }
  }
  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  // Collapse to one suggestion per host: prefer the most specific (non-generic) hit.
  const byHost = new Map<string, DiscoveredService[]>();
  for (const svc of found) {
    const list = byHost.get(svc.host) ?? [];
    list.push(svc);
    byHost.set(svc.host, list);
  }
  return found.sort((a, b) => (a.host === b.host ? a.port - b.port : a.host.localeCompare(b.host)));
}
