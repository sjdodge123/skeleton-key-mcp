import net from "node:net";
import os from "node:os";
import http from "node:http";
import https from "node:https";

/**
 * Opt-in LAN discovery. Finds open ports, then *fingerprints* each one (SSH
 * banner or HTTP response content) so we report what a service actually is
 * rather than guessing from the port alone. This only *proposes* targets — the
 * caller confirms and attaches credentials before anything is registered.
 * Nothing here sends credentials.
 */

export type Confidence = "confirmed" | "likely" | "open";

export interface DiscoveredService {
  host: string;
  port: number;
  connectorType: string;
  label: string;
  confidence: Confidence;
}

interface PortProbe {
  port: number;
  kind: "ssh" | "http" | "https";
  /** Fallback guess for a distinctive port when the HTTP body doesn't self-identify. */
  hint?: { type: string; label: string };
}

/**
 * Ports worth probing. Distinctive ports carry a `hint` used only when the HTTP
 * response doesn't self-identify; ambiguous ports (80/443/8443/9000/9443) get no
 * hint, so an unrecognized response is reported as a generic HTTP service rather
 * than mislabeled.
 */
const PORT_PROBES: PortProbe[] = [
  { port: 22, kind: "ssh" },
  { port: 80, kind: "http" },
  { port: 443, kind: "https" },
  { port: 5000, kind: "http", hint: { type: "synology", label: "Synology DSM" } },
  { port: 5001, kind: "https", hint: { type: "synology", label: "Synology DSM" } },
  { port: 8006, kind: "https", hint: { type: "proxmox", label: "Proxmox VE" } },
  { port: 8123, kind: "http", hint: { type: "home-assistant", label: "Home Assistant" } },
  { port: 8443, kind: "https" },
  { port: 9000, kind: "http" },
  { port: 9443, kind: "https" },
  { port: 32400, kind: "http", hint: { type: "plex", label: "Plex" } },
];

/** Content signatures matched against an HTTP response (headers + title + body). */
export const HTTP_FINGERPRINTS: { type: string; label: string; re: RegExp }[] = [
  { type: "proxmox", label: "Proxmox VE", re: /proxmox|pve-?manager/i },
  { type: "home-assistant", label: "Home Assistant", re: /home\s*assistant|homeassistant|hass-frontend/i },
  { type: "portainer", label: "Portainer", re: /portainer/i },
  { type: "synology", label: "Synology DSM", re: /synology|diskstation|synohdpack|synowebfmanager/i },
  { type: "unifi", label: "UniFi", re: /\bunifi\b|ubnt/i },
  { type: "pihole", label: "Pi-hole", re: /pi-?hole/i },
  { type: "plex", label: "Plex Media Server", re: /plex media server|x-plex/i },
];

/** Match an HTTP response against the fingerprints. Exported for testing. */
export function matchHttp(headers: Record<string, string | string[] | undefined>, body: string): { type: string; label: string } | null {
  const title = body.match(/<title>([^<]*)<\/title>/i)?.[1] ?? "";
  const hay = [
    body.slice(0, 8192),
    title,
    String(headers["server"] ?? ""),
    String(headers["x-powered-by"] ?? ""),
    String(headers["www-authenticate"] ?? ""),
    String(headers["location"] ?? ""),
  ].join(" ");
  for (const f of HTTP_FINGERPRINTS) if (f.re.test(hay)) return { type: f.type, label: f.label };
  return null;
}

/** Is `prefix` (an "a.b.c" /24 prefix) inside an RFC1918 private range? */
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

function tcpOpen(host: string, port: number, timeoutMs: number): Promise<boolean> {
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

/** Read an SSH server's greeting banner (sent immediately on connect). */
function sshBanner(host: string, port: number, timeoutMs: number): Promise<string | null> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (v: string | null) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(v);
    };
    socket.setTimeout(timeoutMs);
    socket.once("data", (d) => done(d.toString("utf8").split("\n")[0]!.trim()));
    socket.once("timeout", () => done(null));
    socket.once("error", () => done(null));
    socket.connect(port, host);
  });
}

/** GET / and capture status, headers, and a bounded body slice. Null if no HTTP response. */
function httpProbe(
  host: string,
  port: number,
  useHttps: boolean,
  timeoutMs: number,
): Promise<{ headers: Record<string, string | string[] | undefined>; body: string } | null> {
  return new Promise((resolve) => {
    const mod = useHttps ? https : http;
    const req = mod.request(
      { host, port, path: "/", method: "GET", timeout: timeoutMs, rejectUnauthorized: false, headers: { "user-agent": "skeleton-key-scan" } },
      (res) => {
        let body = "";
        res.on("data", (chunk: Buffer) => {
          if (body.length < 8192) body += chunk.toString("utf8");
          else req.destroy();
        });
        res.on("end", () => resolve({ headers: res.headers, body }));
      },
    );
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
    req.on("error", () => resolve(null));
    req.end();
  });
}

async function fingerprint(host: string, probe: PortProbe, timeoutMs: number): Promise<DiscoveredService | null> {
  if (probe.kind === "ssh") {
    const banner = await sshBanner(host, probe.port, timeoutMs);
    if (banner && /^SSH-/.test(banner)) {
      return { host, port: probe.port, connectorType: "ssh", label: "SSH host", confidence: "confirmed" };
    }
    return null;
  }
  const res = await httpProbe(host, probe.port, probe.kind === "https", timeoutMs);
  if (!res) return null;
  const match = matchHttp(res.headers, res.body);
  if (match) return { host, port: probe.port, connectorType: match.type, label: match.label, confidence: "confirmed" };
  if (probe.hint) return { host, port: probe.port, connectorType: probe.hint.type, label: probe.hint.label, confidence: "likely" };
  return { host, port: probe.port, connectorType: "http", label: "HTTP service", confidence: "open" };
}

export interface ScanOptions {
  subnets?: string[];
  start?: number;
  end?: number;
  timeoutMs?: number;
  concurrency?: number;
}

/**
 * Scan the configured private subnets: TCP-connect each candidate port, then
 * fingerprint the open ones. LAN-scoped only (RFC1918). Per host, drops generic
 * "HTTP service" entries when a real service was identified, to cut noise.
 */
export async function scanLan(opts: ScanOptions = {}): Promise<DiscoveredService[]> {
  const detected = localSubnets();
  const requested = opts.subnets && opts.subnets.length > 0 ? opts.subnets : detected;
  const subnets = requested.filter(isPrivateSubnet);
  if (subnets.length === 0) return [];

  const start = opts.start ?? 1;
  const end = opts.end ?? 254;
  const timeoutMs = opts.timeoutMs ?? 700;
  const concurrency = opts.concurrency ?? 96;

  const jobs: { host: string; probe: PortProbe }[] = [];
  for (const subnet of subnets) {
    for (let h = start; h <= end; h++) {
      const host = `${subnet}.${h}`;
      for (const probe of PORT_PROBES) jobs.push({ host, probe });
    }
  }

  const found: DiscoveredService[] = [];
  let cursor = 0;
  async function worker(): Promise<void> {
    while (cursor < jobs.length) {
      const job = jobs[cursor++];
      if (!job) return;
      // Cheap TCP check first; only fingerprint if the port is actually open.
      if (!(await tcpOpen(job.host, job.probe.port, Math.min(timeoutMs, 400)))) continue;
      const svc = await fingerprint(job.host, job.probe, timeoutMs);
      if (svc) found.push(svc);
    }
  }
  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  // Per host: if anything was identified (confirmed/likely), drop the generic
  // "open" HTTP entries so the gateway doesn't list four things it isn't.
  const byHost = new Map<string, DiscoveredService[]>();
  for (const svc of found) {
    const list = byHost.get(svc.host) ?? [];
    list.push(svc);
    byHost.set(svc.host, list);
  }
  const result: DiscoveredService[] = [];
  for (const list of byHost.values()) {
    const identified = list.some((s) => s.confidence !== "open");
    for (const s of list) {
      if (identified && s.confidence === "open") continue;
      result.push(s);
    }
  }
  return result.sort((a, b) => (a.host === b.host ? a.port - b.port : a.host.localeCompare(b.host)));
}
