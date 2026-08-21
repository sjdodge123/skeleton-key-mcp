import { isIP } from "node:net";
import type { VerifySpec } from "./credential-requests.js";

/**
 * Pre-store verification probe for the credential hand-off.
 *
 * The agent can attach a `verify` spec to a request ("GET
 * https://discord.com/api/v10/users/@me with Authorization: Bot {{value}}").
 * After the user submits, and BEFORE anything is written to the vault, the
 * server templates the submitted value(s) into the headers and performs the
 * request. A wrong value (the Discord Client Secret where the Bot Token was
 * expected) fails here instead of after a deploy.
 *
 * Security posture:
 *  - The secret is SENT to `url`, so the URL is restricted to https, with plain
 *    http allowed only for RFC1918 / loopback LAN hosts, and the host is shown
 *    to the human in the approval prompt and on the form.
 *  - Redirects are not followed (a 3xx would otherwise forward the secret to a
 *    host nobody approved).
 *  - Nothing from the response body, and none of the templated headers, are
 *    ever logged, echoed, or returned — only the status code and host.
 */

export const MAX_VERIFY_TIMEOUT_MS = 15_000;
export const DEFAULT_VERIFY_TIMEOUT_MS = 8_000;

/** RFC1918 + loopback + link-local literal IPs, and `localhost`. */
export function isLanHost(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost" || h === "::1") return true;
  if (isIP(h) === 4) {
    const [a, b] = h.split(".").map(Number) as [number, number];
    if (a === 10 || a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
  }
  return false;
}

/** Returns an error message when `url` is not an acceptable probe target, else null. */
export function validateVerifyUrl(url: string): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return "verify.url is not a valid absolute URL.";
  }
  if (u.username || u.password) return "verify.url must not embed credentials.";
  if (u.protocol === "https:") return null;
  if (u.protocol === "http:") {
    return isLanHost(u.hostname) ? null : "verify.url must be https (plain http is allowed only for RFC1918/localhost LAN hosts).";
  }
  return "verify.url must use https (or http for LAN hosts).";
}

const TEMPLATE_RE = /\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g;

/** Placeholder names referenced by the header templates (e.g. `value`, `DISCORD_BOT_TOKEN`). */
export function templatePlaceholders(headers: Record<string, string> | undefined): string[] {
  const names = new Set<string>();
  for (const v of Object.values(headers ?? {})) {
    for (const m of v.matchAll(TEMPLATE_RE)) names.add(m[1]!);
  }
  return [...names];
}

/** Substitute `{{name}}` placeholders with `values[name]`; unknown names are left untouched. */
export function templateHeaders(headers: Record<string, string> | undefined, values: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers ?? {})) {
    out[k] = v.replace(TEMPLATE_RE, (whole, name: string) => (name in values ? values[name]! : whole));
  }
  return out;
}

export interface VerifyResult {
  ok: boolean;
  /** Hostname (+port) of the probe target, safe to display. */
  host: string;
  /** HTTP status when a response was received. */
  status?: number;
  /** Safe, value-free reason for a failure (timeout / network / unexpected status). */
  reason?: string;
}

/**
 * Run the probe. `values` maps placeholder names to submitted values (`value`
 * for single-secret mode, field names for multi-field). Never throws — every
 * failure becomes `{ ok: false, reason }` with no secret material in it.
 */
export async function runVerifyProbe(
  spec: VerifySpec,
  values: Record<string, string>,
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<VerifyResult> {
  let host = spec.url;
  try {
    host = new URL(spec.url).host;
  } catch {
    /* reported below by validateVerifyUrl */
  }
  const urlError = validateVerifyUrl(spec.url);
  if (urlError) return { ok: false, host, reason: urlError };

  const timeoutMs = Math.min(MAX_VERIFY_TIMEOUT_MS, Math.max(500, spec.timeoutMs ?? DEFAULT_VERIFY_TIMEOUT_MS));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let headers = templateHeaders(spec.headers, values);
  try {
    const res = await fetchImpl(spec.url, {
      method: spec.method,
      headers,
      redirect: "manual",
      signal: controller.signal,
    });
    // Discard the body without reading it into anything we keep.
    await res.body?.cancel().catch(() => {});
    const expected = spec.expectStatus?.length ? spec.expectStatus : null;
    const ok = expected ? expected.includes(res.status) : res.status >= 200 && res.status < 300;
    return ok ? { ok: true, host, status: res.status } : { ok: false, host, status: res.status, reason: `HTTP ${res.status} from ${host}` };
  } catch (err) {
    // Deliberately NOT err.message: undici errors can embed request details.
    const aborted = (err as { name?: string })?.name === "AbortError";
    const code = (err as { cause?: { code?: string } })?.cause?.code;
    return {
      ok: false,
      host,
      reason: aborted ? `timed out after ${timeoutMs}ms contacting ${host}` : `could not reach ${host}${code ? ` (${code})` : ""}`,
    };
  } finally {
    clearTimeout(timer);
    headers = {};
  }
}

/** Compile a field `pattern` as a full-match regex, or null if it doesn't compile. */
export function compileFullMatch(pattern: string): RegExp | null {
  try {
    return new RegExp(`^(?:${pattern})$`, "u");
  } catch {
    try {
      return new RegExp(`^(?:${pattern})$`);
    } catch {
      return null;
    }
  }
}

export type ConstraintProblem = "too short" | "too long" | "does not match the expected pattern";

/**
 * Check one value against its constraints. Returns a value-free problem
 * description, or null when it passes.
 */
export function checkConstraints(
  value: string,
  c: { pattern?: string; minLength?: number; maxLength?: number } | undefined,
): ConstraintProblem | null {
  if (!c) return null;
  const len = value.length;
  if (c.minLength !== undefined && len < c.minLength) return "too short";
  if (c.maxLength !== undefined && len > c.maxLength) return "too long";
  if (c.pattern) {
    const re = compileFullMatch(c.pattern);
    if (re && !re.test(value)) return "does not match the expected pattern";
  }
  return null;
}
