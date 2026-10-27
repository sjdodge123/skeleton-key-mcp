import { createGuardrails, generateSecret, generateSync, verifySync } from "otplib";

/**
 * The admin second factor. Every TOTP operation goes through here so the
 * parameters an enrolled authenticator app depends on — base32 secret, SHA-1,
 * 6 digits, 30-second step, current-step-only window — live in one place and
 * are pinned by `totp.test.ts` independently of the library underneath.
 *
 * Every option is explicit rather than inherited from otplib's defaults, so a
 * library upgrade can't silently widen the window or change the digest.
 */

const PERIOD = 30;
const DIGITS = 6;
/** Bytes of entropy in a new secret: 10 → 16 base32 chars, the shape every existing enrollment has. */
const SECRET_BYTES = 10;

const OPTIONS = {
  algorithm: "sha1",
  digits: DIGITS,
  period: PERIOD,
  // otplib 13 refuses secrets under 16 bytes by default; every secret enrolled
  // under otplib 12 is 10 bytes, so the floor must sit at 10 or the admin is
  // locked out.
  guardrails: createGuardrails({ MIN_SECRET_BYTES: SECRET_BYTES }),
} as const;

/** A fresh base32 secret for enrollment (10 random bytes → 16 chars, no padding). */
export function generateTotpSecret(): string {
  return generateSecret({ length: SECRET_BYTES });
}

/**
 * The `otpauth://` URI an authenticator app scans at enrollment. Built by hand:
 * otplib 13's `generateURI` omits period/digits/algorithm, and this keeps the
 * exact string otplib 12 produced.
 */
export function totpKeyUri(accountLabel: string, issuer: string, secret: string): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountLabel)}`;
  return `otpauth://totp/${label}?secret=${secret}&period=${PERIOD}&digits=${DIGITS}&algorithm=SHA1&issuer=${encodeURIComponent(issuer)}`;
}

/**
 * True only for the code of the current 30-second step. Never throws: a
 * malformed token or secret is simply not a match, so callers fail closed.
 */
export function verifyTotpCode(token: string, secret: string): boolean {
  try {
    return verifySync({ ...OPTIONS, token, secret, epochTolerance: 0 }).valid;
  } catch (err) {
    // A malformed token (wrong length, non-digits) is just a wrong code. Anything
    // else — a secret the library rejects, a guardrail tightened by an upgrade —
    // would lock the admin out with no trace, so log it (the error name only:
    // otplib messages can quote the input).
    const name = err instanceof Error ? err.name : "unknown error";
    if (!/^Token\w*Error$/.test(name)) {
      console.warn(`[skeleton-key] TOTP verification failed with ${name}; refusing the code.`);
    }
    return false;
  }
}

/** The current code for `secret` (tests and diagnostics; production only verifies). */
export function generateTotpCode(secret: string): string {
  return generateSync({ ...OPTIONS, secret });
}
