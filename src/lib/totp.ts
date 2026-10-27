import { authenticator } from "otplib";

/**
 * The admin second factor. Every TOTP operation goes through here so the
 * parameters an enrolled authenticator app depends on — base32 secret, SHA-1,
 * 6 digits, 30-second step, current-step-only window — live in one place and
 * are pinned by `totp.test.ts` independently of the library underneath.
 */

/** A fresh base32 secret for enrollment (10 random bytes → 16 chars, no padding). */
export function generateTotpSecret(): string {
  return authenticator.generateSecret();
}

/** The `otpauth://` URI an authenticator app scans at enrollment. */
export function totpKeyUri(accountLabel: string, issuer: string, secret: string): string {
  return authenticator.keyuri(accountLabel, issuer, secret);
}

/**
 * True only for the code of the current 30-second step. Never throws: a
 * malformed token or secret is simply not a match, so callers fail closed.
 */
export function verifyTotpCode(token: string, secret: string): boolean {
  try {
    return authenticator.verify({ token, secret });
  } catch {
    return false;
  }
}

/** The current code for `secret` (tests and diagnostics; production only verifies). */
export function generateTotpCode(secret: string): string {
  return authenticator.generate(secret);
}
