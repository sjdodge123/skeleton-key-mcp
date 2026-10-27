/**
 * An error whose message is safe to show an HTTP client verbatim. Its text is
 * composed only by our own code, from fixed wording plus values the admin
 * already sees (a target or vault-item name, a configured path) — never request
 * input that could be a secret, an upstream service's response, or a credential
 * value. The web layer echoes ONLY these (and zod issue paths); any other error
 * reaches a client as a fixed string, because its message can quote a request
 * body, a `bw` stderr line, or a value from upstream.
 */
export class UserFacingError extends Error {
  override readonly name = "UserFacingError";

  constructor(
    message: string,
    /** HTTP status the web layer answers with. */
    readonly status: number = 400,
  ) {
    super(message);
  }
}
