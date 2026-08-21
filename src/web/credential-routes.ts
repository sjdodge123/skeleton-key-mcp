import { Router } from "express";
import type { AppState } from "../app.js";
import type { CredentialField, CredentialRequest, FieldConstraints, VerificationOutcome } from "./credential-requests.js";
import { safeHost } from "./credential-requests.js";
import { checkConstraints, runVerifyProbe } from "./credential-verify.js";
import { firstStr } from "./http-util.js";
import { htmlEscape } from "./html.js";

/**
 * Secure credential hand-off (issue #18). The agent creates a request via the
 * `request_credential` MCP tool and hands the user a one-time link here. The
 * user enters the secret into this TOTP-gated form, which writes it straight
 * into the scoped vault — so the secret never transits the chat/MCP channel.
 *
 * These routes are intentionally unauthenticated (like the OAuth consent page):
 * the GET page reveals only request metadata (never a secret), and the POST that
 * stores a secret is gated by the admin TOTP. It only functions post-setup with
 * an unlocked store+vault (needed to verify TOTP and write the item).
 *
 * Submit pipeline (all BEFORE any vault write): CSRF → TOTP → required values →
 * per-field shape constraints → claim → optional verification probe → store.
 * A rejection at any step leaves the link claimable for a retry, and never
 * echoes a submitted value.
 */

const STYLE =`:root{color-scheme:dark}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:radial-gradient(1000px 500px at 50% -10%,#182033,#0f1115 60%);color:#e6e9ef;display:flex;min-height:100vh;align-items:center;justify-content:center}
.box{background:#171a21;border:1px solid #262b36;border-radius:14px;padding:28px;max-width:440px;width:92%;box-shadow:0 10px 30px rgba(0,0,0,.3)}
h1{font-size:20px;margin:0 0 6px}.mut{color:#8b93a7;font-size:14px}
.warn{background:#2a1f1f;border:1px solid #4a2b2b;color:#ffb4b4;padding:10px 12px;border-radius:8px;font-size:13px;margin:16px 0}
.note{background:#1f2433;border:1px solid #2c3d5e;color:#bcd0ff;padding:10px 12px;border-radius:8px;font-size:13px;margin:12px 0;word-break:break-all}
.who{background:#0d0f14;border:1px solid #2b3140;border-radius:8px;padding:12px;margin:14px 0;font-size:14px}
.who b{color:#e6e9ef}.who .row2{color:#8b93a7;margin-top:4px}
label{display:block;font-size:13px;color:#8b93a7;margin:14px 0 6px}
input{width:100%;padding:11px;border-radius:9px;border:1px solid #2b3140;background:#0d0f14;color:#e6e9ef;font-size:16px;box-sizing:border-box}
input.code{letter-spacing:3px;text-align:center}
input.bad{border-color:#ff6b6b}
.hint{font-size:12px;color:#8b93a7;margin:5px 0 0;line-height:1.4}
.hint.bad{color:#ff6b6b}
.row{display:flex;gap:10px;margin-top:18px}
button{flex:1;padding:11px;border-radius:9px;border:1px solid transparent;font-size:14px;font-weight:600;cursor:pointer}
.approve{background:#4d7cfe;color:#fff}.deny{background:#232733;color:#e6e9ef;border-color:#262b36}
.err{color:#ff6b6b;font-size:13px;margin-top:10px;min-height:16px}
.chk{display:flex;gap:8px;align-items:flex-start;font-size:13px;color:#ffd38a;margin-top:12px}
.chk input{width:auto;margin-top:2px}
code{background:#0d0f14;border:1px solid #2b3140;border-radius:6px;padding:1px 6px}`;

function shell(title: string, inner: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${htmlEscape(title)} — Skeleton Key</title><style>${STYLE}</style></head><body><div class="box">${inner}</div></body></html>`;
}

function messagePage(title: string, body: string): string {
  return shell(title, `<h1>🗝️ ${htmlEscape(title)}</h1><p class="mut">${htmlEscape(body)}</p>`);
}

/**
 * Form field name for a multi-field value. Prefixed so a requested field can
 * never shadow a control field (`formToken`, `totp`, `action`, `username`).
 */
export const FIELD_INPUT_PREFIX = "f_";

/** Single-secret mode's input name (its constraints are keyed by this too). */
const SECRET_INPUT = "secret";

/** HTML attributes + hint markup for one constrained input. */
function constraintAttrs(c: FieldConstraints | undefined): string {
  if (!c) return "";
  const parts: string[] = [];
  if (c.pattern) parts.push(`pattern="${htmlEscape(c.pattern)}" data-pattern="${htmlEscape(c.pattern)}"`);
  if (c.minLength !== undefined) parts.push(`minlength="${c.minLength}"`);
  if (c.maxLength !== undefined) parts.push(`maxlength="${c.maxLength}"`);
  if (c.hint) parts.push(`title="${htmlEscape(c.hint)}" data-hint="${htmlEscape(c.hint)}"`);
  return parts.length ? " " + parts.join(" ") : "";
}

function hintMarkup(inputName: string, c: FieldConstraints | undefined, failed: boolean): string {
  const bits: string[] = [];
  if (c?.hint) bits.push(htmlEscape(c.hint));
  const shape: string[] = [];
  if (c?.minLength !== undefined && c?.maxLength !== undefined) shape.push(`${c.minLength}–${c.maxLength} chars`);
  else if (c?.minLength !== undefined) shape.push(`at least ${c.minLength} chars`);
  else if (c?.maxLength !== undefined) shape.push(`at most ${c.maxLength} chars`);
  if (shape.length) bits.push(`(${shape.join(", ")})`);
  if (!bits.length && !failed) return "";
  const text = failed ? `✗ That doesn't look right. ${bits.join(" ")}` : bits.join(" ");
  return `<div class="hint${failed ? " bad" : ""}" data-hint-for="${htmlEscape(inputName)}">${text}</div>`;
}

function fieldInputs(fields: CredentialField[], failed: Set<string>): string {
  return fields
    .map((f, idx) => {
      const help = f.label ? ` <span class="mut">— ${htmlEscape(f.label)}</span>` : "";
      const inputName = FIELD_INPUT_PREFIX + f.name;
      const bad = failed.has(f.name);
      return `<label>${htmlEscape(f.name)}${help}</label>
    <input type="${f.secret ? "password" : "text"}" name="${htmlEscape(inputName)}" autocomplete="off"${idx === 0 ? " autofocus" : ""}${bad ? ' class="bad"' : ""}${constraintAttrs(f)}/>
    ${hintMarkup(inputName, f, bad)}`;
    })
    .join("\n    ");
}

interface FormOptions {
  error?: string;
  /** Field names (multi) or `secret` (single) whose value failed its constraints. */
  failedFields?: string[];
  /** Render the "store anyway" override after a failed verification probe. */
  offerStoreAnyway?: boolean;
}

function formPage(req: CredentialRequest, opts: FormOptions = {}): string {
  const multi = req.fields?.length ? req.fields : null;
  const failed = new Set(opts.failedFields ?? []);
  const secretLabel = req.kind === "token" ? "API token / key" : "Password";
  const usernameField = `<label>Username</label><input type="text" name="username" value="${htmlEscape(req.username ?? "")}" placeholder="e.g. root" autocomplete="off"/>`;
  const what = multi ? `${multi.length} value${multi.length === 1 ? "" : "s"}` : (req.kind ?? "credential");
  const title = multi ? "Provide credentials" : "Provide a credential";
  const secretBad = failed.has(SECRET_INPUT);
  const inputs = multi
    ? fieldInputs(multi, failed)
    : `${req.kind === "password" ? usernameField : ""}
    <label>${secretLabel}</label>
    <input type="password" name="${SECRET_INPUT}" autocomplete="off" autofocus${secretBad ? ' class="bad"' : ""}${constraintAttrs(req.constraints)}/>
    ${hintMarkup(SECRET_INPUT, req.constraints, secretBad)}`;
  const verifyNote = req.verify
    ? `<div class="note">🔎 Skeleton Key will <b>test ${multi ? "these values" : "this value"}</b> against <b>${htmlEscape(req.verify.url)}</b> before storing — ${multi ? "they are" : "it is"} sent to that host and nowhere else.</div>`
    : "";
  const overwriteNote = req.overwrite
    ? `<div class="warn">⚠️ This <b>replaces</b> the values of the existing vault item <b>${htmlEscape(req.name)}</b>. The item keeps its id; other fields are left as they are.</div>`
    : "";
  const expires = new Date(req.expiresAt).toLocaleString("en-US", { hour: "numeric", minute: "2-digit", hour12: true, timeZoneName: "short" });
  const storeAnyway = opts.offerStoreAnyway
    ? `<label class="chk"><input type="checkbox" name="storeAnyway" value="1"/> Store anyway — I know this value is right even though the test failed.</label>`
    : "";
  return shell(
    title,
    `<h1>🗝️ ${htmlEscape(title)}</h1>
  <p class="mut">Claude is asking you to store ${multi ? "credentials" : "a credential"} so it can access a host. It never sees what you type here — ${multi ? "the values go" : "the value goes"} straight into your scoped vault.</p>
  <div class="who">
    <b>${htmlEscape(req.name)}</b> — ${htmlEscape(what)} for <b>${htmlEscape(req.host)}</b>
    <div class="row2">Reason: ${htmlEscape(req.reason)}</div>
    <div class="row2">Link expires: <span data-expires="${req.expiresAt}">${htmlEscape(expires)}</span></div>
  </div>
  ${overwriteNote}
  ${verifyNote}
  <div class="warn">Only continue if <b>you</b> just asked Claude to onboard this host. This stores ${multi ? "credentials" : "a credential"} in your vault.</div>
  <form method="post" action="/credential/${htmlEscape(req.id)}">
    <input type="hidden" name="formToken" value="${htmlEscape(req.formToken)}"/>
    ${inputs}
    <label>6-digit authenticator code</label>
    <input class="code" type="text" name="totp" inputmode="numeric" autocomplete="one-time-code" placeholder="000000"/>
    <div class="err">${opts.error ? htmlEscape(opts.error) : ""}</div>
    ${storeAnyway}
    <div class="row">
      <button class="deny" type="submit" name="action" value="decline">Cancel</button>
      <button class="approve" type="submit" name="action" value="submit">Store credential${multi ? "s" : ""}</button>
    </div>
  </form>
  <script>
  (function(){
    var f = document.querySelector('form'); var busy = false;
    var exp = document.querySelector('[data-expires]');
    if (exp) { exp.textContent = new Date(Number(exp.getAttribute('data-expires'))).toLocaleString(); }
    // Client-side shape check: block submit and surface the hint when a value
    // doesn't match its pattern / length. The server re-checks regardless.
    function check(){
      var bad = 0;
      f.querySelectorAll('input[data-pattern],input[minlength],input[maxlength]').forEach(function(inp){
        var v = inp.value, ok = true, p = inp.getAttribute('data-pattern');
        var min = inp.getAttribute('minlength'), max = inp.getAttribute('maxlength');
        if (min && v.length < Number(min)) ok = false;
        if (max && v.length > Number(max)) ok = false;
        if (ok && p) { try { ok = new RegExp('^(?:' + p + ')$', 'u').test(v); } catch (_) { try { ok = new RegExp('^(?:' + p + ')$').test(v); } catch (__) { ok = true; } } }
        var hint = f.querySelector('[data-hint-for="' + inp.name + '"]');
        if (!ok) {
          bad++; inp.classList.add('bad');
          if (!hint) { hint = document.createElement('div'); hint.setAttribute('data-hint-for', inp.name); inp.insertAdjacentElement('afterend', hint); }
          hint.className = 'hint bad';
          hint.textContent = "✗ That doesn't look right. " + (inp.getAttribute('data-hint') || '') + (min || max ? ' (' + (min && max ? min + '–' + max : min ? 'at least ' + min : 'at most ' + max) + ' chars)' : '');
        } else { inp.classList.remove('bad'); if (hint) { hint.className = 'hint'; } }
      });
      return bad === 0;
    }
    f.addEventListener('submit', function(e){
      if (busy){ e.preventDefault(); return; }        // block double-submit
      var s = f.querySelector('button.approve');
      if (s && e.submitter === s && !check()) { e.preventDefault(); return; }
      busy = true;
      if (s && e.submitter === s){ s.textContent = 'Storing…'; } // feedback without disabling (keeps its value)
      f.querySelectorAll('button').forEach(function(b){ b.style.opacity = '0.6'; b.style.cursor = 'default'; });
    });
  })();
  </script>`,
  );
}

/** Human-readable page for a request that can't accept input. */
function terminalPage(req: CredentialRequest): string | null {
  switch (req.status) {
    case "fulfilled":
      return messagePage("Already provided", "This credential was already stored. You can close this tab.");
    case "declined":
      return messagePage("Cancelled", "This request was cancelled. You can close this tab.");
    case "expired":
      return messagePage("Link expired", "This request link has expired. Ask Claude to send a new one.");
    default:
      return null;
  }
}

export function buildCredentialRouter(app: AppState): Router {
  const router = Router();

  router.get("/credential/:id", async (req, res) => {
    if (!(await app.isSetupComplete())) {
      res.status(404).type("html").send(messagePage("Not available", "Skeleton Key setup isn't complete yet."));
      return;
    }
    const request = app.credentialRequests.get(req.params.id!);
    if (!request) {
      res.status(404).type("html").send(messagePage("Unknown link", "This credential link is not valid."));
      return;
    }
    const terminal = terminalPage(request);
    if (terminal) {
      res.type("html").send(terminal);
      return;
    }
    res.type("html").send(formPage(request));
  });

  router.post("/credential/:id", async (req, res) => {
    const request = app.credentialRequests.get(req.params.id!);
    if (!request) {
      res.status(404).type("html").send(messagePage("Unknown link", "This credential link is not valid."));
      return;
    }
    const terminal = terminalPage(request);
    if (terminal) {
      res.type("html").send(terminal);
      return;
    }

    // CSRF: the form token is only present in the same-origin rendered page, so
    // a blind cross-site POST (which can't read the page) can't act on the link.
    if (firstStr(req.body.formToken) !== request.formToken) {
      res.status(403).type("html").send(messagePage("Expired form", "This form is stale — reopen the link and try again."));
      return;
    }

    if (firstStr(req.body.action) === "decline") {
      app.credentialRequests.decline(request.id);
      res.type("html").send(messagePage("Cancelled", "No credential was stored. You can close this tab."));
      return;
    }

    // The store must be unlocked to verify TOTP and write to the vault.
    if (app.store.locked || !app.vault.unlocked) {
      res.status(409).type("html").send(formPage(request, { error: "Skeleton Key is locked — unlock it first, then reopen this link." }));
      return;
    }

    const totp = firstStr(req.body.totp);
    if (!app.verifyTotp(totp)) {
      res.status(403).type("html").send(formPage(request, { error: "Invalid authenticator code — try again." }));
      return;
    }

    const multi = request.fields?.length ? request.fields : null;

    // Collect the submitted value(s). Multi-field: every requested field is
    // required, so a half-filled item never lands in the vault.
    let values: { name: string; value: string; hidden: boolean }[] = [];
    let secret = "";
    if (multi) {
      const missing: string[] = [];
      for (const f of multi) {
        const value = firstStr(req.body[FIELD_INPUT_PREFIX + f.name]);
        if (!value) missing.push(f.name);
        else values.push({ name: f.name, value, hidden: f.secret });
      }
      if (missing.length) {
        res.status(400).type("html").send(formPage(request, { error: `Fill in every value — missing: ${missing.join(", ")}.` }));
        return;
      }
    } else {
      secret = firstStr(req.body.secret);
      if (!secret) {
        res.status(400).type("html").send(formPage(request, { error: "Enter the credential value." }));
        return;
      }
    }
    const username = firstStr(req.body.username) || request.username;

    // Per-field shape constraints, server-side — the browser check is a
    // convenience, this is the gate. Names the failing field(s) and their
    // hints; NEVER the value.
    {
      const failed: { name: string; problem: string }[] = [];
      if (multi) {
        for (const f of multi) {
          const problem = checkConstraints(values.find((v) => v.name === f.name)!.value, f);
          if (problem) failed.push({ name: f.name, problem });
        }
      } else {
        const problem = checkConstraints(secret, request.constraints);
        if (problem) failed.push({ name: SECRET_INPUT, problem });
      }
      if (failed.length) {
        values = [];
        secret = "";
        const describe = failed.map((f) => `${f.name === SECRET_INPUT ? "the value" : f.name} (${f.problem})`).join("; ");
        res.status(400).type("html").send(
          formPage(request, {
            error: `Not stored — ${describe}. Check the hint under the field and try again.`,
            failedFields: failed.map((f) => f.name),
          }),
        );
        return;
      }
    }

    // Claim BEFORE the probe / vault write, so two concurrent valid submits
    // can't both write the item (TOCTOU). The loser sees the already-provided page.
    if (!app.credentialRequests.claim(request.id)) {
      values = [];
      secret = "";
      res.type("html").send(messagePage("Already provided", "This credential was just stored. You can close this tab."));
      return;
    }

    // Optional verification probe — runs BEFORE the vault write so a wrong
    // value never lands. Audited as host + status only.
    let verification: VerificationOutcome = "skipped";
    if (request.verify) {
      const templateValues: Record<string, string> = multi ? Object.fromEntries(values.map((v) => [v.name, v.value])) : { value: secret };
      const result = await runVerifyProbe(request.verify, templateValues);
      for (const k of Object.keys(templateValues)) delete templateValues[k];
      const storeAnyway = firstStr(req.body.storeAnyway) === "1";
      app.audit.record({
        ts: new Date().toISOString(),
        tool: "credential.verify",
        target: result.host,
        tier: "execute",
        args: { name: request.name, host: result.host, status: result.status ?? null, storeAnyway },
        status: result.ok ? "ok" : "error",
        detail: result.ok
          ? `verification probe passed (HTTP ${result.status}) for '${request.name}'`
          : `verification probe failed for '${request.name}': ${result.reason}${storeAnyway ? " — stored anyway by user override" : ""}`,
      });
      if (result.ok) {
        verification = "passed";
      } else if (storeAnyway) {
        verification = "failed";
      } else {
        app.credentialRequests.release(request.id);
        values = [];
        secret = "";
        res.status(400).type("html").send(
          formPage(request, {
            error: `Verification failed: ${result.reason}. Nothing was stored — double-check the value, or tick "store anyway" to override.`,
            offerStoreAnyway: true,
          }),
        );
        return;
      }
    }

    const fingerprints: Record<string, string> = {};
    try {
      // One vault item for the whole set: each requested field becomes a custom
      // field (hidden type when it's a secret). A field literally named
      // `username` also populates the item's login username so
      // `Credential.username` resolves naturally for connectors.
      const loginUsername = multi ? values.find((v) => v.name === "username")?.value : request.kind === "password" ? username : undefined;
      const fields = multi ? values : request.kind === "token" ? [{ name: "token", value: secret, hidden: true }] : [];
      if (request.overwrite) {
        // Re-fill the EXISTING item in place (same id): listed fields are
        // replaced by name, everything else on the item is kept.
        await app.vault.updateLoginItem(request.name, {
          username: loginUsername,
          password: !multi && request.kind === "password" ? secret : undefined,
          fields,
        });
      } else {
        await app.vault.createLoginItem({
          name: request.name,
          username: loginUsername,
          password: !multi && request.kind === "password" ? secret : undefined,
          // An SSH login gets an ssh:// URI; an API token / arbitrary field set is
          // not SSH, so leave the URI off rather than mislabel it.
          url: !multi && request.kind === "password" ? `ssh://${request.host}` : undefined,
          notes: `Stored via Skeleton Key credential hand-off. ${request.reason}`,
          fields,
          collectionName: app.store.get().bwCollectionName,
        });
      }
      // Keyed fingerprints (len + HMAC prefix) so the agent can later compare
      // what the vault holds with what a stack reports — without the value.
      for (const f of fields) fingerprints[f.name] = await app.fingerprint(f.value);
      if (!multi && request.kind === "password") fingerprints.password = await app.fingerprint(secret);
    } catch (err) {
      // Roll the claim back so the user can retry the same link.
      app.credentialRequests.release(request.id);
      const message = err instanceof Error ? err.message : String(err);
      res.status(400).type("html").send(formPage(request, { error: `Could not store the credential${multi ? "s" : ""}: ${message}` }));
      return;
    } finally {
      // Drop the plaintext values as soon as the write is done (or failed) —
      // they must not linger in this closure.
      values = [];
      secret = "";
    }
    app.credentialRequests.complete(request.id, { verification, fingerprints });

    const fieldNames = multi ? multi.map((f) => f.name) : null;
    // Audit the fulfillment — field NAMES only, never a submitted value.
    app.audit.record({
      ts: new Date().toISOString(),
      tool: "credential.provide",
      target: request.host,
      tier: "execute",
      args: { name: request.name, kind: request.kind, fields: fieldNames ?? undefined, overwrite: request.overwrite, verification },
      status: "ok",
      detail:
        `credential '${request.name}' ${request.overwrite ? "updated" : "stored"} via hand-off` +
        `${fieldNames ? ` (${fieldNames.length} fields)` : ""} [verification: ${verification}]`,
    });
    res.type("html").send(
      messagePage(
        "Stored ✓",
        `${request.overwrite ? "Updated" : "Saved as"} “${request.name}”${fieldNames ? ` with ${fieldNames.length} field(s): ${fieldNames.join(", ")}` : ""}` +
          `${verification === "passed" ? ` — verified against ${safeHost(request.verify!.url)}` : verification === "failed" ? " — stored WITHOUT passing verification (your override)" : ""}. ` +
          `Return to Claude — it can now use ${fieldNames ? "these credentials" : "this credential"}. You can close this tab.`,
      ),
    );
  });

  return router;
}
