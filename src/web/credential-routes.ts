import { Router } from "express";
import type { AppState } from "../app.js";
import type { CredentialRequest } from "./credential-requests.js";
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
 */

const STYLE =`:root{color-scheme:dark}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:radial-gradient(1000px 500px at 50% -10%,#182033,#0f1115 60%);color:#e6e9ef;display:flex;min-height:100vh;align-items:center;justify-content:center}
.box{background:#171a21;border:1px solid #262b36;border-radius:14px;padding:28px;max-width:440px;width:92%;box-shadow:0 10px 30px rgba(0,0,0,.3)}
h1{font-size:20px;margin:0 0 6px}.mut{color:#8b93a7;font-size:14px}
.warn{background:#2a1f1f;border:1px solid #4a2b2b;color:#ffb4b4;padding:10px 12px;border-radius:8px;font-size:13px;margin:16px 0}
.who{background:#0d0f14;border:1px solid #2b3140;border-radius:8px;padding:12px;margin:14px 0;font-size:14px}
.who b{color:#e6e9ef}.who .row2{color:#8b93a7;margin-top:4px}
label{display:block;font-size:13px;color:#8b93a7;margin:14px 0 6px}
input{width:100%;padding:11px;border-radius:9px;border:1px solid #2b3140;background:#0d0f14;color:#e6e9ef;font-size:16px;box-sizing:border-box}
input.code{letter-spacing:3px;text-align:center}
.row{display:flex;gap:10px;margin-top:18px}
button{flex:1;padding:11px;border-radius:9px;border:1px solid transparent;font-size:14px;font-weight:600;cursor:pointer}
.approve{background:#4d7cfe;color:#fff}.deny{background:#232733;color:#e6e9ef;border-color:#262b36}
.err{color:#ff6b6b;font-size:13px;margin-top:10px;min-height:16px}
code{background:#0d0f14;border:1px solid #2b3140;border-radius:6px;padding:1px 6px}`;

function shell(title: string, inner: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${htmlEscape(title)} — Skeleton Key</title><style>${STYLE}</style></head><body><div class="box">${inner}</div></body></html>`;
}

function messagePage(title: string, body: string): string {
  return shell(title, `<h1>🗝️ ${htmlEscape(title)}</h1><p class="mut">${htmlEscape(body)}</p>`);
}

function formPage(req: CredentialRequest, error?: string): string {
  const secretLabel = req.kind === "token" ? "API token / key" : "Password";
  const usernameField = `<label>Username</label><input type="text" name="username" value="${htmlEscape(req.username ?? "")}" placeholder="e.g. root" autocomplete="off"/>`;
  return shell(
    "Provide a credential",
    `<h1>🗝️ Provide a credential</h1>
  <p class="mut">Claude is asking you to store a credential so it can access a host. It never sees what you type here — the value goes straight into your scoped vault.</p>
  <div class="who">
    <b>${htmlEscape(req.name)}</b> — ${htmlEscape(req.kind)} for <b>${htmlEscape(req.host)}</b>
    <div class="row2">Reason: ${htmlEscape(req.reason)}</div>
  </div>
  <div class="warn">Only continue if <b>you</b> just asked Claude to onboard this host. This stores a credential in your vault.</div>
  <form method="post" action="/credential/${htmlEscape(req.id)}">
    <input type="hidden" name="formToken" value="${htmlEscape(req.formToken)}"/>
    ${req.kind === "password" ? usernameField : ""}
    <label>${secretLabel}</label>
    <input type="password" name="secret" autocomplete="off" autofocus/>
    <label>6-digit authenticator code</label>
    <input class="code" type="text" name="totp" inputmode="numeric" autocomplete="one-time-code" placeholder="000000"/>
    <div class="err">${error ? htmlEscape(error) : ""}</div>
    <div class="row">
      <button class="deny" type="submit" name="action" value="decline">Cancel</button>
      <button class="approve" type="submit" name="action" value="submit">Store credential</button>
    </div>
  </form>`,
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
      res.status(409).type("html").send(formPage(request, "Skeleton Key is locked — unlock it first, then reopen this link."));
      return;
    }

    const totp = firstStr(req.body.totp);
    if (!app.verifyTotp(totp)) {
      res.status(403).type("html").send(formPage(request, "Invalid authenticator code — try again."));
      return;
    }

    const secret = firstStr(req.body.secret);
    if (!secret) {
      res.status(400).type("html").send(formPage(request, "Enter the credential value."));
      return;
    }
    const username = firstStr(req.body.username) || request.username;

    // Claim BEFORE the vault write, so two concurrent valid submits can't both
    // write the item (TOCTOU). The loser sees the already-provided page.
    if (!app.credentialRequests.claim(request.id)) {
      res.type("html").send(messagePage("Already provided", "This credential was just stored. You can close this tab."));
      return;
    }

    try {
      await app.vault.createLoginItem({
        name: request.name,
        username: request.kind === "password" ? username : undefined,
        password: request.kind === "password" ? secret : undefined,
        // An SSH login gets an ssh:// URI; an API token is not SSH, so leave the
        // URI off rather than mislabel it.
        url: request.kind === "password" ? `ssh://${request.host}` : undefined,
        notes: `Stored via Skeleton Key credential hand-off. ${request.reason}`,
        fields: request.kind === "token" ? [{ name: "token", value: secret, hidden: true }] : [],
        collectionName: app.store.get().bwCollectionName,
      });
    } catch (err) {
      // Roll the claim back so the user can retry the same link.
      app.credentialRequests.release(request.id);
      const message = err instanceof Error ? err.message : String(err);
      res.status(400).type("html").send(formPage(request, `Could not store the credential: ${message}`));
      return;
    }

    // Audit the fulfillment — never the secret value.
    app.audit.record({
      ts: new Date().toISOString(),
      tool: "credential.provide",
      target: request.host,
      tier: "execute",
      args: { name: request.name, kind: request.kind },
      status: "ok",
      detail: `credential '${request.name}' stored via hand-off`,
    });
    res.type("html").send(
      messagePage("Stored ✓", `Saved as “${request.name}”. Return to Claude — it can now use this credential. You can close this tab.`),
    );
  });

  return router;
}
