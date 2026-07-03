import { Router, type Response } from "express";
import { z } from "zod";
import type { AppState } from "../app.js";
import { OAUTH_SCOPE } from "../oauth/oauth-service.js";
import { baseUrl, firstStr } from "./http-util.js";
import { htmlEscape } from "./html.js";

/**
 * OAuth 2.1 endpoints for the MCP authorization flow. Claude discovers these via
 * the well-known metadata, dynamically registers itself, then runs the
 * authorization-code + PKCE flow. Human consent happens on a TOTP-gated screen,
 * so only the admin (with the authenticator) can authorize an agent.
 */

function consentPage(params: {
  clientName: string;
  fields: Record<string, string>;
  error?: string;
}): string {
  const hidden = Object.entries(params.fields)
    .map(([k, v]) => `<input type="hidden" name="${htmlEscape(k)}" value="${htmlEscape(v)}"/>`)
    .join("");
  return `<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Authorize agent — Skeleton Key</title><style>
  :root{color-scheme:dark}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:radial-gradient(1000px 500px at 50% -10%,#182033,#0f1115 60%);color:#e6e9ef;display:flex;min-height:100vh;align-items:center;justify-content:center}
  .box{background:#171a21;border:1px solid #262b36;border-radius:14px;padding:28px;max-width:440px;width:92%;box-shadow:0 10px 30px rgba(0,0,0,.3)}
  h1{font-size:20px;margin:0 0 6px}.mut{color:#8b93a7;font-size:14px}
  .warn{background:#2a1f1f;border:1px solid #4a2b2b;color:#ffb4b4;padding:10px 12px;border-radius:8px;font-size:13px;margin:16px 0}
  .who{background:#0d0f14;border:1px solid #2b3140;border-radius:8px;padding:12px;margin:14px 0}
  label{display:block;font-size:13px;color:#8b93a7;margin:14px 0 6px}
  input[type=text]{width:100%;padding:11px;border-radius:9px;border:1px solid #2b3140;background:#0d0f14;color:#e6e9ef;font-size:16px;letter-spacing:3px;text-align:center}
  .row{display:flex;gap:10px;margin-top:18px}
  button{flex:1;padding:11px;border-radius:9px;border:1px solid transparent;font-size:14px;font-weight:600;cursor:pointer}
  .approve{background:#4d7cfe;color:#fff}.deny{background:#232733;color:#e6e9ef;border-color:#262b36}
  .err{color:#ff6b6b;font-size:13px;margin-top:10px;min-height:16px}
  code{background:#0d0f14;border:1px solid #2b3140;border-radius:6px;padding:1px 6px}
</style></head><body>
<div class="box">
  <h1>🗝️ Authorize an AI agent</h1>
  <p class="mut">An application wants access to your Skeleton Key homelab through Claude.</p>
  <div class="who"><b>${htmlEscape(params.clientName)}</b><br/><span class="mut">Scope: <code>${htmlEscape(OAUTH_SCOPE)}</code> — read logs and run approved tools across your registered targets.</span></div>
  <div class="warn">Only approve if <b>you</b> just started this connection from Claude. This grants the agent access to your infrastructure.</div>
  <form method="post" action="/oauth/authorize/decision">
    ${hidden}
    <label>Enter your 6-digit authenticator code to approve</label>
    <input type="text" name="totp" inputmode="numeric" autocomplete="one-time-code" placeholder="000000" autofocus/>
    <div class="err">${params.error ? htmlEscape(params.error) : ""}</div>
    <div class="row">
      <button class="deny" type="submit" name="action" value="deny">Deny</button>
      <button class="approve" type="submit" name="action" value="approve">Approve</button>
    </div>
  </form>
</div></body></html>`;
}

export function buildOAuthRouter(app: AppState): Router {
  const router = Router();

  // --- Discovery metadata ---
  router.get("/.well-known/oauth-authorization-server", (req, res) => {
    const b = baseUrl(req, app);
    res.json({
      issuer: b,
      authorization_endpoint: `${b}/oauth/authorize`,
      token_endpoint: `${b}/oauth/token`,
      registration_endpoint: `${b}/oauth/register`,
      revocation_endpoint: `${b}/oauth/revoke`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: [OAUTH_SCOPE],
    });
  });

  router.get("/.well-known/oauth-protected-resource", (req, res) => {
    const b = baseUrl(req, app);
    res.json({ resource: `${b}/mcp`, authorization_servers: [b], scopes_supported: [OAUTH_SCOPE] });
  });

  // --- Dynamic client registration (RFC 7591) ---
  router.post("/oauth/register", (req, res) => {
    const parsed = z
      .object({ client_name: z.string().optional(), redirect_uris: z.array(z.string().url()).min(1) })
      .safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_client_metadata", error_description: parsed.error.message });
      return;
    }
    const client = app.oauth.registerClient(parsed.data);
    res.status(201).json({
      client_id: client.client_id,
      client_name: client.client_name,
      redirect_uris: client.redirect_uris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
    });
  });

  // --- Authorization endpoint: render the consent screen ---
  router.get("/oauth/authorize", (req, res) => {
    // firstStr guards against array-valued (duplicated) query params.
    const client_id = firstStr(req.query.client_id);
    const redirect_uri = firstStr(req.query.redirect_uri);
    const response_type = firstStr(req.query.response_type);
    const code_challenge = firstStr(req.query.code_challenge);
    const code_challenge_method = firstStr(req.query.code_challenge_method);
    const state = firstStr(req.query.state);
    const client = client_id ? app.oauth.getClient(client_id) : undefined;
    if (!client) {
      res.status(400).send("Unknown client_id");
      return;
    }
    if (!client.redirect_uris.includes(redirect_uri)) {
      res.status(400).send("redirect_uri not registered for this client");
      return;
    }
    if (response_type !== "code") return redirectError(res, redirect_uri, state, "unsupported_response_type");
    if (!code_challenge || code_challenge_method !== "S256") {
      return redirectError(res, redirect_uri, state, "invalid_request", "PKCE S256 required");
    }
    res.type("html").send(
      consentPage({
        clientName: client.client_name,
        fields: { client_id, redirect_uri, state, code_challenge, scope: OAUTH_SCOPE },
      }),
    );
  });

  // --- Consent decision (TOTP-gated) ---
  router.post("/oauth/authorize/decision", (req, res) => {
    const client_id = firstStr(req.body.client_id);
    const redirect_uri = firstStr(req.body.redirect_uri);
    const state = firstStr(req.body.state);
    const code_challenge = firstStr(req.body.code_challenge);
    const totp = firstStr(req.body.totp);
    const action = firstStr(req.body.action);
    const client = client_id ? app.oauth.getClient(client_id) : undefined;
    if (!client || !client.redirect_uris.includes(redirect_uri)) {
      res.status(400).send("Invalid client or redirect_uri");
      return;
    }
    if (action === "deny") {
      return redirectError(res, redirect_uri, state, "access_denied", "User denied the request");
    }
    if (!app.verifyTotp(totp)) {
      res.type("html").send(
        consentPage({
          clientName: client.client_name,
          error: "Invalid authenticator code — try again.",
          fields: { client_id, redirect_uri, state, code_challenge, scope: OAUTH_SCOPE },
        }),
      );
      return;
    }
    const code = app.oauth.createAuthCode({ client_id, redirect_uri, code_challenge, scope: OAUTH_SCOPE });
    app.audit.record({
      ts: new Date().toISOString(), tool: "oauth.authorize", target: client.client_name,
      tier: "execute", args: { client_id }, status: "ok", detail: "agent authorized",
    });
    const url = new URL(redirect_uri);
    url.searchParams.set("code", code);
    if (state) url.searchParams.set("state", state);
    res.redirect(url.toString());
  });

  // --- Token endpoint ---
  router.post("/oauth/token", (req, res) => {
    const grant_type = firstStr(req.body.grant_type);
    const code = firstStr(req.body.code);
    const client_id = firstStr(req.body.client_id);
    const redirect_uri = firstStr(req.body.redirect_uri);
    const code_verifier = firstStr(req.body.code_verifier);
    const refresh_token = firstStr(req.body.refresh_token);
    try {
      if (grant_type === "authorization_code") {
        const out = app.oauth.redeemAuthCode({ code, client_id, redirect_uri, code_verifier });
        res.json({ token_type: "Bearer", access_token: out.access_token, refresh_token: out.refresh_token, expires_in: out.expires_in, scope: out.scope });
      } else if (grant_type === "refresh_token") {
        // client_id is optional for public clients; refresh() checks it only if present.
        const out = app.oauth.refresh(refresh_token, client_id || undefined);
        res.json({ token_type: "Bearer", access_token: out.access_token, refresh_token: out.refresh_token, expires_in: out.expires_in, scope: out.scope });
      } else {
        res.status(400).json({ error: "unsupported_grant_type" });
      }
    } catch (err) {
      res.status(400).json({ error: "invalid_grant", error_description: err instanceof Error ? err.message : String(err) });
    }
  });

  // --- Token revocation (RFC 7009) ---
  router.post("/oauth/revoke", (req, res) => {
    const t = firstStr(req.body.token);
    if (t) app.oauth.revokeToken(t);
    // RFC 7009: always 200, even for unknown/invalid tokens.
    res.status(200).end();
  });

  return router;
}

function redirectError(res: Response, redirectUri: string, state: string | undefined, error: string, description?: string): void {
  try {
    const url = new URL(redirectUri);
    url.searchParams.set("error", error);
    if (description) url.searchParams.set("error_description", description);
    if (state) url.searchParams.set("state", state);
    res.redirect(url.toString());
  } catch {
    res.status(400).send(`${error}: ${description ?? ""}`);
  }
}
