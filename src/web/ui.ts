/**
 * The first-run setup wizard, served as a single self-contained page. Kept as an
 * embedded string so it ships in the image with no separate build/copy step.
 * Vanilla JS talks to the /api endpoints in routes.ts.
 */
export const WIZARD_HTML = /* html */ `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Skeleton Key — Setup</title>
<style>
  :root { color-scheme: dark; --bg:#0f1115; --panel:#171a21; --panel2:#1c202b; --line:#262b36; --acc:#4d7cfe; --acc-h:#3b6bf0; --ok:#3ecf8e; --bad:#ff6b6b; --mut:#8b93a7; --text:#e6e9ef; --radius:10px; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; font-size:15px; line-height:1.55; color:var(--text); min-height:100vh; background:radial-gradient(1100px 560px at 50% -12%, #182033 0%, var(--bg) 62%); }
  header { padding:16px 28px; border-bottom:1px solid var(--line); display:flex; align-items:center; gap:12px; background:rgba(23,26,33,.65); backdrop-filter:blur(8px); position:sticky; top:0; z-index:5; }
  header .logo { font-size:22px; }
  header h1 { font-size:17px; margin:0; font-weight:600; letter-spacing:.2px; }
  main { max-width:720px; margin:0 auto; padding:28px 20px 64px; }

  /* Stepper / breadcrumbs */
  .steps { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:26px; }
  .step { font-size:12.5px; padding:6px 12px; border-radius:999px; background:var(--panel2); color:var(--mut); border:1px solid var(--line); user-select:none; display:inline-flex; align-items:center; gap:7px; transition:border-color .15s,color .15s,background .15s; }
  .step .num { display:inline-flex; align-items:center; justify-content:center; width:18px; height:18px; border-radius:50%; background:#2a3040; font-size:11px; font-weight:600; }
  .step.done { color:var(--ok); border-color:#274b3d; }
  .step.done .num { background:#1f3b30; color:var(--ok); }
  .step.active { color:#fff; background:var(--acc); border-color:var(--acc); }
  .step.active .num { background:rgba(255,255,255,.28); color:#fff; }
  .step.clickable { cursor:pointer; }
  .step.clickable:hover { border-color:var(--acc); color:#fff; }

  /* Card */
  .card { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:24px; margin-bottom:18px; box-shadow:0 10px 30px rgba(0,0,0,.25); }
  h2 { margin:0 0 6px; font-size:21px; font-weight:650; }
  h3 { font-size:12px; margin:18px 0 8px; color:var(--mut); text-transform:uppercase; letter-spacing:.6px; }

  /* Forms */
  label { display:block; font-size:13px; color:var(--mut); margin:14px 0 6px; }
  .form-control { width:100%; padding:11px 12px; border-radius:var(--radius); border:1px solid #2b3140; background:#0d0f14; color:var(--text); font-size:14px; transition:border-color .15s,box-shadow .15s; }
  .form-control:focus { outline:none; border-color:var(--acc); box-shadow:0 0 0 3px rgba(77,124,254,.22); }

  /* Buttons */
  .btn { display:inline-flex; align-items:center; justify-content:center; gap:8px; background:var(--acc); color:#fff; border:1px solid transparent; padding:10px 18px; border-radius:var(--radius); font-size:14px; font-weight:550; cursor:pointer; margin-top:16px; transition:background .15s,border-color .15s,opacity .15s; }
  .btn:hover:not(:disabled) { background:var(--acc-h); }
  .btn:disabled { opacity:.65; cursor:not-allowed; }
  .btn-secondary { background:var(--panel2); border-color:var(--line); color:var(--text); }
  .btn-secondary:hover:not(:disabled) { background:#242a37; }
  .btn-outline { background:transparent; border-color:#2b3140; color:var(--mut); }
  .btn-outline:hover:not(:disabled) { background:transparent; border-color:var(--acc); color:#fff; }
  .btn-sm { padding:7px 12px; font-size:13px; margin:0; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }

  /* Spinner */
  .spinner { width:15px; height:15px; border:2px solid rgba(255,255,255,.35); border-top-color:#fff; border-radius:50%; display:inline-block; animation:spin .6s linear infinite; }
  .btn-secondary .spinner, .btn-outline .spinner { border-color:rgba(139,147,167,.35); border-top-color:var(--text); }
  @keyframes spin { to { transform:rotate(360deg); } }

  /* Checks */
  .check { padding:10px 14px; border-radius:10px; margin:8px 0; background:#0d0f14; border-left:3px solid var(--mut); }
  .check.ok { border-color:var(--ok); }
  .check.bad { border-color:var(--bad); }
  .check .n { font-weight:600; }
  .check .d { color:var(--mut); font-size:13px; }

  /* Misc */
  code, pre { background:#0d0f14; border:1px solid #2b3140; border-radius:8px; }
  pre { padding:14px; overflow:auto; font-size:12.5px; }
  code { padding:2px 6px; font-size:12.5px; }
  .muted { color:var(--mut); font-size:13.5px; }
  .svc { display:flex; align-items:center; gap:10px; padding:10px 4px; border-bottom:1px solid var(--line); }
  .err { color:var(--bad); margin-top:12px; min-height:18px; font-size:13.5px; }
  ol { padding-left:20px; } ol li { margin:7px 0; }
  img.qr { background:#fff; padding:8px; border-radius:8px; margin-top:12px; }
  .pwwrap { position:relative; display:flex; align-items:center; }
  .pwwrap .form-control { padding-right:78px; }
  .pwwrap .btn-reveal { position:absolute; right:6px; top:50%; transform:translateY(-50%); }
</style>
</head>
<body>
<header><span class="logo">🗝️</span><h1>Skeleton Key — First-run setup</h1></header>
<main>
  <div class="steps" id="steps"></div>
  <div id="view"></div>
  <div class="err" id="err"></div>
</main>
<script>
const S = { step:0, max:0, discovered:[], bearer:null };
const STEP_NAMES = ["Passphrase","Welcome","Vaultwarden","Connect","Verify","Discover","2FA","Auto-unlock","Claude","Done"];
const el = (id)=>document.getElementById(id);
const err = (m)=>{ el("err").textContent = m || ""; };
async function api(path, body){
  const r = await fetch("/api"+path, { method: body?"POST":"GET", headers:{"content-type":"application/json"}, body: body?JSON.stringify(body):undefined });
  const j = await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(j.error || (r.status+" "+r.statusText));
  return j;
}
function renderSteps(){
  el("steps").innerHTML = STEP_NAMES.map((n,i)=>{
    const state = i===S.step ? "active" : (i<=S.max ? "done" : "");
    const clickable = i<=S.max && i!==S.step; // any reached step can be revisited
    return '<div class="step '+state+(clickable?" clickable":"")+'"'+(clickable?' onclick="go('+i+')"':'')+
      ' title="'+(clickable?"Go to "+n:n)+'"><span class="num">'+(i+1)+'</span>'+n+'</div>';
  }).join("");
}
function checksHtml(checks){
  return checks.map(c=>'<div class="check '+(c.passed?"ok":"bad")+'"><div class="n">'+(c.passed?"✓":"✗")+" "+c.name+'</div><div class="d">'+c.detail+'</div></div>').join("");
}
function go(n){ S.step=n; if(n>S.max) S.max=n; render(); }

const views = {
  0: async ()=>{
    const st = await api("/status");
    if(st.storeExists && st.storeLocked){
      return card("Unlock", '<p class="muted">A configuration already exists. Enter your master passphrase to unlock it.</p>'+
        pwField("passphrase","Master passphrase")+
        btn("Unlock", async()=>{ await api("/store/unlock",{passphrase:val("passphrase")}); if(st.setupComplete){ render(); } else { go(1); } }));
    }
    if(st.storeExists && !st.storeLocked){
      if(st.setupComplete) return adminCard();
      go(1); return "";
    }
    return card("Choose a master passphrase",
      '<p class="muted">This passphrase encrypts Skeleton Key\\'s own secrets at rest and is your admin login. Minimum 8 characters. There is no recovery — store it safely. Use <b>Show</b> to reveal what you typed before confirming.</p>'+
      pwField("passphrase","Master passphrase")+
      pwField("passphrase2","Confirm master passphrase")+
      btn("Create", async()=>{ const p=val("passphrase"), c=val("passphrase2"); if(p.length<8){err("Passphrase must be at least 8 characters.");return;} if(p!==c){err("Passphrases do not match.");return;} await api("/store/init",{passphrase:p}); go(1); }));
  },
  1: async ()=> card("Welcome — how Skeleton Key stays safe",
    '<p>Skeleton Key lets Claude read logs and (with your approval) act across your homelab.</p>'+
    '<ul><li><b>Scoped vault:</b> it reads credentials only from a dedicated Vaultwarden collection — never your personal passwords.</li>'+
    '<li><b>Offline cache:</b> it keeps working if your Vaultwarden server is down.</li>'+
    '<li><b>Approval + audit:</b> every state-changing action is confirmed and logged.</li>'+
    '<li><b>LAN only:</b> never expose this to the internet.</li></ul>'+
    btn("Get started", ()=>go(2))),
  2: async ()=> card("Set up the scoped Vaultwarden account",
    '<p class="muted">Do this once in the Vaultwarden <b>web vault</b> (your Vaultwarden URL in a browser). The service account <b>creates its own org</b>, so there are no org invites or SMTP to deal with. Replace <code>&lt;vaultwarden&gt;</code> below with your Vaultwarden URL.</p>'+
    '<h3>1 · Create a dedicated account</h3>'+
    '<p class="muted">Skeleton Key needs its own empty account, e.g. <code>skeleton-key@home.lan</code>, so it can never reach your personal vault.</p>'+
    '<ul>'+
    '<li><b>If sign-ups are enabled:</b> open <code>&lt;vaultwarden&gt;/#/signup</code>, register that email, and set a master password.</li>'+
    '<li><b>If sign-ups are disabled</b> (the usual case, and why there is no "add user" button) — enable the admin page and invite it:'+
      '<ol>'+
      '<li>Add an <code>ADMIN_TOKEN</code> env var to your Vaultwarden container (generate one with <code>openssl rand -base64 32</code>) and restart it.</li>'+
      '<li>Open <code>&lt;vaultwarden&gt;/admin</code>, log in with that token, and under <b>Users → Invite User</b> enter the email.</li>'+
      '<li>No SMTP needed: open <code>&lt;vaultwarden&gt;/#/signup</code>, enter that <b>same invited email</b>, and set its master password.</li>'+
      '</ol>'+
    '</li></ul>'+
    '<h3>2 · Log in as that new account</h3>'+
    '<p class="muted">Sign out of your normal account and sign in as the new one. Its vault is empty — that is exactly what keeps your real passwords out of reach.</p>'+
    '<h3>3 · Create the organization</h3>'+
    '<p class="muted">On the <b>Vaults</b> page, in the <b>FILTERS</b> panel (the middle column), under <b>All vaults</b>, click <b>＋ New organization</b>. Choose the <b>Free</b> plan if prompted and name it <b>Skeleton Key</b>.</p>'+
    '<h3>4 · Add a collection and your logins</h3>'+
    '<p class="muted">Open the org → <b>Collections → New collection</b> named <b>Homelab</b>. Add your infra logins (SSH keys, NAS, Proxmox, UniFi, …) into that collection.</p>'+
    '<h3>5 · Get the API key</h3>'+
    '<p class="muted">Go to <b>Settings → Security → Keys → View API Key</b> to reveal <code>client_id</code> / <code>client_secret</code>.</p>'+
    '<p class="muted">Because this account owns only this one org and holds no personal data, it is cryptographically unable to read your real passwords. Keep the API key and this account\\'s master password for the next step.</p>'+
    btn("I\\'ve done this", ()=>go(3))),
  3: async ()=> card("Connect the vault",
    field("serverUrl","Vaultwarden internal URL (LAN)","text","http://192.168.0.x:port")+
    field("collectionName","Collection name (optional)","text","Homelab")+
    field("clientId","API key client_id","text")+
    pwField("clientSecret","API key client_secret")+
    pwField("masterPassword","Service account master password")+
    btn("Connect &amp; verify", async()=>{
      const checks = (await api("/setup/vault",{
        serverUrl:val("serverUrl"), collectionName:val("collectionName")||undefined,
        clientId:val("clientId"), clientSecret:val("clientSecret"), masterPassword:val("masterPassword")
      })).checks;
      S.checks = checks; go(4);
    })),
  4: async ()=>{
    const checks = S.checks || (await api("/setup/checks")).checks;
    const allPass = checks.every(c=>c.passed);
    return card("Verify scoping &amp; durability", checksHtml(checks)+
      '<p class="muted">'+(allPass?"All checks passed — the account is correctly scoped.":"Some checks failed. Fix them in Vaultwarden, then re-run.")+'</p>'+
      '<div class="row">'+btn("Re-run checks", async()=>{ S.checks=(await api("/setup/checks")).checks; render(); },"ghost")+
      btn("Continue", ()=>go(5))+'</div>');
  },
  5: async ()=> card("Discover &amp; register services",
    '<p class="muted">Optional: scan for known services. You confirm each before it\\'s registered — nothing connects automatically.</p>'+
    '<p class="muted"><b>Running in a bridged Docker container?</b> It only sees Docker\\'s internal network (e.g. <code>172.x</code>), not your LAN. Enter your real subnet below (the first three octets, e.g. <code>192.168.0</code>) to scan it, or leave blank to auto-detect.</p>'+
    field("scan_subnet","Subnet to scan (optional)","text","192.168.0")+
    btn("Scan network", async()=>{ const sn=val("scan_subnet"); err("Scanning…"); const r=await api("/setup/discover", sn?{subnets:[sn]}:{}); S.discovered=r.services; err(r.services.length?"":"No services found on that subnet. Try Add manually below."); render(); })+
    (S.discovered.length? '<h3>Detected</h3>'+S.discovered.map((s,i)=>
      '<div class="svc"><code>'+s.host+':'+s.port+'</code> — '+s.label+
      ' <button class="btn btn-secondary btn-sm" onclick="addSvc('+i+')">Register</button></div>').join(""):"")+
    '<h3>Add manually</h3>'+
    field("t_name","Name","text","nas1")+field("t_type","Type","text","ssh")+
    field("t_host","Host","text","192.168.1.50")+field("t_port","Port","text","22")+
    field("t_cred","Vault item name (credentialRef)","text")+
    btn("Add target", async()=>{ await registerTarget({name:val("t_name"),type:val("t_type"),host:val("t_host"),port:Number(val("t_port"))||undefined,credentialRef:val("t_cred")||undefined}); })+
    '<div id="tlist"></div>'+
    btn("Continue", ()=>go(6),"ghost")),
  6: async ()=>{
    const e = await api("/setup/totp/begin",{});
    return card("Secure this UI with 2FA",
      '<p class="muted">Scan this QR in your authenticator app, then enter a code to confirm.</p>'+
      '<img class="qr" src="'+e.qrDataUrl+'" alt="TOTP QR"/>'+
      '<p class="muted">Or enter the secret manually: <code>'+e.secret+'</code></p>'+
      field("totp","6-digit code","text")+
      btn("Verify &amp; continue", async()=>{
        const r = await api("/setup/totp/verify",{token:val("totp")});
        if(!r.valid){ err("Code invalid, try again."); return; }
        go(7);
      }));
  },
  7: async ()=>{
    const a = await api("/store/autounlock");
    return card("Boot auto-unlock (optional)",
      '<p class="muted">By default, every container restart <b>re-locks</b> the vault until you type your passphrase here — a deliberate kill-switch. Enabling auto-unlock trades that away for convenience: Skeleton Key generates a <b>random unlock key</b> (never your passphrase) and stores it in a file at <code>'+a.keyFile+'</code>, which must be a <b>host-mounted directory</b> (see the volumes example in docker-compose.yml). Restarts then unlock on their own.</p>'+
      (a.enabled? '<p class="muted">✓ Currently <b>enabled</b>.</p>':'')+
      '<div class="row">'+
      btn(a.enabled?"Re-enroll key":"Enable auto-unlock", async()=>{ await api("/store/autounlock/enable",{}); go(8); })+
      btn(a.enabled?"Continue":"Skip — stay locked on restart", ()=>go(8),"ghost")+
      '</div>');
  },
  8: async ()=>{
    const url = location.protocol+"//"+location.host+"/mcp";
    // Ensure a bearer token exists so setup can complete (used as a fallback path).
    const t = (await api("/setup/token",{})).token;
    S.bearer = t;
    const cmd = 'claude mcp add --transport http skeleton-key '+url;
    const snippet = JSON.stringify({ mcpServers: { "skeleton-key": { type:"http", url } } }, null, 2);
    return card("Connect Claude",
      '<p class="muted">Skeleton Key uses <b>OAuth</b> — no token to copy. Add the server, and the first time Claude connects it opens a browser page here asking you to approve the agent with your authenticator code.</p>'+
      '<h3>Claude Code</h3><pre>'+cmd.replace(/</g,"&lt;")+'</pre>'+
      '<h3>Claude Desktop (config)</h3><pre>'+snippet.replace(/</g,"&lt;")+'</pre>'+
      '<p class="muted">On first use you will see an <b>Authorize an AI agent</b> page — enter your 6-digit code to approve. You can revoke access anytime from the admin console. Tokens are short-lived and refresh automatically.</p>'+
      '<details><summary class="muted">Advanced: static bearer token (fallback)</summary>'+
      '<p class="muted">If your client does not support OAuth, use a bearer header instead:</p>'+
      '<pre>Authorization: Bearer '+t.replace(/</g,"&lt;")+'</pre></details>'+
      btn("Finish setup", async()=>{ await api("/setup/complete",{}); go(9); }));
  },
  9: async ()=> card("You're all set 🗝️",
    '<p>The MCP endpoint is now live at <code>/mcp</code>. From here you can finish onboarding <b>just by talking to Claude</b> — no more forms.</p>'+
    '<p class="muted">Try asking Claude to:</p>'+
    '<ul>'+
    '<li>“<b>Map my network</b>” (my LAN is <code>192.168.0</code>) — runs <code>network_scan</code>.</li>'+
    '<li>“<b>Generate an SSH key</b> for that NAS as user <code>skeletonkey</code> and register it” — <code>vault_generate_ssh_key</code> + <code>register_target</code>. It stores the private key in your vault and gives you the public key to install.</li>'+
    '<li>“<b>Validate</b> access to it” — <code>vault_validate_ssh</code>.</li>'+
    '</ul>'+
    '<p class="muted">Installing each returned public key on the target host is the one manual step — that boundary is deliberate. Restart this container? Unless you enabled auto-unlock, you\\'ll be asked for your master passphrase to unlock again.</p>'),
};

/** Post-setup landing: shown when the store is already unlocked. Manages the
 *  boot auto-unlock keyslot (TOTP-gated, like OAuth revocation). */
async function adminCard(){
  const a = await api("/store/autounlock");
  const status = a.enabled
    ? "✓ <b>Enabled</b> — a random unlock key in <code>"+a.keyFile+"</code> unlocks the store at boot."+
      (a.keyFilePresent? "" : ' <span style="color:var(--bad)">⚠ The key file is missing — restarts will need manual unlock. Disable, then re-enable to write a fresh key.</span>')
    : "<b>Disabled</b> — after a restart, unlock here with your passphrase (the kill-switch default).";
  return card("Unlocked ✓",
    '<p class="muted">Skeleton Key is unlocked and serving MCP clients at <code>/mcp</code>.</p>'+
    '<h3>Boot auto-unlock</h3>'+
    '<p class="muted">'+status+'</p>'+
    '<p class="muted">Enabling stores a <b>random unlock key</b> — never your passphrase — in a host-mounted file ('+a.keyFile+'), so container restarts unlock automatically. Requires the compose file to mount a writable host directory there; see docker-compose.yml. Changing this requires your authenticator code.</p>'+
    field("au_totp","6-digit authenticator code","text")+
    '<div class="row">'+
    (a.enabled
      ? btn("Disable auto-unlock", async()=>{ await api("/store/autounlock/disable",{totp:val("au_totp")}); render(); })
      : btn("Enable auto-unlock", async()=>{ await api("/store/autounlock/enable",{totp:val("au_totp")}); render(); }))+
    '</div>');
}

function card(title, inner){ return '<div class="card"><h2>'+title+'</h2>'+inner+'</div>'; }
function field(id,label,type,ph){ return '<label>'+label+'</label><input id="'+id+'" class="form-control" type="'+(type||"text")+'" placeholder="'+(ph||"")+'"/>'; }
function pwField(id,label,ph){ return '<label>'+label+'</label><div class="pwwrap"><input id="'+id+'" class="form-control" type="password" placeholder="'+(ph||"")+'"/><button type="button" class="btn btn-outline btn-sm btn-reveal" onclick="togglePw(\\''+id+'\\',this)">Show</button></div>'; }
window.togglePw=(id,b)=>{ const i=el(id); if(!i)return; const show=i.type==="password"; i.type=show?"text":"password"; b.textContent=show?"Hide":"Show"; };
// Async-aware button: shows a spinner + "Working…" and disables itself while the
// handler runs, so slow actions (argon2 unlock, vault auth) never look frozen.
function btn(label,fn,cls){
  const id="b"+Math.random().toString(36).slice(2);
  const klass="btn "+(cls==="ghost"?"btn-secondary":(cls||"btn-primary"));
  setTimeout(()=>{ const b=el(id); if(!b) return; b.onclick=async()=>{
    if(b.dataset.busy) return;
    err(""); b.dataset.busy="1"; b.disabled=true;
    const orig=b.innerHTML; b.innerHTML='<span class="spinner"></span> Working…';
    try { await fn(); }
    catch(e){ err((e&&e.message)||String(e)); }
    finally { if(document.body.contains(b)){ b.disabled=false; b.innerHTML=orig; b.removeAttribute("data-busy"); } }
  };},0);
  return '<button id="'+id+'" class="'+klass+'">'+label+'</button>';
}
const val = (id)=> (el(id)?.value||"").trim();
async function registerTarget(t){ try{ await api("/targets",t); await refreshTargets(); }catch(e){ err(e.message); } }
window.addSvc = async (i)=>{ const s=S.discovered[i]; const name=prompt("Name for "+s.host+":", s.host.replace(/\\./g,"-")); if(!name)return; const cred=prompt("Vault item name for credentials (blank if none):")||undefined; await registerTarget({name,type:(s.registerType||s.connectorType),host:s.host,port:s.port,credentialRef:cred}); };
async function refreshTargets(){ const list=el("tlist"); if(!list)return; const r=await api("/targets"); list.innerHTML = r.targets.length? '<h3>Registered</h3>'+r.targets.map(t=>'<div class="svc"><code>'+t.name+'</code> ('+t.type+') → '+t.host+'</div>').join(""):""; }
async function render(){ renderSteps(); try{ el("view").innerHTML = await views[S.step](); if(S.step===5) refreshTargets(); }catch(e){ err(e.message); } }
render();
</script>
</body>
</html>`;
