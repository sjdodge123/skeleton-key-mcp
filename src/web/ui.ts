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
  :root { color-scheme: dark; --bg:#0f1115; --panel:#171a21; --acc:#5b8cff; --ok:#3ecf8e; --bad:#ff6b6b; --mut:#8b93a7; }
  * { box-sizing: border-box; }
  body { margin:0; font:15px/1.5 system-ui,sans-serif; background:var(--bg); color:#e6e9ef; }
  header { padding:20px 28px; border-bottom:1px solid #232733; display:flex; align-items:center; gap:12px; }
  header h1 { font-size:18px; margin:0; }
  .key { font-size:22px; }
  main { max-width:760px; margin:0 auto; padding:28px; }
  .steps { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:24px; }
  .steps span { font-size:12px; padding:4px 10px; border-radius:20px; background:#1c202b; color:var(--mut); }
  .steps span.active { background:var(--acc); color:#fff; }
  .steps span.done { background:#22303f; color:var(--ok); }
  .card { background:var(--panel); border:1px solid #232733; border-radius:12px; padding:22px; margin-bottom:18px; }
  h2 { margin-top:0; font-size:20px; }
  label { display:block; font-size:13px; color:var(--mut); margin:12px 0 4px; }
  input { width:100%; padding:10px; border-radius:8px; border:1px solid #2b3140; background:#0d0f14; color:#e6e9ef; }
  button { background:var(--acc); color:#fff; border:0; padding:10px 18px; border-radius:8px; font-size:14px; cursor:pointer; margin-top:16px; }
  button.ghost { background:#232733; }
  button:disabled { opacity:.5; cursor:not-allowed; }
  .row { display:flex; gap:10px; flex-wrap:wrap; }
  .check { padding:8px 12px; border-radius:8px; margin:6px 0; background:#0d0f14; border-left:3px solid var(--mut); }
  .check.ok { border-color:var(--ok); }
  .check.bad { border-color:var(--bad); }
  .check .n { font-weight:600; }
  .check .d { color:var(--mut); font-size:13px; }
  code, pre { background:#0d0f14; border:1px solid #2b3140; border-radius:8px; }
  pre { padding:12px; overflow:auto; }
  code { padding:2px 6px; }
  .muted { color:var(--mut); font-size:13px; }
  .svc { display:flex; align-items:center; gap:10px; padding:8px; border-bottom:1px solid #232733; }
  .err { color:var(--bad); margin-top:10px; min-height:18px; }
  ol { padding-left:20px; } ol li { margin:6px 0; }
  img.qr { background:#fff; padding:8px; border-radius:8px; margin-top:12px; }
  .pwwrap { position:relative; }
  .pwwrap input { padding-right:46px; }
  .eye { position:absolute; right:6px; top:6px; margin:0; padding:6px 9px; background:transparent; font-size:16px; line-height:1; }
  .eye:hover { background:#232733; }
  .eye.on { background:#22303f; }
</style>
</head>
<body>
<header><span class="key">🗝️</span><h1>Skeleton Key — First-run setup</h1></header>
<main>
  <div class="steps" id="steps"></div>
  <div id="view"></div>
  <div class="err" id="err"></div>
</main>
<script>
const S = { step:0, discovered:[], bearer:null };
const STEP_NAMES = ["Passphrase","Welcome","Vaultwarden","Connect","Verify","Discover","2FA","Claude","Done"];
const el = (id)=>document.getElementById(id);
const err = (m)=>{ el("err").textContent = m || ""; };
async function api(path, body){
  const r = await fetch("/api"+path, { method: body?"POST":"GET", headers:{"content-type":"application/json"}, body: body?JSON.stringify(body):undefined });
  const j = await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(j.error || (r.status+" "+r.statusText));
  return j;
}
function renderSteps(){
  el("steps").innerHTML = STEP_NAMES.map((n,i)=>
    '<span class="'+(i===S.step?"active":(i<S.step?"done":""))+'">'+(i+1)+". "+n+'</span>').join("");
}
function checksHtml(checks){
  return checks.map(c=>'<div class="check '+(c.passed?"ok":"bad")+'"><div class="n">'+(c.passed?"✓":"✗")+" "+c.name+'</div><div class="d">'+c.detail+'</div></div>').join("");
}
function go(n){ S.step=n; render(); }

const views = {
  0: async ()=>{
    const st = await api("/status");
    if(st.storeExists && st.storeLocked){
      return card("Unlock", '<p class="muted">A configuration already exists. Enter your master passphrase to unlock it.</p>'+
        pwField("passphrase","Master passphrase")+
        btn("Unlock", async()=>{ await api("/store/unlock",{passphrase:val("passphrase")}); go(1); }));
    }
    if(st.storeExists && !st.storeLocked){ go(1); return ""; }
    return card("Choose a master passphrase",
      '<p class="muted">This passphrase encrypts Skeleton Key\\'s own secrets at rest and is your admin login. Minimum 8 characters. There is no recovery — store it safely. Use the eye to reveal what you typed before confirming.</p>'+
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
    '<p class="muted">Do this once in the Vaultwarden <b>web vault</b> — open your Vaultwarden URL in a browser. Organizations <b>cannot</b> be created from the mobile or desktop app, which is why there\\'s no org button there. The trick: the service account <b>creates its own org</b>, so there are no invites or SMTP to configure.</p>'+
    '<ol>'+
    '<li><b>Create a dedicated account</b> for Skeleton Key (e.g. <code>skeleton-key@home.lan</code>) on the web vault\\'s <em>Create account</em> screen. If sign-ups are disabled, add it from the Vaultwarden <code>/admin</code> page (<em>Invite User</em>) or enable sign-ups briefly.</li>'+
    '<li><b>Log in as that new account</b>, not your normal one. Its vault is empty — that is exactly what keeps your real passwords out of reach.</li>'+
    '<li>In the left sidebar click <b>New organization</b> (or open <code>/#/create-organization</code>), choose the <b>Free</b> plan, and name it <b>Skeleton Key</b>.</li>'+
    '<li>Open the org → <b>Collections</b> → <b>New collection</b> named <b>Homelab</b>.</li>'+
    '<li>Add your infra logins (SSH keys, NAS, Proxmox, UniFi, …) into that collection.</li>'+
    '<li>Go to <b>Account settings → Security → Keys → View API Key</b> to reveal <code>client_id</code>/<code>client_secret</code>.</li>'+
    '</ol>'+
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
    '<p class="muted">Optional: scan your LAN for known services. You confirm each before it\\'s registered — nothing connects automatically.</p>'+
    btn("Scan my network", async()=>{ err("Scanning…"); const r=await api("/setup/discover",{}); S.discovered=r.services; err(""); render(); })+
    (S.discovered.length? '<h3>Detected</h3>'+S.discovered.map((s,i)=>
      '<div class="svc"><code>'+s.host+':'+s.port+'</code> — '+s.label+
      ' <button class="ghost" onclick="addSvc('+i+')">Register</button></div>').join(""):"")+
    '<h3>Add manually</h3>'+
    field("t_name","Name","text","asura1")+field("t_type","Type","text","ssh")+
    field("t_host","Host","text","192.168.0.x")+field("t_port","Port","text","22")+
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
    const t = (await api("/setup/token",{})).token;
    S.bearer = t;
    const url = location.protocol+"//"+location.host+"/mcp";
    const snippet = JSON.stringify({ mcpServers: { "skeleton-key": { type:"http", url, headers:{ Authorization:"Bearer "+t } } } }, null, 2);
    return card("Connect Claude",
      '<p class="muted">Add this to your Claude Code / Desktop MCP config. This bearer token is shown once.</p>'+
      '<pre>'+snippet.replace(/</g,"&lt;")+'</pre>'+
      btn("Finish setup", async()=>{ await api("/setup/complete",{}); go(8); }));
  },
  8: async ()=> card("You're all set 🗝️",
    '<p>The MCP endpoint is now live at <code>/mcp</code>. Claude can see tools for your registered services.</p>'+
    '<p class="muted">Restart this container? You\\'ll be asked for your master passphrase to unlock again.</p>'),
};

function card(title, inner){ return '<div class="card"><h2>'+title+'</h2>'+inner+'</div>'; }
function field(id,label,type,ph){ return '<label>'+label+'</label><input id="'+id+'" type="'+(type||"text")+'" placeholder="'+(ph||"")+'"/>'; }
function pwField(id,label,ph){ return '<label>'+label+'</label><div class="pwwrap"><input id="'+id+'" type="password" placeholder="'+(ph||"")+'"/><button type="button" class="eye" onclick="togglePw(\\''+id+'\\',this)" aria-label="Show or hide">👁</button></div>'; }
window.togglePw=(id,b)=>{ const i=el(id); if(!i)return; const show=i.type==="password"; i.type=show?"text":"password"; b.textContent=show?"🙈":"👁"; b.classList.toggle("on",show); };
function btn(label,fn,cls){ const id="b"+Math.random().toString(36).slice(2); setTimeout(()=>{const b=el(id); if(b)b.onclick=()=>{err("");fn().catch?fn().catch(e=>err(e.message)):fn();};},0); return '<button id="'+id+'" class="'+(cls||"")+'">'+label+'</button>'; }
const val = (id)=> (el(id)?.value||"").trim();
async function registerTarget(t){ try{ await api("/targets",t); await refreshTargets(); }catch(e){ err(e.message); } }
window.addSvc = async (i)=>{ const s=S.discovered[i]; const name=prompt("Name for "+s.host+":", s.host.replace(/\\./g,"-")); if(!name)return; const cred=prompt("Vault item name for credentials (blank if none):")||undefined; await registerTarget({name,type:s.connectorType,host:s.host,port:s.port,credentialRef:cred}); };
async function refreshTargets(){ const list=el("tlist"); if(!list)return; const r=await api("/targets"); list.innerHTML = r.targets.length? '<h3>Registered</h3>'+r.targets.map(t=>'<div class="svc"><code>'+t.name+'</code> ('+t.type+') → '+t.host+'</div>').join(""):""; }
async function render(){ renderSteps(); try{ el("view").innerHTML = await views[S.step](); if(S.step===5) refreshTargets(); }catch(e){ err(e.message); } }
render();
</script>
</body>
</html>`;
