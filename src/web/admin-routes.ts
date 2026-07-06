import { Router } from "express";
import type { AppState } from "../app.js";

/**
 * Admin activity view — a transparency/trust surface that shows what Skeleton Key
 * has done on the LAN: every tool call (read + execute) and MCP session event,
 * from the append-only audit log.
 *
 * Like the credential and OAuth-consent pages, the GET page itself is
 * unauthenticated but reveals NOTHING — the log data is fetched from the
 * TOTP-gated `POST /api/audit/recent`, so a fresh code (and an unlocked store) is
 * required to see any activity. Rows are rendered client-side with textContent,
 * so a hostile `detail`/`target` value can't inject markup.
 */

const STYLE = `:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:radial-gradient(1200px 600px at 50% -10%,#182033,#0f1115 60%);color:#e6e9ef;min-height:100vh;padding:28px}
.wrap{max-width:1000px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}.mut{color:#8b93a7;font-size:14px;margin:0 0 20px}
.bar{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;background:#171a21;border:1px solid #262b36;border-radius:12px;padding:16px;margin-bottom:18px}
label{display:block;font-size:12px;color:#8b93a7;margin:0 0 6px}
input,select{padding:10px;border-radius:9px;border:1px solid #2b3140;background:#0d0f14;color:#e6e9ef;font-size:15px}
input.code{width:130px;letter-spacing:3px;text-align:center}
button{padding:10px 16px;border-radius:9px;border:1px solid transparent;background:#4d7cfe;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
.err{color:#ff6b6b;font-size:13px;margin:0 0 12px;min-height:16px}
.tablewrap{overflow-x:auto;border:1px solid #262b36;border-radius:12px}
table{border-collapse:collapse;width:100%;font-size:13px;min-width:760px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid #20242e;white-space:nowrap}
th{color:#8b93a7;font-weight:600;background:#141821;position:sticky;top:0}
td.detail{white-space:normal;color:#c7cdda;max-width:360px}
td.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#aeb6c6}
.tier{font-size:11px;padding:2px 7px;border-radius:20px;border:1px solid #2b3140;color:#aeb6c6}
.tier.execute{color:#ffd38a;border-color:#5a4326}.tier.session{color:#8fb7ff;border-color:#2c3d5e}
.st-ok{color:#57d38c}.st-error{color:#ff6b6b}.st-denied{color:#ffb454}`;

function page(): string {
  return `<!doctype html><html><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Activity — Skeleton Key</title><style>${STYLE}</style></head>
<body><div class="wrap">
  <h1>🗝️ Activity log</h1>
  <p class="mut">Everything Skeleton Key did on your network — every tool call and session. Arguments are stored only as a hash, never in the clear.</p>
  <div class="bar">
    <div><label>Authenticator code</label><input class="code" id="totp" inputmode="numeric" autocomplete="one-time-code" placeholder="000000"/></div>
    <div><label>Show</label><select id="limit"><option>100</option><option>250</option><option>500</option><option>1000</option></select></div>
    <button id="load">Load activity</button>
  </div>
  <div class="err" id="err"></div>
  <div class="tablewrap"><table>
    <thead><tr><th>Time</th><th>Tier</th><th>Tool</th><th>Target</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody id="rows"></tbody>
  </table></div>
</div>
<script>
(function(){
  var totp=document.getElementById('totp'),limit=document.getElementById('limit'),
      err=document.getElementById('err'),rows=document.getElementById('rows'),btn=document.getElementById('load');
  function td(text,cls){var d=document.createElement('td');d.textContent=text==null?'':String(text);if(cls)d.className=cls;return d;}
  async function load(){
    err.textContent='';
    var body={totp:totp.value.trim(),limit:Number(limit.value)};
    var r;
    try{ r=await fetch('/api/audit/recent',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}); }
    catch(e){ err.textContent='Network error.'; return; }
    if(!r.ok){ var j={}; try{j=await r.json();}catch(_){} err.textContent=(j&&j.error)||('HTTP '+r.status); return; }
    var data=await r.json(); rows.innerHTML='';
    if(!data.entries.length){ err.textContent='No activity recorded yet.'; return; }
    data.entries.forEach(function(e){
      var tr=document.createElement('tr');
      var t=td(new Date(e.ts).toLocaleString()); t.className='mono'; tr.appendChild(t);
      var tier=document.createElement('td'); var span=document.createElement('span');
      span.className='tier '+(e.tier||''); span.textContent=e.tier||''; tier.appendChild(span); tr.appendChild(tier);
      tr.appendChild(td(e.tool,'mono'));
      tr.appendChild(td(e.target));
      tr.appendChild(td(e.status,'st-'+(e.status||'')));
      tr.appendChild(td(e.detail,'detail'));
      rows.appendChild(tr);
    });
  }
  btn.addEventListener('click',load);
  totp.addEventListener('keydown',function(e){ if(e.key==='Enter') load(); });
})();
</script>
</body></html>`;
}

export function buildAdminRouter(app: AppState): Router {
  const router = Router();
  router.get(["/admin", "/admin/activity"], async (_req, res) => {
    if (!(await app.isSetupComplete())) {
      res.status(404).type("html").send("<!doctype html><meta charset=utf-8><p>Skeleton Key setup isn't complete yet.</p>");
      return;
    }
    res.type("html").send(page());
  });
  return router;
}
