import {oracleHandler, scheduledSync} from './oracle-sync.mjs';
import {operationsHandler} from './operations.mjs';
// 4114 single-site operator portal. Operator uses a 4-digit shared PIN.
// The owner changes the shared PIN on this SAME Worker at /admin.
// No secrets or private user information are sent to clients.
const enc = new TextEncoder();
const textHeaders = {
  'content-type': 'text/html; charset=utf-8',
  'cache-control': 'no-store',
  'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'x-robots-tag': 'noindex,nofollow',
};
const cookieName = '__Host-wos_operator';
const PIN_RE = /^\d{4}$/;
const MAX_SESSION_SEC = 8 * 3600;
const OWNER_SESSION_SEC = 45 * 60;
const ownerCookieName = '__Host-wos_owner';
const ownerIDPattern = /^[A-Za-z0-9._@-]{3,80}$/;
// Only validation results are returned to the UI; NEVER reveal actual secret values.
function ownerConfigIssues(env) {
  const issues=[];
  if(!env?.DB) issues.push('DB 연결');
  if(typeof env?.SESSION_SECRET!=='string' || env.SESSION_SECRET.length<32) issues.push('SESSION_SECRET (32자 이상)');
  if(typeof env?.OWNER_LOGIN_ID!=='string' || !ownerIDPattern.test(env.OWNER_LOGIN_ID)) issues.push('OWNER_LOGIN_ID (3~80자 / 영문·숫자·._@-)');
  if(typeof env?.OWNER_LOGIN_SECRET!=='string' || env.OWNER_LOGIN_SECRET.length<20) issues.push('OWNER_LOGIN_SECRET (20자 이상)');
  return issues;
}
function ownerConfigOk(env) { return ownerConfigIssues(env).length===0; }

function responseJSON(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-robots-tag': 'noindex,nofollow', ...extra,
  }});
}
const bytesToHex = b => [...b].map(x=>x.toString(16).padStart(2,'0')).join('');
const randomHex = n => bytesToHex(crypto.getRandomValues(new Uint8Array(n)));
function constantTimeEqual(a,b) {
  if(typeof a !== 'string' || typeof b !== 'string') return false;
  let diff = a.length ^ b.length;
  for(let i=0;i<Math.max(a.length,b.length);i++) diff |= (a.charCodeAt(i)||0) ^ (b.charCodeAt(i)||0);
  return diff === 0;
}
function configOk(env) {
  return !!env?.DB && PIN_RE.test(env.OPERATOR_PIN||'') && typeof env.SESSION_SECRET==='string' && env.SESSION_SECRET.length >= 32;
}
async function hmac(secret,message) {
  const key = await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return bytesToHex(new Uint8Array(await crypto.subtle.sign('HMAC',key,enc.encode(message))));
}
function readCookie(header) {
  for(const p of (header||'').split(';')) {
    const n=p.indexOf('=');
    if(n>0 && p.slice(0,n).trim()===cookieName) return p.slice(n+1).trim();
  }
  return '';
}
function validOrigin(req) {
  try { return req.headers.get('origin') === new URL(req.url).origin && (req.headers.get('content-type')||'').startsWith('application/json'); }
  catch {return false;}
}
async function parseBody(req,maxChars=55000) {
  const length=Number(req.headers.get('content-length')||'0');
  if(!Number.isFinite(length)||length>maxChars*4) throw Error('Too large');
  const body=await req.text();
  if(body.length>maxChars) throw Error('Too large');
  return JSON.parse(body);
}
async function pinDigest(env, pin) {
  return hmac(env.SESSION_SECRET, `4114-operator-pin-v3:${pin}`);
}
async function activePinDigest(env) {
  const row = await env.DB.prepare('SELECT pin_hmac_hex FROM wos_operator_pin_settings WHERE id=1').first();
  return row?.pin_hmac_hex || await pinDigest(env, env.OPERATOR_PIN);
}
async function signSession(env, exp, nonce) {
  // Binding the session signature to the current PIN invalidates sessions after PIN rotation.
  const value = `v1.${exp}.${nonce}`;
  const sig = await hmac(env.SESSION_SECRET,`wos4114|${value}|${await activePinDigest(env)}`);
  return `${value}.${sig}`;
}
async function authenticated(req,env,now) {
  const raw=readCookie(req.headers.get('cookie'));
  const match=/^v1\.(\d{10})\.([a-f0-9]{32})\.([a-f0-9]{64})$/.exec(raw);
  if(!match) return false;
  const exp=Number(match[1]);
  if(exp<=now || exp>now+MAX_SESSION_SEC) return false;
  const sig = await hmac(env.SESSION_SECRET,`wos4114|v1.${match[1]}.${match[2]}|${await activePinDigest(env)}`);
  return constantTimeEqual(sig,match[3]);
}
const sessionCookie = (token) => `${cookieName}=${token}; Path=/; Max-Age=${MAX_SESSION_SEC}; Secure; HttpOnly; SameSite=Strict`;
const removeCookie = () => `${cookieName}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`;
async function attemptInfo(env, clientHash, now) {
  const window=now-900;
  // Existing D1 table from step 002. No new SQL migration required.
  const [byIp, all] = await Promise.all([
    env.DB.prepare('SELECT COUNT(*) AS n FROM wos_operator_login_attempts WHERE username=? AND client_hmac_hex=? AND attempted_unix>=?').bind('shared-pin-gate',clientHash,window).first(),
    env.DB.prepare('SELECT COUNT(*) AS n FROM wos_operator_login_attempts WHERE username=? AND attempted_unix>=?').bind('shared-pin-gate',window).first(),
  ]);
  return {perIp:Number(byIp?.n||0), global:Number(all?.n||0)};
}
async function recordFailure(env,clientHash,now) {
  await env.DB.prepare('INSERT INTO wos_operator_login_attempts(username,client_hmac_hex,attempted_unix) VALUES(?,?,?)').bind('shared-pin-gate',clientHash,now).run();
}
async function audit(env,action,target) {
  try {await env.DB.prepare('INSERT INTO wos_api_audit(id,issuer,subject,action,target) VALUES(?,?,?,?,?)').bind(crypto.randomUUID(),'operator-pin','shared',''+action,''+target).run();} catch {}
}
async function login(req,env,now) {
  if(!validOrigin(req)) return responseJSON({error:'잘못된 요청입니다.'},403);
  let body;try{body=await parseBody(req)}catch{return responseJSON({error:'요청 형식이 올바르지 않습니다.'},400)}
  const rawIp=req.headers.get('cf-connecting-ip')||'unknown';
  const clientHash=await hmac(env.SESSION_SECRET,`ip:${rawIp}`);
  let counts;
  try{counts=await attemptInfo(env,clientHash,now)}catch{return responseJSON({error:'로그인 확인을 사용할 수 없습니다.'},503)}
  if(counts.perIp>=5 || counts.global>=15) return responseJSON({error:'로그인 시도가 많습니다. 15분 후 다시 시도해주세요.'},429);
  const pin=body?.pin;
  if(typeof pin!=='string'||!PIN_RE.test(pin)||!constantTimeEqual(await pinDigest(env,pin), await activePinDigest(env))) {
    try{await recordFailure(env,clientHash,now)}catch{return responseJSON({error:'로그인을 처리할 수 없습니다.'},503)}
    return responseJSON({error:'비밀번호가 올바르지 않습니다.'},401);
  }
  const exp=now+MAX_SESSION_SEC;
  const token=await signSession(env,exp,randomHex(16));
  await audit(env,'PIN_LOGIN','operators');
  return responseJSON({ok:true},200,{'set-cookie':sessionCookie(token)});
}
function home(){
  const html = String.raw`<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>4114 WOS COMMAND CENTER | STATE 4114</title>
  <style>
  :root{color-scheme:light;font-family:system-ui,-apple-system,'Malgun Gothic',sans-serif;color:#17314c}
  *{box-sizing:border-box}body{margin:0;padding:16px;background:linear-gradient(140deg,#e9f4ff,#f9fcff);line-height:1.55}
  main{width:min(1100px,100%);margin:22px auto;background:#fff;border:1px solid #d4e3f0;border-radius:18px;padding:26px;box-shadow:0 12px 35px #1045710c}
  h1{font-size:24px;margin:0 0 4px}h2{font-size:19px;margin:10px 0}p{margin:6px 0 12px}small,.muted{color:#63778b}
  section.panel{border:1px solid #e1eaf3;border-radius:12px;padding:16px;margin:15px 0}
  input,button,textarea,select{font:inherit;border-radius:8px;padding:10px;max-width:100%}input,textarea,select{border:1px solid #b8cada;background:#fff;width:100%}textarea{min-height:96px;resize:vertical}
  button{border:1px solid #17689f;background:#17689f;color:#fff;cursor:pointer;white-space:normal}
  button:hover{filter:brightness(.96)}button.secondary{background:#f5faff;color:#17527d;border-color:#bdd3e6}button.danger{background:#fff4f4;color:#963b42;border-color:#ead3d3}
  button:disabled{opacity:.55;cursor:not-allowed}form{display:grid;gap:9px}label{font-weight:650;font-size:14px}.hidden{display:none!important}
  .row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.row > input,.row > select{flex:1;min-width:120px}
  .pill{display:inline-block;padding:4px 9px;border-radius:50px;background:#ecf6ff;color:#245779;font-size:12px;font-weight:650}
  header a{color:#17689f;font-weight:650;text-decoration:underline;text-underline-offset:3px}header .links{display:flex;gap:15px;flex-wrap:wrap}
  .tabs{display:flex;gap:8px;flex-wrap:wrap;margin-top:20px}.tabs button{min-width:130px}.tabs button[aria-selected=false]{background:#f5faff;color:#30617f;border-color:#d5e2ed}
  .grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}.grid > div{padding:11px;background:#f5f9fc;border-radius:10px}.grid b{display:block;font-size:24px}
  .scroll{overflow:auto;max-height:525px;border:1px solid #e4ebf2;border-radius:10px}table{border-collapse:collapse;width:100%;min-width:700px;font-size:13px}
  td,th{text-align:left;padding:8px;border-bottom:1px solid #e0eaf2}th{background:#f5faff;position:sticky;top:0}td input[type=checkbox]{width:auto}td select{width:auto;min-width:76px;padding:6px}td button{padding:7px 9px}
  .notice{padding:13px;border:1px solid #d7e4ef;background:#fcfdff;border-radius:12px;margin:12px 0;overflow-wrap:anywhere}
  .notice p{white-space:pre-wrap;margin-top:8px}.muted-code{font-family:ui-monospace,monospace;white-space:pre-wrap;font-size:12px;color:#586d80}
  .pin{letter-spacing:12px;font-size:26px;max-width:200px;text-align:center}#error{color:#a92130}#message{color:#157047}
  .safe{padding:11px 14px;background:#f2f8fd;border:1px solid #e1ecf7;border-radius:10px}
  .two-col{display:grid;grid-template-columns:1fr 1fr;gap:13px}
  @media(max-width:720px){main{padding:15px}h1{font-size:21px}.two-col,.grid{grid-template-columns:1fr}.tabs button{flex:1}}

  /* v5 command center · source-backed operations theme */
  :root{--ice:#e8f3ff;--navy:#112b49;--line:#dfe9f4;--slate:#57718a;--zzn:#c99a45;--ggz:#16a6a1}
  body{background:radial-gradient(ellipse at top left,#dceefa 0,transparent 42%),linear-gradient(135deg,#f3f8fd,#e9f3fc);padding:0 15px 26px}
  main{width:min(1320px,100%);margin:22px auto;padding:0 0 25px;border:1px solid #d2e0ee;overflow:hidden;border-radius:22px;box-shadow:0 18px 65px #183d6117}
  main>header{padding:28px 32px;background:linear-gradient(116deg,#102842,#1d4a71 75%,#236a82);color:white}
  header h1{font-size:26px;letter-spacing:.02em}header p small{color:#cbdfe9}header a{color:#e3f3ff!important}
  main>#error,main>#message,main>#login,main>#app{margin-left:27px;margin-right:27px}
  main>#login{max-width:520px;margin:30px auto!important}main>#app{margin-top:20px}
  h2{color:#183956}h3{font-size:16px;color:#254661}
  .tabs{position:sticky;top:0;z-index:5;padding:10px 0;background:#ffffffec;backdrop-filter:blur(10px);border-bottom:1px solid #e7eef5;flex-wrap:nowrap;overflow:auto;scrollbar-width:thin}
  .tabs button{min-width:110px;border:0!important;border-radius:9px;background:transparent;color:#436783!important;padding:11px 10px;font-size:13px;font-weight:700}
  .tabs button[aria-selected=true]{background:#dcecf9;color:#14537f!important;box-shadow:inset 0 -2px #2379b4}
  .tabs button[aria-selected=false]{background:transparent}
  section.panel{border-color:#e0e9f1;box-shadow:0 1px 7px #234f710a;margin:16px 0;border-radius:15px;padding:20px}
  .command-hero{background:linear-gradient(120deg,#eff7ff,#fff);padding:25px 25px 16px;border:1px solid var(--line);border-radius:15px;margin-top:18px}
  .eyebrow{letter-spacing:2px;font-size:11px;font-weight:900;color:#357299}.command-hero h2{font-size:27px;margin:6px 0}.command-hero p{color:#55718b}
  .metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:15px}
  .metric{padding:18px;background:#fff;border:1px solid var(--line);border-radius:14px;min-width:0}
  .metric small{color:#668099;font-weight:700}.metric strong{display:block;font-size:25px;line-height:1.35;color:#193953;overflow-wrap:anywhere}.metric .sub{font-size:12px;color:#68819a}
  .alliance-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.alliance-card{border:1px solid var(--line);border-radius:14px;background:#fcfeff;padding:20px}
  .alliance-card h3{margin:0 0 8px}.alliance-card.zzn{border-top:5px solid var(--zzn)}.alliance-card.ggz{border-top:5px solid var(--ggz)}
  .alliance-card .big{font-size:30px;font-weight:800}.alliance-card small{color:#657f96}
  .bar-track{height:9px;overflow:hidden;border-radius:15px;background:#e8eff6;margin:12px 0 7px}.bar-fill{height:100%;background:#c99a45;border-radius:15px}.ggz .bar-fill{background:#16a6a1}
  .list-clean{list-style:none;padding:0;margin:7px 0}.list-clean li{padding:9px 0;border-bottom:1px solid #edf2f7;font-size:13px}
  .focus-hint{display:inline-block;border-radius:8px;padding:6px 10px;background:#edf5fb;color:#406987;font-size:12px;font-weight:700}
  .toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
  .compact-actions{display:flex;align-items:center;flex-wrap:wrap;gap:8px}.compact-actions button{padding:7px 10px;font-size:12px}
  .badge-zzn,.badge-ggz{display:inline-block;border-radius:100px;padding:3px 10px;font-size:11px;font-weight:750}
  .badge-zzn{background:#fff4dc;color:#916014}.badge-ggz{background:#d9f8f5;color:#117b77}
  .stat-strip{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.stat-strip>div{background:#f1f6fb;border-radius:10px;padding:12px;font-size:13px}
  .helper{text-align:left;font-size:12px;color:#6c8296}
  @media(max-width:760px){main{margin:0;border-radius:0}main>header{padding:20px}main>#app,main>#login,main>#error,main>#message{margin-left:14px;margin-right:14px}.metric-grid,.alliance-grid,.stat-strip{grid-template-columns:1fr 1fr}.metric strong{font-size:22px}.tabs button{min-width:98px;font-size:12px}.command-hero h2{font-size:23px}}
  @media(max-width:430px){.metric-grid,.alliance-grid{grid-template-columns:1fr 1fr}.metric{padding:12px}.metric strong{font-size:21px}.stat-strip{grid-template-columns:1fr}}
  
  /* v6 — Original COMMAND CENTER-inspired PRIVATE OPERATIONS visual system.
     Historical site title/layout hierarchy verified. Exact source CSS not accessible. */
  :root{--ink:#10233b;--ice:#a7ebff;--bronze:#cfaf74;--surface:#f6f9fe;--panel:#fff;--stroke:#dbe6f1;--quiet:#60758e}
  body{background:radial-gradient(circle at 8% 2%,#c7dcef 0,transparent 30%),#edf3f9;color:var(--ink);padding:0 16px 32px}
  body:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(90deg,#0c294408 1px,transparent 1px),linear-gradient(#0c294408 1px,transparent 1px);background-size:40px 40px;opacity:.38}
  main{position:relative;width:min(1490px,100%);margin:20px auto;padding:0 0 23px;border-radius:19px;border:1px solid #c8d9e9;background:var(--surface);overflow:hidden;box-shadow:0 22px 80px #152d4c24}
  main>header{position:relative;overflow:hidden;padding:30px 36px 24px;background:linear-gradient(106deg,#08192f 0%,#112d4b 62%,#144b65 100%);color:#fff;border-bottom:1px solid #3b6d80}
  main>header:after{content:"";pointer-events:none;position:absolute;width:310px;height:310px;border:1px solid #9fcbdc25;transform:rotate(36deg);right:5%;top:-190px;border-radius:58px;box-shadow:0 0 0 54px #9fcbdc09,0 0 0 112px #9fcbdc06}
  header .brandline{display:flex;gap:17px;align-items:center;position:relative;z-index:1;flex-wrap:wrap}
  header .brandmark{width:62px;height:62px;display:grid;place-items:center;border-radius:17px;border:1px solid #a6d7e05a;background:#badfe414;font-size:28px;color:#c2effa;flex:none}
  header .brandlabel{color:#9ad1e1;font-size:11px;letter-spacing:2.3px;font-weight:800}
  header h1{color:#f7fbff;font-size:clamp(22px,2.7vw,33px);letter-spacing:.07em;line-height:1.25;margin:5px 0}
  header .brandsub{color:#c8dce8;font-size:12px;letter-spacing:1.6px;font-weight:700}
  header .links{position:relative;z-index:1;margin-top:18px;gap:9px}
  header .links a{display:inline-flex;align-items:center;min-height:33px;padding:6px 12px;border:1px solid #97d1e35c;border-radius:7px;background:#bfe8ff12;color:#dceff8!important;text-decoration:none;font-size:12px}
  h2{color:#162f48;font-weight:800;letter-spacing:-.02em}
  main>#app,main>#login,main>#error,main>#message{margin-left:22px;margin-right:22px}
  main>#app{margin-top:14px;display:grid;grid-template-columns:200px minmax(0,1fr);column-gap:20px;align-items:start}
  #app>.row:first-child{grid-column:1/-1;justify-content:space-between;padding:8px 0 13px;border-bottom:1px solid #d8e5ef}
  #app>.tabs{grid-column:1;grid-row:2/3;position:sticky;top:14px;margin-top:17px;display:flex;flex-direction:column;gap:5px;overflow:visible;padding:11px;background:#0e2841;border:1px solid #294860;border-radius:13px;box-shadow:0 8px 20px #1c355b17}
  #app>.tabs button{display:block;width:100%;min-width:0!important;text-align:left;padding:13px 12px;border-radius:8px;border:1px solid transparent!important;background:transparent;color:#bfd2e3!important;font-size:13px;font-weight:700;transition:background .15s}
  #app>.tabs button:hover{background:#ffffff12}
  #app>.tabs button[aria-selected=true]{background:#d8edff!important;color:#0f405e!important;box-shadow:inset 3px 0 #3a9cc6}
  #app>[id$="-view"]{grid-column:2;grid-row:2/3;min-width:0;margin-top:15px}
  section.panel{background:var(--panel);border:1px solid var(--stroke);box-shadow:0 3px 18px #142e460a;border-radius:12px;padding:20px;margin:0 0 17px}
  .command-hero{position:relative;overflow:hidden;background:linear-gradient(110deg,#10304b,#1a5266);color:#fff;border:none;padding:31px;border-radius:12px;margin:0 0 16px}
  .command-hero:after{content:"❄";position:absolute;right:22px;top:-19px;font-size:180px;color:#fff;opacity:.065;pointer-events:none}
  .command-hero .eyebrow{color:#9cddf1}.command-hero h2{color:#fff;font-size:clamp(23px,3vw,33px)}.command-hero p{color:#d1e2eb;max-width:700px}
  .command-hero .focus-hint{background:#d1ebff1c;color:#daeffc;border:1px solid #cae9ff3c}
  .eyebrow{color:#29718e;font-weight:800;font-size:11px;letter-spacing:2px}
  .metric-grid{gap:12px;margin-bottom:17px}
  .metric{border-color:#dce8f2;border-radius:12px;background:#fff;box-shadow:0 3px 12px #17385406;border-top:3px solid #87b4c5}
  .metric:nth-child(2){border-top-color:#c7a873}.metric:nth-child(3){border-top-color:#36a3a7}.metric strong{color:#102d46}
  .alliance-card{border-radius:12px;background:linear-gradient(140deg,#fff,#f8fbfe);box-shadow:0 3px 12px #17385409}
  .alliance-card.zzn{border-top-color:#c7a873}.alliance-card.ggz{border-top-color:#26a7a9}
  .pill{background:#d9ebf5;border:1px solid #bed9e8;color:#275670}.focus-hint{font-size:12px}
  button{background:#175a79;border-color:#175a79;border-radius:7px;font-weight:700}
  button.secondary{background:#eef6fa;color:#194c67;border-color:#c7deec}
  button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible,a:focus-visible{outline:3px solid #e0b66d;outline-offset:2px}
  input,textarea,select{background:#fdfefe;border-color:#cddbe7;border-radius:7px}
  .scroll{border-color:#d8e3ed;border-radius:10px}.scroll th{background:#ebf2f9;color:#264b63}
  #oracle-preview-data{border-left:4px solid #3c9eb4;background:#f6fbff}
  .diagnostic{border:1px solid #c4dcea;padding:16px;background:#eff7fc;border-radius:10px;margin-top:12px}
  .diagnostic h3{margin:0 0 8px}
  .oracle-columns{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  .oracle-result{padding:14px;background:#fff;border:1px solid #d9e5ee;border-radius:9px}
  .oracle-result strong{display:block;margin-bottom:5px}
  .oracle-result .warn{color:#9a6225;font-size:12px}
  .diag-error{color:#a12737;font-weight:650}
  #login{background:#fff;max-width:540px;margin:32px auto!important;padding:27px;box-shadow:0 12px 35px #173f6312}
  #login h2{font-size:23px}#login .pin{max-width:230px}
  @media(max-width:1020px){main>#app{grid-template-columns:180px minmax(0,1fr);column-gap:12px}main>#app{margin-left:13px;margin-right:13px}.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
  @media(max-width:760px){body{padding:0}main{margin:0;width:100%;border-radius:0;border:0}main>header{padding:23px 17px}header .brandmark{width:49px;height:49px;font-size:23px}header .brandline{gap:10px}header .brandlabel{font-size:9px;letter-spacing:1px}header h1{font-size:21px;letter-spacing:.015em}header .brandsub{font-size:10px;letter-spacing:.7px}
    main>#app{display:block;margin:0 11px}#app>.tabs{position:sticky;top:0;display:flex;flex-direction:row;flex-wrap:nowrap;overflow:auto;scrollbar-width:thin;background:#0e2841;padding:7px;gap:5px;z-index:10;margin:10px 0;white-space:nowrap;border-radius:9px}
    #app>.tabs button{display:inline-flex;width:auto;min-width:90px!important;flex:none;text-align:center;justify-content:center;padding:9px 10px}
    #app>[id$="-view"]{margin-top:12px}section.panel{padding:16px}.oracle-columns{grid-template-columns:1fr}.two-col,.alliance-grid,.stat-strip{grid-template-columns:1fr}
    .command-hero{padding:20px}.command-hero h2{font-size:24px}.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
  @media(max-width:430px){.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.metric{padding:12px}.metric strong{font-size:21px}}
  </style></head><body><main><header><div class="brandline"><div class="brandmark" aria-hidden="true">❄</div><div><div class="brandlabel">WHITEOUT SURVIVAL · PRIVATE OPERATIONS</div><h1>4114 WOS COMMAND CENTER</h1><div class="brandsub">ZZN &amp; GGZ · STATE 4114 · OPERATIONS DESK</div></div></div><div class="links"><a href="https://wos-svs-office-zzn-2026.cozybard21.chatgpt.site/" target="_blank" rel="noopener noreferrer">SVS 관직 신청</a><a href="https://wos-svs-office-zzn-2026.cozybard21.chatgpt.site/schedule" target="_blank" rel="noopener noreferrer">관직 배정표</a></div></header>
  <p id="error" role="alert"></p><p id="message" role="status"></p>
  <section id="login" class="panel"><h2>운영진 간편 로그인</h2><p>공용 비밀번호 네 자리(숫자 4자리)만 입력하세요.</p>
  <form id="login-form"><label for="pin">운영진 공용 비밀번호</label><input id="pin" class="pin" type="password" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" autocomplete="off" required><button type="submit">입장하기</button></form>
  <p><small>최고관리자는 이 사이트의 <a href="/admin">비밀번호 설정</a>에서 공용 PIN을 변경할 수 있습니다.</small></p></section>
  <div id="app" class="hidden"><div class="row" style="justify-content:space-between"><span class="pill">운영진 로그인 중 · 8시간 유효</span><button class="secondary" id="logout">로그아웃</button></div>
  <nav class="tabs" aria-label="운영 메뉴"><button id="tab-overview" aria-selected="true" type="button">◫ 통합 현황</button><button id="tab-players" aria-selected="false" type="button">♙ 인원 배치</button><button id="tab-svs" aria-selected="false" type="button">⚔ SVS 준비전</button><button id="tab-resources" aria-selected="false" type="button">◈ 자원 분배</button><button id="tab-calendar" aria-selected="false" type="button">▣ 일정</button><button id="tab-insights" aria-selected="false" type="button">↗ 운영 분석</button><button id="tab-notices" aria-selected="false" type="button">✎ 공지 보관함</button><button id="tab-oracle" aria-selected="false" type="button">❄ Oracle+</button></nav>
  <div id="overview-view"><div class="command-hero"><span class="eyebrow">WHITEOUT SURVIVAL · ALLIANCE OPERATIONS</span><h2>두 연맹, 하나의 작전실.</h2><p>4114 서버 ZZN과 GGZ의 인원·전력·SVS·자원·일정을 실제 D1 기록으로 확인합니다. 숫자가 없는 항목은 추정하지 않습니다.</p><span class="focus-hint">운영진 데이터 · 4114 · KST / UTC</span></div>
    <div class="metric-grid" id="overview-metrics"></div>
    <div class="alliance-grid" style="margin-top:15px"><div class="alliance-card zzn" id="overview-zzn"></div><div class="alliance-card ggz" id="overview-ggz"></div></div>
    <div class="two-col"><section class="panel"><div class="toolbar"><h2>예정된 주요 일정</h2><button id="overview-refresh" type="button" class="secondary">새로고침</button></div><ul id="overview-events" class="list-clean"></ul></section>
    <section class="panel"><h2>작전 체크포인트</h2><ul id="overview-checkpoints" class="list-clean"></ul></section></div>
    <section class="panel"><h2>Oracle+ 수집 현황</h2><p class="helper">최신 명단 동기화 기록을 표시합니다. 현재 서버 순위·SVS 상대 분석은 아직 API 데이터를 연결하지 않았습니다.</p><div id="overview-oracle"></div></section></div>
  <div id="members-view" class="hidden">
   <section class="panel"><h2>연맹원 관리 · 인원 현황</h2><div class="grid"><div><small>ZZN</small><b id="count-zzn">0</b></div><div><small>GGZ</small><b id="count-ggz">0</b></div><div><small>총 인원</small><b id="count-all">0</b></div></div>
   <p class="safe"><small>현재 명단은 Cloudflare D1 기준입니다. Oracle+ 동기화는 Oracle+ 탭에서 먼저 미리보기로 검증한 다음 실행할 수 있습니다. R5/R4/부계정 표시는 별도 저장됩니다.</small></p>
   <label for="member-search">연맹원 검색</label><input id="member-search" placeholder="닉네임 또는 플레이어 ID">
   <div id="players" class="scroll" style="margin-top:12px"></div></section>
   <div class="two-col"><section class="panel"><h2>연맹원 추가·수정</h2><form id="member-form">
   <label for="member-fid">플레이어 ID (숫자)</label><input id="member-fid" required inputmode="numeric" pattern="[0-9]{6,15}" maxlength="15" placeholder="게임 ID">
   <label for="member-name">닉네임</label><input id="member-name" maxlength="80" required placeholder="게임 닉네임">
   <label for="member-alliance">연맹</label><select id="member-alliance"><option value="ZZN">ZZN</option><option value="GGZ">GGZ</option></select>
   <button type="submit">명단에 저장</button></form><p><small>같은 ID가 있으면 이름·연맹만 수정합니다. 수동으로 지정한 직책·부계정은 유지됩니다.</small></p></section>
   <section class="panel"><h2>CSV 명단 가져오기</h2><p><small>첫 줄은 <code>fid,nickname,alliance_tag</code>, 이후 한 줄에 한 명. 200명까지 한번에 저장할 수 있습니다. 기존 명단은 삭제하지 않습니다.</small></p>
   <label for="csvfile">CSV 파일 선택</label><input type="file" id="csvfile" accept=".csv,text/csv">
   <label for="csvtext">또는 CSV 내용을 붙여넣기</label><textarea id="csvtext" placeholder="fid,nickname,alliance_tag&#10;123456789,테스트,ZZN" style="min-height:115px"></textarea>
   <button id="import-csv" type="button" class="secondary">내용 확인 후 가져오기</button></section></div>
  </div>
  <div id="svs-view" class="hidden"><section class="panel"><span class="eyebrow">SVS PREPARATION</span><h2>SVS 준비전 · 기여도</h2><p class="muted">준비전 회차를 만들고 연맹원별 점수와 서버 순위를 수동 기록합니다. Oracle+ 순위 확정 데이터와 혼동하지 않습니다.</p>
   <div class="two-col"><form id="svs-round-form"><label for="svs-round-name">회차 이름</label><input id="svs-round-name" placeholder="예: 11월 SVS 준비전" maxlength="100" required><button type="submit">새 SVS 회차 만들기</button></form><div><label for="svs-round-select">확인할 회차</label><select id="svs-round-select"></select><div class="compact-actions" style="margin-top:8px"><button type="button" class="secondary" id="svs-close">선택 회차 마감</button><button type="button" class="secondary" id="svs-reopen">선택 회차 재개</button></div></div></div></section>
   <section class="panel"><h2>기여 점수 입력</h2><form id="svs-score-form" class="two-col"><div><label for="svs-player">연맹원</label><select id="svs-player" required></select></div><div><label for="svs-score">기여 점수</label><input id="svs-score" type="number" min="0" max="10000000000000" step="1" required placeholder="예: 12000000"></div><div><label for="svs-rank">서버 순위 (선택)</label><input id="svs-rank" type="number" min="1" max="1000000" placeholder="순위 미확인이면 빈칸"></div><div><label for="svs-note">기록 메모</label><input id="svs-note" maxlength="200" placeholder="예: 수동 확인"></div><button type="submit">기여도 저장</button></form></section>
   <section class="panel"><div class="toolbar"><h2>ZZN · GGZ 기여도 순위</h2><button id="svs-copy" type="button" class="secondary">순위표 복사</button></div><div id="svs-summary" class="stat-strip"></div><div id="svs-ranking" class="scroll" style="margin-top:15px"></div><p class="helper">TOP 50 / TOP 100은 직접 입력한 서버 순위 기준입니다. 공식 지급 자격을 확정하지 않습니다.</p></section></div>
  <div id="resources-view" class="hidden"><section class="panel"><span class="eyebrow">RESOURCE DISTRIBUTION</span><h2>자원 분배 · 투명한 장부</h2><p class="muted">보유 총량을 입력하고 수령자별 배분을 기록합니다. 잔여량보다 많이 배분할 수 없으며, 취소 기록은 남깁니다. 실제 게임 지급은 자동 처리하지 않습니다.</p>
   <div id="resource-cards" class="metric-grid"></div><form id="resource-pool-form" class="two-col" style="margin-top:17px"><div><label for="pool-kind">자원 종류</label><select id="pool-kind"><option value="FC">🔥 불의 수정 (개)</option><option value="SPEEDUP">⏱ 가속권 (일)</option><option value="GEMS">💎 다이아 (개)</option><option value="CHEST">🎁 보급 상자 (개)</option></select></div><div><label for="pool-total">보유 총량</label><input id="pool-total" type="number" min="0" step="1" required></div><button type="submit" class="secondary">보유 총량 저장</button></form></section>
   <div class="two-col"><section class="panel"><h2>자원 배분 기록</h2><form id="resource-allocate-form"><label for="alloc-player">받는 연맹원</label><select id="alloc-player" required></select><label for="alloc-kind">분배 자원</label><select id="alloc-kind"><option value="FC">불의 수정</option><option value="SPEEDUP">가속권 (일)</option><option value="GEMS">다이아</option><option value="CHEST">보급 상자</option></select><label for="alloc-amount">배분 수량</label><input id="alloc-amount" type="number" min="1" step="1" required><label for="alloc-reason">분배 근거</label><select id="alloc-reason"><option>SVS 준비전 보상</option><option>요새·성채 보상</option><option>군비사관 보상</option><option>운영진 배분</option><option>기타</option></select><label for="alloc-note">메모</label><input id="alloc-note" maxlength="200"><button type="submit">배분 기록 추가</button></form></section>
   <section class="panel"><h2>연맹별 분배 비교</h2><div id="resource-comparison"></div><p class="helper">분배 기록 기준이며 게임 내 실제 지급 여부와 다릅니다.</p></section></div>
   <section class="panel"><div class="toolbar"><h2>분배 장부</h2><button id="resource-copy" type="button" class="secondary">장부 복사</button></div><div id="resource-ledger" class="scroll"></div></section></div>
  <div id="calendar-view" class="hidden"><section class="panel"><span class="eyebrow">OPERATIONS CALENDAR</span><h2>주요 일정 · UTC ↔ KST</h2><p class="muted">등록 시각은 게임 기준 UTC이며, 목록에서는 한국 시간(KST)도 함께 표시됩니다. 자동으로 게임 이벤트를 생성하지 않습니다.</p>
   <form id="event-form" class="two-col"><div><label for="event-title">일정 이름</label><input id="event-title" maxlength="120" placeholder="예: 성 전투" required></div><div><label for="event-type">일정 종류</label><select id="event-type"><option>SVS</option><option>캐슬전</option><option>곰 사냥</option><option>이민</option><option>일반</option></select></div><div><label for="event-start">시작 시각 (UTC)</label><input id="event-start" type="datetime-local" required></div><div><label for="event-end">종료 시각 (UTC · 선택)</label><input id="event-end" type="datetime-local"></div><div><label for="event-note">운영 메모</label><input id="event-note" maxlength="500"></div><button type="submit">일정 추가</button></form></section>
   <section class="panel"><div class="toolbar"><h2>등록된 일정</h2><button type="button" id="events-copy" class="secondary">일정 공지 복사</button></div><div id="events-list" class="scroll"></div></section></div>
  <div id="insights-view" class="hidden"><section class="panel"><span class="eyebrow">COMMAND INSIGHTS</span><h2>서버 4114 · ZZN & GGZ 운영 분석</h2><p class="muted">실제 등록된 연맹원 명단과 수동 입력한 SVS·자원 데이터를 기준으로 지표를 계산합니다. 데이터가 없는 분석 항목은 미연동으로 표시합니다.</p><div id="insights-content"></div><button class="secondary" type="button" id="insights-copy">운영 요약 복사</button></section><section class="panel"><h2>확장할 분석 기능</h2><ul class="list-clean"><li>상대 서버 비교: Oracle+ 상대 서버 데이터 검증 후 추가</li><li>지심·SVS 공식 랭킹: 확인된 소스로만 산정</li><li>이민 후보 검토: 별도 승인·기록 관리</li><li>명함 이벤트 선발과 TOP100 요새 보상: 서로 독립된 자격·회차로 관리</li></ul></section></div>
  <div id="notices-view" class="hidden"><section class="panel"><h2>공지 보관함</h2><p class="safe"><small>게임 내 채팅용 공지를 저장·수정·삭제·복사할 수 있습니다. 복사 내용은 자동으로 게임에 전송되지 않습니다.</small></p>
  <form id="notice-form"><label for="notice-title">공지 제목</label><input id="notice-title" maxlength="120" required>
  <div class="two-col"><div><label for="notice-category">분류</label><select id="notice-category"><option>일반</option><option>SVS</option><option>캐슬전</option><option>보상</option><option>연맹규칙</option><option>기타</option></select></div><div><label for="notice-lang">언어</label><select id="notice-lang"><option value="KO">한국어</option><option value="EN">English</option></select></div></div>
  <label for="notice-body">공지 내용 (최대 4,000자)</label><textarea id="notice-body" maxlength="4000" rows="6" required></textarea>
  <div class="row"><button type="submit" id="notice-save">공지 저장</button><button type="button" id="notice-cancel" class="secondary hidden">수정 취소</button></div></form></section>
  <section class="panel"><div class="row" style="justify-content:space-between"><h2>저장된 공지</h2><select id="chunk-size" style="width:auto"><option value="160">160자씩 분할</option><option value="220">220자씩 분할</option><option value="300">300자씩 분할</option></select></div><div id="notices"></div></section></div>
  <div id="oracle-view" class="hidden">
    <section class="panel"><span class="eyebrow">API CONNECTION · STATE 4114</span><h2>Oracle+ · ZZN / GGZ 명단 동기화</h2>
      <p class="safe"><small>이 사이트 하나에서 Oracle+를 이용합니다. API 토큰은 Cloudflare Secret으로만 보관하며 브라우저에 표시하지 않습니다. 최초에는 연맹 ID 저장 → 미리보기 → 승인 후 동기화 순서로 진행합니다.</small></p>
      <p id="oracle-status" class="muted" aria-live="polite">설정을 확인하고 있습니다.</p>
      <div class="diagnostic"><h3>1. Oracle+ 서버 연결 진단</h3><p class="helper">4114 왕국의 상위 10개 연맹을 읽기 전용으로 조회합니다. 연맹 ID 대조 및 API_TOKEN 연결 확인에 사용합니다. 호출 1회가 Oracle+ 사용량에 포함됩니다.</p>
      <button id="oracle-diagnose" type="button" class="secondary">4114 서버 연결 확인 · AID 찾기</button><div id="oracle-diagnosis" class="notice" aria-live="polite">아직 진단을 실행하지 않았습니다.</div></div>
      <form id="oracle-config"><label for="oracle-zzn">ZZN Oracle+ 연맹 ID (AID)</label><input id="oracle-zzn" inputmode="numeric" pattern="[0-9]{5,20}" required placeholder="숫자 연맹 ID">
      <label for="oracle-ggz">GGZ Oracle+ 연맹 ID (AID)</label><input id="oracle-ggz" inputmode="numeric" pattern="[0-9]{5,20}" required placeholder="숫자 연맹 ID">
      <p class="muted"><small>기존 4114 WOS COMMAND CENTER 개발 기록의 연맹 ID는 ZZN 4114000047 / GGZ 4114000235입니다. 실제 API 응답으로 재확인되기 전에는 갱신하지 마세요. 연맹 태그가 맞지 않으면 저장하지 않습니다.</small></p>
      <button type="submit" class="secondary">연맹 ID 저장</button></form>
      <div class="row" style="margin-top:13px"><button id="oracle-preview-zzn" type="button" class="secondary">ZZN만 미리보기</button><button id="oracle-preview-ggz" type="button" class="secondary">GGZ만 미리보기</button><button id="oracle-preview" type="button" class="secondary">양쪽 명단 확인 (읽기 전용)</button></div>
      <div class="row" style="margin-top:9px"><button id="oracle-sync" type="button" disabled>검증 후 명단 갱신</button><small class="muted">한쪽이라도 미확인되면 갱신할 수 없습니다.</small></div>
      <div id="oracle-preview-data" class="notice" aria-live="polite">각 연맹을 따로 확인할 수 있습니다. ID 미연결 인원은 경고로 표시되며 기존 명단을 삭제하지 않습니다.</div>
    </section>
    <section class="panel"><h2>자동 갱신</h2><p>첫 번째 수동 동기화가 성공하면 자동 동기화를 켤 수 있습니다. UTC 기준 6시간 간격으로 확인하며 두 연맹 응답 모두 정상일 때만 DB를 갱신합니다.</p>
      <div class="row"><button id="oracle-auto-on" type="button" class="secondary">자동 갱신 켜기</button><button id="oracle-auto-off" type="button" class="secondary">자동 갱신 끄기</button></div>
      <p class="muted"><small>명단에 없는 플레이어를 자동 삭제하지 않습니다. R4/R5/부계정은 변경하지 않습니다. 실제 실행을 위해서는 Cloudflare의 API_TOKEN Secret 등록이 필요합니다.</small></p></section>
  </div></div>
  </main><script nonce="__NONCE__">
  const get=id=>document.getElementById(id), err=get('error'),msg=get('message');
  const elt=(tag,content)=>{const x=document.createElement(tag);if(content!==undefined)x.textContent=String(content??'');return x};
  const btn=(text,handler,cls)=>{const b=elt('button',text);b.type='button';if(cls)b.className=cls;b.addEventListener('click',handler);return b};
  let players=[],notices=[],editNotice=null;
  function setError(e){err.textContent=e instanceof Error?e.message:String(e);msg.textContent=''}
  async function api(url,method='GET',data){const o={method,headers:{}};if(data!==undefined){o.headers['content-type']='application/json';o.body=JSON.stringify(data)}
    const r=await fetch(url,o);if(!(r.headers.get('content-type')||'').includes('application/json'))throw Error('서버에서 JSON 대신 다른 응답을 보냈습니다. HTTP '+r.status);
    const v=await r.json();if(!r.ok)throw Error(v.error||'요청 실패');return v;}
  const tabViews={overview:'overview-view',players:'members-view',svs:'svs-view',resources:'resources-view',calendar:'calendar-view',insights:'insights-view',notices:'notices-view',oracle:'oracle-view'};
  function showTab(name){for(const n of Object.keys(tabViews)){get('tab-'+n).setAttribute('aria-selected',String(n===name));get(tabViews[n]).classList.toggle('hidden',n!==name)}
    err.textContent='';msg.textContent='';if(name==='overview')loadDashboard().catch(setError);if(name==='svs')loadSvs().catch(setError);if(name==='resources')loadResources().catch(setError);if(name==='calendar')loadEvents().catch(setError);if(name==='insights')renderInsights();if(name==='oracle')loadOracleStatus().catch(setError)}
  for(const name of Object.keys(tabViews))get('tab-'+name).onclick=()=>showTab(name);
  let oraclePreviewValid=false;
  async function loadOracleStatus(){const x=await api('/api/oracle/status');
    get('oracle-status').textContent='API 토큰: '+(x.tokenConfigured?'등록됨':'미등록')+' · 자동 갱신: '+(x.automaticEnabled?'켜짐':'꺼짐')+' · 최근 24시간 호출: '+x.limits.day+'/900'+
      ' · 마지막 ZZN 갱신: '+(x.alliances.ZZN.last_synced_at||'없음')+' · GGZ 갱신: '+(x.alliances.GGZ.last_synced_at||'없음');
    if(!get('oracle-zzn').value)get('oracle-zzn').value=x.alliances.ZZN.aid||'4114000047';
    if(!get('oracle-ggz').value)get('oracle-ggz').value=x.alliances.GGZ.aid||'4114000235';
  }
  get('oracle-config').onsubmit=async e=>{e.preventDefault();try{err.textContent='';const x=await api('/api/oracle/config','POST',{ZZN:get('oracle-zzn').value,GGZ:get('oracle-ggz').value});oraclePreviewValid=false;get('oracle-sync').disabled=true;msg.textContent=x.message;await loadOracleStatus()}catch(x){setError(x)}};
  get('oracle-diagnose').onclick=async()=>{const b=get('oracle-diagnose'),host=get('oracle-diagnosis');b.disabled=true;host.replaceChildren();host.append(elt('p','4114 서버의 Oracle+ 응답을 확인하고 있습니다.'));
    try{err.textContent='';const r=await api('/api/oracle/diagnose','POST',{});host.replaceChildren();host.append(elt('p','Oracle+ 인증 성공 · 추적된 왕국 플레이어 '+r.tracked_players+'명 · 조회 가능 상위 '+r.alliances.length+'개 연맹'));
      const table=elt('table'),thead=elt('thead'),tr=elt('tr');for(const h of ['연맹','연맹 ID(AID)','인원','입력'])tr.append(elt('th',h));thead.append(tr);table.append(thead);const tbody=elt('tbody');for(const a of r.alliances){const row=elt('tr');for(const x of [a.abbr+' · '+a.name,a.id,a.member_count])row.append(elt('td',x));const tools=elt('td');if(['ZZN','GGZ'].includes(a.abbr.toUpperCase()))tools.append(btn(a.abbr.toUpperCase()+'에 입력',()=>{get('oracle-'+a.abbr.toLowerCase()).value=a.id;oraclePreviewValid=false;get('oracle-sync').disabled=true;msg.textContent='입력칸에 ID를 반영했습니다. 연맹 ID 저장 버튼을 눌러 주세요.'},'secondary'));row.append(tools);tbody.append(row)}table.append(tbody);const scroll=elt('div');scroll.className='scroll';scroll.append(table);host.append(scroll);host.append(elt('p','참고: Oracle+ Plus에서는 상위 10개 연맹만 표시됩니다. 목록에 없더라도 연맹이 없다는 의미는 아닙니다.'));
    }catch(e){host.replaceChildren();const p=elt('p','연결 진단 실패: '+e.message);p.className='diag-error';host.append(p);setError(e)}finally{b.disabled=false}};
  async function oraclePreview(tag){const b=get(tag?'oracle-preview-'+tag.toLowerCase():'oracle-preview'),host=get('oracle-preview-data');
    try{err.textContent='';b.disabled=true;oraclePreviewValid=false;get('oracle-sync').disabled=true;host.replaceChildren();host.append(elt('p',(tag||'ZZN·GGZ')+' 응답 조회 중…'));
      const r=await api('/api/oracle/preview','POST',tag?{tag}:{});host.replaceChildren();host.append(elt('p',r.message));
      const cards=elt('div');cards.className='oracle-columns';
      for(const a of r.alliances){const card=elt('div');card.className='oracle-result';card.append(elt('strong',a.tag+' · '+a.name+' · AID '+a.aid));
        card.append(elt('p','조회 명단 '+a.roster_count+'명 · 연결된 플레이어 '+a.count+'명 · ID 미연결 '+a.unlinked_count+'명'+(a.reported_count!==null?' · API 전체 '+a.reported_count+'명':'')));
        if(a.examples.length)card.append(elt('p','예시: '+a.examples.map(p=>p.nickname+' ('+p.fid+')').join(', ')));
        for(const warning of a.warnings||[]){const p=elt('p','⚠ '+warning);p.className='warn';card.append(p)}
        cards.append(card);
      }
      for(const e of r.errors||[]){const card=elt('div');card.className='oracle-result';const p=elt('p',e.tag+' 조회 실패 ['+e.code+']: '+e.error);p.className='diag-error';card.append(p);cards.append(card)}host.append(cards);
      oraclePreviewValid=!!r.readyForSync;get('oracle-sync').disabled=!oraclePreviewValid;
      if(r.errors&&r.errors.length)err.textContent='API 진단 결과를 확인해 주세요. 기존 명단은 변경되지 않았습니다.';
    }catch(e){oraclePreviewValid=false;get('oracle-sync').disabled=true;host.replaceChildren();const p=elt('p',e.message);p.className='diag-error';host.append(p);setError(e)}finally{b.disabled=false}}
  get('oracle-preview').onclick=()=>oraclePreview(null);
  get('oracle-preview-zzn').onclick=()=>oraclePreview('ZZN');
  get('oracle-preview-ggz').onclick=()=>oraclePreview('GGZ');
  get('oracle-sync').onclick=async()=>{if(!oraclePreviewValid)return;if(!confirm('ZZN·GGZ 기존 닉네임·소속·전투력을 Oracle+ 최신 정보로 갱신하시겠습니까? R4·부계정은 보존됩니다.'))return;
    try{get('oracle-sync').disabled=true;const r=await api('/api/oracle/sync','POST',{confirm:true});msg.textContent='동기화 완료: ZZN '+r.counts.ZZN+'명, GGZ '+r.counts.GGZ+'명';oraclePreviewValid=false;await Promise.all([fetchPlayers(),loadOracleStatus()]);}catch(x){setError(x)} };
  for(const [id,enabled] of [['oracle-auto-on',true],['oracle-auto-off',false]])get(id).onclick=async()=>{try{const x=await api('/api/oracle/automatic','POST',{enabled});msg.textContent=x.message;await loadOracleStatus()}catch(x){setError(x)}};
  function clearRows(node){node.replaceChildren()}
  function renderPlayers(){get('count-zzn').textContent=players.filter(x=>x.alliance_tag==='ZZN').length;get('count-ggz').textContent=players.filter(x=>x.alliance_tag==='GGZ').length;get('count-all').textContent=players.length;
    const q=get('member-search').value.toLowerCase().trim();const matches=players.filter(x=>!q||String(x.nickname).toLowerCase().includes(q)||String(x.fid).includes(q));const host=get('players');clearRows(host);
    if(!matches.length){host.append(elt('p',players.length?'검색 결과가 없습니다.':'명단이 비어 있습니다. 연맹원을 등록하거나 CSV를 가져오세요.'));return;}
    const table=elt('table');const head=elt('thead'),tr=elt('tr');for(const h of ['연맹','닉네임','ID','직책','부계정','저장'])tr.append(elt('th',h));head.append(tr);table.append(head);const body=elt('tbody');
    for(const p of matches){const row=elt('tr');for(const v of [p.alliance_tag,p.nickname,p.fid])row.append(elt('td',v));
      const rankCell=elt('td'),rank=elt('select');for(const v of ['UNSET','R5','R4','R3','R2','R1']){const op=elt('option',v==='UNSET'?'미지정':v);op.value=v;rank.append(op)}rank.value=p.game_rank||'UNSET';rankCell.append(rank);row.append(rankCell);
      const altCell=elt('td'),alt=elt('input');alt.type='checkbox';alt.checked=!!p.is_alt;alt.setAttribute('aria-label',p.nickname+' 부계정');altCell.append(alt);row.append(altCell);
      const action=elt('td');action.append(btn('표시 저장',async()=>{try{err.textContent='';await api('/api/players/'+encodeURIComponent(p.fid)+'/labels','PATCH',{game_rank:rank.value,is_alt:alt.checked});msg.textContent=p.nickname+' 표시를 저장했습니다.';await fetchPlayers()}catch(e){setError(e)}}));row.append(action);body.append(row)}table.append(body);host.append(table);
  }
  get('member-search').oninput=renderPlayers;
  async function fetchPlayers(){const r=await api('/api/players');players=r.players||[];renderPlayers();fillSelect('svs-player');fillSelect('alloc-player')}
  async function fetchNotices(){const r=await api('/api/notices');notices=r.notices||[];renderNotices()}

  // v5: original COMMAND CENTER operating views (D1 backed, no simulated data)
  let dashboardData=null,svsData={rounds:[],active:null,ranking:[]},resourceData={pool:[],ledger:[]},eventsData={events:[]};
  const numberFormat=n=>Number(n||0).toLocaleString('ko-KR');
  const formatPower=n=>Number(n)>=1e9?(Number(n)/1e9).toFixed(2)+'B':Number(n)>=1e6?(Number(n)/1e6).toFixed(1)+'M':numberFormat(n);
  const resourceTypes={FC:'🔥 불의 수정',SPEEDUP:'⏱ 가속권 (일)',GEMS:'💎 다이아',CHEST:'🎁 보급 상자'};
  function fillSelect(id){const select=get(id);if(!select)return;const old=select.value;select.replaceChildren();if(!players.length){const op=elt('option','연맹원을 먼저 등록해 주세요');op.value='';select.append(op);return}
    for(const p of players){const op=elt('option',p.alliance_tag+' · '+p.nickname+' ('+p.fid+')');op.value=p.fid;select.append(op)}if(players.some(p=>p.fid===old))select.value=old;
  }
  function metric(label,value,detail){const node=elt('div');node.className='metric';const a=elt('small',label),b=elt('strong',value),c=elt('div',detail);c.className='sub';node.append(a,b,c);return node;}
  function li(text){return elt('li',text)}
  const dateKst=s=>s?new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}).format(new Date(s+'Z')):'—';
  function paintAlliance(tag,data){const host=get('overview-'+tag.toLowerCase());host.replaceChildren();host.append(elt('h3',tag+(tag==='ZZN'?' · 지존':' · GGZ')),elt('div',data.count+'명 / 정원 100명'));
    const b=elt('div');b.className='bar-track';const f=elt('div');f.className='bar-fill';f.style.width=Math.min(100,data.count)+'%';b.append(f);host.append(b);
    const metrics=elt('div');metrics.className='stat-strip';for(const [label,v] of [['파악된 전투력',data.powerKnown?formatPower(data.power):'미확인'],['R5·R4',data.r4+'명'],['부계정',data.alts+'명']]){const box=elt('div');box.append(elt('small',label),elt('div',v));metrics.append(box)}host.append(metrics);
    host.append(elt('small','전투력 확인 '+data.powerKnown+'/'+data.count+'명 · Oracle+ 또는 수동 등록 원시값'));
  }
  function renderDashboard(){if(!dashboardData)return;
    const d=dashboardData,zzn=d.alliances.ZZN,ggz=d.alliances.GGZ,metrics=get('overview-metrics');metrics.replaceChildren();
    metrics.append(metric('총 등록 인원',numberFormat(d.totalPlayers)+'명','ZZN '+zzn.count+' · GGZ '+ggz.count),metric('합산 전투력',zzn.powerKnown+ggz.powerKnown?formatPower(zzn.power+ggz.power):'미확인','실제 전투력 확인 '+(zzn.powerKnown+ggz.powerKnown)+'명'),metric('운영 공지',d.notices+'건','D1 공지 보관함'),metric('SVS 진행 회차',d.round?d.round.label:'없음',d.round?(d.round.status==='OPEN'?'입력 중':'마감'):'먼저 회차 생성'));
    paintAlliance('ZZN',zzn);paintAlliance('GGZ',ggz);
    const upcoming=get('overview-events');upcoming.replaceChildren();if(!d.upcoming.length)upcoming.append(li('예정된 일정이 없습니다. 일정 탭에서 등록하세요.'));
    for(const e of d.upcoming)upcoming.append(li(e.event_type+' · '+e.title+' · UTC '+e.start_utc.replace('T',' ')+' / KST '+dateKst(e.start_utc)));
    const checks=get('overview-checkpoints');checks.replaceChildren();const gap=Math.abs(zzn.count-ggz.count);checks.append(li('두 연맹 인원 차이: '+gap+'명'));
    checks.append(li('전투력 확인: '+(zzn.powerKnown+ggz.powerKnown)+' / '+d.totalPlayers+'명'));
    checks.append(li('SVS 회차: '+(d.round?d.round.label+' ('+(d.round.status==='OPEN'?'진행':'마감')+')':'등록되지 않음')));
    checks.append(li('확인할 운영 공지: '+d.notices+'건 저장'));
    const oracle=get('overview-oracle');oracle.replaceChildren();if(!d.oracleRecent.length)oracle.append(elt('p','아직 명단 자동 갱신 기록이 없습니다. Oracle+ 탭에서 미리보기를 먼저 실행하세요.'));
    for(const r of d.oracleRecent)oracle.append(li(r.alliance_tag+' · '+r.member_count+'명 · '+r.synced_at+' UTC'));
  }
  async function loadDashboard(){dashboardData=await api('/api/ops/dashboard');renderDashboard()}
  get('overview-refresh').onclick=()=>loadDashboard().catch(setError);
  async function loadSvs(roundId){const chosen=roundId||get('svs-round-select').value;svsData=await api('/api/ops/svs'+(chosen?'?round='+encodeURIComponent(chosen):''));renderSvs()}
  function renderSvs(){const s=svsData,select=get('svs-round-select'),old=select.value;select.replaceChildren();
    for(const r of s.rounds){const op=elt('option',r.label+' ('+(r.status==='OPEN'?'진행':'마감')+')');op.value=r.id;select.append(op)}
    if(s.rounds.some(x=>x.id===old))select.value=old;else if(s.active)select.value=s.active.id;
    fillSelect('svs-player');get('svs-close').disabled=!s.active||s.active.status==='CLOSED';get('svs-reopen').disabled=!s.active||s.active.status==='OPEN';
    get('svs-score-form').querySelector('button').disabled=!s.active||s.active.status==='CLOSED';
    const summary=get('svs-summary');summary.replaceChildren();const z=s.ranking.filter(x=>x.alliance_tag==='ZZN').reduce((acc,x)=>acc+Number(x.score),0),g=s.ranking.filter(x=>x.alliance_tag==='GGZ').reduce((acc,x)=>acc+Number(x.score),0);
    for(const [name,value] of [['ZZN 기여',numberFormat(z)+'점'],['GGZ 기여',numberFormat(g)+'점'],['등록 인원',s.ranking.length+'명']]){const box=elt('div');box.append(elt('small',name),elt('h3',value));summary.append(box)}
    const host=get('svs-ranking');host.replaceChildren();if(!s.active){host.append(elt('p','SVS 회차를 먼저 만들어 주세요.'));return}
    if(!s.ranking.length){host.append(elt('p','등록된 기여 점수가 없습니다.'));return}
    const table=elt('table'),header=elt('tr');for(const v of ['순위','연맹원','연맹','기여 점수','서버 순위'])header.append(elt('th',v));const head=elt('thead');head.append(header);table.append(head);const body=elt('tbody');s.ranking.forEach((x,i)=>{const tr=elt('tr');for(const value of [i+1,x.nickname,x.alliance_tag,numberFormat(x.score),x.server_rank||'미확인'])tr.append(elt('td',value));body.append(tr)});table.append(body);host.append(table);
  }
  get('svs-round-select').onchange=()=>loadSvs(get('svs-round-select').value).catch(setError);
  get('svs-round-form').onsubmit=async e=>{e.preventDefault();try{const created=await api('/api/ops/svs/rounds','POST',{label:get('svs-round-name').value.trim()});e.target.reset();await loadSvs(created.id);msg.textContent='SVS 회차를 생성했습니다.'}catch(x){setError(x)}};
  get('svs-score-form').onsubmit=async e=>{e.preventDefault();if(!svsData.active){setError('SVS 회차를 먼저 생성하세요.');return}try{
    await api('/api/ops/svs/scores','POST',{round_id:svsData.active.id,fid:get('svs-player').value,score:Number(get('svs-score').value),server_rank:get('svs-rank').value?Number(get('svs-rank').value):null,note:get('svs-note').value});
    await loadSvs();msg.textContent='기여 점수를 저장했습니다.'}catch(x){setError(x)}};
  for(const [id,status] of [['svs-close','CLOSED'],['svs-reopen','OPEN']])get(id).onclick=async()=>{if(!svsData.active)return;if(!confirm('회차 상태를 변경하시겠습니까?'))return;
    try{await api('/api/ops/svs/rounds/'+svsData.active.id+'/status','PATCH',{status});await loadSvs();msg.textContent='회차 상태를 저장했습니다.'}catch(x){setError(x)}};
  get('svs-copy').onclick=()=>{const x=svsData;if(!x.active)return;const text=[x.active.label+' · SVS 기여도',...x.ranking.map((r,i)=>(i+1)+'위 '+r.alliance_tag+' '+r.nickname+' '+numberFormat(r.score)+'점 · 서버 순위 '+(r.server_rank||'미확인'))].join('\n');navigator.clipboard.writeText(text).then(()=>msg.textContent='SVS 순위표를 복사했습니다.').catch(setError)};
  async function loadResources(){resourceData=await api('/api/ops/resources');renderResources()}
  function resourceSummary(){const map={};for(const type of Object.keys(resourceTypes))map[type]={total:0,used:0,ZZN:0,GGZ:0};for(const p of resourceData.pool){if(map[p.resource_type])map[p.resource_type].total=Number(p.total_amount)}
    for(const a of resourceData.totals||[]){if(!map[a.resource_type]||!tagSet(a.alliance_tag))continue;map[a.resource_type].used+=Number(a.used);map[a.resource_type][a.alliance_tag]+=Number(a.used)}return map;}
  const tagSet=x=>x==='ZZN'||x==='GGZ';
  function renderResources(){fillSelect('alloc-player');const summary=resourceSummary();const host=get('resource-cards');host.replaceChildren();
    for(const [type,name] of Object.entries(resourceTypes)){const m=summary[type];host.append(metric(name,numberFormat(m.total-m.used),'총 '+numberFormat(m.total)+' · 분배 '+numberFormat(m.used)))}
    const compare=get('resource-comparison');compare.replaceChildren();for(const [type,name] of Object.entries(resourceTypes)){const m=summary[type];const section=elt('div');section.className='notice';section.append(elt('strong',name));section.append(elt('p','ZZN '+numberFormat(m.ZZN)+' · GGZ '+numberFormat(m.GGZ)));compare.append(section)}
    const ledger=get('resource-ledger');ledger.replaceChildren();if(!resourceData.ledger.length){ledger.append(elt('p','배분 기록이 아직 없습니다.'));return}
    const table=elt('table'),head=elt('thead'),tr=elt('tr');for(const h of ['날짜 (UTC)','연맹원','자원','수량','근거','상태 / 작업'])tr.append(elt('th',h));head.append(tr);table.append(head);const body=elt('tbody');for(const a of resourceData.ledger){const row=elt('tr');for(const v of [a.created_at,a.alliance_tag+' '+a.nickname,resourceTypes[a.resource_type],numberFormat(a.amount),a.reason])row.append(elt('td',v));
      const action=elt('td');if(a.voided_at)action.append(elt('small','취소됨'));else action.append(btn('배분 취소',async()=>{if(!confirm(a.nickname+' 배분 기록을 취소하시겠습니까?'))return;try{await api('/api/ops/resources/allocations/'+a.id+'/void','POST',{});await loadResources();msg.textContent='배분 기록을 취소했습니다.'}catch(e){setError(e)}},'danger'));row.append(action);body.append(row)}table.append(body);ledger.append(table);
  }
  get('resource-pool-form').onsubmit=async e=>{e.preventDefault();try{await api('/api/ops/resources/pool','POST',{resource_type:get('pool-kind').value,total_amount:Number(get('pool-total').value)});await loadResources();msg.textContent='보유량을 저장했습니다.'}catch(x){setError(x)}};
  get('resource-allocate-form').onsubmit=async e=>{e.preventDefault();try{await api('/api/ops/resources/allocations','POST',{fid:get('alloc-player').value,resource_type:get('alloc-kind').value,amount:Number(get('alloc-amount').value),reason:get('alloc-reason').value,memo:get('alloc-note').value});get('alloc-amount').value='';get('alloc-note').value='';await loadResources();msg.textContent='배분 기록을 추가했습니다.'}catch(x){setError(x)}};
  get('resource-copy').onclick=()=>{const lines=resourceData.ledger.map(a=>a.created_at+' '+a.alliance_tag+' '+a.nickname+' '+resourceTypes[a.resource_type]+' '+numberFormat(a.amount)+' '+a.reason+(a.voided_at?' [취소됨]':''));navigator.clipboard.writeText(lines.join('\n')).then(()=>msg.textContent='자원 배분 장부를 복사했습니다.').catch(setError)};
  async function loadEvents(){eventsData=await api('/api/ops/events');renderEvents()}
  function renderEvents(){const host=get('events-list');host.replaceChildren();if(!eventsData.events.length){host.append(elt('p','등록된 일정이 없습니다.'));return}
    const table=elt('table'),head=elt('thead'),tr=elt('tr');for(const h of ['일정','종류','게임 UTC','한국 KST','작업'])tr.append(elt('th',h));head.append(tr);table.append(head);const body=elt('tbody');for(const e of eventsData.events){const row=elt('tr');for(const v of [e.title,e.event_type,e.start_utc.replace('T',' '),dateKst(e.start_utc)])row.append(elt('td',v));const cell=elt('td');cell.append(btn('삭제',async()=>{if(!confirm('일정을 삭제하시겠습니까?'))return;try{await api('/api/ops/events/'+e.id,'DELETE',{});await loadEvents();msg.textContent='일정을 삭제했습니다.'}catch(x){setError(x)}},'danger'));row.append(cell);body.append(row)}table.append(body);host.append(table)}
  get('event-form').onsubmit=async e=>{e.preventDefault();try{await api('/api/ops/events','POST',{title:get('event-title').value,event_type:get('event-type').value,start_utc:get('event-start').value,end_utc:get('event-end').value||null,note:get('event-note').value});e.target.reset();await loadEvents();msg.textContent='일정을 저장했습니다.'}catch(x){setError(x)}};
  get('events-copy').onclick=()=>{const lines=eventsData.events.map(e=>'['+e.event_type+'] '+e.title+' · UTC '+e.start_utc.replace('T',' ')+' / KST '+dateKst(e.start_utc));navigator.clipboard.writeText(lines.join('\n')).then(()=>msg.textContent='일정 공지를 복사했습니다.').catch(setError)};
  function insightsText(){if(!dashboardData)return '운영 데이터 조회 중';const d=dashboardData,z=d.alliances.ZZN,g=d.alliances.GGZ;
    const line=['4114 ZZN&GGZ 운영 현황','ZZN '+z.count+'명 / GGZ '+g.count+'명 · 인원 차이 '+Math.abs(z.count-g.count)+'명',
      '등록된 전투력 ZZN '+(z.powerKnown?formatPower(z.power):'미확인')+' / GGZ '+(g.powerKnown?formatPower(g.power):'미확인'),
      'R5·R4 ZZN '+z.r4+'명 / GGZ '+g.r4+'명','부계정 ZZN '+z.alts+'명 / GGZ '+g.alts+'명',
      '명단 출처: D1 저장 정보 · 공식 SVS 순위 미연동'];return line.join('\n')}
  function renderInsights(){const host=get('insights-content');host.replaceChildren();if(!dashboardData){loadDashboard().then(renderInsights).catch(setError);return}const text=insightsText();const pre=elt('pre',text);pre.style.cssText='white-space:pre-wrap;line-height:1.9;background:#f4f9fe;border:1px solid #e0ebf5;border-radius:12px;padding:18px';host.append(pre)}
  get('insights-copy').onclick=()=>navigator.clipboard.writeText(insightsText()).then(()=>msg.textContent='운영 요약을 복사했습니다.').catch(setError);
  async function init(){try{await api('/api/me')}catch{get('login').classList.remove('hidden');get('app').classList.add('hidden');return}
    get('login').classList.add('hidden');get('app').classList.remove('hidden');const outcome=await Promise.allSettled([fetchPlayers(),fetchNotices()]);for(const x of outcome)if(x.status==='rejected')setError(x.reason);showTab('overview')}
  get('login-form').onsubmit=async e=>{e.preventDefault();err.textContent='';try{await api('/api/login','POST',{pin:get('pin').value});get('pin').value='';await init()}catch(x){setError(x)}};
  get('logout').onclick=async()=>{try{await api('/api/logout','POST',{})}finally{location.reload()}};
  get('member-form').onsubmit=async e=>{e.preventDefault();err.textContent='';try{await api('/api/players/import','POST',{players:[{fid:get('member-fid').value,nickname:get('member-name').value,alliance_tag:get('member-alliance').value}]});e.target.reset();msg.textContent='연맹원을 저장했습니다.';await fetchPlayers()}catch(x){setError(x)}};
  function parseCsv(source){const rows=[];let row=[],cell='',inside=false;for(let i=0;i<source.length;i++){const c=source[i];if(c==='"'){if(inside&&source[i+1]==='"'){cell+='"';i++}else inside=!inside}else if(c===','&&!inside){row.push(cell);cell=''}else if((c==='\n'||c==='\r')&&!inside){if(c==='\r'&&source[i+1]==='\n')i++;row.push(cell);if(row.some(x=>x.trim()))rows.push(row);row=[];cell=''}else cell+=c;}if(inside)throw Error('CSV 따옴표 형식을 확인하세요.');row.push(cell);if(row.some(x=>x.trim()))rows.push(row);
    const h=(rows.shift()||[]).map(x=>x.trim().replace(/^\ufeff/,''));const key=x=>h.findIndex(v=>v.toLowerCase()===x||({'fid':['아이디','플레이어id','id'],'nickname':['닉네임','name'],'alliance_tag':['연맹','alliance']}[x]||[]).includes(v.toLowerCase()));const a=key('fid'),b=key('nickname'),c=key('alliance_tag');
    if(a<0||b<0||c<0)throw Error('CSV 첫 줄에 fid,nickname,alliance_tag가 필요합니다.');return rows.map(r=>({fid:(r[a]||'').trim(),nickname:(r[b]||'').trim(),alliance_tag:(r[c]||'').trim().toUpperCase()}))}
  get('csvfile').onchange=async e=>{const f=e.target.files?.[0];if(!f)return;if(f.size>50000){setError(Error('CSV 파일은 50KB 이하여야 합니다.'));return}get('csvtext').value=await f.text()};
  get('import-csv').onclick=async()=>{try{err.textContent='';const list=parseCsv(get('csvtext').value);if(!list.length||list.length>200)throw Error('CSV에는 1~200명만 넣을 수 있습니다.');if(!confirm(list.length+'명을 가져오시겠습니까? 기존 명단은 삭제하지 않습니다.'))return;
      const r=await api('/api/players/import','POST',{players:list});msg.textContent=r.saved+'명의 명단을 저장했습니다.';get('csvtext').value='';get('csvfile').value='';await fetchPlayers()}catch(e){setError(e)}};
  function resetNotice(){editNotice=null;get('notice-form').reset();get('notice-save').textContent='공지 저장';get('notice-cancel').classList.add('hidden')}
  get('notice-cancel').onclick=resetNotice;
  get('notice-form').onsubmit=async e=>{e.preventDefault();err.textContent='';const v={title:get('notice-title').value,body:get('notice-body').value,language:get('notice-lang').value,category:get('notice-category').value};try{
    if(editNotice)await api('/api/notices/'+encodeURIComponent(editNotice),'PATCH',v);else await api('/api/notices','POST',v);resetNotice();msg.textContent='공지를 저장했습니다.';await fetchNotices()}catch(e){setError(e)}};
  async function copyText(s){try{await navigator.clipboard.writeText(s);msg.textContent='복사했습니다.'}catch{setError(Error('복사 권한이 거부되었습니다. 브라우저의 클립보드 허용을 확인하세요.'))}}
  function renderNotices(){const host=get('notices');clearRows(host);if(!notices.length){host.append(elt('p','저장된 공지가 없습니다.'));return;}const size=Number(get('chunk-size').value)||160;
    for(const n of notices){const card=elt('article');card.className='notice';const line=elt('div');line.className='row';const title=elt('strong',n.title);const tag=elt('span',n.category+' · '+n.language);tag.className='pill';line.append(title,tag);card.append(line,elt('p',n.body));
      const actions=elt('div');actions.className='row';actions.append(btn('전체 복사',()=>copyText(n.body)),btn('수정',()=>{editNotice=n.id;get('notice-title').value=n.title;get('notice-body').value=n.body;get('notice-lang').value=n.language;get('notice-category').value=['일반','SVS','캐슬전','보상','연맹규칙','기타'].includes(n.category)?n.category:'기타';get('notice-save').textContent='수정 저장';get('notice-cancel').classList.remove('hidden');get('notice-form').scrollIntoView({behavior:'smooth',block:'start'})},'secondary'),btn('삭제',async()=>{if(!confirm('이 공지를 삭제하시겠습니까?'))return;try{await api('/api/notices/'+encodeURIComponent(n.id),'DELETE',{});msg.textContent='공지 삭제 완료';if(editNotice===n.id)resetNotice();await fetchNotices()}catch(e){setError(e)}},'danger'));card.append(actions);
      const chars=Array.from(n.body);if(chars.length>size){const cnt=Math.ceil(chars.length/size),note=elt('small','분할 복사 · '+cnt+'개 구간 ('+size+'자 기준)');card.append(note);const parts=elt('div');parts.className='row';for(let i=0;i<cnt;i++){const part=chars.slice(i*size,(i+1)*size).join('');parts.append(btn((i+1)+'/'+cnt+' 복사',()=>copyText(part),'secondary'))}card.append(parts)}host.append(card);}}
  get('chunk-size').onchange=renderNotices;
  init();
  </script></body></html>`;
  const nonce = randomHex(16);
  return new Response(html.replace('__NONCE__',nonce),{headers:{...textHeaders,'content-security-policy':`${textHeaders['content-security-policy']}; script-src 'nonce-${nonce}'`}});
}

// Owner authentication uses strong, independent credentials configured as Worker Secrets.
// It does not grant access to the older owner site or to game data APIs.
function getCookie(req, name) {
  for (const p of (req.headers.get('cookie')||'').split(';')) {
    const n=p.indexOf('=');
    if(n>0 && p.slice(0,n).trim()===name) return p.slice(n+1).trim();
  }
  return '';
}
async function ownerSigned(env, message) {
  return hmac(env.SESSION_SECRET, `wos4114-owner|${env.OWNER_LOGIN_SECRET}|${message}`);
}
async function ownerAuthenticated(req, env, now) {
  if(!ownerConfigOk(env)) return false;
  const raw=getCookie(req, ownerCookieName);
  const m=/^v1\.(\d{10})\.([a-f0-9]{32})\.([a-f0-9]{64})$/.exec(raw);
  if(!m) return false;
  const exp=Number(m[1]);
  if(exp<=now || exp>now+OWNER_SESSION_SEC) return false;
  return constantTimeEqual(await ownerSigned(env, `v1.${m[1]}.${m[2]}`),m[3]);
}
function ownerPage(){
  const html=String.raw`<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>4114 비밀번호 설정</title>
  <style>body{margin:0;padding:22px;background:radial-gradient(circle at 0 0,#c8ddec,transparent 40%),#eef3f9;font:16px/1.6 system-ui,-apple-system,'Malgun Gothic',sans-serif;color:#14304a}main{max-width:580px;margin:34px auto;background:#fff;border:1px solid #cfdeeb;border-radius:17px;padding:0 28px 25px;overflow:hidden;box-shadow:0 18px 60px #112c4828}h1{margin:0 -28px 23px;background:linear-gradient(110deg,#091b32,#124964);padding:25px 28px;color:#eef8ff;font-size:24px;letter-spacing:.04em}h2{font-size:19px;color:#173853}input,button{box-sizing:border-box;width:100%;padding:12px;font:inherit;border-radius:8px;margin:5px 0 12px;border:1px solid #bdcede}button{background:#195e7d;border:0;color:white;cursor:pointer;font-weight:700}small{color:#59748d}.hidden{display:none!important}#err{color:#b12a32}#msg{color:#08775d}a{color:#176b95}input:focus-visible,button:focus-visible,a:focus-visible{outline:3px solid #d4b67d;outline-offset:2px}@media(max-width:600px){body{padding:0}main{margin:0;border-radius:0;min-height:100vh}}</style></head><body><main><h1>4114 WOS COMMAND CENTER</h1><h2>최고관리자 · 공용 비밀번호 설정</h2><p><small>현재 운영진 사이트와 같은 주소에서 PIN만 변경합니다. 연맹원·보상 관리 권한과는 무관합니다.</small></p><p id="err" role="alert"></p><p id="msg" role="status"></p>
  <section id="owner-login"><form id="owner-login-form"><label for="owner-id">최고관리자 ID</label><input id="owner-id" autocomplete="username" required><label for="owner-secret">최고관리자 비밀번호</label><input id="owner-secret" type="password" autocomplete="current-password" required><button>최고관리자 로그인</button></form></section>
  <section id="owner-setup" class="hidden"><p>새 운영진 공용 비밀번호를 입력하세요. 변경 즉시 기존 운영진 로그인 세션은 만료됩니다.</p><form id="pin-form"><label for="new-pin">새 공용 비밀번호 (숫자 4자리)</label><input id="new-pin" type="password" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" autocomplete="new-password" required><label for="again">비밀번호 확인</label><input id="again" type="password" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" autocomplete="new-password" required><button>공용 비밀번호 변경</button></form><button id="owner-logout" type="button">최고관리자 로그아웃</button></section><p><a href="/">운영진 로그인으로 돌아가기</a></p></main><script nonce="__NONCE__">
  const by=id=>document.getElementById(id),err=by('err'),msg=by('msg');
  async function call(path,method='GET',v){const init={method,headers:{}};if(v!==undefined){init.headers['content-type']='application/json';init.body=JSON.stringify(v)}const r=await fetch(path,init);if(!(r.headers.get('content-type')||'').includes('application/json'))throw Error('서버 응답 오류: HTTP '+r.status);const data=await r.json();if(!r.ok)throw Error(data.error||'요청 실패');return data;}
  function display(ok){by('owner-login').classList.toggle('hidden',ok);by('owner-setup').classList.toggle('hidden',!ok)}

  // v5: original COMMAND CENTER operating views (D1 backed, no simulated data)
  let dashboardData=null,svsData={rounds:[],active:null,ranking:[]},resourceData={pool:[],ledger:[]},eventsData={events:[]};
  const numberFormat=n=>Number(n||0).toLocaleString('ko-KR');
  const formatPower=n=>Number(n)>=1e9?(Number(n)/1e9).toFixed(2)+'B':Number(n)>=1e6?(Number(n)/1e6).toFixed(1)+'M':numberFormat(n);
  const resourceTypes={FC:'🔥 불의 수정',SPEEDUP:'⏱ 가속권 (일)',GEMS:'💎 다이아',CHEST:'🎁 보급 상자'};
  function fillSelect(id){const select=get(id);if(!select)return;const old=select.value;select.replaceChildren();if(!players.length){const op=elt('option','연맹원을 먼저 등록해 주세요');op.value='';select.append(op);return}
    for(const p of players){const op=elt('option',p.alliance_tag+' · '+p.nickname+' ('+p.fid+')');op.value=p.fid;select.append(op)}if(players.some(p=>p.fid===old))select.value=old;
  }
  function metric(label,value,detail){const node=elt('div');node.className='metric';const a=elt('small',label),b=elt('strong',value),c=elt('div',detail);c.className='sub';node.append(a,b,c);return node;}
  function li(text){return elt('li',text)}
  const dateKst=s=>s?new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}).format(new Date(s+'Z')):'—';
  function paintAlliance(tag,data){const host=get('overview-'+tag.toLowerCase());host.replaceChildren();host.append(elt('h3',tag+(tag==='ZZN'?' · 지존':' · GGZ')),elt('div',data.count+'명 / 정원 100명'));
    const b=elt('div');b.className='bar-track';const f=elt('div');f.className='bar-fill';f.style.width=Math.min(100,data.count)+'%';b.append(f);host.append(b);
    const metrics=elt('div');metrics.className='stat-strip';for(const [label,v] of [['파악된 전투력',data.powerKnown?formatPower(data.power):'미확인'],['R5·R4',data.r4+'명'],['부계정',data.alts+'명']]){const box=elt('div');box.append(elt('small',label),elt('div',v));metrics.append(box)}host.append(metrics);
    host.append(elt('small','전투력 확인 '+data.powerKnown+'/'+data.count+'명 · Oracle+ 또는 수동 등록 원시값'));
  }
  function renderDashboard(){if(!dashboardData)return;
    const d=dashboardData,zzn=d.alliances.ZZN,ggz=d.alliances.GGZ,metrics=get('overview-metrics');metrics.replaceChildren();
    metrics.append(metric('총 등록 인원',numberFormat(d.totalPlayers)+'명','ZZN '+zzn.count+' · GGZ '+ggz.count),metric('합산 전투력',zzn.powerKnown+ggz.powerKnown?formatPower(zzn.power+ggz.power):'미확인','실제 전투력 확인 '+(zzn.powerKnown+ggz.powerKnown)+'명'),metric('운영 공지',d.notices+'건','D1 공지 보관함'),metric('SVS 진행 회차',d.round?d.round.label:'없음',d.round?(d.round.status==='OPEN'?'입력 중':'마감'):'먼저 회차 생성'));
    paintAlliance('ZZN',zzn);paintAlliance('GGZ',ggz);
    const upcoming=get('overview-events');upcoming.replaceChildren();if(!d.upcoming.length)upcoming.append(li('예정된 일정이 없습니다. 일정 탭에서 등록하세요.'));
    for(const e of d.upcoming)upcoming.append(li(e.event_type+' · '+e.title+' · UTC '+e.start_utc.replace('T',' ')+' / KST '+dateKst(e.start_utc)));
    const checks=get('overview-checkpoints');checks.replaceChildren();const gap=Math.abs(zzn.count-ggz.count);checks.append(li('두 연맹 인원 차이: '+gap+'명'));
    checks.append(li('전투력 확인: '+(zzn.powerKnown+ggz.powerKnown)+' / '+d.totalPlayers+'명'));
    checks.append(li('SVS 회차: '+(d.round?d.round.label+' ('+(d.round.status==='OPEN'?'진행':'마감')+')':'등록되지 않음')));
    checks.append(li('확인할 운영 공지: '+d.notices+'건 저장'));
    const oracle=get('overview-oracle');oracle.replaceChildren();if(!d.oracleRecent.length)oracle.append(elt('p','아직 명단 자동 갱신 기록이 없습니다. Oracle+ 탭에서 미리보기를 먼저 실행하세요.'));
    for(const r of d.oracleRecent)oracle.append(li(r.alliance_tag+' · '+r.member_count+'명 · '+r.synced_at+' UTC'));
  }
  async function loadDashboard(){dashboardData=await api('/api/ops/dashboard');renderDashboard()}
  get('overview-refresh').onclick=()=>loadDashboard().catch(setError);
  async function loadSvs(roundId){const chosen=roundId||get('svs-round-select').value;svsData=await api('/api/ops/svs'+(chosen?'?round='+encodeURIComponent(chosen):''));renderSvs()}
  function renderSvs(){const s=svsData,select=get('svs-round-select'),old=select.value;select.replaceChildren();
    for(const r of s.rounds){const op=elt('option',r.label+' ('+(r.status==='OPEN'?'진행':'마감')+')');op.value=r.id;select.append(op)}
    if(s.rounds.some(x=>x.id===old))select.value=old;else if(s.active)select.value=s.active.id;
    fillSelect('svs-player');get('svs-close').disabled=!s.active||s.active.status==='CLOSED';get('svs-reopen').disabled=!s.active||s.active.status==='OPEN';
    get('svs-score-form').querySelector('button').disabled=!s.active||s.active.status==='CLOSED';
    const summary=get('svs-summary');summary.replaceChildren();const z=s.ranking.filter(x=>x.alliance_tag==='ZZN').reduce((acc,x)=>acc+Number(x.score),0),g=s.ranking.filter(x=>x.alliance_tag==='GGZ').reduce((acc,x)=>acc+Number(x.score),0);
    for(const [name,value] of [['ZZN 기여',numberFormat(z)+'점'],['GGZ 기여',numberFormat(g)+'점'],['등록 인원',s.ranking.length+'명']]){const box=elt('div');box.append(elt('small',name),elt('h3',value));summary.append(box)}
    const host=get('svs-ranking');host.replaceChildren();if(!s.active){host.append(elt('p','SVS 회차를 먼저 만들어 주세요.'));return}
    if(!s.ranking.length){host.append(elt('p','등록된 기여 점수가 없습니다.'));return}
    const table=elt('table'),header=elt('tr');for(const v of ['순위','연맹원','연맹','기여 점수','서버 순위'])header.append(elt('th',v));const head=elt('thead');head.append(header);table.append(head);const body=elt('tbody');s.ranking.forEach((x,i)=>{const tr=elt('tr');for(const value of [i+1,x.nickname,x.alliance_tag,numberFormat(x.score),x.server_rank||'미확인'])tr.append(elt('td',value));body.append(tr)});table.append(body);host.append(table);
  }
  get('svs-round-select').onchange=()=>loadSvs(get('svs-round-select').value).catch(setError);
  get('svs-round-form').onsubmit=async e=>{e.preventDefault();try{const created=await api('/api/ops/svs/rounds','POST',{label:get('svs-round-name').value.trim()});e.target.reset();await loadSvs(created.id);msg.textContent='SVS 회차를 생성했습니다.'}catch(x){setError(x)}};
  get('svs-score-form').onsubmit=async e=>{e.preventDefault();if(!svsData.active){setError('SVS 회차를 먼저 생성하세요.');return}try{
    await api('/api/ops/svs/scores','POST',{round_id:svsData.active.id,fid:get('svs-player').value,score:Number(get('svs-score').value),server_rank:get('svs-rank').value?Number(get('svs-rank').value):null,note:get('svs-note').value});
    await loadSvs();msg.textContent='기여 점수를 저장했습니다.'}catch(x){setError(x)}};
  for(const [id,status] of [['svs-close','CLOSED'],['svs-reopen','OPEN']])get(id).onclick=async()=>{if(!svsData.active)return;if(!confirm('회차 상태를 변경하시겠습니까?'))return;
    try{await api('/api/ops/svs/rounds/'+svsData.active.id+'/status','PATCH',{status});await loadSvs();msg.textContent='회차 상태를 저장했습니다.'}catch(x){setError(x)}};
  get('svs-copy').onclick=()=>{const x=svsData;if(!x.active)return;const text=[x.active.label+' · SVS 기여도',...x.ranking.map((r,i)=>(i+1)+'위 '+r.alliance_tag+' '+r.nickname+' '+numberFormat(r.score)+'점 · 서버 순위 '+(r.server_rank||'미확인'))].join('\n');navigator.clipboard.writeText(text).then(()=>msg.textContent='SVS 순위표를 복사했습니다.').catch(setError)};
  async function loadResources(){resourceData=await api('/api/ops/resources');renderResources()}
  function resourceSummary(){const map={};for(const type of Object.keys(resourceTypes))map[type]={total:0,used:0,ZZN:0,GGZ:0};for(const p of resourceData.pool){if(map[p.resource_type])map[p.resource_type].total=Number(p.total_amount)}
    for(const a of resourceData.totals||[]){if(!map[a.resource_type]||!tagSet(a.alliance_tag))continue;map[a.resource_type].used+=Number(a.used);map[a.resource_type][a.alliance_tag]+=Number(a.used)}return map;}
  const tagSet=x=>x==='ZZN'||x==='GGZ';
  function renderResources(){fillSelect('alloc-player');const summary=resourceSummary();const host=get('resource-cards');host.replaceChildren();
    for(const [type,name] of Object.entries(resourceTypes)){const m=summary[type];host.append(metric(name,numberFormat(m.total-m.used),'총 '+numberFormat(m.total)+' · 분배 '+numberFormat(m.used)))}
    const compare=get('resource-comparison');compare.replaceChildren();for(const [type,name] of Object.entries(resourceTypes)){const m=summary[type];const section=elt('div');section.className='notice';section.append(elt('strong',name));section.append(elt('p','ZZN '+numberFormat(m.ZZN)+' · GGZ '+numberFormat(m.GGZ)));compare.append(section)}
    const ledger=get('resource-ledger');ledger.replaceChildren();if(!resourceData.ledger.length){ledger.append(elt('p','배분 기록이 아직 없습니다.'));return}
    const table=elt('table'),head=elt('thead'),tr=elt('tr');for(const h of ['날짜 (UTC)','연맹원','자원','수량','근거','상태 / 작업'])tr.append(elt('th',h));head.append(tr);table.append(head);const body=elt('tbody');for(const a of resourceData.ledger){const row=elt('tr');for(const v of [a.created_at,a.alliance_tag+' '+a.nickname,resourceTypes[a.resource_type],numberFormat(a.amount),a.reason])row.append(elt('td',v));
      const action=elt('td');if(a.voided_at)action.append(elt('small','취소됨'));else action.append(btn('배분 취소',async()=>{if(!confirm(a.nickname+' 배분 기록을 취소하시겠습니까?'))return;try{await api('/api/ops/resources/allocations/'+a.id+'/void','POST',{});await loadResources();msg.textContent='배분 기록을 취소했습니다.'}catch(e){setError(e)}},'danger'));row.append(action);body.append(row)}table.append(body);ledger.append(table);
  }
  get('resource-pool-form').onsubmit=async e=>{e.preventDefault();try{await api('/api/ops/resources/pool','POST',{resource_type:get('pool-kind').value,total_amount:Number(get('pool-total').value)});await loadResources();msg.textContent='보유량을 저장했습니다.'}catch(x){setError(x)}};
  get('resource-allocate-form').onsubmit=async e=>{e.preventDefault();try{await api('/api/ops/resources/allocations','POST',{fid:get('alloc-player').value,resource_type:get('alloc-kind').value,amount:Number(get('alloc-amount').value),reason:get('alloc-reason').value,memo:get('alloc-note').value});get('alloc-amount').value='';get('alloc-note').value='';await loadResources();msg.textContent='배분 기록을 추가했습니다.'}catch(x){setError(x)}};
  get('resource-copy').onclick=()=>{const lines=resourceData.ledger.map(a=>a.created_at+' '+a.alliance_tag+' '+a.nickname+' '+resourceTypes[a.resource_type]+' '+numberFormat(a.amount)+' '+a.reason+(a.voided_at?' [취소됨]':''));navigator.clipboard.writeText(lines.join('\n')).then(()=>msg.textContent='자원 배분 장부를 복사했습니다.').catch(setError)};
  async function loadEvents(){eventsData=await api('/api/ops/events');renderEvents()}
  function renderEvents(){const host=get('events-list');host.replaceChildren();if(!eventsData.events.length){host.append(elt('p','등록된 일정이 없습니다.'));return}
    const table=elt('table'),head=elt('thead'),tr=elt('tr');for(const h of ['일정','종류','게임 UTC','한국 KST','작업'])tr.append(elt('th',h));head.append(tr);table.append(head);const body=elt('tbody');for(const e of eventsData.events){const row=elt('tr');for(const v of [e.title,e.event_type,e.start_utc.replace('T',' '),dateKst(e.start_utc)])row.append(elt('td',v));const cell=elt('td');cell.append(btn('삭제',async()=>{if(!confirm('일정을 삭제하시겠습니까?'))return;try{await api('/api/ops/events/'+e.id,'DELETE',{});await loadEvents();msg.textContent='일정을 삭제했습니다.'}catch(x){setError(x)}},'danger'));row.append(cell);body.append(row)}table.append(body);host.append(table)}
  get('event-form').onsubmit=async e=>{e.preventDefault();try{await api('/api/ops/events','POST',{title:get('event-title').value,event_type:get('event-type').value,start_utc:get('event-start').value,end_utc:get('event-end').value||null,note:get('event-note').value});e.target.reset();await loadEvents();msg.textContent='일정을 저장했습니다.'}catch(x){setError(x)}};
  get('events-copy').onclick=()=>{const lines=eventsData.events.map(e=>'['+e.event_type+'] '+e.title+' · UTC '+e.start_utc.replace('T',' ')+' / KST '+dateKst(e.start_utc));navigator.clipboard.writeText(lines.join('\n')).then(()=>msg.textContent='일정 공지를 복사했습니다.').catch(setError)};
  function insightsText(){if(!dashboardData)return '운영 데이터 조회 중';const d=dashboardData,z=d.alliances.ZZN,g=d.alliances.GGZ;
    const line=['4114 ZZN&GGZ 운영 현황','ZZN '+z.count+'명 / GGZ '+g.count+'명 · 인원 차이 '+Math.abs(z.count-g.count)+'명',
      '등록된 전투력 ZZN '+(z.powerKnown?formatPower(z.power):'미확인')+' / GGZ '+(g.powerKnown?formatPower(g.power):'미확인'),
      'R5·R4 ZZN '+z.r4+'명 / GGZ '+g.r4+'명','부계정 ZZN '+z.alts+'명 / GGZ '+g.alts+'명',
      '명단 출처: D1 저장 정보 · 공식 SVS 순위 미연동'];return line.join('\n')}
  function renderInsights(){const host=get('insights-content');host.replaceChildren();if(!dashboardData){loadDashboard().then(renderInsights).catch(setError);return}const text=insightsText();const pre=elt('pre',text);pre.style.cssText='white-space:pre-wrap;line-height:1.9;background:#f4f9fe;border:1px solid #e0ebf5;border-radius:12px;padding:18px';host.append(pre)}
  get('insights-copy').onclick=()=>navigator.clipboard.writeText(insightsText()).then(()=>msg.textContent='운영 요약을 복사했습니다.').catch(setError);
  async function init(){try{await call('/api/owner/me');display(true)}catch{display(false)}}
  by('owner-login-form').onsubmit=async e=>{e.preventDefault();err.textContent='';try{await call('/api/owner/login','POST',{id:by('owner-id').value,password:by('owner-secret').value});by('owner-secret').value='';display(true)}catch(x){err.textContent=x.message}};
  by('pin-form').onsubmit=async e=>{e.preventDefault();err.textContent='';if(by('new-pin').value!==by('again').value){err.textContent='비밀번호 확인이 일치하지 않습니다.';return;}try{await call('/api/owner/pin','POST',{pin:by('new-pin').value});by('new-pin').value='';by('again').value='';msg.textContent='공용 비밀번호가 변경되었습니다. 기존 운영진 로그인은 해제됩니다.';}catch(x){err.textContent=x.message}};
  by('owner-logout').onclick=async()=>{await call('/api/owner/logout','POST',{});display(false);msg.textContent='최고관리자 로그아웃 완료'};
  init();
  </script></body></html>`;
  const nonce=randomHex(16);return new Response(html.replace('__NONCE__',nonce),{headers:{...textHeaders,'content-security-policy':`${textHeaders['content-security-policy']}; script-src 'nonce-${nonce}'`}});
}
async function ownerRequest(req,env,now,path) {
  if(path==='/admin' && req.method==='GET') return ownerPage();
  if(!ownerConfigOk(env)) return responseJSON({error:'Cloudflare 설정 확인 필요: '+ownerConfigIssues(env).join(' / ')},503);
  if(path==='/api/owner/login' && req.method==='POST') {
    if(!validOrigin(req)) return responseJSON({error:'잘못된 요청입니다.'},403);
    let v;try{v=await parseBody(req,1500)}catch{return responseJSON({error:'로그인 요청이 올바르지 않습니다.'},400)}
    const ipHash=await hmac(env.SESSION_SECRET,'owner:'+String(req.headers.get('cf-connecting-ip')||'unknown'));
    const window=now-900;
    const stats=await Promise.all([
      env.DB.prepare('SELECT COUNT(*) AS n FROM wos_operator_login_attempts WHERE username=? AND client_hmac_hex=? AND attempted_unix>=?').bind('owner-settings',ipHash,window).first(),
      env.DB.prepare('SELECT COUNT(*) AS n FROM wos_operator_login_attempts WHERE username=? AND attempted_unix>=?').bind('owner-settings',window).first()
    ]);
    if(Number(stats[0]?.n||0)>=5||Number(stats[1]?.n||0)>=15) return responseJSON({error:'로그인 시도 횟수 초과. 15분 후 다시 시도하세요.'},429);
    const good=typeof v?.id==='string'&&typeof v?.password==='string' &&
      constantTimeEqual(v.id,env.OWNER_LOGIN_ID) && constantTimeEqual(v.password,env.OWNER_LOGIN_SECRET);
    if(!good){await env.DB.prepare('INSERT INTO wos_operator_login_attempts(username,client_hmac_hex,attempted_unix) VALUES(?,?,?)').bind('owner-settings',ipHash,now).run();return responseJSON({error:'아이디 또는 비밀번호가 일치하지 않습니다.'},401);}
    const exp=now+OWNER_SESSION_SEC, value=`v1.${exp}.${randomHex(16)}`,sig=await ownerSigned(env,value);
    await audit(env,'OWNER_LOGIN','pin-settings');
    return responseJSON({ok:true},200,{'set-cookie':`${ownerCookieName}=${value}.${sig}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${OWNER_SESSION_SEC}`});
  }
  if(!await ownerAuthenticated(req,env,now)) return responseJSON({error:'최고관리자 로그인이 필요합니다.'},401);
  if(path==='/api/owner/me'&&req.method==='GET')return responseJSON({role:'OWNER',capabilities:['PIN_CHANGE']});
  if(path==='/api/owner/logout'&&req.method==='POST'){
    if(!validOrigin(req))return responseJSON({error:'잘못된 요청입니다.'},403);
    return responseJSON({ok:true},200,{'set-cookie':`${ownerCookieName}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`});
  }
  if(path==='/api/owner/pin'&&req.method==='POST'){
    if(!validOrigin(req)) return responseJSON({error:'잘못된 요청입니다.'},403);
    let v;try{v=await parseBody(req,1000)}catch{return responseJSON({error:'잘못된 입력입니다.'},400)}
    if(typeof v?.pin!=='string'||!PIN_RE.test(v.pin))return responseJSON({error:'숫자 네 자리로 입력해주세요.'},400);
    const hashed=await pinDigest(env,v.pin);
    await env.DB.prepare('INSERT INTO wos_operator_pin_settings(id,pin_hmac_hex,version) VALUES(1,?,1) ON CONFLICT(id) DO UPDATE SET pin_hmac_hex=excluded.pin_hmac_hex,version=version+1,updated_at=CURRENT_TIMESTAMP').bind(hashed).run();
    await audit(env,'SHARED_PIN_CHANGED','operators');
    return responseJSON({changed:true});
  }
  return responseJSON({error:'Not found'},404);
}

function validateNotice(v){
  if(!v||typeof v.title!=='string'||typeof v.body!=='string'||typeof v.language!=='string')return null;
  const title=v.title.trim(),body=v.body,language=v.language,category=v.category||'일반';
  if(!title||title.length>120||!body.trim()||body.length>4000||!['KO','EN'].includes(language)||
    typeof category!=='string'||category.length>40||!category.trim())return null;
  return {title,body,language,category:category.trim()};
}
async function main(req,env,now) {
  const url = new URL(req.url); const p=url.pathname;
  if(p==='/health' && req.method==='GET') return responseJSON({service:'4114 unified operator PIN portal',version:'6.0.0',oracleDiagnostics:true,configured:configOk(env),ownerConfigured:ownerConfigOk(env)});
  if(!env.DB) return responseJSON({error:'DB 연결이 필요합니다.'},503);
  if(p==='/' && req.method==='GET') return home();
  if(p==='/admin'||p.startsWith('/api/owner/')) return ownerRequest(req,env,now,p);
  if(!configOk(env)) return responseJSON({error:'운영진 사이트 설정이 완료되지 않았습니다.'},503);
  if(p==='/api/login' && req.method==='POST') return login(req,env,now);
  if(p==='/api/logout' && req.method==='POST') {
    if(!validOrigin(req)) return responseJSON({error:'잘못된 요청입니다.'},403);
    return responseJSON({ok:true},200,{'set-cookie':removeCookie()});
  }
  if(!await authenticated(req,env,now)) return responseJSON({error:'운영진 로그인이 필요합니다.'},401);
  if(p==='/api/me' && req.method==='GET') return responseJSON({role:'OFFICER',auth:'shared-pin'});
  if(p.startsWith('/api/oracle/')) return oracleHandler(req,env,p,{validOrigin,parseBody});
  if(p.startsWith('/api/ops/')) return operationsHandler(req,env,p,{validOrigin,parseBody,audit});
  if(p==='/api/players' && req.method==='GET') {
    const result=await env.DB.prepare("SELECT p.fid,p.nickname,p.alliance_tag,p.power_text,COALESCE(l.game_rank,'UNSET') AS game_rank,COALESCE(l.is_alt,0) AS is_alt FROM wos_players p LEFT JOIN wos_member_labels l ON l.fid=p.fid WHERE p.alliance_tag IN ('ZZN','GGZ') ORDER BY p.alliance_tag,p.nickname LIMIT 300").all();
    return responseJSON({players:result.results||[]});
  }
  if(p==='/api/notices' && req.method==='GET') {
    const result=await env.DB.prepare('SELECT id,title,body,category,language,updated_at FROM wos_notice_templates ORDER BY updated_at DESC LIMIT 100').all();
    return responseJSON({notices:result.results||[]});
  }
  if(p==='/api/notices' && req.method==='POST') {
    if(!validOrigin(req))return responseJSON({error:'잘못된 요청입니다.'},403);
    let v;try{v=await parseBody(req,10000)}catch{return responseJSON({error:'요청 형식이 올바르지 않습니다.'},400)}
    const n=validateNotice(v);if(!n)return responseJSON({error:'공지 제목·내용·언어를 확인해 주세요.'},400);
    const id=crypto.randomUUID();
    await env.DB.prepare('INSERT INTO wos_notice_templates(id,title,body,category,language,created_by,updated_by) VALUES(?,?,?,?,?,?,?)').bind(id,n.title,n.body,n.category,n.language,'shared-pin','shared-pin').run();
    await audit(env,'NOTICE_CREATE',id);
    return responseJSON({created:true,id},201);
  }
  if(p==='/api/players/import' && req.method==='POST') {
    if(!validOrigin(req))return responseJSON({error:'잘못된 요청입니다.'},403);
    let v;try{v=await parseBody(req,55000)}catch{return responseJSON({error:'명단 요청 형식을 확인해 주세요.'},400)}
    const input=v?.players;
    if(!Array.isArray(input)||input.length<1||input.length>200)return responseJSON({error:'한 번에 1~200명만 가져올 수 있습니다.'},400);
    const clean=[];const seen=new Set();
    for(const entry of input){
      const fid=typeof entry?.fid==='string'?entry.fid.trim():'';
      const nickname=typeof entry?.nickname==='string'?entry.nickname.trim():'';
      const alliance=typeof entry?.alliance_tag==='string'?entry.alliance_tag.trim().toUpperCase():'';
      if(!/^\d{6,15}$/.test(fid)||!nickname||nickname.length>80||!['ZZN','GGZ'].includes(alliance)||seen.has(fid))
        return responseJSON({error:'플레이어 ID·닉네임·연맹 또는 중복 ID를 확인해 주세요.'},400);
      seen.add(fid);clean.push({fid,nickname,alliance});
    }
    const sql="INSERT INTO wos_players(fid,nickname,alliance_tag,source) VALUES(?,?,?,'MANUAL') ON CONFLICT(fid) DO UPDATE SET nickname=excluded.nickname, alliance_tag=excluded.alliance_tag, source='MANUAL', updated_at=CURRENT_TIMESTAMP";
    // D1 batch is transactional; either all players in this import are saved or none.
    await env.DB.batch(clean.map(x=>env.DB.prepare(sql).bind(x.fid,x.nickname,x.alliance)));
    await audit(env,'MEMBER_IMPORT',String(clean.length));
    return responseJSON({saved:clean.length});
  }
  const labelMatch=p.match(/^\/api\/players\/(\d{6,15})\/labels$/);
  if(labelMatch&&req.method==='PATCH') {
    if(!validOrigin(req))return responseJSON({error:'잘못된 요청입니다.'},403);
    let v;try{v=await parseBody(req)}catch{return responseJSON({error:'요청 형식이 올바르지 않습니다.'},400)}
    const rank=v?.game_rank,alt=v?.is_alt,fid=labelMatch[1];
    if(!['UNSET','R5','R4','R3','R2','R1'].includes(rank)||typeof alt!=='boolean')
      return responseJSON({error:'직책 또는 부계정 표시를 확인해 주세요.'},400);
    const player=await env.DB.prepare('SELECT fid FROM wos_players WHERE fid=?').bind(fid).first();
    if(!player)return responseJSON({error:'먼저 연맹원을 명단에 등록하세요.'},404);
    await env.DB.prepare('INSERT INTO wos_member_labels(fid,game_rank,is_alt,updated_by) VALUES(?,?,?,?) ON CONFLICT(fid) DO UPDATE SET game_rank=excluded.game_rank,is_alt=excluded.is_alt,updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP').bind(fid,rank,alt?1:0,'shared-pin').run();
    await audit(env,'MEMBER_LABEL_UPDATE',fid);
    return responseJSON({updated:true,fid,game_rank:rank,is_alt:alt});
  }
  const noticeMatch=p.match(/^\/api\/notices\/([0-9a-f]{8}-[0-9a-f-]{27,})$/i);
  if(noticeMatch&&(req.method==='PATCH'||req.method==='DELETE')) {
    if(!validOrigin(req))return responseJSON({error:'잘못된 요청입니다.'},403);
    const id=noticeMatch[1];
    const old=await env.DB.prepare('SELECT id FROM wos_notice_templates WHERE id=?').bind(id).first();
    if(!old)return responseJSON({error:'공지 항목을 찾지 못했습니다.'},404);
    if(req.method==='DELETE'){
      await env.DB.prepare('DELETE FROM wos_notice_templates WHERE id=?').bind(id).run();
      await audit(env,'NOTICE_DELETE',id);return responseJSON({deleted:true,id});
    }
    let v;try{v=await parseBody(req,10000)}catch{return responseJSON({error:'요청 형식이 올바르지 않습니다.'},400)}
    const checked=validateNotice(v);
    if(!checked)return responseJSON({error:'공지 제목·내용·언어를 확인해 주세요.'},400);
    await env.DB.prepare('UPDATE wos_notice_templates SET title=?,body=?,category=?,language=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(checked.title,checked.body,checked.category,checked.language,'shared-pin',id).run();
    await audit(env,'NOTICE_UPDATE',id);return responseJSON({updated:true,id});
  }
  return responseJSON({error:'Not found'},404);
}
export default { async fetch(req,env) { try { return await main(req,env,Math.floor(Date.now()/1000)); } catch(e) { console.error('Operator portal error:',String(e?.message||'unexpected')); return responseJSON({error:'요청 처리 중 문제가 발생했습니다.'},500); } }, async scheduled(event,env,ctx) { ctx.waitUntil(scheduledSync(env)); } };
export const _testing={configOk,signSession,authenticated,login,constantTimeEqual,attemptInfo,pinDigest,activePinDigest,ownerConfigOk,ownerConfigIssues,ownerAuthenticated,ownerRequest};
