import {oracleHandler, scheduledSync} from './oracle-sync.mjs';
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
  const html = String.raw`<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>4114 운영진 | ZZN · GGZ</title>
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
  </style></head><body><main><header><h1>❄ 4114 WOS COMMAND CENTER</h1><p><small>ZZN · GGZ 운영진 포털</small></p><div class="links"><a href="https://wos-svs-office-zzn-2026.cozybard21.chatgpt.site/" target="_blank" rel="noopener noreferrer">SVS 관직 신청</a><a href="https://wos-svs-office-zzn-2026.cozybard21.chatgpt.site/schedule" target="_blank" rel="noopener noreferrer">관직 배정표</a></div></header>
  <p id="error" role="alert"></p><p id="message" role="status"></p>
  <section id="login" class="panel"><h2>운영진 간편 로그인</h2><p>공용 비밀번호 네 자리(숫자 4자리)만 입력하세요.</p>
  <form id="login-form"><label for="pin">운영진 공용 비밀번호</label><input id="pin" class="pin" type="password" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" autocomplete="off" required><button type="submit">입장하기</button></form>
  <p><small>최고관리자는 이 사이트의 <a href="/admin">비밀번호 설정</a>에서 공용 PIN을 변경할 수 있습니다.</small></p></section>
  <div id="app" class="hidden"><div class="row" style="justify-content:space-between"><span class="pill">운영진 로그인 중 · 8시간 유효</span><button class="secondary" id="logout">로그아웃</button></div>
  <nav class="tabs" aria-label="메뉴"><button id="tab-players" aria-selected="true" type="button">연맹원 관리</button><button id="tab-notices" aria-selected="false" type="button">공지 보관함</button><button id="tab-oracle" aria-selected="false" type="button">Oracle+ 동기화</button></nav>
  <div id="members-view">
   <section class="panel"><h2>연맹원 현황</h2><div class="grid"><div><small>ZZN</small><b id="count-zzn">0</b></div><div><small>GGZ</small><b id="count-ggz">0</b></div><div><small>총 인원</small><b id="count-all">0</b></div></div>
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
  <div id="notices-view" class="hidden"><section class="panel"><h2>공지 보관함</h2><p class="safe"><small>게임 내 채팅용 공지를 저장·수정·삭제·복사할 수 있습니다. 복사 내용은 자동으로 게임에 전송되지 않습니다.</small></p>
  <form id="notice-form"><label for="notice-title">공지 제목</label><input id="notice-title" maxlength="120" required>
  <div class="two-col"><div><label for="notice-category">분류</label><select id="notice-category"><option>일반</option><option>SVS</option><option>캐슬전</option><option>보상</option><option>연맹규칙</option><option>기타</option></select></div><div><label for="notice-lang">언어</label><select id="notice-lang"><option value="KO">한국어</option><option value="EN">English</option></select></div></div>
  <label for="notice-body">공지 내용 (최대 4,000자)</label><textarea id="notice-body" maxlength="4000" rows="6" required></textarea>
  <div class="row"><button type="submit" id="notice-save">공지 저장</button><button type="button" id="notice-cancel" class="secondary hidden">수정 취소</button></div></form></section>
  <section class="panel"><div class="row" style="justify-content:space-between"><h2>저장된 공지</h2><select id="chunk-size" style="width:auto"><option value="160">160자씩 분할</option><option value="220">220자씩 분할</option><option value="300">300자씩 분할</option></select></div><div id="notices"></div></section></div>
  <div id="oracle-view" class="hidden">
    <section class="panel"><h2>Oracle+ · ZZN / GGZ 명단 동기화</h2>
      <p class="safe"><small>이 사이트 하나에서 Oracle+를 이용합니다. API 토큰은 Cloudflare Secret으로만 보관하며 브라우저에 표시하지 않습니다. 최초에는 연맹 ID 저장 → 미리보기 → 승인 후 동기화 순서로 진행합니다.</small></p>
      <p id="oracle-status" class="muted" aria-live="polite">설정을 확인하고 있습니다.</p>
      <form id="oracle-config"><label for="oracle-zzn">ZZN Oracle+ 연맹 ID (AID)</label><input id="oracle-zzn" inputmode="numeric" pattern="[0-9]{5,20}" required placeholder="숫자 연맹 ID">
      <label for="oracle-ggz">GGZ Oracle+ 연맹 ID (AID)</label><input id="oracle-ggz" inputmode="numeric" pattern="[0-9]{5,20}" required placeholder="숫자 연맹 ID">
      <p class="muted"><small>이전 테스트 코드에는 ZZN 4114000047 / GGZ 4114000235라는 후보가 있었지만 아직 실제 API 응답으로 검증되지 않았습니다. 연맹 태그가 맞지 않으면 저장하지 않습니다.</small></p>
      <button type="submit" class="secondary">연맹 ID 저장</button></form>
      <div class="row" style="margin-top:13px"><button id="oracle-preview" type="button" class="secondary">1. 실제 명단 미리보기 (DB 변경 없음)</button><button id="oracle-sync" type="button" disabled>2. 확인 후 명단 갱신</button></div>
      <div id="oracle-preview-data" class="notice" aria-live="polite">미리보기를 실행하면 실제 연맹 태그·인원과 일부 닉네임을 확인할 수 있습니다.</div>
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
  function showTab(name){for(const n of ['players','notices','oracle']){get('tab-'+n).setAttribute('aria-selected',String(n===name));get(n==='players'?'members-view':n==='notices'?'notices-view':'oracle-view').classList.toggle('hidden',n!==name)}}
  get('tab-players').onclick=()=>showTab('players');get('tab-notices').onclick=()=>showTab('notices');
  get('tab-oracle').onclick=()=>{showTab('oracle');loadOracleStatus().catch(setError)};
  let oraclePreviewValid=false;
  async function loadOracleStatus(){const x=await api('/api/oracle/status');
    get('oracle-status').textContent='API 토큰: '+(x.tokenConfigured?'등록됨':'미등록')+' · 자동 갱신: '+(x.automaticEnabled?'켜짐':'꺼짐')+' · 최근 24시간 호출: '+x.limits.day+'/900'+
      ' · 마지막 ZZN 갱신: '+(x.alliances.ZZN.last_synced_at||'없음')+' · GGZ 갱신: '+(x.alliances.GGZ.last_synced_at||'없음');
    if(!get('oracle-zzn').value)get('oracle-zzn').value=x.alliances.ZZN.aid||'';
    if(!get('oracle-ggz').value)get('oracle-ggz').value=x.alliances.GGZ.aid||'';
  }
  get('oracle-config').onsubmit=async e=>{e.preventDefault();try{err.textContent='';const x=await api('/api/oracle/config','POST',{ZZN:get('oracle-zzn').value,GGZ:get('oracle-ggz').value});oraclePreviewValid=false;get('oracle-sync').disabled=true;msg.textContent=x.message;await loadOracleStatus()}catch(x){setError(x)}};
  get('oracle-preview').onclick=async()=>{try{err.textContent='';get('oracle-preview').disabled=true;get('oracle-preview-data').textContent='Oracle+ 응답을 조회하고 있습니다.';
    const r=await api('/api/oracle/preview','POST',{});oraclePreviewValid=true;get('oracle-sync').disabled=false;
    const host=get('oracle-preview-data');host.replaceChildren();host.append(elt('p',r.message));
    for(const a of r.alliances){host.append(elt('h3',a.tag+' · '+a.name+' · '+a.count+'명 · AID '+a.aid));
      const sample=a.examples.map(p=>p.nickname+' ('+p.fid+')').join(', ');host.append(elt('p','샘플: '+sample));}
  }catch(x){oraclePreviewValid=false;get('oracle-sync').disabled=true;get('oracle-preview-data').textContent='미리보기에 실패했습니다. 연맹 ID와 API_TOKEN을 확인하세요.';setError(x)}finally{get('oracle-preview').disabled=false}};
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
  async function fetchPlayers(){const r=await api('/api/players');players=r.players||[];renderPlayers()}
  async function fetchNotices(){const r=await api('/api/notices');notices=r.notices||[];renderNotices()}
  async function init(){try{await api('/api/me')}catch{get('login').classList.remove('hidden');get('app').classList.add('hidden');return}
    get('login').classList.add('hidden');get('app').classList.remove('hidden');const outcome=await Promise.allSettled([fetchPlayers(),fetchNotices()]);for(const x of outcome)if(x.status==='rejected')setError(x.reason)}
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
  <style>body{margin:0;padding:25px;background:#eaf3ff;font:16px/1.6 system-ui,-apple-system,'Malgun Gothic',sans-serif;color:#173451}main{max-width:550px;margin:35px auto;background:white;border:1px solid #d5e3ef;border-radius:16px;padding:28px}h1{font-size:24px}input,button{box-sizing:border-box;width:100%;padding:12px;font:inherit;border-radius:9px;margin:5px 0 12px;border:1px solid #a5bed0}button{background:#14659d;border:0;color:white;cursor:pointer}small{color:#5b7186}.hidden{display:none!important}#err{color:#b12a32}#msg{color:#08775d}a{color:#14659d}</style></head><body><main><h1>4114 WOS COMMAND CENTER</h1><h2>최고관리자 · 공용 비밀번호 설정</h2><p><small>현재 운영진 사이트와 같은 주소에서 PIN만 변경합니다. 연맹원·보상 관리 권한과는 무관합니다.</small></p><p id="err" role="alert"></p><p id="msg" role="status"></p>
  <section id="owner-login"><form id="owner-login-form"><label for="owner-id">최고관리자 ID</label><input id="owner-id" autocomplete="username" required><label for="owner-secret">최고관리자 비밀번호</label><input id="owner-secret" type="password" autocomplete="current-password" required><button>최고관리자 로그인</button></form></section>
  <section id="owner-setup" class="hidden"><p>새 운영진 공용 비밀번호를 입력하세요. 변경 즉시 기존 운영진 로그인 세션은 만료됩니다.</p><form id="pin-form"><label for="new-pin">새 공용 비밀번호 (숫자 4자리)</label><input id="new-pin" type="password" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" autocomplete="new-password" required><label for="again">비밀번호 확인</label><input id="again" type="password" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" autocomplete="new-password" required><button>공용 비밀번호 변경</button></form><button id="owner-logout" type="button">최고관리자 로그아웃</button></section><p><a href="/">운영진 로그인으로 돌아가기</a></p></main><script nonce="__NONCE__">
  const by=id=>document.getElementById(id),err=by('err'),msg=by('msg');
  async function call(path,method='GET',v){const init={method,headers:{}};if(v!==undefined){init.headers['content-type']='application/json';init.body=JSON.stringify(v)}const r=await fetch(path,init);if(!(r.headers.get('content-type')||'').includes('application/json'))throw Error('서버 응답 오류: HTTP '+r.status);const data=await r.json();if(!r.ok)throw Error(data.error||'요청 실패');return data;}
  function display(ok){by('owner-login').classList.toggle('hidden',ok);by('owner-setup').classList.toggle('hidden',!ok)}
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
  if(p==='/health' && req.method==='GET') return responseJSON({service:'4114 unified operator PIN portal',configured:configOk(env),ownerConfigured:ownerConfigOk(env)});
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
  if(p==='/api/players' && req.method==='GET') {
    const result=await env.DB.prepare("SELECT p.fid,p.nickname,p.alliance_tag,COALESCE(l.game_rank,'UNSET') AS game_rank,COALESCE(l.is_alt,0) AS is_alt FROM wos_players p LEFT JOIN wos_member_labels l ON l.fid=p.fid WHERE p.alliance_tag IN ('ZZN','GGZ') ORDER BY p.alliance_tag,p.nickname LIMIT 300").all();
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
