// 4114 operator-only PIN portal. Deploy as a SEPARATE Worker.
// The existing wos-4114-staging owner Worker MUST remain under Cloudflare Access.
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
async function parseBody(req) {
  const length=Number(req.headers.get('content-length')||'0');
  if(length>1024) throw Error('Too large');
  const body=await req.text();
  if(body.length>1024) throw Error('Too large');
  return JSON.parse(body);
}
async function signSession(env, exp, nonce) {
  // Binding the session signature to the current PIN invalidates sessions after PIN rotation.
  const value = `v1.${exp}.${nonce}`;
  const sig = await hmac(env.SESSION_SECRET,`wos4114|${value}|${env.OPERATOR_PIN}`);
  return `${value}.${sig}`;
}
async function authenticated(req,env,now) {
  const raw=readCookie(req.headers.get('cookie'));
  const match=/^v1\.(\d{10})\.([a-f0-9]{32})\.([a-f0-9]{64})$/.exec(raw);
  if(!match) return false;
  const exp=Number(match[1]);
  if(exp<=now || exp>now+MAX_SESSION_SEC) return false;
  const sig = await hmac(env.SESSION_SECRET,`wos4114|v1.${match[1]}.${match[2]}|${env.OPERATOR_PIN}`);
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
  if(typeof pin!=='string'||!PIN_RE.test(pin)||!constantTimeEqual(pin,env.OPERATOR_PIN)) {
    try{await recordFailure(env,clientHash,now)}catch{return responseJSON({error:'로그인을 처리할 수 없습니다.'},503)}
    return responseJSON({error:'비밀번호가 올바르지 않습니다.'},401);
  }
  const exp=now+MAX_SESSION_SEC;
  const token=await signSession(env,exp,randomHex(16));
  await audit(env,'PIN_LOGIN','operators');
  return responseJSON({ok:true},200,{'set-cookie':sessionCookie(token)});
}
function home(){
  const html=`<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>4114 운영진</title><style>
  :root{color-scheme:light}body{font:16px system-ui,-apple-system,sans-serif;background:linear-gradient(140deg,#e9f4ff,#f8fbff);color:#1c344e;padding:18px;margin:0}main{max-width:850px;margin:28px auto;background:white;padding:24px;border:1px solid #d6e5f2;border-radius:17px;box-shadow:0 10px 30px #173f6410}h1{font-size:25px;margin-bottom:4px}h2{font-size:19px}p{line-height:1.55}small{color:#55728c}.hidden{display:none}input,button,textarea,select{font:inherit;border-radius:9px;padding:11px;box-sizing:border-box}input,textarea,select{border:1px solid #b8cada;width:100%;background:white}button{background:#15649d;color:white;border:none;cursor:pointer}button.outline{background:#f5faff;color:#235579;border:1px solid #c8d9ea}form{display:grid;gap:10px}section{border-top:1px solid #e1ebf5;padding-top:16px;margin-top:18px}#error{color:#b11a32}#message{color:#177344}.pin{letter-spacing:12px;font-size:27px;max-width:220px;text-align:center}.notice{padding:11px;background:#f4f9ff;border:1px solid #e1edf6;border-radius:10px;margin:10px 0}.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:8px;border-bottom:1px solid #dce7f2} .scroll{max-width:100%;overflow:auto}
  </style></head><body><main><h1>❄ 4114 WOS COMMAND CENTER</h1><p><small>ZZN · GGZ 운영진 전용</small></p><p id="error" role="alert"></p><p id="message" role="status"></p>
  <section id="login"><h2>운영진 간편 로그인</h2><p>공용 비밀번호 네 자리만 입력하세요. 아이디는 필요하지 않습니다.</p><form id="login-form"><label for="pin">운영진 공용 비밀번호</label><input id="pin" class="pin" type="password" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" autocomplete="off" required><button type="submit">입장하기</button></form><p><small>이 비밀번호로 최고관리자 설정에는 접근할 수 없습니다.</small></p></section>
  <section id="app" class="hidden"><div class="row"><strong>운영진 화면</strong><button id="logout" class="outline">로그아웃</button></div><p><small>공용 비밀번호로 입장했습니다. 8시간 이후 다시 로그인해야 합니다.</small></p><section><h2>연맹원 명단</h2><div id="players" class="scroll"></div></section><section><h2>공지 보관함</h2><form id="notice-form"><label for="title">제목</label><input id="title" maxlength="120" required><label for="body">내용</label><textarea id="body" rows="4" maxlength="4000" required></textarea><label for="lang">언어</label><select id="lang"><option value="KO">한국어</option><option value="EN">English</option></select><button type="submit">공지 저장</button></form><div id="notices"></div></section></section></main>
  <script nonce="__NONCE__">
  const get=id=>document.getElementById(id),error=get('error'),message=get('message');
  async function api(url,method='GET',data){const opts={method,headers:{}};if(data!==undefined){opts.headers['content-type']='application/json';opts.body=JSON.stringify(data)}const r=await fetch(url,opts);if(!(r.headers.get('content-type')||'').includes('application/json'))throw Error('서버 응답 오류 ('+r.status+')');const v=await r.json();if(!r.ok)throw Error(v.error||'요청 실패');return v}
  function el(name,content){const x=document.createElement(name);x.textContent=String(content??'');return x}
  async function refresh(){error.textContent='';try{await api('/api/me');get('login').classList.add('hidden');get('app').classList.remove('hidden');const [p,n]=await Promise.all([api('/api/players'),api('/api/notices')]);get('players').replaceChildren();if(!p.players.length)get('players').append(el('p','연맹원 데이터 연결 전입니다.'));else{const table=el('table',''),row=el('tr','');for(const h of ['연맹','닉네임','ID','직책','부계정'])row.append(el('th',h));table.append(row);for(const player of p.players){const tr=el('tr','');for(const v of [player.alliance_tag,player.nickname,player.fid,player.game_rank||'-',player.is_alt?'✓':'-'])tr.append(el('td',v));table.append(tr)}get('players').append(table)}get('notices').replaceChildren();for(const notice of n.notices){const box=el('div','');box.className='notice';box.append(el('strong',notice.title+' ('+notice.language+')'),el('p',notice.body));const copy=el('button','복사');copy.type='button';copy.onclick=async()=>{try{await navigator.clipboard.writeText(notice.body);message.textContent='공지 복사 완료'}catch{error.textContent='복사 실패'}};box.append(copy);get('notices').append(box)}}catch(e){get('login').classList.remove('hidden');get('app').classList.add('hidden');}}
  get('login-form').onsubmit=async e=>{e.preventDefault();error.textContent='';try{await api('/api/login','POST',{pin:get('pin').value});get('pin').value='';await refresh()}catch(e){error.textContent=e.message}};
  get('notice-form').onsubmit=async e=>{e.preventDefault();error.textContent='';try{await api('/api/notices','POST',{title:get('title').value,body:get('body').value,language:get('lang').value});e.target.reset();message.textContent='공지를 저장했습니다.';await refresh()}catch(e){error.textContent=e.message}};
  get('logout').onclick=async()=>{await api('/api/logout','POST',{});location.reload()};refresh();
  </script></body></html>`;
  const nonce = randomHex(16);
  return new Response(html.replace('__NONCE__',nonce),{headers:{...textHeaders,'content-security-policy':`${textHeaders['content-security-policy']}; script-src 'nonce-${nonce}'`}});
}
async function main(req,env,now) {
  const url = new URL(req.url); const p=url.pathname;
  if(p==='/health' && req.method==='GET') return responseJSON({service:'4114 operator PIN portal',configured:configOk(env)});
  if(!env.DB) return responseJSON({error:'DB 연결이 필요합니다.'},503);
  if(p==='/' && req.method==='GET') return home();
  if(!configOk(env)) return responseJSON({error:'운영진 사이트 설정이 완료되지 않았습니다.'},503);
  if(p==='/api/login' && req.method==='POST') return login(req,env,now);
  if(p==='/api/logout' && req.method==='POST') {
    if(!validOrigin(req)) return responseJSON({error:'잘못된 요청입니다.'},403);
    return responseJSON({ok:true},200,{'set-cookie':removeCookie()});
  }
  if(!await authenticated(req,env,now)) return responseJSON({error:'운영진 로그인이 필요합니다.'},401);
  if(p==='/api/me' && req.method==='GET') return responseJSON({role:'OFFICER',auth:'shared-pin'});
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
    let v;try{v=await parseBody(req)}catch{return responseJSON({error:'요청 형식이 올바르지 않습니다.'},400)}
    if(typeof v.title!=='string'||!v.title.trim()||v.title.length>120||typeof v.body!=='string'||!v.body.trim()||v.body.length>4000||!['KO','EN'].includes(v.language))return responseJSON({error:'공지 입력을 확인해 주세요.'},400);
    const id=crypto.randomUUID();
    await env.DB.prepare('INSERT INTO wos_notice_templates(id,title,body,category,language,created_by,updated_by) VALUES(?,?,?,?,?,?,?)').bind(id,v.title.trim(),v.body,'일반',v.language,'shared-pin','shared-pin').run();
    await audit(env,'NOTICE_CREATE',id);
    return responseJSON({created:true,id},201);
  }
  return responseJSON({error:'Not found'},404);
}
export default { async fetch(req,env) { try { return await main(req,env,Math.floor(Date.now()/1000)); } catch(e) { console.error('Operator portal error:',String(e?.message||'unexpected')); return responseJSON({error:'요청 처리 중 문제가 발생했습니다.'},500); } } };
export const _testing={configOk,signSession,authenticated,login,constantTimeEqual,attemptInfo};
