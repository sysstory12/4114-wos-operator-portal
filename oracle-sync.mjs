// WoS Oracle+ integration for ONE operator Worker. Bearer token is server-side only.
// This module never deletes players or modifies wos_member_labels.
const API = 'https://wosoracle.com/api/v1';
const TAGS = ['ZZN', 'GGZ'];
const AID_RE = /^\d{5,20}$/;
const FID_RE = /^\d{6,15}$/;
const REMOTE_TIMEOUT_MS = 12000;
const MAX_BYTES = 1500000;
const MAX_MEMBERS = 200;
const CANDIDATES = Object.freeze({ZZN:'4114000047', GGZ:'4114000235'}); // UNVERIFIED hints; never sync until live tag match.
function j(data,status=200){return new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer','x-robots-tag':'noindex,nofollow'}})}
const obj=x=>x && typeof x==='object' && !Array.isArray(x);
const cleanString=(v,n=80)=>String(v??'').trim().slice(0,n);
function tokenOk(env){return typeof env.API_TOKEN==='string' && env.API_TOKEN.trim().length>=12;}
const asInt=x=>Number.isFinite(Number(x))?Math.max(0,Math.trunc(Number(x))):0;
async function getSettings(env){
 const rows=await env.DB.prepare('SELECT alliance_tag, aid, is_enabled, last_synced_at FROM wos_oracle_alliance_config ORDER BY alliance_tag').all();
 const out={};for(const x of rows.results||[])out[x.alliance_tag]={aid:String(x.aid),is_enabled:!!x.is_enabled,last_synced_at:x.last_synced_at};
 return out;
}
async function budgetCounts(db,now){
 const row=await db.prepare('SELECT SUM(CASE WHEN requested_unix>=? THEN 1 ELSE 0 END) AS second_count, SUM(CASE WHEN requested_unix>=? THEN 1 ELSE 0 END) AS minute_count, SUM(CASE WHEN requested_unix>=? THEN 1 ELSE 0 END) AS day_count FROM wos_oracle_request_log WHERE requested_unix>=?')
 .bind(now-1,now-59,now-86399,now-86399).first();
 return {second:asInt(row?.second_count),minute:asInt(row?.minute_count),day:asInt(row?.day_count)};
}
async function reserveBudget(db,tag,now){
 // This single D1 INSERT ... SELECT acts as an atomic cap across isolates of this Worker.
 // Counts are separate from any other app that might share the same Oracle+ token.
 const sql=`INSERT INTO wos_oracle_request_log(id,requested_unix,alliance_tag)
 SELECT ?,?,? WHERE
 (SELECT COUNT(*) FROM wos_oracle_request_log WHERE requested_unix >= ?) < 4
 AND (SELECT COUNT(*) FROM wos_oracle_request_log WHERE requested_unix >= ?) < 40
 AND (SELECT COUNT(*) FROM wos_oracle_request_log WHERE requested_unix >= ?) < 900`;
 const id=crypto.randomUUID();
 const r=await db.prepare(sql).bind(id,now,tag,now-1,now-59,now-86399).run();
 if(Number(r?.meta?.changes||0)!==1){const err=new Error('Oracle+ 내부 API 요청 제한(초당 4회, 분당 40회, 24시간 900회)에 도달했습니다.');err.status=429;throw err;}
 return id;
}
function errorWithStatus(message,status=502){const e=new Error(message);e.status=status;return e;}
async function getRemoteAlliance(env,tag,aid,fetchImpl=fetch){
 if(!tokenOk(env))throw errorWithStatus('Cloudflare의 API_TOKEN Secret이 등록되지 않았습니다.',503);
 const now=Math.floor(Date.now()/1000);
 const logId=await reserveBudget(env.DB,tag,now);
 let statusCode=0;
 try{
  const res=await fetchImpl(`${API}/alliances/${encodeURIComponent(aid)}?kid=4114`,{
   method:'GET',headers:{authorization:`Bearer ${env.API_TOKEN}`,'accept':'application/json'},
   signal:AbortSignal.timeout(REMOTE_TIMEOUT_MS),redirect:'error',cf:{cacheTtl:0,cacheEverything:false}
  });
  statusCode=res.status;
  await env.DB.prepare('UPDATE wos_oracle_request_log SET http_status=? WHERE id=?').bind(statusCode,logId).run();
  if(!res.ok){
   if(statusCode===401||statusCode===403)throw errorWithStatus('Oracle+ 토큰 인증이 거부되었습니다.',502);
   if(statusCode===402)throw errorWithStatus('Oracle+ 구독 또는 이용 한도를 확인해 주세요.',502);
   if(statusCode===404)throw errorWithStatus(`${tag}의 연맹 ID를 Oracle+에서 찾지 못했습니다.`,422);
   if(statusCode===429)throw errorWithStatus('Oracle+ 측 요청 제한입니다. 잠시 후 다시 시도해 주세요.',429);
   throw errorWithStatus(`Oracle+ 조회에 실패했습니다 (HTTP ${statusCode}).`);
  }
  if(!(res.headers.get('content-type')||'').toLowerCase().includes('json'))throw errorWithStatus('Oracle+ 응답이 JSON이 아닙니다.');
  if(Number(res.headers.get('content-length')||'0')>MAX_BYTES)throw errorWithStatus('Oracle+ 응답 용량이 너무 큽니다.');
  const raw=await res.text();if(raw.length>MAX_BYTES)throw errorWithStatus('Oracle+ 응답 용량이 너무 큽니다.');
  let payload;try{payload=JSON.parse(raw)}catch{throw errorWithStatus('Oracle+ JSON 응답을 읽을 수 없습니다.');}
  return normalizeAlliance(payload,tag,aid);
 }catch(e){
  if(e?.status)throw e;
  throw errorWithStatus('Oracle+ 네트워크 연결 또는 시간 초과 오류입니다.');
 }
}
function normalizeAlliance(payload,tag,aid){
 // v1 reference: {id, abbr, name, member_count, members:[{id,name,power,...}]}.
 // Permit common data / alliance envelopes, but reject unverified or incomplete rosters.
 const roots=[payload, obj(payload)&&payload.data, obj(payload)&&payload.alliance, obj(payload?.data)&&payload.data.alliance].filter(obj);
 const root=roots.find(x=>Array.isArray(x.members));
 if(!root)throw errorWithStatus(`${tag}: Oracle+ 응답에 members[] 명단이 없습니다. 데이터를 변경하지 않았습니다.`,422);
 const abbr=cleanString(root.abbr??root.tag??root.alliance_tag,12).toUpperCase();
 if(abbr!==tag)throw errorWithStatus(`${tag}: API 응답의 연맹 태그(${abbr||'없음'})가 일치하지 않습니다. 저장하지 않았습니다.`,422);
 if(root.id!==undefined&&String(root.id)!==String(aid))throw errorWithStatus(`${tag}: API 응답의 연맹 ID가 설정과 다릅니다.`,422);
 const source=root.members;
 if(source.length<1||source.length>MAX_MEMBERS)throw errorWithStatus(`${tag}: 명단이 비어 있거나 ${MAX_MEMBERS}명을 초과하여 동기화를 중단했습니다.`,422);
 const total=root.member_count??root.memberCount;
 if(total!==undefined && Number.isFinite(Number(total)) && Number(total)>source.length){
  throw errorWithStatus(`${tag}: 회원 수(${total})보다 실제 응답 명단(${source.length}명)이 적습니다. 일부 누락을 방지하기 위해 중단했습니다.`,422);
 }
 const members=[],seen=new Set();
 for(const x of source){
  const fid=cleanString(x?.id??x?.fid??x?.player_id,30);
  const nickname=cleanString(x?.name??x?.nickname,100);
  if(!FID_RE.test(fid)||!nickname||nickname.length>80||seen.has(fid))
   throw errorWithStatus(`${tag}: 플레이어 데이터가 불완전하거나 ID가 중복되어 저장하지 않았습니다.`,422);
  const power=x.power===null||x.power===undefined?null:cleanString(x.power,50);
  seen.add(fid);members.push({fid,nickname,alliance_tag:tag,power_text:power});
 }
 return {tag,aid:String(aid),name:cleanString(root.name,100),member_count:members.length,members};
}
async function fetchBoth(env,fetchImpl=fetch){
 const conf=await getSettings(env);for(const tag of TAGS)if(!conf[tag]?.aid)throw errorWithStatus('ZZN 및 GGZ 연맹 ID를 먼저 저장해 주세요.',422);
 const z=await getRemoteAlliance(env,'ZZN',conf.ZZN.aid,fetchImpl);
 const g=await getRemoteAlliance(env,'GGZ',conf.GGZ.aid,fetchImpl);
 const seen=new Set();for(const x of [...z.members,...g.members]){if(seen.has(x.fid))throw errorWithStatus('두 연맹의 명단에 중복 플레이어 ID가 있어 갱신을 중단했습니다.',422);seen.add(x.fid)}
 return [z,g];
}
async function applySync(env,alliances,mode='manual'){
 const sql=`INSERT INTO wos_players(fid,nickname,alliance_tag,power_text,source) VALUES(?,?,?,?,'ORACLE')
 ON CONFLICT(fid) DO UPDATE SET nickname=excluded.nickname,alliance_tag=excluded.alliance_tag,
 power_text=excluded.power_text,source='ORACLE',updated_at=CURRENT_TIMESTAMP`;
 const statements=[];
 for(const alliance of alliances)for(const m of alliance.members)statements.push(env.DB.prepare(sql).bind(m.fid,m.nickname,m.alliance_tag,m.power_text));
 for(const a of alliances){
  statements.push(env.DB.prepare('UPDATE wos_oracle_alliance_config SET last_synced_at=CURRENT_TIMESTAMP WHERE alliance_tag=?').bind(a.tag));
  statements.push(env.DB.prepare('INSERT INTO wos_oracle_sync_log(id,alliance_tag,member_count,sync_mode) VALUES(?,?,?,?)').bind(crypto.randomUUID(),a.tag,a.member_count,mode));
 }
 // Transactional D1 batch: all upserts, timestamps and logs succeed or roll back.
 await env.DB.batch(statements);
 return Object.fromEntries(alliances.map(a=>[a.tag,a.member_count]));
}
async function getStatus(env){
 const conf=await getSettings(env),limits=await budgetCounts(env.DB,Math.floor(Date.now()/1000));
 return {tokenConfigured:tokenOk(env),alliances:Object.fromEntries(TAGS.map(tag=>[tag,conf[tag]||{aid:'',is_enabled:false,last_synced_at:null}])),limits,limitCaps:{second:4,minute:40,day:900},automaticEnabled:TAGS.every(tag=>conf[tag]?.is_enabled)};
}
async function handler(req,env,p,{validOrigin,parseBody,fetchImpl=fetch}){
 try{
  if(p==='/api/oracle/status'&&req.method==='GET')return j(await getStatus(env));
  if(req.method!=='POST')return j({error:'찾을 수 없는 기능입니다.'},404);
  if(!validOrigin(req))return j({error:'요청 출처가 올바르지 않습니다.'},403);
  const v=await parseBody(req,2500).catch(()=>null);
  if(!v||typeof v!=='object')return j({error:'요청 형식을 확인하세요.'},400);
  if(p==='/api/oracle/config'){
   const z=String(v.ZZN??'').trim(),g=String(v.GGZ??'').trim();
   if(!AID_RE.test(z)||!AID_RE.test(g)||z===g)return j({error:'ZZN·GGZ의 서로 다른 숫자 연맹 ID를 입력해 주세요.'},400);
   await env.DB.batch(TAGS.map(tag=>env.DB.prepare(`INSERT INTO wos_oracle_alliance_config(alliance_tag,aid,is_enabled) VALUES(?,?,0)
    ON CONFLICT(alliance_tag) DO UPDATE SET aid=excluded.aid,is_enabled=CASE WHEN aid=excluded.aid THEN is_enabled ELSE 0 END,last_synced_at=CASE WHEN aid=excluded.aid THEN last_synced_at ELSE NULL END`)
    .bind(tag,tag==='ZZN'?z:g)));
   return j({saved:true,message:'연맹 ID를 저장했습니다. 미리보기에서 실제 연맹 태그를 확인하세요.'});
  }
  if(p==='/api/oracle/preview'){
   const records=await fetchBoth(env,fetchImpl);
   return j({preview:true,readOnly:true,alliances:records.map(a=>({tag:a.tag,aid:a.aid,name:a.name,count:a.member_count,examples:a.members.slice(0,8)})),message:'실제 응답의 연맹 태그와 명단을 검증했습니다. 아직 D1 명단은 변경하지 않았습니다.'});
  }
  if(p==='/api/oracle/sync'){
   if(v.confirm!==true)return j({error:'명단 갱신 확인이 필요합니다.'},400);
   const records=await fetchBoth(env,fetchImpl);
   const counts=await applySync(env,records,'manual');
   return j({synced:true,counts,message:'두 연맹 명단이 갱신되었습니다. 기존 R4·부계정 표시는 그대로 유지됩니다.'});
  }
  if(p==='/api/oracle/automatic'){
   if(typeof v.enabled!=='boolean')return j({error:'자동 갱신 설정이 올바르지 않습니다.'},400);
   const conf=await getSettings(env);
   if(v.enabled && (!tokenOk(env)||TAGS.some(t=>!conf[t]?.last_synced_at)))return j({error:'API 연결과 최초 명단 동기화를 완료한 뒤 자동 갱신을 켤 수 있습니다.'},422);
   await env.DB.batch(TAGS.map(t=>env.DB.prepare('UPDATE wos_oracle_alliance_config SET is_enabled=? WHERE alliance_tag=?').bind(v.enabled?1:0,t)));
   return j({automaticEnabled:v.enabled,message:v.enabled?'UTC 기준 6시간마다 자동 갱신됩니다.':'자동 갱신을 중단했습니다.'});
  }
  return j({error:'찾을 수 없는 기능입니다.'},404);
 }catch(e){
  if(!e.status)console.error('Oracle integration error (no token):',String(e?.message||'Unexpected'));
  return j({error:e.status?e.message:'Oracle+ 데이터베이스 또는 서버 설정을 확인해 주세요.'},e.status||503);
 }
}
async function scheduledSync(env,fetchImpl=fetch){
 // Cron runs every 6 hours, but does nothing until the operator explicitly enables auto-sync.
 try{
  if(!env?.DB||!tokenOk(env))return {skipped:true,reason:'config'};
  const conf=await getSettings(env);
  if(!TAGS.every(t=>conf[t]?.is_enabled&&conf[t]?.last_synced_at))return {skipped:true,reason:'disabled'};
  const data=await fetchBoth(env,fetchImpl);
  return {synced:true,counts:await applySync(env,data,'scheduled')};
 }catch(e){
  console.error('Oracle scheduled sync failed:',e?.status||'DB_ERROR');
  return {synced:false,error:'Oracle+ 갱신 오류. 기존 명단을 유지했습니다.'};
 }
}
export {handler as oracleHandler, scheduledSync, normalizeAlliance, getStatus, applySync, fetchBoth, CANDIDATES};
