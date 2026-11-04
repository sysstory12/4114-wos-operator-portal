// Oracle+ public API v1: state 4114, ZZN/GGZ. Server-only Bearer token.
// Incomplete member identities are common in the documented API. Preview must not treat
// empty members[].id as an API failure; sync only known IDs, never delete or reset labels.
const API='https://wosoracle.com/api/v1';
const TAGS=['ZZN','GGZ'];
const AID_RE=/^\d{5,20}$/;
const FID_RE=/^\d{6,15}$/;
const TIMEOUT_MS=15000;
const MAX_BYTES=1500000;
const MAX_MEMBERS=200;
const CANDIDATES=Object.freeze({ZZN:'4114000047',GGZ:'4114000235'});
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const trim=(x,n=100)=>String(x??'').trim().slice(0,n);
const asInt=x=>Number.isFinite(Number(x))?Math.max(0,Math.trunc(Number(x))):0;
function j(data,status=200){return new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer','x-robots-tag':'noindex,nofollow'}})}
function fault(msg,status=502,code='UPSTREAM_ERROR',extra={}){const e=new Error(msg);e.status=status;e.code=code;e.details=extra;return e;}
function tokenOk(env){return typeof env?.API_TOKEN==='string'&&env.API_TOKEN.trim().length>0;}
async function getSettings(env){
 const r=await env.DB.prepare('SELECT alliance_tag, aid, is_enabled, last_synced_at FROM wos_oracle_alliance_config ORDER BY alliance_tag').all();
 const result={};for(const x of r.results||[])result[x.alliance_tag]={aid:String(x.aid),is_enabled:!!x.is_enabled,last_synced_at:x.last_synced_at};
 return result;
}
async function budgetCounts(db,now){
 const r=await db.prepare('SELECT SUM(CASE WHEN requested_unix>=? THEN 1 ELSE 0 END) AS second_count, SUM(CASE WHEN requested_unix>=? THEN 1 ELSE 0 END) AS minute_count, SUM(CASE WHEN requested_unix>=? THEN 1 ELSE 0 END) AS day_count FROM wos_oracle_request_log WHERE requested_unix>=?')
  .bind(now-1,now-59,now-86399,now-86399).first();
 return {second:asInt(r?.second_count),minute:asInt(r?.minute_count),day:asInt(r?.day_count)};
}
async function reserveBudget(db,tag,now){
 // Guard usage across concurrent Worker isolates, with margin below Plus limits.
 const sql=`INSERT INTO wos_oracle_request_log(id,requested_unix,alliance_tag)
 SELECT ?,?,? WHERE
 (SELECT COUNT(*) FROM wos_oracle_request_log WHERE requested_unix >= ?) < 4
 AND (SELECT COUNT(*) FROM wos_oracle_request_log WHERE requested_unix >= ?) < 40
 AND (SELECT COUNT(*) FROM wos_oracle_request_log WHERE requested_unix >= ?) < 900`;
 const id=crypto.randomUUID();const r=await db.prepare(sql).bind(id,now,tag,now-1,now-59,now-86399).run();
 if(Number(r?.meta?.changes||0)!==1)throw fault('Oracle+ 안전 요청 한도에 도달했습니다. 최근 호출 횟수를 확인해 주세요.',429,'LOCAL_RATE_LIMIT');
 return id;
}
async function requestOracle(env,tag,path,fetchImpl=fetch){
 if(!tokenOk(env))throw fault('Cloudflare API_TOKEN Secret이 없습니다. 운영진 Worker에 등록해 주세요.',503,'TOKEN_MISSING');
 const id=await reserveBudget(env.DB,tag,Math.floor(Date.now()/1000));
 let res;
 try{
  res=await fetchImpl(API+path,{method:'GET',headers:{authorization:`Bearer ${env.API_TOKEN.trim()}`,accept:'application/json'},signal:AbortSignal.timeout(TIMEOUT_MS),redirect:'error',cf:{cacheTtl:0,cacheEverything:false}});
 }catch(e){throw fault('Oracle+ 서버 연결에 실패했습니다. 네트워크 또는 응답 시간 초과를 확인해 주세요.',502,'NETWORK_TIMEOUT');}
 try{await env.DB.prepare('UPDATE wos_oracle_request_log SET http_status=? WHERE id=?').bind(res.status,id).run();}catch{ /* logging must not hide upstream result */ }
 if(!res.ok){
  if(res.status===401)throw fault('Oracle+가 API_TOKEN을 거부했습니다(401). 발급된 실제 토큰인지 확인해 주세요.',502,'TOKEN_REJECTED',{upstreamStatus:401});
  if(res.status===403)throw fault('Oracle+에서 조회를 거부했습니다(403). 토큰 권한 또는 접근 정책을 확인해 주세요.',502,'API_FORBIDDEN',{upstreamStatus:403});
  if(res.status===402)throw fault('이 API는 현재 Oracle+ 요금제에서 허용되지 않습니다(402).',502,'PLAN_REQUIRED',{upstreamStatus:402});
  if(res.status===404)throw fault('Oracle+에 해당 왕국 또는 연맹 ID가 없습니다(404). 다른 AID를 확인해 주세요.',422,'NOT_FOUND',{upstreamStatus:404});
  if(res.status===429){const retry=Number(res.headers.get('retry-after'));throw fault('Oracle+ 요청 한도 초과(429). 잠시 후 다시 조회해 주세요.',429,'REMOTE_RATE_LIMIT',Number.isFinite(retry)&&retry>0?{retryAfterSeconds:Math.min(retry,3600)}:{});}
  throw fault('Oracle+ 응답 오류 (HTTP '+res.status+').',502,'REMOTE_HTTP_ERROR',{upstreamStatus:res.status});
 }
 if(!(res.headers.get('content-type')||'').toLowerCase().includes('json'))throw fault('Oracle+가 JSON이 아닌 응답을 반환했습니다.',502,'NON_JSON');
 if(Number(res.headers.get('content-length')||0)>MAX_BYTES)throw fault('Oracle+ 응답이 너무 큽니다.',502,'RESPONSE_TOO_LARGE');
 const raw=await res.text();if(raw.length>MAX_BYTES)throw fault('Oracle+ 응답이 너무 큽니다.',502,'RESPONSE_TOO_LARGE');
 try{return JSON.parse(raw)}catch{throw fault('Oracle+ JSON 응답을 해석하지 못했습니다.',502,'INVALID_JSON')}
}
function normalizeAlliance(payload,tag,aid){
 const roots=[payload,obj(payload)&&payload.data,obj(payload)&&payload.alliance,obj(payload?.data)&&payload.data.alliance].filter(obj);
 const root=roots.find(x=>Array.isArray(x.members));
 if(!root)throw fault(tag+': 응답에 members[] 명단이 없습니다.',422,'ROSTER_MISSING');
 const abbr=trim(root.abbr??root.tag??root.alliance_tag,12).toUpperCase();
 if(abbr!==tag)throw fault(tag+': Oracle+ 응답의 태그 '+(abbr||'없음')+'가 일치하지 않습니다.',422,'TAG_MISMATCH');
 if(root.id!==undefined&&String(root.id)!==String(aid))throw fault(tag+': 연맹 ID가 설정과 다릅니다.',422,'AID_MISMATCH');
 if(root.state!==undefined&&Number(root.state)!==4114)throw fault(tag+': 조회된 왕국이 4114가 아닙니다.',422,'STATE_MISMATCH');
 const source=root.members;
 if(!source.length||source.length>MAX_MEMBERS)throw fault(tag+': 명단이 없거나 '+MAX_MEMBERS+'명을 초과합니다.',422,'ROSTER_SIZE');
 const reported=root.member_count??root.memberCount;
 const reportedCount=reported==null?null:asInt(reported);
 const complete=reportedCount===null||reportedCount<=source.length;
 const members=[],unlinked=[],seen=new Set();let invalid=0;
 for(const x of source){
  const fid=trim(x?.id??x?.fid??x?.player_id,30), nickname=trim(x?.name??x?.nickname,100);
  if(!FID_RE.test(fid)||!nickname||nickname.length>80){
   // Empty IDs are expressly supported by Oracle+ v1 and are not evidence of a member leaving.
   unlinked.push({name:nickname||'이름 미확인',reason:!fid?'플레이어 ID 미연결':'ID 또는 이름 확인 필요'});invalid++;continue;
  }
  if(seen.has(fid))throw fault(tag+': 명단 내 플레이어 ID가 중복됩니다.',422,'DUPLICATE_FID');
  seen.add(fid);members.push({fid,nickname,alliance_tag:tag,power_text:x.power===null||x.power===undefined?null:trim(x.power,50)});
 }
 const warnings=[];
 if(!complete)warnings.push('전체 인원 '+reportedCount+'명 중 '+source.length+'명만 응답되었습니다. 미리보기만 가능합니다.');
 if(unlinked.length)warnings.push('플레이어 ID가 미연결/불완전한 '+unlinked.length+'명은 저장하지 않고 기존 기록을 유지합니다.');
 if(!members.length)warnings.push('저장 가능한 플레이어 ID가 없어 동기화를 차단합니다.');
 return {tag,aid:String(aid),name:trim(root.name),reported_count:reportedCount,roster_count:source.length,member_count:members.length,unlinked_count:unlinked.length,unlinked:unlinked.slice(0,12),warnings,canSync:complete&&members.length>0,members,updated_at:trim(root.updated_at,50)};
}
async function getRemoteAlliance(env,tag,aid,fetchImpl=fetch){
 return normalizeAlliance(await requestOracle(env,tag,`/alliances/${encodeURIComponent(aid)}?kid=4114`,fetchImpl),tag,aid);
}
async function fetchBoth(env,fetchImpl=fetch){
 const conf=await getSettings(env);
 for(const tag of TAGS)if(!conf[tag]?.aid)throw fault('ZZN·GGZ 연맹 ID를 저장한 뒤 명단을 조회해 주세요.',422,'AID_MISSING');
 const out=[];
 for(const tag of TAGS){const a=await getRemoteAlliance(env,tag,conf[tag].aid,fetchImpl);if(!a.canSync)throw fault(tag+': 데이터가 불완전하여 동기화를 중단했습니다. 먼저 미리보기 경고를 확인하세요.',422,'ROSTER_INCOMPLETE');out.push(a)}
 const seen=new Set();for(const a of out)for(const m of a.members){if(seen.has(m.fid))throw fault('두 연맹의 플레이어 ID가 중복되어 동기화를 차단했습니다.',422,'CROSS_DUPLICATE');seen.add(m.fid)}
 return out;
}
async function applySync(env,alliances,mode='manual'){
 const sql=`INSERT INTO wos_players(fid,nickname,alliance_tag,power_text,source) VALUES(?,?,?,?,'ORACLE')
 ON CONFLICT(fid) DO UPDATE SET nickname=excluded.nickname,alliance_tag=excluded.alliance_tag,
 power_text=excluded.power_text,source='ORACLE',updated_at=CURRENT_TIMESTAMP`;
 const statements=[];
 for(const a of alliances)for(const m of a.members)statements.push(env.DB.prepare(sql).bind(m.fid,m.nickname,m.alliance_tag,m.power_text));
 for(const a of alliances){
  statements.push(env.DB.prepare('UPDATE wos_oracle_alliance_config SET last_synced_at=CURRENT_TIMESTAMP WHERE alliance_tag=?').bind(a.tag));
  statements.push(env.DB.prepare('INSERT INTO wos_oracle_sync_log(id,alliance_tag,member_count,sync_mode) VALUES(?,?,?,?)').bind(crypto.randomUUID(),a.tag,a.member_count,mode));
 }
 await env.DB.batch(statements);
 return Object.fromEntries(alliances.map(a=>[a.tag,a.member_count]));
}
async function getStatus(env){
 const config=await getSettings(env),limits=await budgetCounts(env.DB,Math.floor(Date.now()/1000));
 return {tokenConfigured:tokenOk(env),alliances:Object.fromEntries(TAGS.map(t=>[t,config[t]||{aid:'',is_enabled:false,last_synced_at:null}])),limits,limitCaps:{second:4,minute:40,day:900},automaticEnabled:TAGS.every(t=>config[t]?.is_enabled)};
}
async function diagnoseState(env,fetchImpl=fetch){
 const body=await requestOracle(env,'STATE','/states/4114',fetchImpl);
 if(!obj(body)||!Array.isArray(body.alliances))throw fault('왕국 정보의 alliances[] 구조가 예상과 다릅니다.',422,'STATE_SCHEMA');
 if(body.sid!==undefined&&Number(body.sid)!==4114)throw fault('왕국 응답 번호가 4114가 아닙니다.',422,'STATE_MISMATCH');
 const alliances=body.alliances.map(x=>({id:String(x.id??''),abbr:trim(x.abbr,15),name:trim(x.name,80),member_count:asInt(x.member_count)})).filter(x=>/^\d+$/.test(x.id)).slice(0,10);
 return {connected:true,server:4114,tracked_players:asInt(body.tracked_players),alliances,source:'Oracle+ Plus: top 10 alliances only',readOnly:true};
}
async function preview(env,tag,fetchImpl=fetch){
 const conf=await getSettings(env),selected=tag&&TAGS.includes(tag)?[tag]:TAGS;
 for(const t of selected)if(!conf[t]?.aid)throw fault(t+': 연맹 ID를 먼저 저장해 주세요.',422,'AID_MISSING');
 const results=[],errors=[];
 for(const t of selected){
  try{const a=await getRemoteAlliance(env,t,conf[t].aid,fetchImpl);results.push({tag:a.tag,aid:a.aid,name:a.name,count:a.member_count,roster_count:a.roster_count,reported_count:a.reported_count,unlinked_count:a.unlinked_count,unlinked:a.unlinked,warnings:a.warnings,canSync:a.canSync,updated_at:a.updated_at,examples:a.members.slice(0,8)});}
  catch(e){errors.push({tag:t,error:e?.message||'알 수 없는 오류',code:e?.code||'UNKNOWN',...(e?.details||{})});}
 }
 const ready=selected.length===2&&results.length===2&&results.every(x=>x.canSync)&&!errors.length;
 return {preview:true,readOnly:true,readyForSync:ready,alliances:results,errors,message:errors.length?'일부 조회에 실패했습니다. 아래 원인별 안내를 확인하세요.':ready?'두 연맹을 조회했습니다. 미리보기 내용을 확인한 후 동기화하세요.':'미리보기 완료. 경고 항목을 확인해 주세요.'};
}
async function handler(req,env,p,{validOrigin,parseBody,fetchImpl=fetch}){
 try{
  if(p==='/api/oracle/status'&&req.method==='GET')return j(await getStatus(env));
  if(req.method!=='POST')return j({error:'찾을 수 없는 Oracle+ 기능입니다.'},404);
  if(!validOrigin(req))return j({error:'요청 출처가 올바르지 않습니다.'},403);
  const v=await parseBody(req,2500).catch(()=>null);
  if(!obj(v))return j({error:'요청 형식이 올바르지 않습니다.'},400);
  if(p==='/api/oracle/diagnose')return j(await diagnoseState(env,fetchImpl));
  if(p==='/api/oracle/config'){
   const ZZN=trim(v.ZZN,30),GGZ=trim(v.GGZ,30);
   if(!AID_RE.test(ZZN)||!AID_RE.test(GGZ)||ZZN===GGZ)return j({error:'서로 다른 숫자 연맹 ID를 입력해 주세요.'},400);
   await env.DB.batch(TAGS.map(tag=>env.DB.prepare(`INSERT INTO wos_oracle_alliance_config(alliance_tag,aid,is_enabled) VALUES(?,?,0)
     ON CONFLICT(alliance_tag) DO UPDATE SET aid=excluded.aid,is_enabled=CASE WHEN aid=excluded.aid THEN is_enabled ELSE 0 END,last_synced_at=CASE WHEN aid=excluded.aid THEN last_synced_at ELSE NULL END`)
     .bind(tag,tag==='ZZN'?ZZN:GGZ)));
   return j({saved:true,message:'연맹 ID가 저장되었습니다. 연결 진단과 미리보기를 진행하세요.'});
  }
  if(p==='/api/oracle/preview'){
   if(v.tag!==undefined&&!TAGS.includes(v.tag))return j({error:'ZZN 또는 GGZ만 선택할 수 있습니다.'},400);
   return j(await preview(env,v.tag,fetchImpl));
  }
  if(p==='/api/oracle/sync'){
   if(v.confirm!==true)return j({error:'명단 갱신을 확인해 주세요.'},400);
   const records=await fetchBoth(env,fetchImpl),counts=await applySync(env,records,'manual');
   return j({synced:true,counts,message:'명단 동기화 완료. 플레이어 ID 미연결 인원과 R4·부계정 정보는 보존됩니다.'});
  }
  if(p==='/api/oracle/automatic'){
   if(typeof v.enabled!=='boolean')return j({error:'자동 갱신 설정이 올바르지 않습니다.'},400);
   const config=await getSettings(env);
   if(v.enabled&&(!tokenOk(env)||TAGS.some(t=>!config[t]?.last_synced_at)))return j({error:'최초 수동 동기화를 마친 뒤 자동 갱신을 켤 수 있습니다.'},422);
   await env.DB.batch(TAGS.map(t=>env.DB.prepare('UPDATE wos_oracle_alliance_config SET is_enabled=? WHERE alliance_tag=?').bind(v.enabled?1:0,t)));
   return j({automaticEnabled:v.enabled,message:v.enabled?'6시간마다 자동으로 조회합니다.':'자동 갱신을 중단했습니다.'});
  }
  return j({error:'찾을 수 없는 Oracle+ 기능입니다.'},404);
 }catch(e){
  if(!e?.status)console.error('Oracle integration internal error (no token):',String(e?.message||'unknown').slice(0,180));
  return j({error:e?.status?e.message:'Oracle+ DB 처리 오류입니다. wos_oracle_ 테이블과 D1 연결을 확인하세요.',code:e?.code||'DATABASE_OR_SERVER',...(e?.details||{})},e?.status||503);
 }
}
async function scheduledSync(env,fetchImpl=fetch){
 try{
  if(!env?.DB||!tokenOk(env))return {skipped:true,reason:'config'};
  const conf=await getSettings(env);if(!TAGS.every(t=>conf[t]?.is_enabled&&conf[t]?.last_synced_at))return {skipped:true,reason:'disabled'};
  return {synced:true,counts:await applySync(env,await fetchBoth(env,fetchImpl),'scheduled')};
 }catch(e){console.error('Oracle scheduled sync failed:',e?.code||'DB_ERROR');return {synced:false,error:'Oracle+ 갱신 오류. 기존 명단을 유지했습니다.'};}
}
export {handler as oracleHandler,scheduledSync,normalizeAlliance,getStatus,applySync,fetchBoth,CANDIDATES,preview,diagnoseState};
