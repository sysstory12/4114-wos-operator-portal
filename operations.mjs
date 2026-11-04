// 4114 WOS COMMAND CENTER operations module.
// Server-side D1 data only. All HTTP requests are gated by the operator PIN in worker.mjs.
const types = ['FC','SPEEDUP','GEMS','CHEST'];
const tagSet = new Set(['ZZN','GGZ']);
const fidPattern = /^\d{6,15}$/;
const eventPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const json = (data,status=200) => new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'}});
const str = (value,max) => typeof value==='string' ? value.trim().slice(0,max+1) : '';
function validAmount(n,max=1e13){return typeof n==='number' && Number.isSafeInteger(n) && n>=0 && n<=max;}
function validDateTime(v){return typeof v==='string'&&eventPattern.test(v)&&!Number.isNaN(Date.parse(v+'Z'))&&new Date(v+'Z').toISOString().slice(0,16)===v;}
const list=async(q)=>{const r=await q.all();return r.results||[]};
function parsePower(v){
  if(v===null||v===undefined||v==='')return null;
  const text=String(v).replace(/,/g,'').trim();
  const m=/^([\d]+(?:\.[\d]+)?)\s*([KMBT])?$/i.exec(text);
  if(!m)return null;
  const n=Number(m[1]),scale=({K:1e3,M:1e6,B:1e9,T:1e12})[(m[2]||'').toUpperCase()]||1;
  const total=n*scale;return Number.isFinite(total)&&total>=0?total:null;
}
async function getDashboard(db){
  const [players,rounds,upcoming,notices,log,pool,allocations]=await Promise.all([
    list(db.prepare("SELECT p.fid,p.nickname,p.alliance_tag,p.power_text,COALESCE(l.game_rank,'UNSET') game_rank,COALESCE(l.is_alt,0) is_alt FROM wos_players p LEFT JOIN wos_member_labels l ON l.fid=p.fid WHERE p.alliance_tag IN ('ZZN','GGZ') LIMIT 300")),
    list(db.prepare('SELECT id,label,status,created_at FROM wos_ops_svs_rounds ORDER BY created_at DESC,id DESC LIMIT 1')),
    list(db.prepare('SELECT id,title,event_type,start_utc FROM wos_ops_calendar_events WHERE start_utc >= ? ORDER BY start_utc ASC LIMIT 5').bind(new Date().toISOString().slice(0,16))),
    db.prepare('SELECT COUNT(*) n FROM wos_notice_templates').first(),
    list(db.prepare('SELECT alliance_tag,member_count,synced_at FROM wos_oracle_sync_log ORDER BY synced_at DESC LIMIT 4')),
    list(db.prepare('SELECT resource_type,total_amount FROM wos_ops_resource_pool')),
    list(db.prepare('SELECT resource_type,SUM(amount) used FROM wos_ops_resource_allocations WHERE voided_at IS NULL GROUP BY resource_type'))
  ]);
  const out={ZZN:{count:0,power:0,powerKnown:0,r4:0,alts:0},GGZ:{count:0,power:0,powerKnown:0,r4:0,alts:0}};
  for(const p of players){const r=out[p.alliance_tag];if(!r)continue;r.count++;if(p.game_rank==='R4'||p.game_rank==='R5')r.r4++;if(p.is_alt)r.alts++;
    const power=parsePower(p.power_text);if(power!==null){r.power+=power;r.powerKnown++}}
  return {alliances:out,totalPlayers:players.length,notices:Number(notices?.n||0),round:rounds[0]||null,
    upcoming,oracleRecent:log,pool,allocations,source:'D1 저장된 명단',powerNote:'전투력은 Oracle+에서 저장한 수치 또는 표기 가능한 원시값만 합산합니다.'};
}
async function getSvs(db,requestedRound=null){
 const rounds=await list(db.prepare('SELECT id,label,status,created_at FROM wos_ops_svs_rounds ORDER BY created_at DESC,id DESC LIMIT 30'));
 if(!rounds.length)return {rounds,active:null,ranking:[]};
 const active=rounds.find(x=>x.id===requestedRound)||rounds.find(x=>x.status==='OPEN')||rounds[0];
 const ranking=await list(db.prepare("SELECT s.fid,s.score,s.server_rank,s.note,s.updated_at,p.nickname,p.alliance_tag FROM wos_ops_svs_scores s JOIN wos_players p ON p.fid=s.fid WHERE s.round_id=? ORDER BY s.score DESC,p.nickname LIMIT 300").bind(active.id));
 return {rounds,active,ranking};
}
async function getResources(db){
 const [pool,ledger]=await Promise.all([
  list(db.prepare('SELECT resource_type,total_amount,updated_at FROM wos_ops_resource_pool ORDER BY resource_type')),
  list(db.prepare('SELECT a.id,a.fid,p.nickname,p.alliance_tag,a.resource_type,a.amount,a.reason,a.memo,a.created_at,a.voided_at FROM wos_ops_resource_allocations a JOIN wos_players p ON p.fid=a.fid ORDER BY a.created_at DESC,a.id DESC LIMIT 400'))
 ]);
 const totals=await list(db.prepare("SELECT a.resource_type,p.alliance_tag,SUM(a.amount) used FROM wos_ops_resource_allocations a JOIN wos_players p ON p.fid=a.fid WHERE a.voided_at IS NULL GROUP BY a.resource_type,p.alliance_tag"));
 return {pool,ledger,totals};
}
async function getEvents(db){return {events:await list(db.prepare('SELECT * FROM wos_ops_calendar_events ORDER BY start_utc ASC LIMIT 250'))};}
async function request(req,env,p,{validOrigin,parseBody,audit}){
 try{
  const db=env.DB;
  if(req.method==='GET'){
   if(p==='/api/ops/dashboard')return json(await getDashboard(db));
   if(p==='/api/ops/svs')return json(await getSvs(db,new URL(req.url).searchParams.get('round')));
   if(p==='/api/ops/resources')return json(await getResources(db));
   if(p==='/api/ops/events')return json(await getEvents(db));
   return json({error:'찾을 수 없는 기능입니다.'},404);
  }
  if(!validOrigin(req))return json({error:'올바른 사이트에서 요청해 주세요.'},403);
  if(!['POST','PATCH','DELETE'].includes(req.method))return json({error:'지원하지 않는 요청입니다.'},405);
  const v=await parseBody(req,5000).catch(()=>null);
  if(!v||typeof v!=='object'||Array.isArray(v))return json({error:'입력 형식을 확인해 주세요.'},400);
  if(p==='/api/ops/svs/rounds'&&req.method==='POST'){
   const label=str(v.label,100);
   if(!label||label.length>100)return json({error:'회차 이름은 1~100자입니다.'},400);
   const id=crypto.randomUUID();
   await db.prepare("INSERT INTO wos_ops_svs_rounds(id,label) VALUES(?,?)").bind(id,label).run();
   await audit(env,'SVS_ROUND_CREATE',id);return json({created:true,id},201);
  }
  const roundMatch=p.match(/^\/api\/ops\/svs\/rounds\/([0-9a-f-]{36})\/status$/i);
  if(roundMatch&&req.method==='PATCH'){
   const status=v.status;if(!['OPEN','CLOSED'].includes(status))return json({error:'OPEN 또는 CLOSED만 가능합니다.'},400);
   const r=await db.prepare('UPDATE wos_ops_svs_rounds SET status=? WHERE id=?').bind(status,roundMatch[1]).run();
   if(!r.meta?.changes)return json({error:'회차를 찾지 못했습니다.'},404);
   await audit(env,'SVS_ROUND_STATUS',roundMatch[1]);return json({updated:true});
  }
  if(p==='/api/ops/svs/scores'&&req.method==='POST'){
   const fid=str(v.fid,16),roundId=str(v.round_id,40),score=v.score,rank=v.server_rank??null,note=str(v.note||'',200);
   if(!fidPattern.test(fid)||!uuidPattern.test(roundId)||!validAmount(score)||!(rank===null||(validAmount(rank,1000000)&&rank>=1))||note.length>200)
    return json({error:'플레이어 ID, 점수, 서버 순위 또는 메모를 확인하세요.'},400);
   const [r,pl]=await Promise.all([db.prepare('SELECT id,status FROM wos_ops_svs_rounds WHERE id=?').bind(roundId).first(),db.prepare('SELECT fid FROM wos_players WHERE fid=?').bind(fid).first()]);
   if(!r||!pl)return json({error:'회차 또는 연맹원 ID를 찾지 못했습니다.'},404);
   if(r.status!=='OPEN')return json({error:'마감된 회차는 수정할 수 없습니다.'},409);
   await db.prepare('INSERT INTO wos_ops_svs_scores(round_id,fid,score,server_rank,note) VALUES(?,?,?,?,?) ON CONFLICT(round_id,fid) DO UPDATE SET score=excluded.score,server_rank=excluded.server_rank,note=excluded.note,updated_at=CURRENT_TIMESTAMP')
    .bind(roundId,fid,score,rank,note).run();
   await audit(env,'SVS_SCORE_SET',`${roundId}:${fid}`);return json({saved:true});
  }
  if(p==='/api/ops/resources/pool'&&req.method==='POST'){
   const kind=v.resource_type,total=v.total_amount;
   if(!types.includes(kind)||!validAmount(total))return json({error:'자원 종류와 총량을 확인하세요.'},400);
   // Refuse to lower the pool below the current active allocations.
   const sql=`INSERT INTO wos_ops_resource_pool(resource_type,total_amount) SELECT ?,?
    WHERE ? >= (SELECT COALESCE(SUM(amount),0) FROM wos_ops_resource_allocations WHERE resource_type=? AND voided_at IS NULL)
    ON CONFLICT(resource_type) DO UPDATE SET total_amount=excluded.total_amount,updated_at=CURRENT_TIMESTAMP
    WHERE excluded.total_amount >= (SELECT COALESCE(SUM(amount),0) FROM wos_ops_resource_allocations WHERE resource_type=excluded.resource_type AND voided_at IS NULL)`;
   const r=await db.prepare(sql).bind(kind,total,total,kind).run();
   if(!r.meta?.changes)return json({error:'이미 분배한 수량보다 총량을 작게 설정할 수 없습니다.'},409);
   await audit(env,'RESOURCE_POOL_SET',kind);return json({saved:true});
  }
  if(p==='/api/ops/resources/allocations'&&req.method==='POST'){
   const fid=str(v.fid,16),kind=v.resource_type,amount=v.amount,reason=str(v.reason,100),memo=str(v.memo||'',200);
   if(!fidPattern.test(fid)||!types.includes(kind)||!validAmount(amount)||amount<=0||!reason||reason.length>100||memo.length>200)
    return json({error:'배분 대상·수량·사유를 확인하세요.'},400);
   const player=await db.prepare('SELECT fid FROM wos_players WHERE fid=?').bind(fid).first();if(!player)return json({error:'등록된 연맹원만 선택할 수 있습니다.'},404);
   const id=crypto.randomUUID();
   // An atomic INSERT ... SELECT enforces the current remaining budget, including concurrent calls.
   const sql=`INSERT INTO wos_ops_resource_allocations(id,fid,resource_type,amount,reason,memo)
    SELECT ?,?,?,?,?,? FROM wos_ops_resource_pool p WHERE p.resource_type=? AND
    p.total_amount >= ? + (SELECT COALESCE(SUM(amount),0) FROM wos_ops_resource_allocations WHERE resource_type=? AND voided_at IS NULL)`;
   const r=await db.prepare(sql).bind(id,fid,kind,amount,reason,memo,kind,amount,kind).run();
   if(!r.meta?.changes)return json({error:'자원 총량이 설정되지 않았거나 잔여량이 부족합니다.'},409);
   await audit(env,'RESOURCE_ALLOCATION',id);return json({created:true,id},201);
  }
  const allocationMatch=p.match(/^\/api\/ops\/resources\/allocations\/([0-9a-f-]{36})\/void$/i);
  if(allocationMatch&&req.method==='POST'){
   const id=allocationMatch[1];
   const r=await db.prepare('UPDATE wos_ops_resource_allocations SET voided_at=CURRENT_TIMESTAMP WHERE id=? AND voided_at IS NULL').bind(id).run();
   if(!r.meta?.changes)return json({error:'기록이 없거나 이미 취소되었습니다.'},404);
   await audit(env,'RESOURCE_ALLOCATION_VOID',id);return json({voided:true});
  }
  if(p==='/api/ops/events'&&req.method==='POST'){
   const title=str(v.title,120),kind=str(v.event_type||'일반',30),start=v.start_utc,end=v.end_utc??null,note=str(v.note||'',500);
   if(!title||title.length>120||!kind||kind.length>30||!validDateTime(start)||!(end===null||validDateTime(end))||(end!==null&&end<start)||note.length>500)
    return json({error:'일정 이름·UTC 날짜·종료 시간을 확인하세요.'},400);
   const id=crypto.randomUUID();await db.prepare('INSERT INTO wos_ops_calendar_events(id,title,event_type,start_utc,end_utc,note) VALUES(?,?,?,?,?,?)').bind(id,title,kind,start,end,note).run();
   await audit(env,'CALENDAR_EVENT_CREATE',id);return json({created:true,id},201);
  }
  const eventMatch=p.match(/^\/api\/ops\/events\/([0-9a-f-]{36})$/i);
  if(eventMatch&&req.method==='DELETE'){
   const r=await db.prepare('DELETE FROM wos_ops_calendar_events WHERE id=?').bind(eventMatch[1]).run();
   if(!r.meta?.changes)return json({error:'일정을 찾지 못했습니다.'},404);
   await audit(env,'CALENDAR_EVENT_DELETE',eventMatch[1]);return json({deleted:true});
  }
  return json({error:'찾을 수 없는 기능입니다.'},404);
 }catch(e){
  console.error('Operations error:',String(e?.message||'Unknown').slice(0,180));
  return json({error:'운영 데이터 저장소를 확인해 주세요. 먼저 v5 D1 SQL을 실행했는지 점검하세요.'},503);
 }
}
export {request as operationsHandler,parsePower,validDateTime,getDashboard};
