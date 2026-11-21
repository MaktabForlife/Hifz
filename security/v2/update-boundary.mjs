import {ascii,requireThat,safeInt} from './codec.mjs';

const newestBoundary="SELECT * FROM jwt_v2_update_boundaries ORDER BY generation DESC LIMIT 1";
const activeGeneration=(column)=>"EXISTS(SELECT 1 FROM ("+newestBoundary+") b WHERE b.status='VERIFIED' AND b.generation=json_extract("+column+",'$.updateGeneration'))";
const cutoffCommitRef=boundary=>'offline-update:'+boundary.generation+':'+boundary.release_id;
const preparing="EXISTS(SELECT 1 FROM jwt_v2_update_boundaries WHERE status='PREPARED')";

export function validateUpdateConfiguration(value){
 if(value===undefined)return;
 requireThat(value&&Object.keys(value).length===2&&safeInt(value.generation,1)&&ascii(value.releaseId,80),'OFFLINE_UPDATE_CONFIGURATION_INVALID',503);
}

export async function requireVerifiedUpdateBoundary(runtime){
 const wanted=runtime.settings.raw.offlineUpdate;
 if(!wanted)return;
 const current=await runtime.store.first(newestBoundary);
 requireThat(current?.generation===wanted.generation&&current.release_id===wanted.releaseId
  &&current.namespace===runtime.settings.prefix&&current.status==='VERIFIED','OFFLINE_UPDATE_NOT_VERIFIED',503);
}

export function requireFamilyUpdateGeneration(runtime,family){
 const wanted=runtime.settings.raw.offlineUpdate;
 if(!wanted)return;
 requireThat(family&&JSON.parse(family.projection_json).updateGeneration===wanted.generation,'SESSION_ENDED',401);
}

export const updateBoundarySchemaSQL=[
 "CREATE TABLE IF NOT EXISTS jwt_v2_update_boundaries(generation INTEGER PRIMARY KEY CHECK(generation>0),release_id TEXT NOT NULL UNIQUE,namespace TEXT NOT NULL,created_at INTEGER NOT NULL,status TEXT NOT NULL CHECK(status IN('PREPARED','VERIFIED')));",
 "CREATE TABLE IF NOT EXISTS jwt_v2_update_sessions(generation INTEGER NOT NULL REFERENCES jwt_v2_update_boundaries(generation),sid TEXT NOT NULL,covered INTEGER NOT NULL DEFAULT 0 CHECK(covered IN(0,1)),PRIMARY KEY(generation,sid));",
 "CREATE TABLE IF NOT EXISTS jwt_v2_update_subjects(generation INTEGER NOT NULL REFERENCES jwt_v2_update_boundaries(generation),sub TEXT NOT NULL,ce INTEGER,ae INTEGER,CHECK((ce IS NULL AND ae IS NULL) OR (ce>0 AND ae>0)),PRIMARY KEY(generation,sub));",
 "CREATE TABLE IF NOT EXISTS jwt_v2_update_accounts(generation INTEGER NOT NULL REFERENCES jwt_v2_update_boundaries(generation),sub TEXT NOT NULL,ce INTEGER NOT NULL,ae INTEGER NOT NULL,operation_id TEXT NOT NULL UNIQUE,PRIMARY KEY(generation,sub));",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_update_boundaries_retained BEFORE DELETE ON jwt_v2_update_boundaries BEGIN SELECT RAISE(ABORT,'update_boundary_retained'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_update_boundaries_immutable BEFORE UPDATE ON jwt_v2_update_boundaries WHEN OLD.generation<>NEW.generation OR OLD.release_id<>NEW.release_id OR OLD.namespace<>NEW.namespace OR OLD.created_at<>NEW.created_at OR OLD.status='VERIFIED' AND NEW.status<>'VERIFIED' BEGIN SELECT RAISE(ABORT,'update_boundary_immutable'); END;"
].join('\n');

export const updateBoundaryGuardsSQL=[
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_update_family_insert BEFORE INSERT ON jwt_v2_families WHEN EXISTS(SELECT 1 FROM jwt_v2_update_boundaries) AND NOT "+activeGeneration("NEW.projection_json")+" BEGIN SELECT RAISE(ABORT,'offline_update_generation'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_update_family_write BEFORE UPDATE ON jwt_v2_families WHEN NEW.state NOT IN('REVOKED','EXPIRED') AND EXISTS(SELECT 1 FROM jwt_v2_update_boundaries) AND NOT "+activeGeneration("NEW.projection_json")+" BEGIN SELECT RAISE(ABORT,'offline_update_generation'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_update_tx_insert BEFORE INSERT ON jwt_v2_http_transactions WHEN EXISTS(SELECT 1 FROM jwt_v2_update_boundaries) AND NOT "+activeGeneration("NEW.payload_json")+" BEGIN SELECT RAISE(ABORT,'offline_update_generation'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_update_tx_write BEFORE UPDATE ON jwt_v2_http_transactions WHEN NEW.status IN('PENDING','COMMITTED') AND EXISTS(SELECT 1 FROM jwt_v2_update_boundaries) AND NOT "+activeGeneration("NEW.payload_json")+" BEGIN SELECT RAISE(ABORT,'offline_update_generation'); END;",
 ...['jwt_v2_ceremonies','jwt_v2_ceremony_pending','jwt_v2_ceremony_attempts','jwt_v2_intents','jwt_v2_parents'].map(table=>
  "CREATE TRIGGER IF NOT EXISTS "+table+"_hold_insert BEFORE INSERT ON "+table+" WHEN "+preparing+" BEGIN SELECT RAISE(ABORT,'offline_update_hold'); END;")
].join('\n');

function held(runtime){
 requireThat(runtime.env.UAA_V111_CUTOVER==='held','OFFLINE_UPDATE_HOLD_REQUIRED',409);
}

async function requireBoundary(runtime,generation){
 const row=await runtime.store.first('SELECT * FROM jwt_v2_update_boundaries ORDER BY generation DESC LIMIT 1');
 requireThat(row?.generation===generation&&row.namespace===runtime.settings.prefix,'OFFLINE_UPDATE_GENERATION_MISMATCH',409);
 return row;
}

export async function prepareUpdateBoundary(runtime,{generation,releaseId}){
 held(runtime);
 requireThat(safeInt(generation,1)&&ascii(releaseId,80),'OFFLINE_UPDATE_GENERATION_MISMATCH',409);
 const wanted=runtime.settings.raw.offlineUpdate;
 requireThat(!wanted||wanted.generation===generation&&wanted.releaseId===releaseId,'OFFLINE_UPDATE_GENERATION_MISMATCH',409);
 const store=runtime.store,prior=await store.first('SELECT * FROM jwt_v2_update_boundaries ORDER BY generation DESC LIMIT 1');
 if(prior?.generation===generation){
  requireThat(prior.release_id===releaseId&&prior.namespace===runtime.settings.prefix,'OFFLINE_UPDATE_GENERATION_MISMATCH',409);
  return {generation,status:prior.status};
 }
 requireThat(!prior||prior.generation<generation&&prior.status==='VERIFIED','OFFLINE_UPDATE_GENERATION_MISMATCH',409);
 const now=runtime.clock();
 const [guard,clear]=store.guard('SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_update_boundaries WHERE generation>=? OR status<>\'VERIFIED\')',[generation]);
 await store.batch([
  guard,
  store.stmt("INSERT INTO jwt_v2_update_boundaries VALUES(?,?,?,?,'PREPARED')",generation,releaseId,runtime.settings.prefix,now),
  store.stmt('INSERT INTO jwt_v2_update_sessions(generation,sid) SELECT ?,sid FROM jwt_v2_families WHERE s_exp>?',generation,now),
  store.stmt(`INSERT INTO jwt_v2_update_subjects(generation,sub,ce,ae)
   SELECT ?, s.sub, a.ce, a.ae FROM (
    SELECT sub FROM jwt_v2_families WHERE s_exp>? AND state NOT IN('REVOKED','EXPIRED')
    UNION SELECT sub FROM jwt_v2_parents WHERE s_exp>? AND state NOT IN('REVOKED','EXPIRED')
    UNION SELECT sub FROM jwt_v2_http_transactions WHERE expires_at>? AND status='PENDING'
    UNION SELECT sub FROM jwt_v2_ceremony_pending WHERE expires_at>? AND status='PENDING'
    ${runtime.app==='academy'?`UNION SELECT sub FROM jwt_v2_ceremonies
     WHERE expires_at>? AND status IN('PENDING','CODE_ISSUED','GRANTED')`:''}
   ) s LEFT JOIN jwt_v2_accounts a ON a.sub=s.sub WHERE s.sub IS NOT NULL`,
   generation,now,now,now,now,...(runtime.app==='academy'?[now]:[])),
  store.stmt("UPDATE jwt_v2_families SET state='REVOKED',cr=cr+1 WHERE state NOT IN('REVOKED','EXPIRED')"),
  store.stmt("UPDATE jwt_v2_parents SET state='REVOKED' WHERE state NOT IN('REVOKED','EXPIRED')"),
  store.stmt('UPDATE jwt_v2_browsers SET cancelled_through=max(cancelled_through,bv)'),
  store.stmt("UPDATE jwt_v2_intents SET state='CANCELLED' WHERE state='ISSUED'"),
  store.stmt("UPDATE jwt_v2_http_transactions SET status='CANCELLED' WHERE status='PENDING'"),
  store.stmt("UPDATE jwt_v2_ceremony_pending SET status='CANCELLED' WHERE status='PENDING'"),
  ...(runtime.app==='academy'?[
   store.stmt("UPDATE jwt_v2_ceremonies SET status='CANCELLED' WHERE status IN('PENDING','CODE_ISSUED','GRANTED')"),
   store.stmt("UPDATE jwt_v2_ceremony_attempts SET status='CANCELLED' WHERE status IN('ISSUED','RESERVED')"),
   store.stmt('UPDATE jwt_v2_pin_gates SET reservation=NULL,reservation_until=NULL'),
   store.stmt('DELETE FROM jwt_v2_ceremony_reservations')
  ]:[]),
  clear
 ]);
 return {generation,status:'PREPARED'};
}

export async function listUpdateSubjects(runtime,{generation,after='',limit=20}){
 held(runtime);
 await requireBoundary(runtime,generation);
 requireThat(typeof after==='string'&&safeInt(limit,1)&&limit<=100,'OFFLINE_UPDATE_INVENTORY_LIMIT',400);
 return runtime.store.all('SELECT sub,ce,ae FROM jwt_v2_update_subjects WHERE generation=? AND sub>? ORDER BY sub LIMIT ?',generation,after,limit);
}

export async function revokeOfflineAcademyAccount(runtime,{generation,sub}){
 held(runtime);
 const boundary=await requireBoundary(runtime,generation),store=runtime.store;
 requireThat(runtime.app==='academy'&&boundary.status==='PREPARED','OFFLINE_UPDATE_CUTOFF_REQUIRED',409);
 let prior=await store.first('SELECT * FROM jwt_v2_update_accounts WHERE generation=? AND sub=?',generation,sub);
 if(!prior){
  const account=await store.first('SELECT * FROM jwt_v2_accounts WHERE sub=?',sub);
  requireThat(account,'OFFLINE_UPDATE_ACCOUNT_UNAVAILABLE',503);
  const operationId=crypto.randomUUID(),[guard,clear]=store.guard('SELECT 1 FROM jwt_v2_accounts WHERE sub=? AND ce=? AND ae=?',[sub,account.ce,account.ae]);
  await store.batch([guard,store.stmt('INSERT INTO jwt_v2_update_accounts VALUES(?,?,?,?,?) ON CONFLICT(generation,sub) DO NOTHING',generation,sub,account.ce,account.ae,operationId),clear]);
  prior=await store.first('SELECT * FROM jwt_v2_update_accounts WHERE generation=? AND sub=?',generation,sub);
 }
 const result=await store.acceptCutoff({sub,ce:prior.ce,ae:prior.ae,operationId:prior.operation_id,kind:'OFFLINE_UPDATE',now:runtime.clock(),offlineUpdateRef:cutoffCommitRef(boundary)});
 requireThat(result.status==='ACCEPTED'&&result.receipt===prior.operation_id,'OFFLINE_UPDATE_CUTOFF_REQUIRED',503);
 requireThat(await runtime.publishPending(result.receipt),'OFFLINE_UPDATE_PUBLICATION_PENDING',503);
 return result;
}

export async function publishUpdateSessions(runtime,{generation,limit=20}){
 held(runtime);
 await requireBoundary(runtime,generation);
 requireThat(safeInt(limit,1)&&limit<=20,'OFFLINE_UPDATE_PUBLICATION_LIMIT',400);
 const store=runtime.store,rows=await store.all('SELECT u.sid,f.s_exp FROM jwt_v2_update_sessions u JOIN jwt_v2_families f ON f.sid=u.sid WHERE generation=? AND covered=0 ORDER BY u.sid LIMIT ?',generation,limit);
 for(const row of rows){
  if(row.s_exp>runtime.clock()){
   const key=runtime.cache.key('security/session/'+row.sid);
   const existing=await store.lifecycle(key);
   if(existing){
    const control=await runtime.publishFamily(row.sid);
    requireThat(['REVOKED','EXPIRED'].includes(control.localState),'OFFLINE_UPDATE_PUBLICATION_PENDING',503);
   }else{
    requireThat(!await runtime.settings.bucket.get(key),'OFFLINE_UPDATE_PUBLICATION_PENDING',503);
   }
  }
  await store.stmt('UPDATE jwt_v2_update_sessions SET covered=1 WHERE generation=? AND sid=?',generation,row.sid).run();
 }
 return {attempted:rows.length,pending:(await store.first('SELECT count(*) n FROM jwt_v2_update_sessions WHERE generation=? AND covered=0',generation)).n};
}

export async function verifyUpdateBoundary(runtime,generation){
 held(runtime);
 const boundary=await requireBoundary(runtime,generation);
 const store=runtime.store;
 const pending=await store.first(`SELECT (
  EXISTS(SELECT 1 FROM jwt_v2_update_sessions WHERE generation=? AND covered=0)
  OR EXISTS(SELECT 1 FROM jwt_v2_families WHERE state NOT IN('REVOKED','EXPIRED'))
  OR EXISTS(SELECT 1 FROM jwt_v2_parents WHERE state NOT IN('REVOKED','EXPIRED'))
  OR EXISTS(SELECT 1 FROM jwt_v2_intents WHERE state='ISSUED')
  OR EXISTS(SELECT 1 FROM jwt_v2_http_transactions WHERE status='PENDING')
  OR EXISTS(SELECT 1 FROM jwt_v2_ceremony_pending WHERE status='PENDING')
 ) pending`,generation);
 requireThat(!pending.pending,'OFFLINE_UPDATE_PUBLICATION_PENDING',503);
 if(runtime.app==='academy'){
  const unapplied=await store.first(`SELECT 1 FROM jwt_v2_update_subjects s
   WHERE s.generation=? AND NOT EXISTS(SELECT 1 FROM jwt_v2_update_accounts a
    WHERE a.generation=s.generation AND a.sub=s.sub) LIMIT 1`,generation);
  requireThat(!unapplied,'OFFLINE_UPDATE_CUTOFF_REQUIRED',503);
  const unconfirmed=await store.first(`SELECT 1 FROM jwt_v2_update_accounts a
   WHERE a.generation=? AND (
    NOT EXISTS(SELECT 1 FROM jwt_v2_worksets w WHERE w.work_id=a.operation_id AND w.state='APPLIED')
    OR (SELECT count(DISTINCT o.target_app) FROM jwt_v2_outbox o
     WHERE o.state='APPLIED' AND o.target_app IN('studio','hifz')
      AND json_extract(o.event_json,'$.operationId')=a.operation_id
      AND json_extract(o.event_json,'$.commitRef')=?)<>2
   ) LIMIT 1`,generation,cutoffCommitRef(boundary));
  requireThat(!unconfirmed,'OFFLINE_UPDATE_CUTOFF_UNCONFIRMED',503);
 }else{
  const uncovered=await store.first(`SELECT 1 FROM jwt_v2_update_subjects s
   WHERE s.generation=? AND NOT EXISTS(
    SELECT 1 FROM jwt_v2_events e JOIN jwt_v2_event_streams v
    ON v.source_app=e.source_app AND v.target_app=e.target_app AND v.stream=e.stream AND v.owner_epoch=e.owner_epoch
    WHERE e.source_app='academy' AND e.target_app=? AND e.stream='account-security'
    AND e.state='APPLIED' AND e.sequence<=v.contiguous_through
    AND json_extract(e.event_json,'$.commitRef')=?
    AND json_extract(e.event_json,'$.target.type')='accountCutoff'
    AND json_extract(e.event_json,'$.target.reason')='OFFLINE_UPDATE'
    AND json_extract(e.event_json,'$.target.sub')=s.sub
    AND (s.ce IS NULL OR s.ce<json_extract(e.event_json,'$.target.maxCe')
     OR (s.ce=json_extract(e.event_json,'$.target.maxCe') AND s.ae<=json_extract(e.event_json,'$.target.maxAe')))
   ) LIMIT 1`,generation,runtime.app,cutoffCommitRef(boundary));
  requireThat(!uncovered,'OFFLINE_UPDATE_CUTOFF_UNCONFIRMED',503);
 }
 const [guard,clear]=store.guard("SELECT 1 FROM jwt_v2_update_boundaries WHERE generation=? AND NOT EXISTS(SELECT 1 FROM jwt_v2_update_boundaries WHERE generation>?)",[generation,generation]);
 await store.batch([guard,store.stmt("UPDATE jwt_v2_update_boundaries SET status='VERIFIED' WHERE generation=?",generation),clear]);
 return {generation,status:'VERIFIED'};
}
