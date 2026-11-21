import {requireThat} from './codec.mjs';

const matchParent='psid=? AND bsid=? AND bv=? AND sub=?';
const currentFamilySQL='SELECT * FROM jwt_v2_families WHERE '+matchParent+' ORDER BY ordinal DESC LIMIT 1';
const barrierSQL='SELECT * FROM jwt_v2_ceremony_barriers WHERE '+matchParent;
const active="state NOT IN('REVOKED','EXPIRED')";

export function hasSharedPredecessor(store,claims){
 return store.first('SELECT 1 FROM ('+currentFamilySQL+') WHERE '+active,claims.psid,claims.bsid,claims.bv,claims.sub);
}

export async function sharedPredecessor(runtime,claims){
 const store=runtime.store,exactParent=[claims.psid,claims.bsid,claims.bv,claims.sub];
 const prior=await store.first(currentFamilySQL,...exactParent);
 const priorBarrier=await store.first(barrierSQL,...exactParent);
 if(!prior){
  requireThat(!priorBarrier,'SHARED_ENTRY_RECOVERY_REQUIRED',409);
  const guards=[
   store.guard('SELECT 1 WHERE NOT EXISTS('+currentFamilySQL+')',exactParent),
   store.guard('SELECT 1 WHERE NOT EXISTS('+barrierSQL+')',exactParent)
  ];
  return {exactParent,prior,priorBarrier,guards};
 }

 const receipt=await store.first(
  'SELECT c.jti,c.tx,c.consumed_at FROM jwt_v2_shared_entry_families i JOIN jwt_v2_ceremony_consumed c USING(tx) WHERE i.sid=?',
  prior.sid
 );
 requireThat(priorBarrier&&receipt,'SHARED_ENTRY_RECOVERY_REQUIRED',409);
 requireThat(!['REVOKED','EXPIRED'].includes(prior.state)
  &&['ce','ae','s_iat','s_exp'].every(key=>prior[key]===claims[key]),'SESSION_ENDED',401);
 requireThat(claims.iat>receipt.consumed_at&&claims.jti!==receipt.jti,'SHARED_ENTRY_RECOVERY_REQUIRED',409);

 // A successor which could not be delivered may itself be recovered only
 // after its predecessors' durable fences have reached the read controls.
 await publishSharedRetirements(runtime,prior.sid);
 const guards=[
  store.guard('SELECT 1 WHERE (?=(SELECT sid FROM ('+currentFamilySQL+'))) AND EXISTS(SELECT 1 FROM jwt_v2_families WHERE sid=? AND cr=? AND '+active+')',[prior.sid,...exactParent,prior.sid,prior.cr]),
  store.guard('SELECT 1 FROM jwt_v2_ceremony_barriers WHERE '+matchParent+' AND revision=?',[...exactParent,priorBarrier.revision]),
  store.guard('SELECT 1 FROM jwt_v2_shared_entry_families i JOIN jwt_v2_ceremony_consumed c USING(tx) WHERE i.sid=? AND c.tx=? AND c.jti=? AND c.consumed_at=?',[prior.sid,receipt.tx,receipt.jti,receipt.consumed_at])
 ];
 return {exactParent,prior,priorBarrier,guards};
}

export function sharedRetirementPlan(store,predecessors,successorSid,operationId){
 return predecessors.flatMap(({sid})=>[
  store.stmt('INSERT INTO jwt_v2_shared_entry_retirements(prior_sid,successor_sid) VALUES(?,?)',sid,successorSid),
  store.stmt("UPDATE jwt_v2_families SET state='REVOKED',authority_ready=0,cr=cr+1 WHERE sid=? AND "+active,sid),
  store.stmt("UPDATE jwt_v2_intents SET state='CANCELLED',superseding_operation=? WHERE sid=? AND state='ISSUED'",operationId,sid)
 ]);
}

export function isSharedRetired(store,sid){
 return store.first('SELECT 1 FROM jwt_v2_shared_entry_retirements WHERE prior_sid=?',sid);
}

export async function publishSharedRetirements(runtime,successorSid){
 const store=runtime.store;
 const rows=await store.all(
  'SELECT p.prior_sid AS sid,f.state,f.s_exp,f.cr FROM jwt_v2_shared_entry_retirements p LEFT JOIN jwt_v2_families f ON f.sid=p.prior_sid WHERE p.successor_sid=? AND p.covered=0',
  successorSid
 );
 for(const row of rows){
  requireThat(['REVOKED','EXPIRED'].includes(row.state),'CHILD_AUTHORITY_PENDING',503);
  if(row.s_exp>runtime.clock()){
   const key=runtime.cache.key('security/session/'+row.sid);
   const life=await store.lifecycle(key);
   if(life){
    const publication=await runtime.publishWinningFamily(row.sid);
    requireThat(publication.cachePublication==='READY','CHILD_AUTHORITY_PENDING',503);
    const {value}=await runtime.cache.read('security/session/'+row.sid);
    requireThat(['REVOKED','EXPIRED'].includes(value.localState)&&value.cr>=row.cr,'CHILD_AUTHORITY_PENDING',503);
   }else requireThat(!await runtime.settings.bucket.get(key),'CHILD_AUTHORITY_PENDING',503);
  }
  await store.stmt('UPDATE jwt_v2_shared_entry_retirements SET covered=1 WHERE successor_sid=? AND prior_sid=?',successorSid,row.sid).run();
 }
}
