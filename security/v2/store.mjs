import {assertCaptureReceipt} from './capture-receipt.mjs';
import {familyPolicyRegistrationPlan} from './policy.mjs';
import {issuanceFloorGuard} from './issuance-floors.mjs';
import {admissionFloorGuard,restrictionPlan} from './publication.mjs';
import {requireThat,reject,canonical,digest,equal,safeInt} from './codec.mjs';
export class PrimaryStore {
 constructor(db,{app,env,academyFence=app==='academy',dependencyManifest,dependencyRegistry=new Map(),securityPrefix}){requireThat(['academy','studio','hifz'].includes(app)&&['production','feature'].includes(env),'INVALID_STORE_OWNER',503);this.app=app;this.env=env;this.academyFence=academyFence;this.dependencyManifest=dependencyManifest;this.dependencyRegistry=dependencyRegistry;this.securityPrefix=securityPrefix;this.owningDB=db;this.db=db.withSession('first-primary');}
 controlKey(suffix){requireThat(typeof this.securityPrefix==='string'&&this.securityPrefix.startsWith('auth-private/v2/'+this.env+'/'+this.app+'/')&&this.securityPrefix.endsWith('/'),'SECURITY_NAMESPACE_NOT_CONFIGURED',503);return this.securityPrefix+suffix;}
 stmt(sql,...args){return this.db.prepare(sql).bind(...args);}
 // first-primary applies only to a session's first query. Runtime instances
 // outlive one request, so authority reads must not reuse their old read session.
 first(sql,...args){return this.owningDB.withSession('first-primary').prepare(sql).bind(...args).first();}
 all(sql,...args){return this.owningDB.withSession('first-primary').prepare(sql).bind(...args).all().then(r=>r.results);}
 batch(items){return this.db.batch(this.academyFence?[this.stmt("INSERT INTO jwt_v2_guards(id,accepted) SELECT 'native-split-fence',NOT EXISTS(SELECT 1 FROM split_write_fence) ON CONFLICT(id) DO UPDATE SET accepted=excluded.accepted"),...items,this.stmt("DELETE FROM jwt_v2_guards WHERE id='native-split-fence'")]:items);}
 guard(sql,args=[]){const id=crypto.randomUUID();return [this.stmt('INSERT INTO jwt_v2_guards(id,accepted) SELECT ?,EXISTS('+sql+')',id,...args),this.stmt('DELETE FROM jwt_v2_guards WHERE id=?',id)];}
 async claimSeed({key,incarnation,generation,nonce}){
  try{await this.stmt("INSERT INTO jwt_v2_objects(object_key,incarnation,generation,state,create_claimed,seed_nonce) VALUES(?,?,?,'SEED',1,?)",key,incarnation,generation,nonce).run();return true;}catch(error){if(await this.lifecycle(key))return false;throw error;}
 }
 lifecycle(key){return this.first('SELECT * FROM jwt_v2_objects WHERE object_key=?',key);}
 async seedObserved(key,nonce){
  const [g,clear]=this.guard("SELECT 1 FROM jwt_v2_objects WHERE object_key=? AND state='SEED' AND seed_nonce=?",[key,nonce]);
  await this.batch([g,this.stmt('UPDATE jwt_v2_objects SET seed_observed=1 WHERE object_key=?',key),clear]);
 }
 async lost(key){
  await this.stmt("UPDATE jwt_v2_objects SET state='LOST' WHERE object_key=? AND state IN('SEED','ACTIVE')",key).run();
 }
 async published(key,revision,receipt){
  const [g,clear]=this.guard("SELECT 1 FROM jwt_v2_objects WHERE object_key=? AND state IN('SEED','ACTIVE') AND seed_observed=1 AND semantic_revision<=?",[key,revision]);
  await this.batch([g,this.stmt("UPDATE jwt_v2_objects SET state='ACTIVE',semantic_revision=?,receipt_json=? WHERE object_key=?",revision,canonical(receipt),key),clear]);
 }
 family(sid){return this.first('SELECT * FROM jwt_v2_families WHERE sid=?',sid);}
 async createFamily(family,{before=[],after=[]}={}){
  const f=family,c=f.binding,projection=canonical(f.projection),binding=canonical(c),state=f.state||'UNLOCKED';
  requireThat(['UNLOCKED','ADMITTED_LOCKED'].includes(state),'INVALID_INITIAL_STATE',409);
  requireThat(c.ver===2&&c.env===this.env&&c.aud==='urn:uaa:'+this.env+':'+this.app+':api:v2','WRONG_FAMILY_NAMESPACE',409);
  requireThat(Array.isArray(f.vectorGuards)&&(state==='ADMITTED_LOCKED'||f.vectorGuards.length>0),'AUTHORITATIVE_VECTOR_REQUIRED',503);
  requireThat(safeInt(f.now)&&safeInt(f.deadline)&&safeInt(f.idleUntil)&&safeInt(f.policyMinutes,15)&&f.policyMinutes<=200&&f.idleUntil<=Math.min(c.s_exp,(f.lastRefresh??f.now)+f.policyMinutes*60),'INVALID_INITIAL_LEASE',409);
  if(state==='UNLOCKED')requireThat(f.deadline<=f.projection.timedUntil,'TIMED_AUTHORITY_EXPIRED',409);
  if(state==='UNLOCKED')await assertCaptureReceipt({capture:f.capture,binding:c,projection:f.projection,guards:f.vectorGuards,manifest:typeof this.dependencyManifest==='function'?this.dependencyManifest(c.sub):this.dependencyManifest,app:this.app,env:this.env,now:f.now});
  const vectorChecks=f.vectorGuards.map(([id,scope,epoch,revision])=>this.guard('SELECT 1 FROM jwt_v2_dependencies WHERE id=? AND scope=? AND owner_epoch=? AND revision=?',[id,scope,epoch,revision]));
  const [g,clear]=this.guard("SELECT 1 FROM jwt_v2_accounts a JOIN jwt_v2_parents p ON p.sub=a.sub JOIN jwt_v2_browsers b ON b.bsid=p.bsid WHERE a.sub=? AND a.active=1 AND a.ce=? AND a.ae=? AND a.le=? AND p.psid=? AND p.ce=a.ce AND p.ae=a.ae AND p.bv=? AND p.bsid=? AND p.state IN('UNLOCKED','LOCKED') AND (?='ADMITTED_LOCKED' OR p.state='UNLOCKED') AND p.s_exp=? AND p.s_exp>? AND b.bv=p.bv AND b.sub=a.sub AND b.psid=p.psid AND b.cancelled_through<p.bv",[c.sub,c.ce,c.ae,c.le,c.psid,c.bv,c.bsid,state,c.s_exp,f.now]);
  const [floor,floorClear]=admissionFloorGuard(this,c);
  const issuance=state==='UNLOCKED'?issuanceFloorGuard(this,{binding:c,projection:f.projection,vectorGuards:f.vectorGuards,state,now:f.now}):[null,null];
  const policyPlan=familyPolicyRegistrationPlan(this,{sid:c.sid,ownerEpoch:f.projection.policyEpoch,revision:f.projection.policyRevision,minutes:f.policyMinutes,now:f.now});
  await this.batch([...before,g,floor,...(issuance[0]?[issuance[0]]:[]),...vectorChecks.map(x=>x[0]),this.stmt("INSERT INTO jwt_v2_families(sid,sub,psid,bsid,bv,ce,ae,le,sv,ue,cr,state,s_iat,s_exp,vat,deadline,idle_until,last_refresh,policy_minutes,fingerprint,fingerprint_generation,binding_json,projection_json,authority_ready) VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,1,?,?,?)",c.sid,c.sub,c.psid,c.bsid,c.bv,c.ce,c.ae,c.le,c.sv,c.ue,f.state||'UNLOCKED',c.s_iat,c.s_exp,c.vat,f.deadline,f.idleUntil,f.lastRefresh??f.now,f.policyMinutes,f.fingerprint,binding,projection,Number(state==='UNLOCKED')),...policyPlan,...vectorChecks.map(x=>x[1]),...(issuance[1]?[issuance[1]]:[]),floorClear,clear,...after]);
 }
 async intent({sid,csrfHash,now,kind='refresh'}){
  const f=await this.family(sid);requireThat(f&&f.s_exp>now,'SESSION_ENDED');
  const previous=await this.first("SELECT * FROM jwt_v2_intents WHERE sid=? AND kind=? AND generation=? AND state='ISSUED'",sid,kind,f.fingerprint_generation);
  if(previous)return previous;
  const record={intent_id:crypto.randomUUID(),sid,kind,binding_json:f.binding_json,csrf_hash:csrfHash,generation:f.fingerprint_generation,state:'ISSUED',expires_at:f.s_exp};
  const [g,clear]=this.guard("SELECT 1 FROM jwt_v2_families WHERE sid=? AND binding_json=? AND fingerprint_generation=? AND state NOT IN('REVOKED','EXPIRED')",[sid,f.binding_json,f.fingerprint_generation]);
  try{await this.batch([g,this.stmt("INSERT INTO jwt_v2_intents(intent_id,sid,kind,binding_json,csrf_hash,generation,state,expires_at) VALUES(?,?,?,?,?,?,'ISSUED',?)",record.intent_id,sid,kind,record.binding_json,csrfHash,record.generation,record.expires_at),clear]);return record;}
  catch(error){const other=await this.first("SELECT * FROM jwt_v2_intents WHERE sid=? AND kind=? AND generation=? AND state='ISSUED'",sid,kind,f.fingerprint_generation);if(other)return other;throw error;}
 }
 async terminate(sid,{operationId,state='REVOKED'}){
  requireThat(['REVOKED','EXPIRED','LOCKED'].includes(state),'INVALID_TRANSITION',400);
  await this.batch([this.stmt("UPDATE jwt_v2_families SET state=?,cr=cr+1 WHERE sid=? AND state NOT IN('REVOKED','EXPIRED')",state,sid),this.stmt("UPDATE jwt_v2_intents SET state='CANCELLED',superseding_operation=? WHERE sid=? AND state='ISSUED'",operationId,sid)]);
 }
 async rotate({sid,fingerprint,intentId,csrfHash,expectedBinding,successorFingerprint,nextBinding,nextProjection,now,idleUntil,deadline,vectorGuards,qualifyingActivity,capture,requireBarrier=false}){
  requireThat(typeof qualifyingActivity==='boolean','ACTIVITY_CLASSIFICATION_REQUIRED',400);
  requireThat(Array.isArray(vectorGuards)&&vectorGuards.length>0,'AUTHORITATIVE_VECTOR_REQUIRED',503);
  const f=await this.family(sid);requireThat(f,'SESSION_ENDED');
  const i=await this.first('SELECT * FROM jwt_v2_intents WHERE intent_id=?',intentId);
  const original=canonical(expectedBinding);
  if(!i||i.sid!==sid||!equal(i.csrf_hash,csrfHash)||i.binding_json!==original)reject('UNPROVEN_OPERATION',409);
  if(i.state!=='ISSUED')return {winner:false,code:'OPERATION_SUPERSEDED',cookies:false};
  if(f.state!=='UNLOCKED'||now>=Math.min(f.s_exp,f.idle_until))return {winner:false,code:f.state==='LOCKED'?'PIN_REQUIRED':'SESSION_ENDED',cookies:false};
  requireThat(f.binding_json===original&&f.fingerprint===fingerprint&&i.generation===f.fingerprint_generation,'REFRESH_SUPERSEDED',409);
  requireThat(nextBinding.sv===f.sv+1&&nextBinding.ue===f.ue&&nextBinding.vat>=f.s_iat&&nextBinding.vat<=now&&deadline<=Math.min(nextBinding.vat+900,idleUntil,f.s_exp),'INVALID_RENEWAL',409);
  requireThat(deadline<=nextProjection.timedUntil,'TIMED_AUTHORITY_EXPIRED',409);
  await assertCaptureReceipt({capture,binding:nextBinding,projection:nextProjection,guards:vectorGuards,manifest:typeof this.dependencyManifest==='function'?this.dependencyManifest(f.sub):this.dependencyManifest,app:this.app,env:this.env,now});
  for(const field of 'ver env iss aud sub sid psid bsid bv ce ae le ue s_iat s_exp'.split(' '))requireThat(nextBinding[field]===expectedBinding[field],'IMMUTABLE_RENEWAL_BINDING',409);
  requireThat(idleUntil>now&&idleUntil===Math.min(f.s_exp,(qualifyingActivity?now:f.last_refresh)+f.policy_minutes*60),'INVALID_INACTIVITY_EXTENSION',409);
  requireThat(canonical(nextProjection.binding)===canonical(nextBinding),'INVALID_PROJECTION_BINDING',409);
  const [g,clear]=this.guard("SELECT 1 FROM jwt_v2_families f JOIN jwt_v2_accounts a ON a.sub=f.sub JOIN jwt_v2_parents p ON p.psid=f.psid JOIN jwt_v2_browsers b ON b.bsid=f.bsid JOIN jwt_v2_intents i ON i.sid=f.sid WHERE f.sid=? AND f.fingerprint=? AND f.binding_json=? AND f.state='UNLOCKED' AND f.idle_until>? AND f.s_exp>? AND a.active=1 AND a.ce=f.ce AND a.ae=f.ae AND a.le=f.le AND p.state='UNLOCKED' AND p.ce=f.ce AND p.ae=f.ae AND b.bv=f.bv AND b.cancelled_through<f.bv AND i.intent_id=? AND i.state='ISSUED' AND i.expires_at>?",[sid,fingerprint,original,now,now,intentId,now]);
  const result={sid,sv:nextBinding.sv,deadline,operationId:intentId};
  const guards=vectorGuards.map(([id,scope,epoch,revision])=>this.guard("SELECT 1 FROM jwt_v2_dependencies WHERE id=? AND scope=? AND owner_epoch=? AND revision=?",[id,scope,epoch,revision]));
  const [floor,floorClear]=admissionFloorGuard(this,expectedBinding);
  const [issuance,issuanceClear]=issuanceFloorGuard(this,{binding:nextBinding,projection:nextProjection,vectorGuards,existingSid:sid,now});
  const barrierGuard=requireBarrier?this.guard("SELECT 1 FROM jwt_v2_ceremony_barriers WHERE psid=? AND bsid=? AND bv=? AND sub=? AND locked=0 AND idle_until>?",[f.psid,f.bsid,f.bv,f.sub,now]):[null,null];
  const items=[g,floor,issuance,...(barrierGuard[0]?[barrierGuard[0]]:[]),...guards.map(x=>x[0]),
   this.stmt('INSERT INTO jwt_v2_refresh_history(fingerprint,sid,generation,binding_json,csrf_hash,complete,spent_at,intent_id,s_exp) VALUES(?,?,?,?,?,1,?,?,?)',fingerprint,sid,f.fingerprint_generation,original,csrfHash,now,intentId,f.s_exp),
   this.stmt("UPDATE jwt_v2_families SET fingerprint=?,fingerprint_generation=fingerprint_generation+1,authority_ready=1,sv=sv+1,cr=cr+1,vat=?,deadline=?,idle_until=?,last_refresh=?,binding_json=?,projection_json=? WHERE sid=?",successorFingerprint,nextBinding.vat,deadline,idleUntil,qualifyingActivity?now:f.last_refresh,canonical(nextBinding),canonical(nextProjection),sid),
   ...(this.app==='academy'&&qualifyingActivity?[this.stmt("UPDATE jwt_v2_parents SET foreground_at=? WHERE psid=? AND sub=? AND bsid=? AND bv=? AND ce=? AND ae=? AND state='UNLOCKED'",now,f.psid,f.sub,f.bsid,f.bv,f.ce,f.ae)]:[]),
   this.stmt('INSERT INTO jwt_v2_ceremony_barriers VALUES(?,?,?,?,?,?,0,1) ON CONFLICT(psid,bsid,bv,sub) DO UPDATE SET last_refresh=excluded.last_refresh,idle_until=excluded.idle_until,revision=revision+1',f.psid,f.bsid,f.bv,f.sub,qualifyingActivity?now:f.last_refresh,idleUntil),
   this.stmt("UPDATE jwt_v2_intents SET state=CASE WHEN intent_id=? THEN 'COMMITTED' ELSE 'SUPERSEDED' END,result_json=?,superseding_operation=? WHERE sid=? AND state='ISSUED'",intentId,canonical(result),intentId,sid),
   this.stmt("INSERT INTO jwt_v2_operations VALUES(?,?, 'refresh',?,?,?)",intentId,f.sub,await digest({fingerprint,intentId,binding:expectedBinding}),canonical(result),now),
   ...guards.map(x=>x[1]),...(barrierGuard[1]?[barrierGuard[1]]:[]),issuanceClear,floorClear,clear];
  try{await this.batch(items);return {winner:true,result,cookies:true};}
  catch(error){const winner=await this.first('SELECT state FROM jwt_v2_intents WHERE intent_id=?',intentId);if(winner?.state!=='ISSUED')return {winner:false,code:'REFRESH_SUPERSEDED',cookies:false};throw error;}
 }
 async classifyReuse({fingerprint,intentId,binding,csrfHash,now,kind='refresh'}){
  const h=await this.first('SELECT * FROM jwt_v2_refresh_history WHERE fingerprint=?',fingerprint);
  if(!h||!h.complete||now>=h.s_exp||h.binding_json!==canonical(binding)||!equal(h.csrf_hash,csrfHash))return {incidentEligible:false};
  const known=await this.first('SELECT * FROM jwt_v2_intents WHERE intent_id=?',intentId);
  if(known&&known.sid===h.sid&&known.binding_json===h.binding_json&&known.kind===kind&&known.generation===h.generation&&equal(known.csrf_hash,csrfHash)&&['COMMITTED','CANCELLED','SUPERSEDED'].includes(known.state))return {incidentEligible:false,reason:'KNOWN_LEGITIMATE_INTENT'};
  // The complete spent binding and genuine original issued-intent receipt are required.
  const issued=await this.first('SELECT * FROM jwt_v2_intents WHERE intent_id=?',h.intent_id);
  if(!issued||issued.state!=='COMMITTED'||issued.kind!==kind||issued.binding_json!==h.binding_json||issued.generation!==h.generation)return {incidentEligible:false};
  return {incidentEligible:true,sub:binding.sub,ce:binding.ce,ae:binding.ae,sid:h.sid};
 }
 async acceptCutoff({sub,ce,ae,operationId,kind,now}){
  requireThat(this.app==='academy'&&safeInt(ce,1)&&safeInt(ae,1),'WRONG_CANONICAL_OWNER',403);
  requireThat(['VOLUNTARY_LOGOUT','VERIFIED_REFRESH_REUSE','SUSPICIOUS_ACTIVITY','CONFIRMED_KEY_COMPROMISE','ACCOUNT_DISABLED'].includes(kind),'INVALID_CUTOFF',400);
  const requestDigest=await digest({sub,ce,ae,kind}),old=await this.first('SELECT * FROM jwt_v2_operations WHERE operation_id=?',operationId);
  if(old){requireThat(old.request_digest===requestDigest,'OPERATION_CONFLICT',409);return JSON.parse(old.result_json);}
  const a=await this.first('SELECT * FROM jwt_v2_accounts WHERE sub=?',sub);requireThat(a,'ACCOUNT_UNAVAILABLE',503);
  if(ce<a.ce||(ce===a.ce&&ae<a.ae)){
   const receipt=await this.first('SELECT operation_id,target_json FROM jwt_v2_cutoffs WHERE sub=? AND ce=? AND ae=?',sub,ce,ae);
   return receipt?{status:'ALREADY_COVERED',cutoff:JSON.parse(receipt.target_json),receipt:receipt.operation_id}:{status:'RECONCILIATION_REQUIRED',cutoff:null};
  }
  if(ce!==a.ce||ae!==a.ae)return {status:'RECONCILIATION_REQUIRED',cutoff:null};
  requireThat(safeInt(a.ae+1,1),'EPOCH_EXHAUSTED',503);
  const cutoff={type:'accountCutoff',sub,maxCe:ce,maxAe:ae,reason:kind,incidentId:kind==='VOLUNTARY_LOGOUT'?null:operationId},result={status:'ACCEPTED',cutoff,receipt:operationId};
  const localWork=await restrictionPlan(this,{workId:operationId,target:cutoff,now});
  const outbox=[],streamGuards=[],streamUpdates=[],streamClears=[];
  for(const targetApp of ['studio','hifz']){
   const stream=await this.first('SELECT * FROM jwt_v2_sender_streams WHERE target_app=? AND stream=?',targetApp,'account-security');
   requireThat(stream&&safeInt(stream.next_sequence+1,1),'OUTBOX_STREAM_UNAVAILABLE',503);
   const e={schema:2,env:this.env,sourceApp:'academy',targetApp,eventId:crypto.randomUUID(),operationId,stream:stream.stream,ownerEpoch:stream.owner_epoch,sequence:stream.next_sequence,sub,kind:'account-revoked',target:cutoff,committedAt:now,commitRef:operationId};
   e.digest=await digest(e);outbox.push(e);
   const [sg,sc]=this.guard('SELECT 1 FROM jwt_v2_sender_streams WHERE target_app=? AND stream=? AND owner_epoch=? AND next_sequence=?',[targetApp,stream.stream,stream.owner_epoch,stream.next_sequence]);
   streamGuards.push(sg);streamClears.push(sc);
   streamUpdates.push(this.stmt('UPDATE jwt_v2_sender_streams SET next_sequence=next_sequence+1 WHERE target_app=? AND stream=?',targetApp,stream.stream));
  }
  const [g,clear]=this.guard('SELECT 1 FROM jwt_v2_accounts WHERE sub=? AND ce=? AND ae=?',[sub,ce,ae]);
  await this.batch([g,...streamGuards,...streamUpdates,this.stmt('UPDATE jwt_v2_accounts SET ae=ae+1,revision=revision+1 WHERE sub=?',sub),
   this.stmt('INSERT INTO jwt_v2_cutoffs VALUES(?,?,?,?,?)',sub,ce,ae,operationId,canonical(cutoff)),
   this.stmt('INSERT INTO jwt_v2_operations VALUES(?,?,?,?,?,?)',operationId,sub,kind,requestDigest,canonical(result),now),
   ...localWork,
   this.stmt("UPDATE jwt_v2_http_transactions SET status='CANCELLED' WHERE sub=? AND status='PENDING'",sub),
   this.stmt("UPDATE jwt_v2_parents SET state='REVOKED' WHERE sub=? AND (ce<? OR (ce=? AND ae<=?))",sub,ce,ce,ae),
   this.stmt("UPDATE jwt_v2_ceremonies SET status='CANCELLED' WHERE sub=? AND status IN('PENDING','CODE_ISSUED','GRANTED')",sub),
   this.stmt("UPDATE jwt_v2_ceremony_attempts SET status='CANCELLED' WHERE sub=? AND status IN('ISSUED','RESERVED')",sub),
   this.stmt('UPDATE jwt_v2_pin_gates SET reservation=NULL,reservation_until=NULL WHERE sub=?',sub),
   this.stmt('DELETE FROM jwt_v2_ceremony_reservations WHERE sub=?',sub),
   ...outbox.map(e=>this.stmt('INSERT INTO jwt_v2_outbox(event_id,event_json,digest,target_app) VALUES(?,?,?,?)',e.eventId,canonical(e),e.digest,e.targetApp)),...streamClears,clear]);
  return result;
 }
}
export function targeted(binding,target){
 switch(target.type){
  case 'accountCutoff':return binding.sub===target.sub&&(binding.ce<target.maxCe||binding.ce===target.maxCe&&binding.ae<=target.maxAe);
  case 'credentialEpoch':return binding.sub===target.sub&&binding.ce<target.newCe;
  case 'parent':return ['sub','psid','bsid','bv','ce','ae'].every(k=>binding[k]===target[k]);
  case 'browser':return binding.bsid===target.bsid&&binding.bv<=target.maxBv;
  case 'localEpoch':return binding.sub===target.sub&&binding.ce===target.ce&&binding.ae===target.ae&&binding.le<=target.maxLe;
  default:return false;
 }
}
