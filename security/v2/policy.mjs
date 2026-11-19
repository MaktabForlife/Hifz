import {canonical,exact,requireThat,reject,ascii,safeInt,uuid,digest} from './codec.mjs';

// Imported by an explicit reviewed additive recipe only; never executed at import/request time.
export const policySchemaSQL=[
 "CREATE TABLE IF NOT EXISTS jwt_v2_policy_epochs(owner_epoch TEXT PRIMARY KEY,base_revision INTEGER NOT NULL CHECK(base_revision>0),highest_seen INTEGER NOT NULL CHECK(highest_seen>0),coherent_through INTEGER NOT NULL CHECK(coherent_through>=0),predecessor_epoch TEXT,predecessor_final_revision INTEGER,sealed_through INTEGER,receipt_ref TEXT NOT NULL);",
 "CREATE TABLE IF NOT EXISTS jwt_v2_policy_heads(app TEXT NOT NULL,env TEXT NOT NULL,owner_epoch TEXT NOT NULL REFERENCES jwt_v2_policy_epochs(owner_epoch),PRIMARY KEY(app,env));",
 "CREATE TABLE IF NOT EXISTS jwt_v2_policy_history(owner_epoch TEXT NOT NULL REFERENCES jwt_v2_policy_epochs(owner_epoch),revision INTEGER NOT NULL CHECK(revision>0),minutes INTEGER NOT NULL CHECK(minutes BETWEEN 15 AND 200),target_json TEXT NOT NULL,target_digest TEXT NOT NULL,received_at INTEGER NOT NULL,PRIMARY KEY(owner_epoch,revision));",
 "CREATE TABLE IF NOT EXISTS jwt_v2_policy_coverage(receipt_ref TEXT PRIMARY KEY,coverage_json TEXT NOT NULL,created_at INTEGER NOT NULL);",
 "CREATE TABLE IF NOT EXISTS jwt_v2_family_policy(sid TEXT PRIMARY KEY REFERENCES jwt_v2_families(sid),owner_epoch TEXT NOT NULL,applied_revision INTEGER NOT NULL CHECK(applied_revision>0),observed_digest TEXT,history_complete INTEGER NOT NULL CHECK(history_complete IN(0,1)),locked_at INTEGER,last_job_id TEXT);",
 "CREATE TABLE IF NOT EXISTS jwt_v2_policy_publications(job_id TEXT PRIMARY KEY,sid TEXT NOT NULL,observation_digest TEXT NOT NULL,owner_epoch TEXT NOT NULL,revision INTEGER NOT NULL,target_json TEXT NOT NULL,expected_cr INTEGER NOT NULL,state TEXT NOT NULL CHECK(state IN('PENDING','APPLIED')),created_at INTEGER NOT NULL,UNIQUE(sid,observation_digest));",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_policy_history_immutable BEFORE UPDATE ON jwt_v2_policy_history BEGIN SELECT RAISE(ABORT,'jwt_v2_policy_history_immutable'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_policy_revision_monotonic BEFORE UPDATE ON jwt_v2_policy_epochs WHEN NEW.owner_epoch<>OLD.owner_epoch OR NEW.base_revision<>OLD.base_revision OR NEW.predecessor_epoch IS NOT OLD.predecessor_epoch OR NEW.predecessor_final_revision IS NOT OLD.predecessor_final_revision OR NEW.highest_seen<OLD.highest_seen OR NEW.coherent_through<OLD.coherent_through OR (OLD.sealed_through IS NOT NULL AND NEW.sealed_through IS NOT OLD.sealed_through) BEGIN SELECT RAISE(ABORT,'jwt_v2_policy_epoch'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_policy_publication_immutable BEFORE UPDATE ON jwt_v2_policy_publications WHEN NEW.job_id<>OLD.job_id OR NEW.sid<>OLD.sid OR NEW.observation_digest<>OLD.observation_digest OR NEW.owner_epoch<>OLD.owner_epoch OR NEW.revision<>OLD.revision OR NEW.target_json<>OLD.target_json OR NEW.expected_cr<>OLD.expected_cr BEGIN SELECT RAISE(ABORT,'jwt_v2_policy_publication_immutable'); END;"
].join('\n');

const policyFields=['type','policyId','ownerEpoch','revision','inactivityMinutes'];
export function validatePolicy(target){
 exact(target,policyFields);
 requireThat(target.type==='policy'&&target.policyId==='session-inactivity'&&ascii(target.ownerEpoch)&&safeInt(target.revision,1)&&safeInt(target.inactivityMinutes,15)&&target.inactivityMinutes<=200,'INVALID_INACTIVITY_POLICY',400);
 return target;
}
const targetFor=(ownerEpoch,revision,inactivityMinutes)=>({type:'policy',policyId:'session-inactivity',ownerEpoch,revision,inactivityMinutes});
const clock=now=>requireThat(safeInt(now),'INVALID_POLICY_TIME',503);
const scope=store=>{requireThat(['academy','studio','hifz'].includes(store.app)&&['production','feature'].includes(store.env),'INVALID_POLICY_OWNER',503);};
async function currentHead(store){
 const head=await store.first('SELECT h.app,h.env,e.* FROM jwt_v2_policy_heads h JOIN jwt_v2_policy_epochs e USING(owner_epoch) WHERE h.app=? AND h.env=?',store.app,store.env);
 requireThat(head,'POLICY_NOT_INITIALISED',503);return head;
}
function epochGuard(store,epoch){
 return store.guard('SELECT 1 FROM jwt_v2_policy_epochs WHERE owner_epoch=? AND highest_seen=? AND coherent_through=? AND sealed_through IS ?',[epoch.owner_epoch,epoch.highest_seen,epoch.coherent_through,epoch.sealed_through]);
}

// Deployment/configured genesis only. Public requests must never call this with wire-selected values.
export async function seedPolicy(store,{ownerEpoch,revision=1,minutes=90,receiptRef,now}){
 scope(store);clock(now);const target=validatePolicy(targetFor(ownerEpoch,revision,minutes));
 requireThat(ascii(receiptRef),'POLICY_GENESIS_RECEIPT_REQUIRED',503);
 const existing=await store.first('SELECT owner_epoch FROM jwt_v2_policy_heads WHERE app=? AND env=?',store.app,store.env);
 if(existing){
  const row=await store.first('SELECT target_json FROM jwt_v2_policy_history WHERE owner_epoch=? AND revision=?',ownerEpoch,revision);
  requireThat(existing.owner_epoch===ownerEpoch&&row?.target_json===canonical(target),'POLICY_GENESIS_CONFLICT',409);return {created:false};
 }
 await store.batch([
  store.stmt('INSERT INTO jwt_v2_policy_epochs VALUES(?,?,?,?,NULL,NULL,NULL,?)',ownerEpoch,revision,revision,revision,receiptRef),
  store.stmt('INSERT INTO jwt_v2_policy_history VALUES(?,?,?,?,?,?)',ownerEpoch,revision,minutes,canonical(target),await digest(target),now),
  store.stmt('INSERT INTO jwt_v2_policy_heads VALUES(?,?,?)',store.app,store.env,ownerEpoch)
 ]);
 return {created:true};
}

// Called only after authenticated explicit predecessor/genesis evidence. No UUID/lexical ordering.
export async function registerPolicySuccessor(store,{ownerEpoch,baseRevision=1,minutes=90,predecessorEpoch,predecessorFinalRevision,receiptRef,now}){
 scope(store);clock(now);const target=validatePolicy(targetFor(ownerEpoch,baseRevision,minutes));
 requireThat(ascii(predecessorEpoch)&&ownerEpoch!==predecessorEpoch&&safeInt(predecessorFinalRevision,1)&&ascii(receiptRef),'INVALID_POLICY_BRIDGE',409);
 const head=await currentHead(store);
 requireThat(head.owner_epoch===predecessorEpoch&&predecessorFinalRevision>=head.highest_seen,'POLICY_BRIDGE_REQUIRED',409);
 const existing=await store.first('SELECT * FROM jwt_v2_policy_epochs WHERE owner_epoch=?',ownerEpoch);
 if(existing){
  const row=await store.first('SELECT target_json FROM jwt_v2_policy_history WHERE owner_epoch=? AND revision=?',ownerEpoch,baseRevision);
  requireThat(existing.predecessor_epoch===predecessorEpoch&&existing.predecessor_final_revision===predecessorFinalRevision&&row?.target_json===canonical(target),'POLICY_BRIDGE_CONFLICT',409);return {created:false};
 }
 const [guard,clear]=epochGuard(store,head);
 await store.batch([
  guard,
  store.stmt('UPDATE jwt_v2_policy_epochs SET sealed_through=? WHERE owner_epoch=?',predecessorFinalRevision,predecessorEpoch),
  store.stmt('INSERT INTO jwt_v2_policy_epochs VALUES(?,?,?,?,?,?,NULL,?)',ownerEpoch,baseRevision,baseRevision,baseRevision-1,predecessorEpoch,predecessorFinalRevision,receiptRef),
  store.stmt('INSERT INTO jwt_v2_policy_history VALUES(?,?,?,?,?,?)',ownerEpoch,baseRevision,minutes,canonical(target),await digest(target),now),
  clear
 ]);
 return {created:true};
}

export async function stagePolicy(store,{target,now}){
 scope(store);clock(now);validatePolicy(target);
 const epoch=await store.first('SELECT * FROM jwt_v2_policy_epochs WHERE owner_epoch=?',target.ownerEpoch);
 requireThat(epoch,'POLICY_EPOCH_RECONCILIATION_REQUIRED',409);
 requireThat(target.revision>=epoch.base_revision&&(epoch.sealed_through===null||target.revision<=epoch.sealed_through),'POLICY_BRIDGE_CONFLICT',409);
 const old=await store.first('SELECT * FROM jwt_v2_policy_history WHERE owner_epoch=? AND revision=?',target.ownerEpoch,target.revision);
 if(old){requireThat(old.target_json===canonical(target),'POLICY_REVISION_CONFLICT',409);return {captured:false};}
 const [guard,clear]=epochGuard(store,epoch);
 await store.batch([
  guard,
  store.stmt('INSERT INTO jwt_v2_policy_history VALUES(?,?,?,?,?,?)',target.ownerEpoch,target.revision,target.inactivityMinutes,canonical(target),await digest(target),now),
  store.stmt('UPDATE jwt_v2_policy_epochs SET highest_seen=max(highest_seen,?) WHERE owner_epoch=?',target.revision,target.ownerEpoch),
  clear
 ]);
 return {captured:true};
}

/*
 * trustedCoverage is produced only by the owning C19 verifier after authenticated
 * contiguous event history or a complete verified snapshot. A last page, watermark,
 * raw boolean or unauthenticated browser input is not such a receipt.
 */
export async function confirmPolicyHistory(store,{trustedCoverage,now}){
 scope(store);clock(now);
 const c=exact(trustedCoverage,['schema','env','sourceApp','targetApp','mode','ownerEpoch','throughRevision','receiptRef']);
 requireThat(c.schema===2&&c.env===store.env&&c.sourceApp==='academy'&&c.targetApp===store.app&&['CONTIGUOUS_EVENTS','VERIFIED_SNAPSHOT'].includes(c.mode)&&ascii(c.ownerEpoch)&&safeInt(c.throughRevision,1)&&ascii(c.receiptRef),'INVALID_POLICY_COVERAGE',409);
 const old=await store.first('SELECT coverage_json FROM jwt_v2_policy_coverage WHERE receipt_ref=?',c.receiptRef);
 if(old){requireThat(old.coverage_json===canonical(c),'POLICY_COVERAGE_CONFLICT',409);return {confirmed:false};}
 const epoch=await store.first('SELECT * FROM jwt_v2_policy_epochs WHERE owner_epoch=?',c.ownerEpoch),head=await currentHead(store);
 requireThat(epoch&&c.throughRevision>=epoch.coherent_through&&c.throughRevision>=epoch.base_revision&&c.throughRevision<=epoch.highest_seen,'POLICY_HISTORY_UNAVAILABLE',409);
 const count=await store.first('SELECT count(*) n FROM jwt_v2_policy_history WHERE owner_epoch=? AND revision BETWEEN ? AND ?',c.ownerEpoch,epoch.base_revision,c.throughRevision);
 requireThat(count.n===c.throughRevision-epoch.base_revision+1,'POLICY_HISTORY_GAP',409);
 if(head.owner_epoch!==c.ownerEpoch){
  requireThat(epoch.predecessor_epoch===head.owner_epoch&&head.sealed_through===epoch.predecessor_final_revision&&head.coherent_through>=epoch.predecessor_final_revision&&head.highest_seen<=epoch.predecessor_final_revision,'POLICY_BRIDGE_REQUIRED',409);
 }
 const [guard,clear]=epochGuard(store,epoch),[headGuard,headClear]=epochGuard(store,head);
 await store.batch([
  guard,headGuard,
  store.stmt('INSERT INTO jwt_v2_policy_coverage VALUES(?,?,?)',c.receiptRef,canonical(c),now),
  store.stmt('UPDATE jwt_v2_policy_epochs SET coherent_through=? WHERE owner_epoch=?',c.throughRevision,c.ownerEpoch),
  store.stmt('UPDATE jwt_v2_policy_heads SET owner_epoch=? WHERE app=? AND env=? AND owner_epoch=?',c.ownerEpoch,store.app,store.env,head.owner_epoch),
  headClear,clear
 ]);
 return {confirmed:true};
}

// Compose these with new-family creation/admission. They never create/mutate a family themselves.
export function familyPolicyRegistrationPlan(store,{sid,ownerEpoch,revision,minutes,now}){
 scope(store);clock(now);validatePolicy(targetFor(ownerEpoch,revision,minutes));requireThat(uuid(sid),'INVALID_POLICY_FAMILY',409);
 const [guard,clear]=store.guard("SELECT 1 FROM jwt_v2_families f JOIN jwt_v2_policy_heads h ON h.app=? AND h.env=? JOIN jwt_v2_policy_epochs e ON e.owner_epoch=h.owner_epoch JOIN jwt_v2_policy_history p ON p.owner_epoch=e.owner_epoch AND p.revision=e.coherent_through WHERE f.sid=? AND e.owner_epoch=? AND e.coherent_through=? AND e.coherent_through=e.highest_seen AND p.minutes=? AND f.policy_minutes=p.minutes AND f.last_refresh<=? AND f.idle_until<=min(f.s_exp,f.last_refresh+p.minutes*60) AND (f.state<>'UNLOCKED' OR (f.idle_until>? AND f.s_exp>?))",[store.app,store.env,sid,ownerEpoch,revision,minutes,now,now,now]);
 return [guard,store.stmt('INSERT INTO jwt_v2_family_policy(sid,owner_epoch,applied_revision,history_complete) VALUES(?,?,?,1)',sid,ownerEpoch,revision),clear];
}
export async function registerFamilyPolicy(store,options){await store.batch(familyPolicyRegistrationPlan(store,options));}

async function policyPath(store,head,applied){
 const path=[];let item=head;const seen=new Set();
 for(let depth=0;depth<16;depth++){
  requireThat(!seen.has(item.owner_epoch),'POLICY_EPOCH_CYCLE',503);seen.add(item.owner_epoch);path.unshift(item);
  if(item.owner_epoch===applied.owner_epoch)return path;
  requireThat(item.predecessor_epoch,'POLICY_FAMILY_RECONCILIATION_REQUIRED',503);
  const previous=await store.first('SELECT * FROM jwt_v2_policy_epochs WHERE owner_epoch=?',item.predecessor_epoch);
  requireThat(previous&&previous.sealed_through===item.predecessor_final_revision&&previous.coherent_through>=item.predecessor_final_revision,'POLICY_BRIDGE_REQUIRED',503);item=previous;
 }
 reject('POLICY_EPOCH_CHAIN_LIMIT',503);
}

export async function prepareFamilyPolicy(store,{sid,now,publicationPlan=()=>[]}){
 scope(store);clock(now);
 const family=await store.family(sid),applied=await store.first('SELECT * FROM jwt_v2_family_policy WHERE sid=?',sid),head=await currentHead(store);
 requireThat(family&&applied,'POLICY_FAMILY_NOT_REGISTERED',503);
 requireThat(safeInt(family.last_refresh)&&family.last_refresh<=now&&safeInt(family.idle_until)&&safeInt(family.s_exp),'POLICY_CLOCK_UNAVAILABLE',503);
 const path=await policyPath(store,head,applied),pending=head.highest_seen!==head.coherent_through;
 const records=[];
 for(let i=0;i<path.length;i++){
  const epoch=path[i],first=i===0?applied.applied_revision+1:epoch.base_revision,last=i===path.length-1?head.highest_seen:path[i+1].predecessor_final_revision;
  if(last<first)continue;
  const rows=await store.all('SELECT * FROM jwt_v2_policy_history WHERE owner_epoch=? AND revision BETWEEN ? AND ? ORDER BY revision LIMIT 2001',epoch.owner_epoch,first,last);
  requireThat(rows.length<=2000&&records.length+rows.length<=2000,'POLICY_HISTORY_LIMIT',503);
  if(!pending||i<path.length-1)requireThat(rows.length===last-first+1,'POLICY_HISTORY_GAP',503);
  records.push(...rows);
 }
 const parent=await store.first('SELECT * FROM jwt_v2_parents WHERE psid=?',family.psid);
 requireThat(parent&&parent.sub===family.sub&&parent.bsid===family.bsid&&parent.bv===family.bv&&parent.ce===family.ce&&parent.ae===family.ae&&parent.s_exp===family.s_exp,'POLICY_PARENT_BINDING_UNAVAILABLE',503);
 let state=family.state,idleUntil=family.idle_until,minutes=family.policy_minutes,validationDeadline=family.deadline;
 if(!['REVOKED','EXPIRED'].includes(state)&&parent.state==='REVOKED')state='REVOKED';
 else if(state!=='REVOKED'&&parent.state==='EXPIRED')state='EXPIRED';
 else if(state==='UNLOCKED'&&parent.state==='LOCKED')state='LOCKED';
 // Expiry is tested before processing a new duration and before any possible activity credit.
 if(state==='UNLOCKED'&&now>=family.s_exp)state='EXPIRED';
 else if(state==='UNLOCKED'&&now>=idleUntil)state='LOCKED';
 for(const row of records){
  const candidate=Math.min(family.s_exp,family.last_refresh+row.minutes*60);
  // Missing/interleaved history may shorten, but never lengthen or enable.
  if(pending){
   if(candidate<idleUntil){idleUntil=candidate;minutes=Math.min(minutes,row.minutes);}
  }else if(state==='UNLOCKED'){
   idleUntil=candidate;minutes=row.minutes;
  }else{
   idleUntil=Math.min(idleUntil,candidate);minutes=row.minutes;
  }
  if(state==='UNLOCKED'&&now>=idleUntil)state='LOCKED';
 }
 validationDeadline=Math.min(validationDeadline,idleUntil,family.s_exp);
 const nextEpoch=pending?applied.owner_epoch:head.owner_epoch,nextRevision=pending?applied.applied_revision:head.coherent_through;
 const observation={ownerEpoch:head.owner_epoch,highestSeen:head.highest_seen,coherentThrough:head.coherent_through,targets:records.map(r=>JSON.parse(r.target_json)),state,idleUntil,minutes,lastRefresh:family.last_refresh,s_exp:family.s_exp};
 const observationDigest=await digest(observation);
 const policyChanged=nextEpoch!==applied.owner_epoch||nextRevision!==applied.applied_revision||pending&&applied.observed_digest!==observationDigest||applied.history_complete!==Number(!pending);
 const familyChanged=state!==family.state||idleUntil!==family.idle_until||minutes!==family.policy_minutes||validationDeadline!==family.deadline;
 const result={sid,changed:policyChanged||familyChanged,ownerEpoch:head.owner_epoch,revision:head.highest_seen,appliedEpoch:nextEpoch,appliedRevision:nextRevision,historyComplete:!pending,requiresReconciliation:pending,state,idleUntil,validationDeadline,vat:family.vat,lastRefresh:family.last_refresh,s_exp:family.s_exp,authorityRebuildRequired:pending||family.authority_ready===0,enforcedPolicies:records.map(r=>JSON.parse(r.target_json)),parentState:parent.state};
 if(!result.changed)return {result,statements:[]};
 const latest=await store.first('SELECT target_json FROM jwt_v2_policy_history WHERE owner_epoch=? AND revision=?',head.owner_epoch,head.highest_seen);
 requireThat(latest,'POLICY_HISTORY_UNAVAILABLE',503);
 const target=JSON.parse(latest.target_json),jobId=crypto.randomUUID(),expectedCR=family.cr+1;
 requireThat(safeInt(expectedCR,1),'POLICY_REVISION_EXHAUSTED',503);
 const [guard,clear]=store.guard('SELECT 1 FROM jwt_v2_families f JOIN jwt_v2_family_policy p USING(sid) JOIN jwt_v2_parents parent ON parent.psid=f.psid JOIN jwt_v2_policy_heads h ON h.app=? AND h.env=? JOIN jwt_v2_policy_epochs e ON e.owner_epoch=h.owner_epoch WHERE f.sid=? AND f.cr=? AND f.binding_json=? AND f.last_refresh=? AND f.idle_until=? AND f.state=? AND p.owner_epoch=? AND p.applied_revision=? AND p.observed_digest IS ? AND e.owner_epoch=? AND e.highest_seen=? AND e.coherent_through=? AND parent.state=?',[store.app,store.env,sid,family.cr,family.binding_json,family.last_refresh,family.idle_until,family.state,applied.owner_epoch,applied.applied_revision,applied.observed_digest,head.owner_epoch,head.highest_seen,head.coherent_through,parent.state]);
 const locked=['LOCKED','ADMITTED_LOCKED'].includes(state),terminal=['REVOKED','EXPIRED'].includes(state);
 const lockParent=!['REVOKED','EXPIRED'].includes(family.state)&&(locked||state==='EXPIRED')&&parent.state==='UNLOCKED';
 result.parentLockSelector=lockParent?{sub:family.sub,psid:family.psid,bsid:family.bsid,bv:family.bv,ce:family.ce,ae:family.ae}:null;
 result.parentLockState=lockParent?(state==='EXPIRED'?'EXPIRED':'LOCKED'):null;
 const extra=await publicationPlan({store,sid,target,jobId,expectedCR,observationDigest,result});
 requireThat(Array.isArray(extra),'INVALID_POLICY_PUBLICATION_PLAN',503);
 return {result:{...result,publicationJobId:jobId,target,expectedCR},statements:[
  guard,
  store.stmt("UPDATE jwt_v2_families SET state=?,idle_until=?,deadline=?,policy_minutes=?,cr=cr+1,authority_ready=CASE WHEN ?=1 THEN 0 ELSE authority_ready END,projection_json=json_set(projection_json,'$.localState',?,'$.idleUntil',?,'$.validationDeadline',?,'$.policyRevision',?,'$.policyEpoch',?,'$.inactivityMinutes',?) WHERE sid=?",state,idleUntil,validationDeadline,minutes,Number(pending),state,idleUntil,validationDeadline,head.highest_seen,head.owner_epoch,minutes,sid),
  ...(lockParent?[store.stmt("UPDATE jwt_v2_parents SET state=CASE WHEN ?='EXPIRED' THEN 'EXPIRED' ELSE 'LOCKED' END WHERE psid=? AND state='UNLOCKED'",state,family.psid)]:[]),
  ...(locked||terminal?[store.stmt("UPDATE jwt_v2_intents SET state='CANCELLED',superseding_operation=? WHERE sid=? AND state='ISSUED'",jobId,sid)]:[]),
  store.stmt('UPDATE jwt_v2_family_policy SET owner_epoch=?,applied_revision=?,observed_digest=?,history_complete=?,locked_at=CASE WHEN ?=1 THEN COALESCE(locked_at,?) ELSE locked_at END,last_job_id=? WHERE sid=?',nextEpoch,nextRevision,observationDigest,Number(!pending),Number(locked),now,jobId,sid),
  store.stmt("INSERT INTO jwt_v2_policy_publications VALUES(?,?,?,?,?,?,?,'PENDING',?)",jobId,sid,observationDigest,head.owner_epoch,head.highest_seen,canonical(target),expectedCR,now),
  ...extra,clear
 ]};
}

export async function applyFamilyPolicy(store,options){
 const plan=await prepareFamilyPolicy(store,options);
 if(plan.statements.length){try{await store.batch(plan.statements);}catch{reject('POLICY_PERSISTENCE_UNAVAILABLE',503);}}
 return plan.result;
}
