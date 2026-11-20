import {canonical,strictJSON,exact,requireThat,ascii,safeInt,digest} from './codec.mjs';
import {exactContext} from './http-context.mjs';
import {validatePolicy} from './policy.mjs';

const same=(a,b)=>canonical(a)===canonical(b);
async function epochHistory(store,epoch,through){
 requireThat(epoch&&ascii(epoch.owner_epoch)&&ascii(epoch.receipt_ref)&&safeInt(epoch.base_revision,1)&&safeInt(through,1)&&through>=epoch.base_revision&&through<=epoch.coherent_through&&through<=epoch.highest_seen,'POLICY_HISTORY_NOT_COVERED',503);
 requireThat(through-epoch.base_revision<2000,'POLICY_HISTORY_LIMIT',503);
 const rows=await store.all('SELECT * FROM jwt_v2_policy_history WHERE owner_epoch=? AND revision BETWEEN ? AND ? ORDER BY revision',epoch.owner_epoch,epoch.base_revision,through);
 requireThat(rows.length===through-epoch.base_revision+1,'POLICY_HISTORY_GAP',503);
 for(let i=0;i<rows.length;i++){
  const row=rows[i],target=validatePolicy(strictJSON(row.target_json));
  requireThat(row.revision===epoch.base_revision+i&&target.ownerEpoch===epoch.owner_epoch&&target.revision===row.revision&&target.inactivityMinutes===row.minutes&&row.target_json===canonical(target)&&row.target_digest===await digest(target),'POLICY_HISTORY_CONFLICT',503);
 }
 // A configured root genesis is already a durable trusted receipt. Every later
 // range and every successor epoch needs the authenticated C19 coverage row.
 if(through===epoch.base_revision&&epoch.predecessor_epoch===null)return rows;
 const receipts=await store.all('SELECT * FROM jwt_v2_policy_coverage');
 let covered=false;
 for(const row of receipts){
  let c;try{c=exact(strictJSON(row.coverage_json),['schema','env','sourceApp','targetApp','mode','ownerEpoch','throughRevision','receiptRef']);}catch{continue;}
  if(c.schema===2&&c.env===store.env&&c.sourceApp==='academy'&&c.targetApp===store.app&&['CONTIGUOUS_EVENTS','VERIFIED_SNAPSHOT'].includes(c.mode)&&c.ownerEpoch===epoch.owner_epoch&&safeInt(c.throughRevision,1)&&c.throughRevision>=through&&c.throughRevision<=epoch.coherent_through&&c.receiptRef===row.receipt_ref&&ascii(c.receiptRef)&&row.coverage_json===canonical(c)){covered=true;break;}
 }
 requireThat(covered,'POLICY_COVERAGE_RECEIPT_REQUIRED',503);return rows;
}
async function publishedProjection(store,{projection,sid}){
 requireThat(projection?.schema===2&&projection.state==='ACTIVE'&&projection.app===store.app&&projection.env===store.env,'POLICY_PUBLICATION_REQUIRED',503);
 const key=store.controlKey(sid===null?'control/app':'security/session/'+sid),life=await store.lifecycle(key);
 requireThat(life?.state==='ACTIVE'&&life.receipt_json,'POLICY_PUBLICATION_RECEIPT_REQUIRED',503);
 const r=strictJSON(life.receipt_json);
 requireThat(r.incarnation===life.incarnation&&r.generation===life.generation&&r.cr===life.semantic_revision&&r.digest===await digest(projection)&&r.cr===projection.cr&&r.nonce===projection.publicationNonce&&r.incarnation===projection.incarnation&&r.generation===projection.generation,'POLICY_PUBLICATION_RECEIPT_MISMATCH',503);
}
async function matchingUnlock(store,f,lockedAt){
 if(f.state!=='UNLOCKED')return true;
 const rows=await store.all("SELECT c.*,p.purpose,p.expected_json,p.status pending_status FROM jwt_v2_ceremony_consumed c JOIN jwt_v2_ceremony_pending p USING(tx) WHERE c.consumed_at>=? AND p.purpose='unlock'",lockedAt);
 for(const row of rows){
  let result,expected;try{result=strictJSON(row.result_json);expected=exactContext(strictJSON(row.expected_json));if(expected.app!==store.app)continue;}catch{continue;}
  if(row.pending_status!=='COMMITTED'||result.status!=='COMMITTED'||result.state!=='UNLOCKED'||result.sid!==f.sid||result.ue!==f.ue||result.s_exp!==f.s_exp||result.operationId!==row.operation_id||!safeInt(result.sv,1)||result.sv>f.sv)continue;
  if(expected.sid!==f.sid||expected.sub!==f.sub||expected.psid!==f.psid||expected.bsid!==f.bsid||expected.bv!==f.bv||expected.ce!==f.ce||expected.ae!==f.ae||expected.le!==f.le||result.ue!==expected.ue+1||result.sv!==expected.sv+1)continue;
  return true;
 }
 return false;
}

/*
 * This is publication-time proof, never a warm-request or periodic Academy
 * check. Root still commits APPLIED only after every required SID/control
 * publication. History_complete/observation receipts are certificates produced
 * by the tested owning policy transition; their locked_at barrier cannot be
 * removed by a longer duration. A later authenticated local unlock may replace
 * it, and must have its own matching durable ceremony receipt.
 */
export async function verifiedPolicyCoverage(store,{target,projection,sid=null}){
 try{
  validatePolicy(target);requireThat(sid===null||typeof sid==='string','INVALID_POLICY_COVERAGE_SELECTOR',503);
  await publishedProjection(store,{projection,sid});
  const head=await store.first('SELECT e.* FROM jwt_v2_policy_heads h JOIN jwt_v2_policy_epochs e ON e.owner_epoch=h.owner_epoch WHERE h.app=? AND h.env=?',store.app,store.env);
  requireThat(head&&head.coherent_through===head.highest_seen&&head.sealed_through===null&&projection.policyEpoch===head.owner_epoch&&projection.policyRevision===head.highest_seen,'POLICY_CURRENT_HEAD_REQUIRED',503);
  const currentRows=await epochHistory(store,head,head.highest_seen),current=currentRows.at(-1);
  requireThat(current.minutes===projection.inactivityMinutes,'POLICY_CURRENT_VALUE_REQUIRED',503);
  let epoch=head,through=head.highest_seen,found=false;const seen=new Set();
  for(let depth=0;depth<16;depth++){
   requireThat(!seen.has(epoch.owner_epoch),'POLICY_EPOCH_CYCLE',503);seen.add(epoch.owner_epoch);
   const rows=depth===0?currentRows:await epochHistory(store,epoch,through);
   if(epoch.owner_epoch===target.ownerEpoch){
    const row=rows.find(r=>r.revision===target.revision);
    requireThat(row&&row.target_json===canonical(target)&&row.target_digest===await digest(target),'HISTORICAL_POLICY_TARGET_NOT_COVERED',503);found=true;break;
   }
   requireThat(epoch.predecessor_epoch&&safeInt(epoch.predecessor_final_revision,1),'POLICY_BRIDGE_REQUIRED',503);
   const previous=await store.first('SELECT * FROM jwt_v2_policy_epochs WHERE owner_epoch=?',epoch.predecessor_epoch);
   requireThat(previous&&previous.sealed_through===epoch.predecessor_final_revision&&previous.highest_seen<=epoch.predecessor_final_revision&&previous.coherent_through>=epoch.predecessor_final_revision,'POLICY_BRIDGE_REQUIRED',503);
   through=epoch.predecessor_final_revision;epoch=previous;
  }
  requireThat(found,'POLICY_TARGET_EPOCH_NOT_COVERED',503);
  if(sid===null)return true;
  const f=await store.family(sid),applied=await store.first('SELECT * FROM jwt_v2_family_policy WHERE sid=?',sid);
  requireThat(f&&applied&&applied.history_complete===1&&applied.owner_epoch===head.owner_epoch&&applied.applied_revision===head.highest_seen,'POLICY_FAMILY_HISTORY_REQUIRED',503);
  requireThat(projection.binding?.sid===sid&&canonical(projection.binding)===f.binding_json&&projection.cr===f.cr&&projection.localState===f.state&&projection.authorityReady===Boolean(f.authority_ready)&&projection.idleUntil===f.idle_until&&projection.validationDeadline===f.deadline&&projection.s_exp===f.s_exp&&f.policy_minutes===current.minutes&&f.idle_until<=Math.min(f.s_exp,f.last_refresh+current.minutes*60),'POLICY_COMMITTED_FAMILY_REQUIRED',503);
  if(applied.last_job_id!==null){
   const job=await store.first('SELECT * FROM jwt_v2_policy_publications WHERE job_id=? AND sid=?',applied.last_job_id,sid);
   requireThat(job&&job.owner_epoch===head.owner_epoch&&job.revision===head.highest_seen&&job.observation_digest===applied.observed_digest&&/^[0-9a-f]{64}$/.test(applied.observed_digest)&&job.expected_cr<=f.cr&&job.target_json===current.target_json,'POLICY_TRANSITION_RECEIPT_REQUIRED',503);
  // A never-transitioned sidecar is the atomic fresh-family registration
  // certificate, which may start at any already coherent head revision.
  }else requireThat(applied.observed_digest===null&&applied.locked_at===null,'POLICY_REGISTRATION_RECEIPT_REQUIRED',503);
  if(applied.locked_at!==null)requireThat(safeInt(applied.locked_at)&&await matchingUnlock(store,f,applied.locked_at),'POLICY_HISTORICAL_LOCK_NOT_PRESERVED',503);
  return true;
 }catch{return false;}
}
