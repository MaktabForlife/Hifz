import {verifiedPolicyCoverage} from './policy-coverage.mjs';
import {scopedVectorId,dependencyScope} from './issuance-floors.mjs';
import {coversFloor} from './floors.mjs';
import {coversKeyWithdrawal} from './key-withdrawal.mjs';
import {canonical,requireThat,digest} from './codec.mjs';

function where(t){
 switch(t.type){
  case 'accountCutoff':return {sql:'sub=? AND (ce<? OR (ce=? AND ae<=?))',args:[t.sub,t.maxCe,t.maxCe,t.maxAe]};
  case 'credentialEpoch':return {sql:'sub=? AND ce<?',args:[t.sub,t.newCe]};
  case 'parent':return {sql:'sub=? AND psid=? AND bsid=? AND bv=? AND ce=? AND ae=?',args:[t.sub,t.psid,t.bsid,t.bv,t.ce,t.ae]};
  case 'localEpoch':return {sql:'sub=? AND ce=? AND ae=? AND le<=?',args:[t.sub,t.ce,t.ae,t.maxLe]};
  case 'browser':return {sql:'bsid=? AND bv<=?',args:[t.bsid,t.maxBv]};
  case 'key':return t.purpose==='academy-shared-access'
   ? {sql:"json_extract(projection_json,'$.sharedAcademyAdmission.kid')=?",args:[t.kid]}
   : {sql:'1',args:[]};
  default:return {sql:'1',args:[]}; // policy/dependency/key changes must cover the complete selected owning-app set.
 }
}
export async function restrictionPlan(store,{workId,target,now,requiredControlKeys=[],sub=null}){
 const targetJSON=canonical(target),hash=await digest(target),base=where(target),scopeSub=sub??target.sub??null,w=scopeSub&&base.sql==='1'?{sql:'sub=?',args:[scopeSub]}:base;
 requireThat(!['policy','key'].includes(target.type)||requiredControlKeys.includes(store.controlKey('control/app')),'APP_CONTROL_BARRIER_REQUIRED',503);
 const revoke=['accountCutoff','credentialEpoch','parent','browser','localEpoch'].includes(target.type)||target.type==='key'&&target.purpose==='academy-shared-access';
 return [
  store.stmt('INSERT INTO jwt_v2_restrictions(restriction_id,target_json,scope_sub,digest,created_at) VALUES(?,?,?,?,?)',workId,targetJSON,scopeSub,hash,now),
  store.stmt("INSERT INTO jwt_v2_worksets(work_id,target_json,scope_sub,watermark,created_at,state) SELECT ?,?,?,COALESCE(MAX(ordinal),0),?,'PENDING' FROM jwt_v2_families",workId,targetJSON,scopeSub,now),
  ...(revoke?[
   store.stmt("UPDATE jwt_v2_families SET state=CASE WHEN state='EXPIRED' THEN state ELSE 'REVOKED' END,cr=cr+1 WHERE s_exp>? AND "+w.sql,now,...w.args),
   store.stmt("UPDATE jwt_v2_intents SET state='CANCELLED',superseding_operation=? WHERE state='ISSUED' AND sid IN(SELECT sid FROM jwt_v2_families WHERE "+w.sql+")",workId,...w.args)
  ]:[store.stmt('UPDATE jwt_v2_families SET authority_ready=0,cr=cr+1 WHERE s_exp>? AND '+w.sql,now,...w.args),store.stmt("UPDATE jwt_v2_intents SET state='CANCELLED',superseding_operation=? WHERE state='ISSUED' AND sid IN(SELECT sid FROM jwt_v2_families WHERE "+w.sql+")",workId,...w.args)]),
  ...requiredControlKeys.map(key=>store.stmt('INSERT INTO jwt_v2_control_publications(work_id,object_key,target_json) VALUES(?,?,?)',workId,key,targetJSON)),
  store.stmt('INSERT INTO jwt_v2_publications(work_id,sid,expected_cr) SELECT ?,sid,cr FROM jwt_v2_families WHERE ordinal<=(SELECT watermark FROM jwt_v2_worksets WHERE work_id=?) AND s_exp>? AND '+w.sql,workId,workId,now,...w.args)
 ];
}
export async function markSessionCovered(store,{workId,sid,projection,controlKey,now}){
 requireThat(controlKey===store.controlKey('security/session/'+sid),'WRONG_PUBLICATION_CONTROL_PURPOSE',409);
 const [[work],[f],[row],[life]]=await store.readBatch([
  ['SELECT * FROM jwt_v2_worksets WHERE work_id=?',workId],
  ['SELECT * FROM jwt_v2_families WHERE sid=?',sid],
  ['SELECT * FROM jwt_v2_publications WHERE work_id=? AND sid=?',workId,sid],
  ['SELECT * FROM jwt_v2_objects WHERE object_key=?',controlKey]
 ]);
 requireThat(work&&f&&row,'PUBLICATION_WORK_UNKNOWN',409);const target=JSON.parse(work.target_json);
 requireThat(!projection||canonical(projection.binding)===f.binding_json,'PUBLICATION_BINDING_CONFLICT',409);
 if(now>=f.s_exp){
  await store.stmt('UPDATE jwt_v2_publications SET covered_by_expiry=1 WHERE work_id=? AND sid=? AND EXISTS(SELECT 1 FROM jwt_v2_families WHERE sid=? AND s_exp<=?)',workId,sid,sid,now).run();
  return;
 }
 requireThat(life?.state==='ACTIVE'&&life.receipt_json,'DURABLE_PUBLICATION_RECEIPT_REQUIRED',409);
 const receipt=JSON.parse(life.receipt_json);
 requireThat(receipt.digest===await digest(projection)&&receipt.nonce===projection.publicationNonce&&receipt.incarnation===projection.incarnation&&receipt.generation===projection.generation&&receipt.cr===projection.cr,'PUBLICATION_RECEIPT_MISMATCH',409);
 requireThat(projection?.state==='ACTIVE'&&projection.cr===f.cr&&projection.cr>=row.expected_cr&&Boolean(f.authority_ready)===projection.authorityReady&&f.state===projection.localState&&projection.binding?.sid===sid,'PUBLICATION_NOT_COVERED',409);
 if(projection.authorityReady&&projection.localState==='UNLOCKED'){
  const saved=JSON.parse(f.projection_json);
  for(const field of ['ownerVector','rightsHash','deniedActions','policyEpoch','policyRevision','keyRegistryEpoch','keyRegistryRevision'])requireThat(saved[field]!==undefined&&projection[field]!==undefined&&canonical(saved[field])===canonical(projection[field]),'UNCOMMITTED_PERMISSION_PROJECTION',409);
  requireThat(projection.timedUntil<=Math.min(f.s_exp,saved.timedUntil??f.s_exp),'UNCOMMITTED_TIMED_BOUND',409);
 }
 // A larger cr alone never proves that this target was actually enforced.
 requireThat(Array.isArray(projection.enforcedTargets)&&projection.enforcedTargets.some(x=>coversFloor(x,target)),'TARGET_PREDICATE_NOT_COVERED',409);
 if(['accountCutoff','credentialEpoch','parent','browser','localEpoch'].includes(target.type))requireThat(where(target).sql!=='1'&&projection.localState==='REVOKED','RESTRICTION_NOT_ENFORCED',409);
 if(target.type==='dependency'){
  const scope=dependencyScope(work.scope_sub),vectorId=await scopedVectorId(target.id,scope);
  const current=projection.ownerVector?.find(v=>v[0]===vectorId&&v[1]===target.ownerEpoch);
  const foreign=target.id.startsWith('academy:')&&store.app!=='academy';
  let applied=false;
  if(foreign&&projection.authorityReady){
   const rule=store.dependencyRegistry.get(target.id);
   requireThat(rule?.ownerApp==='academy'&&rule.epoch===target.ownerEpoch&&rule.recipients?.includes(store.app),'FOREIGN_DEPENDENCY_OWNER_REQUIRED',409);
   const receipt=await store.first('SELECT * FROM jwt_v2_applied_dependencies WHERE dependency=? AND scope=? AND owner_epoch=?',target.id,scope,target.ownerEpoch);
   if(receipt?.revision>=target.revision){
    const refs=JSON.parse(receipt.native_vector_json);applied=refs.length>0;
    for(const [id,refScope,epoch,revision] of refs){
     const native=await store.first('SELECT owner_epoch,revision FROM jwt_v2_dependencies WHERE id=? AND scope=?',id,refScope);
     const scopedId=await scopedVectorId(id,refScope);
     if(!native||native.owner_epoch!==epoch||native.revision!==revision||!projection.ownerVector?.some(v=>v[0]===scopedId&&v[1]===epoch&&v[2]===revision))applied=false;
    }
   }
  }
  requireThat(projection.authorityReady===false||!foreign&&current&&current[2]>=target.revision||foreign&&applied||target.effect==='DENY'&&target.deniedActions.every(a=>projection.deniedActions?.includes(a)),'DEPENDENCY_FLOOR_NOT_ENFORCED',409);
  if(projection.authorityReady!==false&&!foreign&&target.effect==='DENY'&&current?.[2]===target.revision)requireThat(target.deniedActions.every(a=>projection.deniedActions?.includes(a)),'DENIED_ACTION_NOT_ENFORCED',409);
 }
 if(target.type==='policy')requireThat(await verifiedPolicyCoverage(store,{target,projection,sid}),'POLICY_NOT_ENFORCED',409);
 if(target.type==='key'){
  requireThat(coversKeyWithdrawal(projection,target),'KEY_WITHDRAWAL_NOT_ENFORCED',409);
  if(target.purpose==='academy-shared-access')requireThat(projection.localState==='REVOKED','RESTRICTION_NOT_ENFORCED',409);
 }
 const [guard,clear]=store.guard(`SELECT 1 FROM jwt_v2_publications p JOIN jwt_v2_worksets w USING(work_id)
  JOIN jwt_v2_families f ON f.sid=p.sid JOIN jwt_v2_objects o ON o.object_key=?
  WHERE p.work_id=? AND p.sid=? AND p.expected_cr=? AND w.target_json=? AND w.scope_sub IS ?
   AND f.cr=? AND f.binding_json=? AND f.state=? AND f.authority_ready=? AND o.state='ACTIVE' AND o.receipt_json=?`,
  [controlKey,workId,sid,row.expected_cr,work.target_json,work.scope_sub,f.cr,f.binding_json,f.state,f.authority_ready,life.receipt_json]);
 await store.batch([guard,store.stmt('UPDATE jwt_v2_publications SET published_cr=? WHERE work_id=? AND sid=?',projection.cr,workId,sid),clear]);
}
export async function worksetApplied(store,workId){
 const statement=store.stmt(`UPDATE jwt_v2_worksets SET state='APPLIED' WHERE work_id=?
  AND NOT EXISTS(SELECT 1 FROM jwt_v2_publications WHERE work_id=? AND published_cr IS NULL AND covered_by_expiry=0)
  AND NOT EXISTS(SELECT 1 FROM jwt_v2_control_publications WHERE work_id=? AND covered=0)
  RETURNING work_id`,workId,workId,workId);
 const result=await statement.first();
 if(result)return true;
 requireThat(await store.first('SELECT 1 FROM jwt_v2_worksets WHERE work_id=?',workId),'PUBLICATION_WORK_UNKNOWN',409);
 return false;
}
export function admissionFloorCondition(binding){
 // Every newly created/renewed SID is checked against durable restrictions, including after the workset watermark.
 return {sql:"SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_restrictions r WHERE "+
 "(json_extract(r.target_json,'$.type')='accountCutoff' AND json_extract(r.target_json,'$.sub')=? AND (?<json_extract(r.target_json,'$.maxCe') OR (?=json_extract(r.target_json,'$.maxCe') AND ?<=json_extract(r.target_json,'$.maxAe')))) OR "+
 "(json_extract(r.target_json,'$.type')='credentialEpoch' AND json_extract(r.target_json,'$.sub')=? AND ?<json_extract(r.target_json,'$.newCe')) OR "+
 "(json_extract(r.target_json,'$.type')='browser' AND json_extract(r.target_json,'$.bsid')=? AND ?<=json_extract(r.target_json,'$.maxBv')) OR "+
 "(json_extract(r.target_json,'$.type')='localEpoch' AND json_extract(r.target_json,'$.sub')=? AND json_extract(r.target_json,'$.ce')=? AND json_extract(r.target_json,'$.ae')=? AND ?<=json_extract(r.target_json,'$.maxLe')) OR "+
 "(json_extract(r.target_json,'$.type')='parent' AND json_extract(r.target_json,'$.psid')=? AND json_extract(r.target_json,'$.bsid')=? AND json_extract(r.target_json,'$.bv')=? AND json_extract(r.target_json,'$.ce')=? AND json_extract(r.target_json,'$.ae')=?))",
 args:[binding.sub,binding.ce,binding.ce,binding.ae,binding.sub,binding.ce,binding.bsid,binding.bv,binding.sub,binding.ce,binding.ae,binding.le,binding.psid,binding.bsid,binding.bv,binding.ce,binding.ae]};
}

export function admissionFloorGuard(store,binding){const p=admissionFloorCondition(binding);return store.guard(p.sql,p.args);}

export async function markControlCovered(store,{workId,controlKey,projection}){
 const row=await store.first('SELECT * FROM jwt_v2_control_publications WHERE work_id=? AND object_key=?',workId,controlKey),life=await store.lifecycle(controlKey);
 requireThat(controlKey===store.controlKey('control/app')||controlKey.startsWith(store.controlKey('control/resource/')),'WRONG_PUBLICATION_CONTROL_PURPOSE',409);
 requireThat(row&&life?.state==='ACTIVE'&&life.receipt_json,'DURABLE_PUBLICATION_RECEIPT_REQUIRED',409);
 const r=JSON.parse(life.receipt_json),target=JSON.parse(row.target_json);
 requireThat(r.digest===await digest(projection)&&r.nonce===projection.publicationNonce&&r.incarnation===projection.incarnation&&r.generation===projection.generation,'PUBLICATION_RECEIPT_MISMATCH',409);
 if(target.type==='policy')requireThat(await verifiedPolicyCoverage(store,{target,projection}),'APP_POLICY_NOT_ENFORCED',409);
 else if(target.type==='key')requireThat(coversKeyWithdrawal(projection,target),'APP_KEY_NOT_WITHDRAWN',409);
 else requireThat(projection.authorityReady===false||projection.enforcedTargets?.some(t=>canonical(t)===canonical(target)),'CONTROL_TARGET_NOT_COVERED',409);
 await store.stmt('UPDATE jwt_v2_control_publications SET covered=1 WHERE work_id=? AND object_key=?',workId,controlKey).run();
}

export function isVoluntaryAccountCutoff(target){
 return target?.type==='accountCutoff'&&target.reason==='VOLUNTARY_LOGOUT';
}

export function isLocalLogoutCutoff(target,app,workId){
 return target?.type==='localEpoch'&&['studio','hifz'].includes(app)&&target.app===app&&workId.startsWith('local-report-');
}

export async function markLogoutSessionCovered(store,{workId,sid,target,projection,now,localLogout=false}){
 requireThat(isVoluntaryAccountCutoff(target)||localLogout&&isLocalLogoutCutoff(target,store.app,workId),
  'INVALID_LOGOUT_TARGET',409);
 const targetJSON=canonical(target);
 const expires=projection===undefined||now>=projection.s_exp;
 const work="EXISTS(SELECT 1 FROM jwt_v2_worksets w WHERE w.work_id=p.work_id AND w.target_json=? AND w.scope_sub=?)";
 let statement;
 if(expires){
  statement=store.stmt(
   "UPDATE jwt_v2_publications AS p SET covered_by_expiry=1 WHERE p.work_id=? AND p.sid=? AND "+work+
   " AND EXISTS(SELECT 1 FROM jwt_v2_families f WHERE f.sid=p.sid AND f.s_exp<=?) RETURNING sid",
   workId,sid,targetJSON,target.sub,now);
 }else{
  requireThat(projection.state==='ACTIVE'&&projection.localState==='REVOKED'&&projection.binding?.sid===sid&&
   projection.enforcedTargets?.some(floor=>coversFloor(floor,target)),'TARGET_PREDICATE_NOT_COVERED',409);
  const key=store.controlKey('security/session/'+sid);
  const objectDigest=await digest(projection);
  // Compare the receipt and current family in the write that marks coverage.
  // No optimistic read or guard row needs to survive a second transaction.
  statement=store.stmt(
   "UPDATE jwt_v2_publications AS p SET published_cr=? WHERE p.work_id=? AND p.sid=? AND p.expected_cr<=? AND "+work+
   " AND EXISTS(SELECT 1 FROM jwt_v2_families f JOIN jwt_v2_objects o ON o.object_key=? "+
   "WHERE f.sid=p.sid AND f.s_exp>? AND f.s_exp=? AND f.cr=? AND f.binding_json=? "+
   "AND f.state='REVOKED' AND f.authority_ready=? AND o.state='ACTIVE' AND o.incarnation=? AND o.generation=? "+
   "AND json_extract(o.receipt_json,'$.digest')=? AND json_extract(o.receipt_json,'$.nonce')=? "+
   "AND json_extract(o.receipt_json,'$.incarnation')=? AND json_extract(o.receipt_json,'$.generation')=? "+
   "AND json_extract(o.receipt_json,'$.cr')=?) RETURNING sid",
   projection.cr,workId,sid,projection.cr,targetJSON,target.sub,key,now,projection.s_exp,
   projection.cr,canonical(projection.binding),Number(projection.authorityReady),projection.incarnation,projection.generation,
   objectDigest,projection.publicationNonce,projection.incarnation,projection.generation,projection.cr);
 }
 // Use the owning store batch so Academy retains the split-state write fence.
 const results=await store.batch([statement]);
 const result=results[store.academyFence?1:0];
 requireThat(result?.results?.[0]?.sid===sid,'LOGOUT_PUBLICATION_NOT_COVERED',409);
}
