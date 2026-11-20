import {canonical,requireThat,ascii,safeInt,scalar,bytes,b64u,sha256,digest,uuid} from './codec.mjs';

// Explicit additive recipe only. Imported modules never install it.
export const issuanceFloorSchemaSQL=[
 "CREATE TABLE IF NOT EXISTS jwt_v2_applied_dependencies(dependency TEXT NOT NULL,scope TEXT NOT NULL,owner_app TEXT NOT NULL CHECK(owner_app='academy'),owner_epoch TEXT NOT NULL,revision INTEGER NOT NULL CHECK(revision>0 AND revision<=9007199254740991),projection_digest TEXT NOT NULL,commit_ref TEXT NOT NULL,native_vector_json TEXT NOT NULL,receipt_digest TEXT NOT NULL,PRIMARY KEY(dependency,scope,owner_epoch));",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_applied_dependency_monotonic BEFORE UPDATE ON jwt_v2_applied_dependencies WHEN OLD.dependency<>NEW.dependency OR OLD.scope<>NEW.scope OR OLD.owner_app<>NEW.owner_app OR OLD.owner_epoch<>NEW.owner_epoch OR NEW.revision<OLD.revision OR (NEW.revision=OLD.revision AND (OLD.projection_digest<>NEW.projection_digest OR OLD.commit_ref<>NEW.commit_ref)) BEGIN SELECT RAISE(ABORT,'jwt_v2_applied_dependency_conflict'); END;"
].join('\n');

export const asciiUpper=value=>String(value).replace(/[a-z]/g,c=>c.toUpperCase());
export function dependencyScope(scopeSub){
 if(scopeSub===null)return 'GLOBAL';
 requireThat(typeof scopeSub==='string'&&bytes(scopeSub).length>0&&bytes(scopeSub).length<=180&&!/[\u0000-\u0020\u007f]/.test(scopeSub),'INVALID_DEPENDENCY_SCOPE',503);
 scalar(scopeSub);const scope='ACCOUNT:'+scopeSub;requireThat(bytes(scope).length<=512,'INVALID_DEPENDENCY_SCOPE',503);return scope;
}
export async function scopedVectorId(id,scope){
 requireThat(ascii(id)&&typeof scope==='string'&&bytes(scope).length>0&&bytes(scope).length<=512,'INVALID_SCOPED_DEPENDENCY',503);
 return id+':'+b64u(await sha256(bytes(scope))).slice(0,22);
}
const q=name=>{requireThat(typeof name==='string'&&/^[a-z_][a-z0-9_]*$/i.test(name)&&!/^sqlite_/i.test(name),'INVALID_NATIVE_PROVENANCE_IDENTIFIER',503);return '"'+name+'"';};
const validOwner=store=>requireThat(['academy','studio','hifz'].includes(store.app)&&['production','feature'].includes(store.env),'INVALID_ISSUANCE_OWNER',503);
const dependencyFields=['deniedActions','effect','id','ownerEpoch','revision','type'];
function validateDependency(target){
 requireThat(target&&canonical(Object.keys(target).sort())===canonical(dependencyFields)&&target.type==='dependency'&&ascii(target.id)&&ascii(target.ownerEpoch)&&safeInt(target.revision,1)&&['INVALIDATE','DENY'].includes(target.effect)&&Array.isArray(target.deniedActions)&&target.deniedActions.every(a=>ascii(a))&&new Set(target.deniedActions).size===target.deniedActions.length&&(target.effect==='DENY'?target.deniedActions.length>0:target.deniedActions.length===0),'INVALID_DEPENDENCY_FLOOR',503);
}
function references(store,rows,scope){
 requireThat(Array.isArray(rows)&&rows.length>0&&rows.length<=256,'NATIVE_PROJECTION_REFERENCES_REQUIRED',503);
 const out=rows.map(r=>{
  requireThat(r&&ascii(r.id)&&r.id.startsWith(store.app+':native:')&&ascii(r.ownerEpoch)&&typeof r.scope==='string'&&(r.scope==='GLOBAL'||r.scope===scope),'INVALID_NATIVE_PROJECTION_REFERENCE',503);
  return {id:r.id,scope:r.scope,ownerEpoch:r.ownerEpoch};
 }).sort((a,b)=>canonical(a)<canonical(b)?-1:1);
 requireThat(out.every((r,i)=>i===0||canonical(r)!==canonical(out[i-1])),'DUPLICATE_NATIVE_PROJECTION_REFERENCE',503);return out;
}

/*
 * Only authenticated business-projection intake may construct this plan. The
 * structured native guard must name real persisted provenance columns. Fact
 * writes, exact owner/scope/revision/digest verification, local dependency
 * snapshot and receipt commit together. There is no boolean/metadata-only ACK.
 *
 * A subsequent captured native authority write invalidates the saved vector;
 * local provenance must then be rechecked before this receipt can enable again.
 */
export async function appliedDependencyPlan(store,{target,scopeSub=null,dependencyRegistry,projectionDigest,commitRef,nativePlan}){
 validOwner(store);validateDependency(target);
 const rule=dependencyRegistry instanceof Map&&dependencyRegistry.get(target.id),scope=dependencyScope(scopeSub);
 requireThat(rule&&rule.ownerApp==='academy'&&rule.ownerApp!==store.app&&rule.epoch===target.ownerEpoch&&rule.recipients?.includes(store.app),'FOREIGN_DEPENDENCY_OWNER_REQUIRED',503);
 requireThat(/^[0-9a-f]{64}$/.test(projectionDigest)&&ascii(commitRef),'NATIVE_PROJECTION_RECEIPT_REQUIRED',503);
 requireThat(nativePlan&&Array.isArray(nativePlan.statements)&&nativePlan.guard&&typeof nativePlan.guard==='object','NATIVE_PROJECTION_PLAN_REQUIRED',503);
 const g=nativePlan.guard;
 requireThat(typeof g.table==='string'&&!/^jwt_v2_/i.test(g.table),'NATIVE_PROVENANCE_TABLE_REQUIRED',503);
 const cols=['scopeColumn','ownerEpochColumn','revisionColumn','projectionDigestColumn'];
 requireThat(cols.every(k=>typeof g[k]==='string')&&new Set(cols.map(k=>g[k])).size===cols.length,'NATIVE_PROVENANCE_GUARD_REQUIRED',503);
 const refs=references(store,nativePlan.references,scope);
 requireThat(refs.some(r=>r.id===store.app+':native:'+g.table),'NATIVE_PROVENANCE_CAPTURE_REQUIRED',503);
 const guardSQL='SELECT 1 FROM '+q(g.table)+' WHERE '+q(g.scopeColumn)+'=? AND '+q(g.ownerEpochColumn)+'=? AND '+q(g.revisionColumn)+'=? AND '+q(g.projectionDigestColumn)+'=?';
 const [guard,clear]=store.guard(guardSQL,[scope,target.ownerEpoch,target.revision,projectionDigest]);
 const refsJSON=canonical(refs);
 const [vectorGuard,vectorClear]=store.guard("SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM json_each(?) j LEFT JOIN jwt_v2_dependencies d ON d.id=json_extract(j.value,'$.id') AND d.scope=json_extract(j.value,'$.scope') WHERE d.id IS NULL OR d.owner_epoch<>json_extract(j.value,'$.ownerEpoch') OR d.revision<1)",[refsJSON]);
 const identity={app:store.app,env:store.env,id:target.id,scope,ownerEpoch:target.ownerEpoch,revision:target.revision,projectionDigest,commitRef};
 return [
  ...nativePlan.statements,guard,vectorGuard,
  store.stmt("INSERT INTO jwt_v2_applied_dependencies(dependency,scope,owner_app,owner_epoch,revision,projection_digest,commit_ref,native_vector_json,receipt_digest) SELECT ?,?,'academy',?,?,?,?,(SELECT json_group_array(json_array(id,scope,owner_epoch,revision)) FROM (SELECT d.id,d.scope,d.owner_epoch,d.revision FROM json_each(?) j JOIN jwt_v2_dependencies d ON d.id=json_extract(j.value,'$.id') AND d.scope=json_extract(j.value,'$.scope') ORDER BY d.id,d.scope)),? ON CONFLICT(dependency,scope,owner_epoch) DO UPDATE SET revision=excluded.revision,projection_digest=excluded.projection_digest,commit_ref=excluded.commit_ref,native_vector_json=excluded.native_vector_json,receipt_digest=excluded.receipt_digest",target.id,scope,target.ownerEpoch,target.revision,projectionDigest,commitRef,refsJSON,await digest(identity)),
  vectorClear,clear
 ];
}

// Returns the same [assertion, clear] shape as PrimaryStore.guard. Place the
// assertion in the owning family transaction, after valid unlock/barrier changes
// when that operation intentionally unlocks a context; no warm request SQL.
export function issuanceFloorGuard(store,{binding,projection,vectorGuards,existingSid=null,state='UNLOCKED',now,dependencyRegistry=store.dependencyRegistry||new Map()}){
 validOwner(store);
 requireThat(binding&&projection&&canonical(projection.binding)===canonical(binding)&&binding.env===store.env&&uuid(binding.sid)&&safeInt(now)&&['UNLOCKED','ADMITTED_LOCKED'].includes(state),'INVALID_ISSUANCE_FLOOR_CONTEXT',503);
 requireThat(existingSid===null||existingSid===binding.sid,'INVALID_EXISTING_FAMILY_SELECTOR',503);
 requireThat(ascii(projection.policyEpoch)&&safeInt(projection.policyRevision,1)&&safeInt(projection.inactivityMinutes,15)&&projection.inactivityMinutes<=200&&Array.isArray(projection.deniedActions)&&projection.deniedActions.every(a=>ascii(a))&&Array.isArray(vectorGuards)&&vectorGuards.length>0,'ISSUANCE_READINESS_REQUIRED',503);
 const registry=[...(dependencyRegistry instanceof Map?dependencyRegistry:new Map()).entries()].map(([id,r])=>({id,ownerApp:r.ownerApp,ownerEpoch:r.epoch,recipients:r.recipients||[]}));
 const sql=String.raw`WITH RECURSIVE
 input AS(SELECT ? binding,? projection,? guards,? app,? env,? sid,? family_state,? now,? registry),
 policy_chain(owner_epoch,depth) AS(
  SELECT h.owner_epoch,0 FROM jwt_v2_policy_heads h,input i WHERE h.app=i.app AND h.env=i.env
  UNION ALL
  SELECT e.predecessor_epoch,c.depth+1 FROM policy_chain c JOIN jwt_v2_policy_epochs e ON e.owner_epoch=c.owner_epoch JOIN jwt_v2_policy_epochs previous ON previous.owner_epoch=e.predecessor_epoch
   WHERE c.depth<15 AND previous.sealed_through=e.predecessor_final_revision AND previous.coherent_through>=e.predecessor_final_revision
 )
 SELECT 1 FROM input i WHERE
 NOT EXISTS(SELECT 1 FROM json_each(i.guards) v LEFT JOIN jwt_v2_dependencies d ON d.id=json_extract(v.value,'$[0]') AND d.scope=json_extract(v.value,'$[1]') WHERE d.id IS NULL OR d.owner_epoch<>json_extract(v.value,'$[2]') OR d.revision<>json_extract(v.value,'$[3]'))
 AND EXISTS(SELECT 1 FROM jwt_v2_policy_heads h JOIN jwt_v2_policy_epochs e ON e.owner_epoch=h.owner_epoch JOIN jwt_v2_policy_history p ON p.owner_epoch=e.owner_epoch AND p.revision=e.highest_seen
  WHERE h.app=i.app AND h.env=i.env AND e.owner_epoch=json_extract(i.projection,'$.policyEpoch') AND e.highest_seen=json_extract(i.projection,'$.policyRevision') AND e.coherent_through=e.highest_seen AND e.sealed_through IS NULL AND p.minutes=json_extract(i.projection,'$.inactivityMinutes'))
 AND (i.sid IS NULL OR EXISTS(SELECT 1 FROM jwt_v2_family_policy fp JOIN jwt_v2_families f ON f.sid=fp.sid
  WHERE fp.sid=i.sid AND fp.history_complete=1 AND fp.owner_epoch=json_extract(i.projection,'$.policyEpoch') AND fp.applied_revision=json_extract(i.projection,'$.policyRevision') AND f.policy_minutes=json_extract(i.projection,'$.inactivityMinutes')))
 AND EXISTS(SELECT 1 FROM jwt_v2_parents p WHERE p.psid=json_extract(i.binding,'$.psid') AND p.sub=json_extract(i.binding,'$.sub') AND p.bsid=json_extract(i.binding,'$.bsid') AND p.bv=json_extract(i.binding,'$.bv') AND p.ce=json_extract(i.binding,'$.ce') AND p.ae=json_extract(i.binding,'$.ae') AND p.s_iat=json_extract(i.binding,'$.s_iat') AND p.s_exp=json_extract(i.binding,'$.s_exp') AND p.s_exp>i.now AND (p.state='UNLOCKED' OR i.family_state='ADMITTED_LOCKED' AND p.state='LOCKED'))
 AND (i.family_state='ADMITTED_LOCKED' OR NOT EXISTS(SELECT 1 FROM jwt_v2_ceremony_barriers b WHERE b.psid=json_extract(i.binding,'$.psid') AND b.bsid=json_extract(i.binding,'$.bsid') AND b.bv=json_extract(i.binding,'$.bv') AND b.sub=json_extract(i.binding,'$.sub') AND (b.locked<>0 OR b.idle_until<=i.now)))
 AND NOT EXISTS(
  SELECT 1 FROM jwt_v2_restrictions r WHERE (r.scope_sub IS NULL OR r.scope_sub=json_extract(i.binding,'$.sub') COLLATE BINARY) AND NOT coalesce(
   CASE json_extract(r.target_json,'$.type')
   WHEN 'dependency' THEN
    json_type(r.target_json,'$.id')='text' AND json_type(r.target_json,'$.ownerEpoch')='text' AND json_type(r.target_json,'$.revision')='integer' AND json_extract(r.target_json,'$.revision')>=1
    AND json_type(r.target_json,'$.deniedActions')='array' AND json_extract(r.target_json,'$.effect') IN('DENY','INVALIDATE')
    AND ((json_extract(r.target_json,'$.effect')='INVALIDATE' AND json_array_length(r.target_json,'$.deniedActions')=0) OR (json_extract(r.target_json,'$.effect')='DENY' AND json_array_length(r.target_json,'$.deniedActions')>0))
    AND (EXISTS(SELECT 1 FROM json_each(i.guards) known WHERE json_extract(known.value,'$[0]')=json_extract(r.target_json,'$.id') AND substr(json_extract(known.value,'$[0]'),1,length(i.app)+8)=i.app||':native:' AND json_extract(known.value,'$[1]')=CASE WHEN r.scope_sub IS NULL THEN 'GLOBAL' ELSE 'ACCOUNT:'||r.scope_sub END AND json_extract(known.value,'$[2]')=json_extract(r.target_json,'$.ownerEpoch')) OR EXISTS(SELECT 1 FROM json_each(i.registry) known WHERE json_extract(known.value,'$.id')=json_extract(r.target_json,'$.id') AND json_extract(known.value,'$.ownerApp')='academy' AND json_extract(known.value,'$.ownerEpoch')=json_extract(r.target_json,'$.ownerEpoch') AND EXISTS(SELECT 1 FROM json_each(known.value,'$.recipients') recipient WHERE recipient.value=i.app)))
    AND (
     (json_extract(r.target_json,'$.effect')='DENY' AND NOT EXISTS(SELECT 1 FROM json_each(r.target_json,'$.deniedActions') a WHERE a.type<>'text' OR NOT EXISTS(SELECT 1 FROM json_each(i.projection,'$.deniedActions') proposed WHERE proposed.value=a.value)))
     OR EXISTS(SELECT 1 FROM json_each(i.guards) v WHERE json_extract(v.value,'$[0]')=json_extract(r.target_json,'$.id') AND substr(json_extract(v.value,'$[0]'),1,length(i.app)+8)=i.app||':native:' AND json_extract(v.value,'$[1]')=CASE WHEN r.scope_sub IS NULL THEN 'GLOBAL' ELSE 'ACCOUNT:'||r.scope_sub END AND json_extract(v.value,'$[2]')=json_extract(r.target_json,'$.ownerEpoch') AND json_extract(v.value,'$[3]')>=json_extract(r.target_json,'$.revision')
      AND (json_extract(r.target_json,'$.effect')='INVALIDATE' OR json_extract(v.value,'$[3]')>json_extract(r.target_json,'$.revision')))
     OR EXISTS(SELECT 1 FROM jwt_v2_applied_dependencies a WHERE a.dependency=json_extract(r.target_json,'$.id') AND a.scope=CASE WHEN r.scope_sub IS NULL THEN 'GLOBAL' ELSE 'ACCOUNT:'||r.scope_sub END AND a.owner_app='academy' AND a.owner_epoch=json_extract(r.target_json,'$.ownerEpoch') AND a.revision>=json_extract(r.target_json,'$.revision') AND json_array_length(a.native_vector_json)>0
      AND NOT EXISTS(SELECT 1 FROM json_each(a.native_vector_json) n LEFT JOIN jwt_v2_dependencies d ON d.id=json_extract(n.value,'$[0]') AND d.scope=json_extract(n.value,'$[1]') WHERE d.id IS NULL OR d.owner_epoch<>json_extract(n.value,'$[2]') OR d.revision<>json_extract(n.value,'$[3]') OR NOT EXISTS(SELECT 1 FROM json_each(i.guards) v WHERE json_extract(v.value,'$[0]')=json_extract(n.value,'$[0]') AND json_extract(v.value,'$[1]')=json_extract(n.value,'$[1]') AND json_extract(v.value,'$[2]')=json_extract(n.value,'$[2]') AND json_extract(v.value,'$[3]')=json_extract(n.value,'$[3]'))))
    )
   WHEN 'policy' THEN json_type(r.target_json,'$.revision')='integer' AND json_type(r.target_json,'$.inactivityMinutes')='integer' AND json_extract(r.target_json,'$.policyId')='session-inactivity' AND EXISTS(SELECT 1 FROM policy_chain c JOIN jwt_v2_policy_epochs e ON e.owner_epoch=c.owner_epoch JOIN jwt_v2_policy_history h ON h.owner_epoch=e.owner_epoch WHERE h.owner_epoch=json_extract(r.target_json,'$.ownerEpoch') AND h.revision=json_extract(r.target_json,'$.revision') AND h.minutes=json_extract(r.target_json,'$.inactivityMinutes') AND e.coherent_through>=h.revision)
   WHEN 'key' THEN json_type(r.target_json,'$.registryRevision')='integer' AND json_extract(r.target_json,'$.purpose')='academy-handoff' AND json_extract(i.projection,'$.handoffRegistryRevision')>=json_extract(r.target_json,'$.registryRevision') AND EXISTS(SELECT 1 FROM json_each(i.projection,'$.withdrawnHandoffKids') k WHERE k.value=json_extract(r.target_json,'$.kid'))
   WHEN 'accountCutoff' THEN NOT(json_extract(r.target_json,'$.sub')=json_extract(i.binding,'$.sub') AND (json_extract(i.binding,'$.ce')<json_extract(r.target_json,'$.maxCe') OR json_extract(i.binding,'$.ce')=json_extract(r.target_json,'$.maxCe') AND json_extract(i.binding,'$.ae')<=json_extract(r.target_json,'$.maxAe')))
   WHEN 'credentialEpoch' THEN NOT(json_extract(r.target_json,'$.sub')=json_extract(i.binding,'$.sub') AND json_extract(i.binding,'$.ce')<json_extract(r.target_json,'$.newCe'))
   WHEN 'parent' THEN NOT(json_extract(r.target_json,'$.sub')=json_extract(i.binding,'$.sub') AND json_extract(r.target_json,'$.psid')=json_extract(i.binding,'$.psid') AND json_extract(r.target_json,'$.bsid')=json_extract(i.binding,'$.bsid') AND json_extract(r.target_json,'$.bv')=json_extract(i.binding,'$.bv') AND json_extract(r.target_json,'$.ce')=json_extract(i.binding,'$.ce') AND json_extract(r.target_json,'$.ae')=json_extract(i.binding,'$.ae'))
   WHEN 'browser' THEN NOT(json_extract(r.target_json,'$.bsid')=json_extract(i.binding,'$.bsid') AND json_extract(i.binding,'$.bv')<=json_extract(r.target_json,'$.maxBv'))
   WHEN 'localEpoch' THEN json_extract(r.target_json,'$.app')=i.app AND NOT(json_extract(r.target_json,'$.sub')=json_extract(i.binding,'$.sub') AND json_extract(r.target_json,'$.ce')=json_extract(i.binding,'$.ce') AND json_extract(r.target_json,'$.ae')=json_extract(i.binding,'$.ae') AND json_extract(i.binding,'$.le')<=json_extract(r.target_json,'$.maxLe'))
   ELSE 0 END,0)
 )`;
 return store.guard(sql,[canonical(binding),canonical(projection),canonical(vectorGuards),store.app,store.env,existingSid,state,now,canonical(registry)]);
}
