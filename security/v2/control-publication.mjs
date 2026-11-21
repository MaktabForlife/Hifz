import {canonical,requireThat,ascii,safeInt,bytes,digest,exact} from './codec.mjs';
import {controlShape} from './control-shapes.mjs';

// Additive recipes only. Importing this module never installs or seeds state.
export const controlPublicationSchemaSQL=[
 "CREATE TABLE IF NOT EXISTS jwt_v2_control_registry_receipts(receipt_ref TEXT PRIMARY KEY,app TEXT NOT NULL,env TEXT NOT NULL,registry_json TEXT NOT NULL,registry_digest TEXT NOT NULL,predecessor_ref TEXT);",
 "CREATE TABLE IF NOT EXISTS jwt_v2_control_registry_heads(app TEXT NOT NULL,env TEXT NOT NULL,receipt_ref TEXT NOT NULL REFERENCES jwt_v2_control_registry_receipts(receipt_ref),PRIMARY KEY(app,env));",
 "CREATE TABLE IF NOT EXISTS jwt_v2_control_genesis(app TEXT NOT NULL,env TEXT NOT NULL,suffix TEXT NOT NULL,receipt_ref TEXT NOT NULL,projection_digest TEXT NOT NULL,native_mapping_json TEXT,PRIMARY KEY(app,env,suffix));",
 "CREATE TABLE IF NOT EXISTS jwt_v2_control_commits(commit_ref TEXT PRIMARY KEY,app TEXT NOT NULL,env TEXT NOT NULL,suffix TEXT NOT NULL,cr INTEGER NOT NULL,projection_digest TEXT NOT NULL,receipt_json TEXT NOT NULL);",
 "CREATE TABLE IF NOT EXISTS jwt_v2_control_targets(object_key TEXT PRIMARY KEY,app TEXT NOT NULL,env TEXT NOT NULL,suffix TEXT NOT NULL,cr INTEGER NOT NULL CHECK(cr>0 AND cr<=9007199254740991),projection_json TEXT NOT NULL CHECK(length(CAST(projection_json AS BLOB))<=16384),projection_digest TEXT NOT NULL,commit_ref TEXT NOT NULL REFERENCES jwt_v2_control_commits(commit_ref),provenance_json TEXT NOT NULL,UNIQUE(app,env,suffix));",
 "CREATE TABLE IF NOT EXISTS jwt_v2_control_native_receipts(commit_ref TEXT NOT NULL REFERENCES jwt_v2_control_commits(commit_ref),dependency TEXT NOT NULL,scope TEXT NOT NULL,owner_epoch TEXT NOT NULL,revision INTEGER NOT NULL,source_table TEXT NOT NULL,change_id INTEGER NOT NULL,operation_id TEXT NOT NULL,target_json TEXT NOT NULL,PRIMARY KEY(commit_ref,dependency,scope));",
 ...['registry_receipts','genesis','commits','native_receipts'].flatMap(name=>[
  "CREATE TRIGGER IF NOT EXISTS jwt_v2_control_"+name+"_immutable BEFORE UPDATE ON jwt_v2_control_"+name+" BEGIN SELECT RAISE(ABORT,'jwt_v2_control_receipt_immutable'); END;",
  "CREATE TRIGGER IF NOT EXISTS jwt_v2_control_"+name+"_retain BEFORE DELETE ON jwt_v2_control_"+name+" BEGIN SELECT RAISE(ABORT,'jwt_v2_control_receipt_retained'); END;"
 ]),
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_control_target_monotonic BEFORE UPDATE ON jwt_v2_control_targets WHEN NEW.object_key<>OLD.object_key OR NEW.app<>OLD.app OR NEW.env<>OLD.env OR NEW.suffix<>OLD.suffix OR NEW.cr<=OLD.cr OR (NEW.suffix='control/app' AND json_extract(NEW.projection_json,'$.migrationFloor')<json_extract(OLD.projection_json,'$.migrationFloor')) BEGIN SELECT RAISE(ABORT,'jwt_v2_control_target_conflict'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_control_target_retain BEFORE DELETE ON jwt_v2_control_targets BEGIN SELECT RAISE(ABORT,'jwt_v2_control_target_retained'); END;"
].join('\n');
const envelope=['schema','generation','incarnation','state','publicationNonce'];
const appRequired=['cr','app','env','policyEpoch','policyRevision','keyRegistryEpoch','keyRegistryRevision','withdrawnKids','migrationFloor','inactivityMinutes'];
const appOptional=['withdrawnHandoffKids','handoffRegistryEpoch','handoffRegistryRevision','sharedAcademyRegistryRevision','withdrawnSharedAcademyKids','denied','authorityReady','enforcedTargets'];
const resourceRequired=['cr','app','env','resourceId','ownerEpoch','revision','deniedActions'];
const q=n=>{requireThat(typeof n==='string'&&/^[a-z_][a-z0-9_]*$/i.test(n)&&!/^sqlite_/i.test(n),'INVALID_NATIVE_PROVENANCE_IDENTIFIER',503);return '"'+n+'"';};
const ref=s=>requireThat(ascii(s,512),'CONTROL_SOURCE_RECEIPT_REQUIRED',503);
const superset=(next,old)=>old.every(k=>next.includes(k));
function list(v,code,kids=false){requireThat(Array.isArray(v)&&v.every(k=>kids?/^[A-Za-z0-9._-]{1,64}$/.test(k):ascii(k))&&new Set(v).size===v.length,code,503);}
function registryOf(p){
 const r={keyRegistryEpoch:p.keyRegistryEpoch,keyRegistryRevision:p.keyRegistryRevision,withdrawnKids:p.withdrawnKids,handoffRegistryEpoch:p.handoffRegistryEpoch??p.keyRegistryEpoch,handoffRegistryRevision:p.handoffRegistryRevision??p.keyRegistryRevision,withdrawnHandoffKids:p.withdrawnHandoffKids??[],...(p.sharedAcademyRegistryRevision===undefined?{}:{sharedAcademyRegistryRevision:p.sharedAcademyRegistryRevision,withdrawnSharedAcademyKids:p.withdrawnSharedAcademyKids})};
 requireThat(ascii(r.keyRegistryEpoch)&&ascii(r.handoffRegistryEpoch)&&safeInt(r.keyRegistryRevision,1)&&safeInt(r.handoffRegistryRevision,1),'MALFORMED_KEY_REGISTRY',503);
 list(r.withdrawnKids,'MALFORMED_KEY_REGISTRY',true);list(r.withdrawnHandoffKids,'MALFORMED_KEY_REGISTRY',true);
 requireThat((p.sharedAcademyRegistryRevision===undefined)===(p.withdrawnSharedAcademyKids===undefined),'MALFORMED_KEY_REGISTRY',503);
 if(r.sharedAcademyRegistryRevision!==undefined){
  requireThat(safeInt(r.sharedAcademyRegistryRevision,1),'MALFORMED_KEY_REGISTRY',503);
  list(r.withdrawnSharedAcademyKids,'MALFORMED_KEY_REGISTRY',true);
 }
 return r;
}
function semantic(p){requireThat(p&&typeof p==='object'&&!Array.isArray(p),'MALFORMED_CONTROL',503);return Object.fromEntries(Object.entries(p).filter(([key])=>!envelope.includes(key)));}
async function checked(store,suffix,input,{allowEnvelope=false}={}){
 const key=store.controlKey(suffix),life=await store.lifecycle(key);
 // Measure before checking unknown fields, including actual lifecycle envelope overhead.
 const candidate={...input,schema:2,generation:life?.generation??store.securityPrefix.split('/').filter(Boolean).at(-1),incarnation:life?.incarnation??'00000000-0000-4000-8000-000000000000',state:'ACTIVE',publicationNonce:'00000000-0000-4000-8000-000000000000'};
 requireThat(bytes(canonical(candidate)).length<=16384,'CONTROL_PARTITION_REQUIRED',503);
 const p=allowEnvelope?semantic(input):input;
 const app=suffix==='control/app';
 requireThat(app||/^control\/resource\/[A-Za-z0-9._:-]{1,128}$/.test(suffix),'INVALID_CONTROL_SOURCE_PURPOSE',503);
 const required=app?appRequired:resourceRequired,allowed=app?[...required,...appOptional]:required;
 requireThat(p&&required.every(k=>Object.hasOwn(p,k))&&Object.keys(p).every(k=>allowed.includes(k)),'MALFORMED_CONTROL_SOURCE',503);
 requireThat(safeInt(p.cr,1),'INVALID_CONTROL_REVISION',503);controlShape(suffix,p,store.securityPrefix);
 if(app){
  registryOf(p);requireThat(ascii(p.policyEpoch),'MALFORMED_APP_CONTROL',503);
  if(Object.hasOwn(p,'denied'))requireThat(typeof p.denied==='boolean','MALFORMED_APP_CONTROL',503);
  if(Object.hasOwn(p,'authorityReady'))requireThat(p.authorityReady===false,'INVALID_APP_AUTHORITY_MARKER',503);
  if(Object.hasOwn(p,'enforcedTargets'))requireThat(Array.isArray(p.enforcedTargets)&&p.enforcedTargets.every(t=>t&&typeof t==='object'&&!Array.isArray(t)),'MALFORMED_CONTROL_TARGETS',503);
 }else{requireThat(ascii(p.ownerEpoch),'MALFORMED_RESOURCE_CONTROL',503);list(p.deniedActions,'MALFORMED_RESOURCE_CONTROL');}
 return {key,projection:JSON.parse(canonical(p)),json:canonical(p),hash:await digest(p)};
}
async function policyState(store,p){
 const row=await store.first('SELECT e.*,v.minutes FROM jwt_v2_policy_heads h JOIN jwt_v2_policy_epochs e ON e.owner_epoch=h.owner_epoch JOIN jwt_v2_policy_history v ON v.owner_epoch=e.owner_epoch AND v.revision=e.coherent_through WHERE h.app=? AND h.env=?',store.app,store.env);
 requireThat(row&&row.owner_epoch===p.policyEpoch&&row.coherent_through===row.highest_seen&&row.coherent_through===p.policyRevision&&row.minutes===p.inactivityMinutes,'CONTROL_POLICY_NOT_COHERENT',503);
 return store.guard('SELECT 1 FROM jwt_v2_policy_heads h JOIN jwt_v2_policy_epochs e ON e.owner_epoch=h.owner_epoch JOIN jwt_v2_policy_history v ON v.owner_epoch=e.owner_epoch AND v.revision=e.coherent_through WHERE h.app=? AND h.env=? AND e.owner_epoch=? AND e.highest_seen=? AND e.coherent_through=? AND v.minutes=?',[store.app,store.env,p.policyEpoch,p.policyRevision,p.policyRevision,p.inactivityMinutes]);
}
async function registryHead(store){return store.first('SELECT r.* FROM jwt_v2_control_registry_heads h JOIN jwt_v2_control_registry_receipts r ON r.receipt_ref=h.receipt_ref WHERE h.app=? AND h.env=?',store.app,store.env);}

// Explicit pinned configuration or exact predecessor bridge; epoch strings have no order.
export async function registryControlPlan(store,{registry,receiptRef,predecessor=null}){
 ref(receiptRef);const value=registryOf(registry),json=canonical(value),hash=await digest(value),old=await registryHead(store);
 const existing=await store.first('SELECT * FROM jwt_v2_control_registry_receipts WHERE receipt_ref=?',receiptRef);
 if(existing){
  requireThat(existing.app===store.app&&existing.env===store.env&&existing.registry_json===json&&old?.receipt_ref===receiptRef,'REGISTRY_RECEIPT_CONFLICT',409);
  const [g,c]=store.guard('SELECT 1 FROM jwt_v2_control_registry_heads WHERE app=? AND env=? AND receipt_ref=?',[store.app,store.env,receiptRef]);return {statements:[g,c],registry:value,receiptRef};
 }
 if(old){
  const prior=JSON.parse(old.registry_json);
  requireThat(predecessor&&predecessor.epoch===prior.keyRegistryEpoch&&predecessor.revision===prior.keyRegistryRevision&&(predecessor.receiptRef===undefined||predecessor.receiptRef===old.receipt_ref),'REGISTRY_BRIDGE_REQUIRED',409);
  requireThat(superset(value.withdrawnKids,prior.withdrawnKids)&&superset(value.withdrawnHandoffKids,prior.withdrawnHandoffKids),'KEY_WITHDRAWAL_ROLLBACK',409);
  if(prior.sharedAcademyRegistryRevision!==undefined){
   requireThat(value.sharedAcademyRegistryRevision>=prior.sharedAcademyRegistryRevision
    &&superset(value.withdrawnSharedAcademyKids,prior.withdrawnSharedAcademyKids),'KEY_WITHDRAWAL_ROLLBACK',409);
   requireThat(value.sharedAcademyRegistryRevision>prior.sharedAcademyRegistryRevision
    ||canonical(value.withdrawnSharedAcademyKids)===canonical(prior.withdrawnSharedAcademyKids),'KEY_REGISTRY_REVISION_ROLLBACK',409);
  }
  for(const [epoch,revision,withdrawn] of [['keyRegistryEpoch','keyRegistryRevision','withdrawnKids'],['handoffRegistryEpoch','handoffRegistryRevision','withdrawnHandoffKids']]){
   if(value[epoch]===prior[epoch])requireThat(value[revision]>=prior[revision]&&(value[revision]>prior[revision]||canonical(value[withdrawn])===canonical(prior[withdrawn])),'KEY_REGISTRY_REVISION_ROLLBACK',409);
   else{
    const used=await store.first("SELECT 1 AS found FROM jwt_v2_control_registry_receipts WHERE app=? AND env=? AND json_extract(registry_json,?)=?",store.app,store.env,'$.'+epoch,value[epoch]);
    requireThat(!used,'REGISTRY_EPOCH_REENTRY',409);
   }
  }
  requireThat(json!==old.registry_json,'REGISTRY_REVISION_UNCHANGED',409);
 }else requireThat(predecessor===null,'REGISTRY_GENESIS_CONFLICT',409);
 const [g,c]=old?store.guard('SELECT 1 FROM jwt_v2_control_registry_heads WHERE app=? AND env=? AND receipt_ref=?',[store.app,store.env,old.receipt_ref]):store.guard('SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_control_registry_heads WHERE app=? AND env=?)',[store.app,store.env]);
 return {registry:value,receiptRef,statements:[g,store.stmt('INSERT INTO jwt_v2_control_registry_receipts VALUES(?,?,?,?,?,?)',receiptRef,store.app,store.env,json,hash,old?.receipt_ref??null),store.stmt('INSERT INTO jwt_v2_control_registry_heads VALUES(?,?,?) ON CONFLICT(app,env) DO UPDATE SET receipt_ref=excluded.receipt_ref',store.app,store.env,receiptRef),c]};
}
export const resourceControlDigest=p=>digest({resourceId:p.resourceId,ownerEpoch:p.ownerEpoch,revision:p.revision,deniedActions:p.deniedActions});
function nativeReceipt(store,p,plan){
 requireThat(plan&&typeof plan==='object'&&!Array.isArray(plan)&&Array.isArray(plan.statements)&&plan.guard,'NATIVE_CONTROL_PLAN_REQUIRED',503);
 const g=plan.guard;exact(g,['table','resourceIdColumn','ownerEpochColumn','revisionColumn','projectionDigestColumn']);
 requireThat(!/^jwt_v2_/i.test(g.table),'NATIVE_PROVENANCE_TABLE_REQUIRED',503);for(const v of Object.values(g))q(v);
 requireThat(new Set(Object.values(g)).size===5,'NATIVE_PROVENANCE_GUARD_REQUIRED',503);
 requireThat(Array.isArray(plan.references)&&plan.references.length>0&&plan.references.length<=256,'NATIVE_CONTROL_REFERENCES_REQUIRED',503);
 const references=plan.references.map(r=>{
  exact(r,['id','scope','ownerEpoch','revision']);requireThat(ascii(r.id)&&r.id.startsWith(store.app+':native:')&&typeof r.scope==='string'&&bytes(r.scope).length>0&&bytes(r.scope).length<=512&&ascii(r.ownerEpoch)&&safeInt(r.revision,1),'INVALID_NATIVE_CONTROL_REFERENCE',503);q(r.id.slice((store.app+':native:').length));return {...r};
 }).sort((a,b)=>canonical(a)<canonical(b)?-1:1);
 requireThat(references.every((r,i)=>i===0||r.id!==references[i-1].id||r.scope!==references[i-1].scope),'DUPLICATE_NATIVE_CONTROL_REFERENCE',503);
 requireThat(references.some(r=>r.id===store.app+':native:'+g.table&&r.ownerEpoch===p.ownerEpoch&&r.revision===p.revision),'NATIVE_CONTROL_CAPTURE_REQUIRED',503);
 return {guard:{...g},references};
}
const nativeMapping=r=>canonical({guard:r.guard,references:r.references.map(({id,scope,ownerEpoch})=>({id,scope,ownerEpoch}))});
async function nativeChecks(store,p,receipt){
 const g=receipt.guard,hash=await resourceControlDigest(p),sourceSQL='SELECT 1 FROM '+q(g.table)+' WHERE '+q(g.resourceIdColumn)+'=? AND '+q(g.ownerEpochColumn)+'=? AND '+q(g.revisionColumn)+'=? AND '+q(g.projectionDigestColumn)+'=?';
 const checks=[store.guard(sourceSQL,[p.resourceId,p.ownerEpoch,p.revision,hash])];
 for(const r of receipt.references){
  const table=r.id.slice((store.app+':native:').length);
  checks.push(store.guard('SELECT 1 FROM jwt_v2_dependencies d WHERE d.id=? AND d.scope=? AND d.owner_epoch=? AND d.revision=? AND EXISTS(SELECT 1 FROM jwt_v2_authority_changes c WHERE c.dependency=d.id AND c.scope=d.scope AND c.owner_epoch=d.owner_epoch AND c.revision=d.revision AND c.source_table=? AND c.operation_id IS NOT NULL AND c.target_json IS NOT NULL)',[r.id,r.scope,r.ownerEpoch,r.revision,table]));
 }
 return checks;
}
async function verifyNativeNow(store,p,r,commitRef){
 // Publication verification is read-only; only prepared source plans use SQL guards.
 const g=r.guard;requireThat(await store.first('SELECT 1 AS found FROM '+q(g.table)+' WHERE '+q(g.resourceIdColumn)+'=? AND '+q(g.ownerEpochColumn)+'=? AND '+q(g.revisionColumn)+'=? AND '+q(g.projectionDigestColumn)+'=?',p.resourceId,p.ownerEpoch,p.revision,await resourceControlDigest(p)),'NATIVE_CONTROL_SOURCE_NOT_CURRENT',503);
 for(const x of r.references){
  requireThat(await store.first('SELECT 1 AS found FROM jwt_v2_control_native_receipts n JOIN jwt_v2_authority_changes c ON c.change_id=n.change_id AND c.dependency=n.dependency AND c.scope=n.scope AND c.owner_epoch=n.owner_epoch AND c.revision=n.revision AND c.source_table=n.source_table AND c.operation_id=n.operation_id AND c.target_json=n.target_json WHERE n.commit_ref=? AND n.dependency=? AND n.scope=? AND n.owner_epoch=? AND n.revision=? AND n.source_table=?',commitRef,x.id,x.scope,x.ownerEpoch,x.revision,x.id.slice((store.app+':native:').length)),'NATIVE_CAPTURE_RECEIPT_MISMATCH',503);
  requireThat(await store.first('SELECT 1 AS found FROM jwt_v2_dependencies d WHERE d.id=? AND d.scope=? AND d.owner_epoch=? AND d.revision=? AND EXISTS(SELECT 1 FROM jwt_v2_authority_changes c WHERE c.dependency=d.id AND c.scope=d.scope AND c.owner_epoch=d.owner_epoch AND c.revision=d.revision AND c.source_table=? AND c.operation_id IS NOT NULL AND c.target_json IS NOT NULL)',x.id,x.scope,x.ownerEpoch,x.revision,x.id.slice((store.app+':native:').length)),'NATIVE_CONTROL_DEPENDENCY_NOT_CURRENT',503);
 }
}


/* Prepare only. Native fact statements, their fixed provenance/vector checks and
 * this target commit belong in ONE primary guarded batch. No R2 or callbacks.
 * Semantic ownership is (app,env,suffix); an initial object_key is retained only
 * as immutable source identity, independent of later physical R2 generations.
 * genesisReceipt is an explicit configured receipt reference, never cache seed.
 */
export async function sourceControlPlan(store,{suffix,projection,expectedCR=null,commitRef,genesisReceipt=null,nativePlan=null}){
 const v=await checked(store,suffix,projection);ref(commitRef);
 requireThat(expectedCR===null||safeInt(expectedCR,1),'CONTROL_EXPECTED_REVISION_REQUIRED',409);
 const old=await store.first('SELECT * FROM jwt_v2_control_targets WHERE app=? AND env=? AND suffix=?',store.app,store.env,suffix),genesis=await store.first('SELECT * FROM jwt_v2_control_genesis WHERE app=? AND env=? AND suffix=?',store.app,store.env,suffix);
 requireThat(old?expectedCR===old.cr:expectedCR===null,'CONTROL_SOURCE_CAS_FAILED',409);
 if(old&&v.projection.cr===old.cr){
  requireThat(old.projection_json===v.json&&old.commit_ref===commitRef,'CONTROL_SAME_REVISION_CONFLICT',409);
  await assertCommittedControl(store,suffix,v.projection);
  const [g,c]=store.guard('SELECT 1 FROM jwt_v2_control_targets WHERE object_key=? AND cr=? AND projection_digest=? AND commit_ref=?',[old.object_key,old.cr,v.hash,commitRef]);return {statements:[g,c],projection:v.projection,receipt:JSON.parse((await store.first('SELECT receipt_json FROM jwt_v2_control_commits WHERE commit_ref=?',commitRef)).receipt_json)};
 }
 requireThat(!old||v.projection.cr>old.cr,'CONTROL_REVISION_ROLLBACK',409);
 if(!old){ref(genesisReceipt);requireThat(!genesis,'CONTROL_GENESIS_CONFLICT',409);}else requireThat(genesisReceipt===null&&genesis,'CONTROL_GENESIS_CONFLICT',409);
 const head=[],tail=[];let provenance;
 if(suffix==='control/app'){
  const [g,c]=await policyState(store,v.projection);head.push(g);tail.push(c);
  if(old)requireThat(v.projection.migrationFloor>=JSON.parse(old.projection_json).migrationFloor,'MIGRATION_FLOOR_ROLLBACK',409);
  let registry=await registryHead(store);
  if(!registry&&!old){const initial=await registryControlPlan(store,{registry:v.projection,receiptRef:genesisReceipt+'/registry'});head.push(...initial.statements);registry={receipt_ref:initial.receiptRef,registry_json:canonical(initial.registry)};}
  requireThat(registry?.registry_json===canonical(registryOf(v.projection)),'CONTROL_REGISTRY_NOT_CURRENT',503);
  const [rg,rc]=store.guard('SELECT 1 FROM jwt_v2_control_registry_heads h JOIN jwt_v2_control_registry_receipts r ON r.receipt_ref=h.receipt_ref WHERE h.app=? AND h.env=? AND h.receipt_ref=? AND r.registry_json=?',[store.app,store.env,registry.receipt_ref,registry.registry_json]);head.push(rg);tail.push(rc);provenance={kind:'configured-registry-policy',registryReceipt:registry.receipt_ref};
 }else{
  const receipt=nativeReceipt(store,v.projection,nativePlan),mapping=nativeMapping(receipt);
  if(old){const prior=JSON.parse(old.projection_json);requireThat(mapping===genesis.native_mapping_json&&v.projection.ownerEpoch===prior.ownerEpoch,'RESOURCE_SOURCE_BRIDGE_REQUIRED',409);requireThat(v.projection.revision>=prior.revision,'RESOURCE_REVISION_ROLLBACK',409);if(canonical(prior.deniedActions)!==canonical(v.projection.deniedActions))requireThat(v.projection.revision>prior.revision,'RESOURCE_NEW_PROVENANCE_REQUIRED',409);}
  const checks=await nativeChecks(store,v.projection,receipt);head.push(...nativePlan.statements,...checks.map(x=>x[0]));tail.push(...checks.map(x=>x[1]));provenance={kind:'native-resource',...receipt};
 }
 const [guard,clear]=old?store.guard('SELECT 1 FROM jwt_v2_control_targets WHERE object_key=? AND cr=? AND projection_digest=? AND commit_ref=?',[old.object_key,old.cr,old.projection_digest,old.commit_ref]):store.guard('SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_control_targets WHERE app=? AND env=? AND suffix=?)',[store.app,store.env,suffix]);
 const receipt={schema:1,app:store.app,env:store.env,suffix,cr:v.projection.cr,commitRef,projectionDigest:v.hash,provenance};
 const statements=[guard,...head];
 if(!old)statements.push(store.stmt('INSERT INTO jwt_v2_control_genesis VALUES(?,?,?,?,?,?)',store.app,store.env,suffix,genesisReceipt,v.hash,provenance.kind==='native-resource'?nativeMapping(provenance):null));
 statements.push(store.stmt('INSERT INTO jwt_v2_control_commits VALUES(?,?,?,?,?,?,?)',commitRef,store.app,store.env,suffix,v.projection.cr,v.hash,canonical(receipt)),store.stmt('INSERT INTO jwt_v2_control_targets VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(object_key) DO UPDATE SET cr=excluded.cr,projection_json=excluded.projection_json,projection_digest=excluded.projection_digest,commit_ref=excluded.commit_ref,provenance_json=excluded.provenance_json',old?.object_key??v.key,store.app,store.env,suffix,v.projection.cr,v.json,v.hash,commitRef,canonical(provenance)));
 if(provenance.kind==='native-resource')for(const r of provenance.references)statements.push(store.stmt('INSERT INTO jwt_v2_control_native_receipts SELECT ?,dependency,scope,owner_epoch,revision,source_table,change_id,operation_id,target_json FROM jwt_v2_authority_changes WHERE dependency=? AND scope=? AND owner_epoch=? AND revision=? AND source_table=? AND operation_id IS NOT NULL AND target_json IS NOT NULL ORDER BY change_id DESC LIMIT 1',commitRef,r.id,r.scope,r.ownerEpoch,r.revision,r.id.slice((store.app+':native:').length)));
 statements.push(...tail,clear);
 return {statements,projection:v.projection,receipt};
}
export async function configuredControlGenesis(store,{suffix,projection,receiptRef,commitRef=receiptRef,nativePlan=null}){
 ref(receiptRef);const old=await store.first('SELECT * FROM jwt_v2_control_genesis WHERE app=? AND env=? AND suffix=?',store.app,store.env,suffix);
 if(old){const v=await checked(store,suffix,projection);requireThat(old.receipt_ref===receiptRef&&old.projection_digest===v.hash,'CONTROL_GENESIS_CONFLICT',409);await assertCommittedControl(store,suffix,projection);return {created:false};}
 const plan=await sourceControlPlan(store,{suffix,projection,commitRef,genesisReceipt:receiptRef,nativePlan});await store.batch(plan.statements);return {created:true,receipt:plan.receipt};
}
export async function assertCommittedControl(store,suffix,committed){
 const v=await checked(store,suffix,committed,{allowEnvelope:true});
 const row=await store.first('SELECT t.*,c.receipt_json,c.projection_digest AS receipt_digest FROM jwt_v2_control_targets t JOIN jwt_v2_control_commits c ON c.commit_ref=t.commit_ref AND c.app=t.app AND c.env=t.env AND c.suffix=t.suffix AND c.cr=t.cr WHERE t.app=? AND t.env=? AND t.suffix=?',store.app,store.env,suffix);
 requireThat(row&&row.app===store.app&&row.env===store.env&&row.suffix===suffix&&row.cr===v.projection.cr&&row.projection_json===v.json&&row.projection_digest===v.hash&&row.receipt_digest===v.hash,'CONTROL_SOURCE_NOT_COMMITTED',503);
 const receipt=JSON.parse(row.receipt_json),provenance=JSON.parse(row.provenance_json);
 requireThat(receipt.commitRef===row.commit_ref&&receipt.projectionDigest===v.hash&&canonical(receipt.provenance)===row.provenance_json,'CONTROL_SOURCE_RECEIPT_MISMATCH',503);
 if(suffix==='control/app'){await policyState(store,v.projection);const r=await registryHead(store);requireThat(r&&r.receipt_ref===provenance.registryReceipt&&r.registry_json===canonical(registryOf(v.projection)),'CONTROL_REGISTRY_NOT_CURRENT',503);}
 else{requireThat(provenance.kind==='native-resource','NATIVE_CONTROL_SOURCE_REQUIRED',503);nativeReceipt(store,v.projection,{...provenance,statements:[]});await verifyNativeNow(store,v.projection,provenance,row.commit_ref);}
 return receipt;
}
