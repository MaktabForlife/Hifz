import {withdrawalFields} from './key-withdrawal.mjs';
import {sharedAccountSelector,sharedAccountBaselinePlan} from './shared-account-baselines.mjs';
import {senderFloorSchemaSQL} from './sender-floors.mjs';
import {bytes,canonical,strictJSON,exact,requireThat,ascii,safeInt,uuid,digest,unb64u,equal} from './codec.mjs';
import {validateEvent,validateTarget,receiveBatch,BUCKETS} from './events.mjs';
import {restrictionPlan,markSessionCovered,markControlCovered,worksetApplied} from './publication.mjs';
import {compactFloors} from './floors.mjs';
import {SnapshotStore,SnapshotReceiver,validateReconcileRequest,requestBinding,buildSnapshot,serveSnapshotPage,encodeEventReplay,verifyEventReplay,persistEventReplay,compareUtf8,snapshotEffect} from './snapshot.mjs';
import {nativeFence} from './capture.mjs';
import {retryDelaySeconds} from './outbox.mjs';
import {sourceControlPlan,registryControlPlan} from './control-publication.mjs';
import {validatePolicy,confirmPolicyHistory,applyFamilyPolicy} from './policy.mjs';

export const runtimeServiceSchemaSQL=[
 "CREATE TABLE IF NOT EXISTS jwt_v2_service_reports(operation_id TEXT PRIMARY KEY,request_digest TEXT NOT NULL,report_json TEXT NOT NULL,result_json TEXT);",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_service_report_binding BEFORE UPDATE ON jwt_v2_service_reports WHEN OLD.operation_id<>NEW.operation_id OR OLD.request_digest<>NEW.request_digest OR OLD.report_json<>NEW.report_json OR (OLD.result_json IS NOT NULL AND OLD.result_json IS NOT NEW.result_json) BEGIN SELECT RAISE(ABORT,'service_report_immutable'); END;",
 "CREATE TABLE IF NOT EXISTS jwt_v2_service_outbox(operation_id TEXT PRIMARY KEY,kind TEXT NOT NULL CHECK(kind IN('logout','incidents')),report_json TEXT NOT NULL,request_digest TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('PENDING','ACKNOWLEDGED')),attempts INTEGER NOT NULL DEFAULT 0,next_attempt_at INTEGER NOT NULL DEFAULT 0,result_json TEXT);",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_service_outbox_immutable BEFORE UPDATE ON jwt_v2_service_outbox WHEN OLD.operation_id<>NEW.operation_id OR OLD.kind<>NEW.kind OR OLD.report_json<>NEW.report_json OR OLD.request_digest<>NEW.request_digest OR NEW.attempts<OLD.attempts OR (OLD.state='ACKNOWLEDGED' AND NEW.state<>'ACKNOWLEDGED') OR (OLD.result_json IS NOT NULL AND OLD.result_json IS NOT NEW.result_json) BEGIN SELECT RAISE(ABORT,'service_outbox_immutable'); END;"
].join('\n')+'\n'+senderFloorSchemaSQL;
const instances=new WeakMap(),child=app=>app==='studio'||app==='hifz';
const bucketFor={accountCutoff:'accountCutoffs',credentialEpoch:'credentialFloors',parent:'parentCutoffs',browser:'browserCutoffs',key:'keyWithdrawals',policy:'policies',dependency:'dependencyFloors'};
const logical=projection=>Object.fromEntries(Object.entries(projection).filter(([key])=>!['schema','incarnation','generation','state','publicationNonce'].includes(key)));
function streamEntry(value){
 exact(value,['sourceApp','targetApp','stream','ownerEpoch','genesis']);
 requireThat(value.sourceApp==='academy'&&child(value.targetApp)&&ascii(value.stream)&&ascii(value.ownerEpoch)&&typeof value.genesis==='boolean','INVALID_SERVICE_STREAM_REGISTRY',503);return value;
}
export function loadServiceRegistry(runtime){
 const raw=runtime.settings.raw;requireThat([3,4].includes(raw.snapshotSchema),'SCOPED_SNAPSHOT_PROFILE_REQUIRED',503);requireThat(Array.isArray(raw.serviceStreams)&&raw.serviceStreams.length>0&&raw.serviceStreams.length<=128&&Array.isArray(raw.ownerBridges)&&raw.ownerBridges.length<=128&&Array.isArray(raw.serviceDependencies)&&raw.serviceDependencies.length<=256,'SERVICE_REGISTRY_REQUIRED',503);
 const streams=raw.serviceStreams.map(streamEntry),seen=new Set();
 for(const s of streams){const key=canonical([s.targetApp,s.stream,s.ownerEpoch]);requireThat(!seen.has(key),'DUPLICATE_SERVICE_STREAM',503);seen.add(key);}
 const bridges=raw.ownerBridges.map(value=>{exact(value,['sourceApp','targetApp','stream','ownerEpoch','predecessorEpoch','coveredThrough','receiptRef','denialsIncluded']);requireThat(value.sourceApp==='academy'&&child(value.targetApp)&&ascii(value.stream)&&ascii(value.ownerEpoch)&&ascii(value.predecessorEpoch)&&value.ownerEpoch!==value.predecessorEpoch&&safeInt(value.coveredThrough)&&ascii(value.receiptRef)&&value.denialsIncluded===true,'INVALID_OWNER_BRIDGE_REGISTRY',503);requireThat(streams.some(s=>s.targetApp===value.targetApp&&s.stream===value.stream&&s.ownerEpoch===value.ownerEpoch)&&streams.some(s=>s.targetApp===value.targetApp&&s.stream===value.stream&&s.ownerEpoch===value.predecessorEpoch),'OWNER_BRIDGE_STREAM_REQUIRED',503);return value;});
 seen.clear();for(const b of bridges){const key=canonical([b.targetApp,b.stream,b.ownerEpoch]);requireThat(!seen.has(key),'DUPLICATE_OWNER_BRIDGE',503);seen.add(key);}
 const dependencies=new Map();
 for(const value of raw.serviceDependencies){exact(value,['id','ownerApp','ownerEpoch','recipients','actions','scope']);requireThat(['ACCOUNT','GLOBAL'].includes(value.scope),'INVALID_SERVICE_DEPENDENCY_SCOPE',503);requireThat(ascii(value.id)&&value.ownerApp==='academy'&&ascii(value.ownerEpoch)&&Array.isArray(value.recipients)&&value.recipients.length>0&&value.recipients.every(child)&&new Set(value.recipients).size===value.recipients.length&&Array.isArray(value.actions)&&value.actions.every(a=>ascii(a))&&new Set(value.actions).size===value.actions.length&&!dependencies.has(value.id),'INVALID_SERVICE_DEPENDENCY_REGISTRY',503);dependencies.set(value.id,{ownerApp:value.ownerApp,epoch:value.ownerEpoch,recipients:[...value.recipients],actions:[...value.actions],scope:value.scope??'UNDECLARED'});}
 return {streams,bridges,dependencies};
}
export function cursorKeys(runtime){
 requireThat(runtime.app==='academy','WRONG_CURSOR_KEY_OWNER',503);
 const input=strictJSON(runtime.env.UAA_V2_CURSOR_KEYS_JSON??'null');exact(input,['currentKid','keys']);
 requireThat(ascii(input.currentKid,64)&&Array.isArray(input.keys)&&input.keys.length>0&&input.keys.length<=20,'CURSOR_KEYS_REQUIRED',503);
 const keys=new Map(),others=[...runtime.settings.csrf.keys.values(),...runtime.settings.draft.keys.values(),...[...runtime.settings.serviceKeys.values()].map(v=>v.key)];
 for(const entry of input.keys){exact(entry,['kid','key']);requireThat(ascii(entry.kid,64)&&!keys.has(entry.kid),'CURSOR_KEY_REGISTRY_CONFLICT',503);const key=unb64u(entry.key,32);requireThat(!others.some(v=>equal(v,key))&&![...keys.values()].some(v=>equal(v,key)),'KEY_PURPOSE_SEPARATION_REQUIRED',503);keys.set(entry.kid,key);}
 requireThat(keys.has(input.currentKid),'CURRENT_CURSOR_KEY_REQUIRED',503);return {keys,currentKid:input.currentKid};
}
class RuntimeServices{
 constructor(runtime){this.runtime=runtime;this.store=runtime.store;this.registry=loadServiceRegistry(runtime);this.snap=new SnapshotStore(this.store);}
 async ledger(targetApp,stream,ownerEpoch){
  const configured=this.registry.streams.find(s=>s.targetApp===targetApp&&s.stream===stream&&s.ownerEpoch===ownerEpoch);requireThat(configured,'UNREGISTERED_SERVICE_EPOCH',409);
  const row=this.runtime.app==='academy'?await this.store.first('SELECT * FROM jwt_v2_sender_streams WHERE target_app=? AND stream=?',targetApp,stream):await this.store.first('SELECT * FROM jwt_v2_event_streams WHERE source_app=? AND target_app=? AND stream=? AND owner_epoch=?','academy',targetApp,stream,ownerEpoch);
  requireThat(row&&(this.runtime.app!=='academy'||row.owner_epoch===ownerEpoch),'SERVICE_STREAM_LEDGER_NOT_INSTALLED',503);return row;
 }
 async eventOptions(peer){
  requireThat(peer.sourceApp==='academy'&&peer.targetApp===this.runtime.app&&child(this.runtime.app),'EVENT_DIRECTION_CONFLICT',403);
  const streams=new Map();for(const entry of this.registry.streams.filter(s=>s.targetApp===this.runtime.app)){await this.ledger(entry.targetApp,entry.stream,entry.ownerEpoch);if(!streams.has(entry.stream))streams.set(entry.stream,new Set());streams.get(entry.stream).add(entry.ownerEpoch);}
  const budget={remaining:20};return {streams,dependencies:this.registry.dependencies,planEffect:e=>{if(e.target.type==='dependency'){const rule=this.registry.dependencies.get(e.target.id);requireThat(rule.scope==='GLOBAL'?e.sub===null:typeof e.sub==='string','EVENT_DEPENDENCY_SCOPE_CONFLICT',409);}return this.effectPlan(e.eventId,e.target,{sub:e.sub});},publishAndCovered:e=>this.publishWork(e.eventId,{budget})};
 }
 async policyPlan(target,now){
  validatePolicy(target);const epoch=await this.store.first('SELECT * FROM jwt_v2_policy_epochs WHERE owner_epoch=?',target.ownerEpoch);requireThat(epoch&&target.revision>=epoch.base_revision&&(epoch.sealed_through===null||target.revision<=epoch.sealed_through),'POLICY_EPOCH_RECONCILIATION_REQUIRED',409);
  const old=await this.store.first('SELECT target_json FROM jwt_v2_policy_history WHERE owner_epoch=? AND revision=?',target.ownerEpoch,target.revision);
  if(old){requireThat(old.target_json===canonical(target),'POLICY_REVISION_CONFLICT',409);return [];}
  const [g,c]=this.store.guard('SELECT 1 FROM jwt_v2_policy_epochs WHERE owner_epoch=? AND highest_seen=? AND coherent_through=?',[epoch.owner_epoch,epoch.highest_seen,epoch.coherent_through]);
  return [g,this.store.stmt('INSERT INTO jwt_v2_policy_history VALUES(?,?,?,?,?,?)',target.ownerEpoch,target.revision,target.inactivityMinutes,canonical(target),await digest(target),now),this.store.stmt('UPDATE jwt_v2_policy_epochs SET highest_seen=max(highest_seen,?) WHERE owner_epoch=?',target.revision,target.ownerEpoch),c];
 }
 async effectPlan(workId,target,{sub=null}={}){
  if(target.type==='key'&&target.purpose==='academy-shared-access')requireThat(child(this.runtime.app)&&this.runtime.settings.sharedAcademy,'SHARED_KEY_REGISTRY_REQUIRED',503);
  const now=this.runtime.clock(),requiredControlKeys=['policy','key'].includes(target.type)?[this.store.controlKey('control/app')]:[];
  const native=typeof this.runtime.native?.applySecurityFactPlan==='function'?await this.runtime.native.applySecurityFactPlan({target,scopeSub:sub}):[];requireThat(Array.isArray(native),'NATIVE_SECURITY_FACT_PLAN_REQUIRED',503);
   return [...native,...(target.type==='policy'?await this.policyPlan(target,now):[]),...await restrictionPlan(this.store,{workId,target,sub,now,requiredControlKeys})];
 }
 async publishWork(workId,{budget={remaining:20}}={}){
  const work=await this.store.first('SELECT * FROM jwt_v2_worksets WHERE work_id=?',workId);requireThat(work,'PUBLICATION_WORK_UNKNOWN',409);const target=strictJSON(work.target_json);
  if(target.type==='policy')await this.finishPolicy(target);
  if(target.type==='key')await this.finishKey(target,workId);
  const controls=await this.store.all('SELECT * FROM jwt_v2_control_publications WHERE work_id=? AND covered=0',workId);
  for(const control of controls){requireThat(control.object_key===this.store.controlKey('control/app'),'UNKNOWN_SERVICE_CONTROL',503);const published=await this.runtime.cache.publish('control/app',async()=>strictJSON((await this.store.first('SELECT projection_json FROM jwt_v2_control_targets WHERE object_key=?',control.object_key)).projection_json));await markControlCovered(this.store,{workId,controlKey:control.object_key,projection:published});}
  {const rows=budget.remaining>0?await this.store.all('SELECT sid FROM jwt_v2_publications WHERE work_id=? AND published_cr IS NULL AND covered_by_expiry=0 LIMIT ?',workId,Math.min(20,budget.remaining)):[];
   for(const row of rows){budget.remaining--;let family=await this.store.family(row.sid);if(this.runtime.clock()>=family.s_exp){await markSessionCovered(this.store,{workId,sid:row.sid,now:this.runtime.clock()});continue;}
    if(target.type==='policy')await applyFamilyPolicy(this.store,{sid:row.sid,now:this.runtime.clock()});
    family=await this.store.family(row.sid);const saved=strictJSON(family.projection_json),next={...saved,enforcedTargets:compactFloors([...(saved.enforcedTargets||[]),target])};
    if(target.type==='key'){
     const fields=withdrawalFields(target.purpose);
     next[fields.revision]=Math.max(saved[fields.revision]??0,target.registryRevision);
     next[fields.withdrawn]=[...new Set([...(saved[fields.withdrawn]||[]),target.kid])].sort();
    }
    const [g,c]=this.store.guard('SELECT 1 FROM jwt_v2_families WHERE sid=? AND cr=? AND projection_json=?',[row.sid,family.cr,family.projection_json]);
    await this.store.batch([g,this.store.stmt('UPDATE jwt_v2_families SET projection_json=?,cr=cr+1 WHERE sid=?',canonical(next),row.sid),c]);
    const projection=await this.runtime.publishFamily(row.sid);await markSessionCovered(this.store,{workId,sid:row.sid,projection,controlKey:this.store.controlKey('security/session/'+row.sid),now:this.runtime.clock()});
   }
  }
  return worksetApplied(this.store,workId);
 }

 async appPrimary(){const row=await this.store.first('SELECT projection_json FROM jwt_v2_control_targets WHERE object_key=?',this.store.controlKey('control/app'));requireThat(row,'APP_CONTROL_SOURCE_UNAVAILABLE',503);return strictJSON(row.projection_json);}
 async finishPolicy(target){
  const epoch=await this.store.first('SELECT * FROM jwt_v2_policy_epochs WHERE owner_epoch=?',target.ownerEpoch);requireThat(epoch&&epoch.highest_seen-epoch.base_revision<2000,'POLICY_HISTORY_UNAVAILABLE',503);
  const history=await this.store.all('SELECT * FROM jwt_v2_policy_history WHERE owner_epoch=? ORDER BY revision',target.ownerEpoch);
  requireThat(history.length===epoch.highest_seen-epoch.base_revision+1&&history.every((h,i)=>h.revision===epoch.base_revision+i),'POLICY_HISTORY_GAP',503);
  if(epoch.coherent_through<epoch.highest_seen){
   const events=await this.store.all("SELECT event_json FROM jwt_v2_events WHERE source_app='academy' AND target_app=? AND json_extract(event_json,'$.kind')='policy-updated' AND json_extract(event_json,'$.target.ownerEpoch')=?",this.runtime.app,target.ownerEpoch);
   const signed=new Map();const streams=new Map();for(const s of this.registry.streams.filter(s=>s.targetApp===this.runtime.app)){if(!streams.has(s.stream))streams.set(s.stream,new Set());streams.get(s.stream).add(s.ownerEpoch);}
   for(const row of events){const event=strictJSON(row.event_json);await validateEvent(event,{env:this.runtime.config.env,targetApp:this.runtime.app,streams,dependencies:this.registry.dependencies});signed.set(canonical(event.target),event.digest);}
   let mode='CONTIGUOUS_EVENTS',receipt;
   const relevant=history.filter(h=>h.revision>epoch.base_revision||epoch.predecessor_epoch!==null);
   if(relevant.every(h=>signed.has(h.target_json)))receipt='policy-events-'+await digest(relevant.map(h=>signed.get(h.target_json)));
   else{
    const captures=await this.store.all("SELECT snapshot_id FROM jwt_v2_receive_snapshots WHERE status IN('VERIFIED','APPLIED') ORDER BY snapshot_id LIMIT 100");
    for(const capture of captures){const rows=await this.store.all("SELECT record_json FROM jwt_v2_receive_records WHERE snapshot_id=? AND bucket='policies'",capture.snapshot_id),records=new Set(rows.map(r=>r.record_json));if(relevant.every(h=>records.has(h.target_json))){mode='VERIFIED_SNAPSHOT';receipt='policy-snapshot-'+capture.snapshot_id;break;}}
   }
   requireThat(receipt,'AUTHENTICATED_POLICY_HISTORY_INCOMPLETE',503);
   await confirmPolicyHistory(this.store,{trustedCoverage:{schema:2,env:this.runtime.config.env,sourceApp:'academy',targetApp:this.runtime.app,mode,ownerEpoch:target.ownerEpoch,throughRevision:epoch.highest_seen,receiptRef:receipt},now:this.runtime.clock()});
  }
  const head=await this.store.first('SELECT e.*,v.minutes FROM jwt_v2_policy_heads h JOIN jwt_v2_policy_epochs e ON e.owner_epoch=h.owner_epoch JOIN jwt_v2_policy_history v ON v.owner_epoch=e.owner_epoch AND v.revision=e.coherent_through WHERE h.app=? AND h.env=?',this.runtime.app,this.runtime.config.env),current=await this.appPrimary();
  requireThat(head&&head.coherent_through===head.highest_seen,'POLICY_HISTORY_NOT_COHERENT',503);
  if(current.policyEpoch!==head.owner_epoch||current.policyRevision!==head.coherent_through||current.inactivityMinutes!==head.minutes){const next={...current,cr:current.cr+1,policyEpoch:head.owner_epoch,policyRevision:head.coherent_through,inactivityMinutes:head.minutes},plan=await sourceControlPlan(this.store,{suffix:'control/app',projection:next,expectedCR:current.cr,commitRef:'service-policy-'+head.owner_epoch+'-'+head.coherent_through});await this.store.batch(plan.statements);}
 }
 async finishKey(target,workId){
  const current=await this.appPrimary(),fields=withdrawalFields(target.purpose);
  const revision=current[fields.revision]??(target.purpose==='academy-handoff'?current.keyRegistryRevision:0);
  const withdrawn=current[fields.withdrawn]||[];
  if(revision>=target.registryRevision&&withdrawn.includes(target.kid))return;
  requireThat(target.registryRevision>revision,'KEY_REGISTRY_CONFLICT',409);
  const next={...current,cr:current.cr+1,[fields.revision]:target.registryRevision,[fields.withdrawn]:[...new Set([...withdrawn,target.kid])].sort()};
  const registry=await registryControlPlan(this.store,{registry:next,receiptRef:'service-key-'+workId,predecessor:{epoch:current.keyRegistryEpoch,revision:current.keyRegistryRevision}});await this.store.batch(registry.statements);
  const plan=await sourceControlPlan(this.store,{suffix:'control/app',projection:next,expectedCR:current.cr,commitRef:'service-key-'+workId});await this.store.batch(plan.statements);
 }
 async acceptReport(body,peer,{kind}){
  exact(body,['schema','env','sourceApp','targetApp','operationId','sub','psid','sid','bsid','bv','ce','ae','kind','evidenceRef']);
  requireThat(this.runtime.app==='academy'&&child(peer.sourceApp)&&body.schema===2&&body.env===this.runtime.config.env&&body.sourceApp===peer.sourceApp&&body.targetApp==='academy'&&uuid(body.operationId)&&uuid(body.psid)&&uuid(body.sid)&&uuid(body.bsid)&&safeInt(body.bv,1)&&safeInt(body.ce,1)&&safeInt(body.ae,1)&&typeof body.sub==='string'&&bytes(body.sub).length>0&&bytes(body.sub).length<=180&&!/[\u0000-\u0020\u007f]/.test(body.sub)&&ascii(body.evidenceRef,128),'INVALID_CHILD_REPORT',400);
  requireThat(kind==='logout'?body.kind==='VOLUNTARY_LOGOUT':['VERIFIED_REFRESH_REUSE','CONFIRMED_KEY_COMPROMISE'].includes(body.kind),'REPORT_PURPOSE_CONFLICT',403);
  const hash=await digest(body),old=await this.store.first('SELECT * FROM jwt_v2_service_reports WHERE operation_id=?',body.operationId);
  requireThat(!old||old.request_digest===hash,'REPORT_OPERATION_CONFLICT',409);if(old?.result_json)return strictJSON(old.result_json);
  const parent=await this.store.first('SELECT * FROM jwt_v2_parents WHERE psid=?',body.psid);
  requireThat(parent&&parent.sub===body.sub&&parent.bsid===body.bsid&&parent.bv===body.bv&&parent.ce===body.ce&&parent.ae===body.ae,'REPORT_PARENT_BINDING_CONFLICT',409);
  if(this.runtime.clock()>=parent.s_exp)return {schema:2,operationId:body.operationId,status:'RECONCILIATION_REQUIRED',cutoff:null,receipt:null};
  // A terminal SID/parent is not an incident-evidence veto. The child attests
  // its immutable owning evidence; only the canonical joint pair can advance.
  if(!old){try{await this.store.stmt('INSERT INTO jwt_v2_service_reports VALUES(?,?,?,NULL)',body.operationId,hash,canonical(body)).run();}catch(e){const raced=await this.store.first('SELECT request_digest FROM jwt_v2_service_reports WHERE operation_id=?',body.operationId);requireThat(raced?.request_digest===hash,'REPORT_OPERATION_CONFLICT',409);}}
  const accepted=await this.store.acceptCutoff({sub:body.sub,ce:body.ce,ae:body.ae,operationId:body.operationId,kind:body.kind,now:this.runtime.clock()}),result={schema:2,operationId:body.operationId,status:accepted.status,cutoff:accepted.cutoff,receipt:accepted.receipt??null};
  const [g,c]=this.store.guard('SELECT 1 FROM jwt_v2_service_reports WHERE operation_id=? AND request_digest=? AND result_json IS NULL',[body.operationId,hash]);
  const nowKnown=await this.store.first('SELECT result_json FROM jwt_v2_service_reports WHERE operation_id=?',body.operationId);
  if(nowKnown.result_json){requireThat(nowKnown.result_json===canonical(result),'REPORT_RECEIPT_CONFLICT',409);return strictJSON(nowKnown.result_json);}
  await this.store.batch([g,this.store.stmt('UPDATE jwt_v2_service_reports SET result_json=? WHERE operation_id=?',canonical(result),body.operationId),c]);
  if(accepted.status==='ACCEPTED')await this.publishWork(body.operationId).catch(()=>{});
  return result;
 }

 async queueReport({binding,kind,operationId,now=this.runtime.clock(),incidentKind,evidenceRef}){
  requireThat(child(this.runtime.app)&&['logout','incidents'].includes(kind)&&uuid(operationId)&&safeInt(now),'INVALID_LOCAL_REPORT',400);
  const family=await this.store.family(binding?.sid);requireThat(family&&['sub','psid','sid','bsid','bv','ce','ae','le'].every(k=>family[k]===binding[k]),'LOCAL_REPORT_CONTEXT_CONFLICT',409);
  if(now>=family.s_exp)return {operationId,outcome:'GLOBAL_UNCONFIRMED',canonicalAccepted:false,globalConfirmed:false,localExpired:true,receipt:null};
  requireThat(kind==='logout'||['VERIFIED_REFRESH_REUSE','CONFIRMED_KEY_COMPROMISE'].includes(incidentKind)&&ascii(evidenceRef,128),'INCIDENT_EVIDENCE_REQUIRED',403);
  const report={schema:2,env:this.runtime.config.env,sourceApp:this.runtime.app,targetApp:'academy',operationId,sub:binding.sub,psid:binding.psid,sid:binding.sid,bsid:binding.bsid,bv:binding.bv,ce:binding.ce,ae:binding.ae,kind:kind==='logout'?'VOLUNTARY_LOGOUT':incidentKind,evidenceRef:kind==='logout'?'local-logout-'+operationId:evidenceRef},hash=await digest(report);
  const old=await this.store.first('SELECT * FROM jwt_v2_service_outbox WHERE operation_id=?',operationId);requireThat(!old||old.request_digest===hash,'REPORT_OPERATION_CONFLICT',409);
  const workId='local-report-'+operationId;
  if(!old){
   requireThat(safeInt(binding.le+1),'LOCAL_EPOCH_EXHAUSTED',503);
   const target={type:'localEpoch',app:this.runtime.app,sub:binding.sub,ce:binding.ce,ae:binding.ae,maxLe:binding.le},effects=await restrictionPlan(this.store,{workId,target,now});
   const [g,c]=this.store.guard('SELECT 1 FROM jwt_v2_families WHERE sid=? AND sub=? AND psid=? AND bsid=? AND bv=? AND ce=? AND ae=? AND le=? AND s_exp>?',[binding.sid,binding.sub,binding.psid,binding.bsid,binding.bv,binding.ce,binding.ae,binding.le,now]);
   try{await this.store.batch([g,...effects,this.store.stmt('UPDATE jwt_v2_accounts SET le=max(le,?),revision=revision+1 WHERE sub=? AND ce=? AND ae=?',binding.le+1,binding.sub,binding.ce,binding.ae),this.store.stmt("INSERT INTO jwt_v2_service_outbox(operation_id,kind,report_json,request_digest,state) VALUES(?,?,?,?,'PENDING')",operationId,kind,canonical(report),hash),c]);}
   catch(e){const raced=await this.store.first('SELECT request_digest FROM jwt_v2_service_outbox WHERE operation_id=?',operationId);requireThat(raced?.request_digest===hash,'LOCAL_REPORT_CAPTURE_UNAVAILABLE',503);}
  }
  await this.publishWork(workId).catch(()=>{});
  await this.deliverReports({limit:1,operationId,now}).catch(()=>{});
  const current=await this.store.first('SELECT * FROM jwt_v2_service_outbox WHERE operation_id=?',operationId),receipt=current.result_json&&strictJSON(current.result_json);
  return {operationId,outcome:current.state==='ACKNOWLEDGED'?'ACCEPTED_PENDING':'GLOBAL_UNCONFIRMED',canonicalAccepted:current.state==='ACKNOWLEDGED',globalConfirmed:false,receipt:receipt??null};
 }
 async deliverReports({limit=20,operationId=null,now=this.runtime.clock(),jitter}={}){
  requireThat(child(this.runtime.app)&&safeInt(limit,1)&&limit<=20&&safeInt(now)&&(operationId===null||uuid(operationId)),'INVALID_REPORT_PUMP',503);
  const rows=operationId?await this.store.all("SELECT * FROM jwt_v2_service_outbox WHERE operation_id=? AND state='PENDING' AND next_attempt_at<=? LIMIT 1",operationId,now):await this.store.all("SELECT * FROM jwt_v2_service_outbox WHERE state='PENDING' AND next_attempt_at<=? ORDER BY next_attempt_at,attempts,operation_id LIMIT ?",now,limit);let attempted=0,acknowledged=0;
  for(const row of rows){const attempt=row.attempts+1,next=now+retryDelaySeconds(attempt,{jitter});requireThat(safeInt(next)&&safeInt(attempt,1),'REPORT_RETRY_EXHAUSTED',503);
   const changed=await this.store.stmt("UPDATE jwt_v2_service_outbox SET attempts=?,next_attempt_at=? WHERE operation_id=? AND state='PENDING' AND attempts=? AND next_attempt_at<=?",attempt,next,row.operation_id,row.attempts,now).run();if(changed.meta?.changes!==1)continue;attempted++;
   try{const {serviceFetch}=await import('./http-service.mjs'),body=strictJSON(row.report_json),reply=await serviceFetch(this.runtime,{targetApp:'academy',path:'/internal/auth/v2/'+row.kind,body,operationId:row.operation_id});exact(reply,['schema','operationId','status','cutoff','receipt']);requireThat(reply.schema===2&&reply.operationId===row.operation_id&&['ACCEPTED','ALREADY_COVERED','RECONCILIATION_REQUIRED'].includes(reply.status),'REPORT_REPLY_CONFLICT',409);
    if(['ACCEPTED','ALREADY_COVERED'].includes(reply.status)){
     requireThat(ascii(reply.receipt,128)&&reply.cutoff?.type==='accountCutoff'&&reply.cutoff.sub===body.sub&&reply.cutoff.maxCe===body.ce&&reply.cutoff.maxAe===body.ae,'REPORT_CUTOFF_CONFLICT',409);
     await this.store.stmt("UPDATE jwt_v2_service_outbox SET state='ACKNOWLEDGED',result_json=? WHERE operation_id=? AND request_digest=? AND state='PENDING'",canonical(reply),row.operation_id,row.request_digest).run();acknowledged++;
    }
   }catch{/* A failed/uncertain authenticated exchange never acknowledges the report. */}
  }
  return {attempted,acknowledged};
 }

 streamMap(targetApp){const result=new Map();for(const s of this.registry.streams.filter(s=>s.targetApp===targetApp)){if(!result.has(s.stream))result.set(s.stream,new Set());result.get(s.stream).add(s.ownerEpoch);}return result;}
 async reconcileOwner(request,peer){
  requireThat(this.runtime.app==='academy'&&peer.sourceApp===request.recipientApp,'RECONCILE_DIRECTION_CONFLICT',403);
  const config={env:this.runtime.config.env,recipientApp:peer.sourceApp,snapshotSchema:this.runtime.settings.raw.snapshotSchema};validateReconcileRequest(request,config);
  const existing=await this.store.first('SELECT * FROM jwt_v2_replay_captures WHERE request_id=?',request.requestId);
  const streams=this.streamMap(peer.sourceApp);
  if(existing){requireThat(existing.request_binding===requestBinding(request),'RECONCILE_REQUEST_CONFLICT',409);await verifyEventReplay({raw:existing.reply_json,request,config,streams,dependencies:this.registry.dependencies});return existing.reply_json;}
  const keys=cursorKeys(this.runtime),captured=await this.store.first('SELECT * FROM jwt_v2_reconcile_captures WHERE request_id=?',request.requestId);
  if(captured){requireThat(captured.request_binding===requestBinding(request),'RECONCILE_REQUEST_CONFLICT',409);const key=keys.keys.get(captured.cursor_key_id);requireThat(key,'SNAPSHOT_CURSOR_KEY_RETIRED',503);if(captured.status!=='READY')await buildSnapshot({store:this.snap,snapshotId:captured.snapshot_id,cursorKey:key,cursorKeyId:captured.cursor_key_id,config,recordConfig:{dependencies:this.registry.dependencies,recognisedEpochs:streams.get(request.stream)},now:this.runtime.clock(),clock:this.runtime.clock,digestStreamFactory:this.runtime.digestStreamFactory});return serveSnapshotPage({store:this.snap,request,config,cursorKey:key,cursorKeyId:captured.cursor_key_id,now:this.runtime.clock()});}
  requireThat(request.pageToken===null,'UNKNOWN_SNAPSHOT_CONTINUATION',409);
  const ledger=await this.store.first('SELECT * FROM jwt_v2_sender_streams WHERE target_app=? AND stream=?',peer.sourceApp,request.stream);
  requireThat(ledger&&streams.get(request.stream)?.has(ledger.owner_epoch),'SOURCE_STREAM_NOT_INSTALLED',503);
  const configured=this.registry.streams.find(s=>s.targetApp===peer.sourceApp&&s.stream===request.stream&&s.ownerEpoch===ledger.owner_epoch),coveredThrough=ledger.next_sequence-1;
  requireThat(safeInt(coveredThrough)&&request.contiguousThrough<=coveredThrough,'RECONCILE_CURSOR_AHEAD',409);
  let bridge=null;
  if(request.ownerEpoch===null)requireThat(configured.genesis,'EXPLICIT_GENESIS_RECONCILIATION_REQUIRED',409);
  else if(request.ownerEpoch!==ledger.owner_epoch){bridge=this.registry.bridges.find(b=>b.targetApp===peer.sourceApp&&b.stream===request.stream&&b.ownerEpoch===ledger.owner_epoch&&b.predecessorEpoch===request.ownerEpoch);requireThat(bridge&&request.contiguousThrough<=bridge.coveredThrough,'OWNER_BRIDGE_REQUIRED',409);}
  const fence=await nativeFence(this.store.db,{academy:true});requireThat(!fence.pending,'SPLIT_WRITE_PENDING',503);
  const guard={sql:"SELECT 1 FROM jwt_v2_sender_streams s JOIN split_read_state r ON r.singleton=1 WHERE s.target_app=? AND s.stream=? AND s.owner_epoch=? AND s.next_sequence=? AND r.version=? AND NOT EXISTS(SELECT 1 FROM split_write_fence) AND NOT EXISTS(SELECT 1 FROM jwt_v2_native_outbox WHERE target_app=? AND event_json IS NULL)",args:[peer.sourceApp,request.stream,ledger.owner_epoch,ledger.next_sequence,fence.version,peer.sourceApp]};
  if(request.ownerEpoch===ledger.owner_epoch&&request.missingRanges.length){
   requireThat(request.missingRanges.every(([,last])=>last<=coveredThrough),'RECONCILE_RANGE_AHEAD',409);
   const clauses=request.missingRanges.map(()=>"CAST(json_extract(event_json,'$.sequence') AS INTEGER) BETWEEN ? AND ?"),params=request.missingRanges.flat(),where="target_app=? AND json_extract(event_json,'$.sourceApp')='academy' AND json_extract(event_json,'$.stream')=? AND json_extract(event_json,'$.ownerEpoch')=? AND ("+clauses.join(' OR ')+')';
   const count=await this.store.first('SELECT count(*) n FROM jwt_v2_sender_history WHERE '+where,peer.sourceApp,request.stream,ledger.owner_epoch,...params),wanted=request.missingRanges.reduce((n,[first,last])=>n+last-first+1,0);
   requireThat(safeInt(wanted),'RECONCILE_RANGE_TOO_LARGE',409);
   if(count.n===wanted){const events=(await this.store.all("SELECT event_json FROM jwt_v2_sender_history WHERE "+where+" ORDER BY CAST(json_extract(event_json,'$.sequence') AS INTEGER) LIMIT 20",peer.sourceApp,request.stream,ledger.owner_epoch,...params)).map(r=>strictJSON(r.event_json));
    try{const raw=await encodeEventReplay({request,events,coveredThrough,ownerEpoch:ledger.owner_epoch,config,streams,dependencies:this.registry.dependencies});return persistEventReplay({store:this.store,request,raw,guard,config,streams,dependencies:this.registry.dependencies});}catch(e){if(e.code!=='SNAPSHOT_REQUIRED')throw e;}
   }
  }
  // Every epoch in the configured predecessor chain must have its complete
  // operational sender ledger retained. Missing history never becomes absence.
  const epochs=[{epoch:ledger.owner_epoch,through:coveredThrough}];let current=ledger.owner_epoch;
  for(let depth=0;depth<16;depth++){const previous=this.registry.bridges.find(b=>b.targetApp===peer.sourceApp&&b.stream===request.stream&&b.ownerEpoch===current);if(!previous)break;requireThat(!epochs.some(e=>e.epoch===previous.predecessorEpoch),'OWNER_BRIDGE_CYCLE',503);epochs.push({epoch:previous.predecessorEpoch,through:previous.coveredThrough});current=previous.predecessorEpoch;}
  requireThat(this.registry.streams.some(s=>s.targetApp===peer.sourceApp&&s.stream===request.stream&&s.ownerEpoch===current&&s.genesis),'OWNER_BRIDGE_CHAIN_INCOMPLETE',503);
  for(const e of epochs){const count=await this.store.first("SELECT count(*) n FROM jwt_v2_sender_history WHERE target_app=? AND json_extract(event_json,'$.sourceApp')='academy' AND json_extract(event_json,'$.stream')=? AND json_extract(event_json,'$.ownerEpoch')=? AND CAST(json_extract(event_json,'$.sequence') AS INTEGER) BETWEEN 1 AND ?",peer.sourceApp,request.stream,e.epoch,e.through);requireThat(count.n===e.through,'SOURCE_OPERATIONAL_HISTORY_UNAVAILABLE',503);guard.sql+=" AND (SELECT count(*) FROM jwt_v2_sender_history WHERE target_app=? AND json_extract(event_json,'$.sourceApp')='academy' AND json_extract(event_json,'$.stream')=? AND json_extract(event_json,'$.ownerEpoch')=? AND CAST(json_extract(event_json,'$.sequence') AS INTEGER) BETWEEN 1 AND ?)=?";guard.args.push(peer.sourceApp,request.stream,e.epoch,e.through,e.through);}
  const historyWhere=epochs.map(()=>"(json_extract(event_json,'$.ownerEpoch')=? AND CAST(json_extract(event_json,'$.sequence') AS INTEGER)<=?)").join(' OR '),historyArgs=epochs.flatMap(e=>[e.epoch,e.through]);
  const clauses="target_app=? AND json_extract(event_json,'$.sourceApp')='academy' AND json_extract(event_json,'$.stream')=? AND ("+historyWhere+')';
  const total=await this.store.first('SELECT count(*) n FROM jwt_v2_sender_history WHERE '+clauses,peer.sourceApp,request.stream,...historyArgs);requireThat(total.n<=10000,'SNAPSHOT_CAPTURE_BUDGET_EXCEEDED',503);
   const conflictSQL="SELECT 1 FROM jwt_v2_sender_facts f JOIN jwt_v2_outbox o ON o.event_id=f.event_id WHERE f.target_app=? AND f.stream=? AND (f.event_json<>o.event_json OR f.digest<>o.digest OR f.target_app<>o.target_app)";
   requireThat(!await this.store.first(conflictSQL,peer.sourceApp,request.stream),'SOURCE_OPERATIONAL_COVERAGE_CONFLICT',503);guard.sql+=' AND NOT EXISTS('+conflictSQL+')';guard.args.push(peer.sourceApp,request.stream);
   let lastEpoch='',lastSequence=0;
   for(let checked=0;checked<total.n;){
    const page=await this.store.all('SELECT event_json,owner_epoch,sequence FROM jwt_v2_sender_history WHERE '+clauses+' AND (owner_epoch>? OR (owner_epoch=? AND sequence>?)) ORDER BY owner_epoch,sequence LIMIT 20',peer.sourceApp,request.stream,...historyArgs,lastEpoch,lastEpoch,lastSequence);
    requireThat(page.length>0,'SOURCE_OPERATIONAL_HISTORY_UNAVAILABLE',503);
    for(const row of page){const event=strictJSON(row.event_json);await validateEvent(event,{env:config.env,targetApp:peer.sourceApp,streams,dependencies:this.registry.dependencies});if(event.target.type==='dependency'){const rule=this.registry.dependencies.get(event.target.id);requireThat(rule.scope==='GLOBAL'?event.sub===null:typeof event.sub==='string','SOURCE_DEPENDENCY_SCOPE_CONFLICT',503);}lastEpoch=row.owner_epoch;lastSequence=row.sequence;checked++;}
   }
  const selectors=Object.entries(bucketFor).map(([type,bucket])=>({bucket,sql:"SELECT DISTINCT "+(type==='dependency'?"json_set(json_extract(event_json,'$.target'),'$.sub',json_extract(event_json,'$.sub'))":"json_extract(event_json,'$.target')")+" record_json FROM jwt_v2_sender_history WHERE "+clauses+" AND json_extract(event_json,'$.target.type')=?",args:[peer.sourceApp,request.stream,...historyArgs,type]}));
  if(config.snapshotSchema===4&&request.stream==='account-security'){
   const baseline=sharedAccountSelector(peer.sourceApp);
   guard.sql+=' AND (SELECT count(*) FROM ('+baseline.sql+'))<=?';
   guard.args.push(...baseline.args,10000);
   selectors.push(baseline);
  }
  const now=this.runtime.clock(),base={schema:config.snapshotSchema,env:this.runtime.config.env,requestId:request.requestId,ownerApp:'academy',recipientApp:peer.sourceApp,stream:request.stream,ownerEpoch:ledger.owner_epoch,coveredThrough,predecessorEpoch:bridge?.predecessorEpoch??null,predecessorCoveredThrough:bridge?.coveredThrough??null,snapshotId:crypto.randomUUID(),createdAt:now,expiresAt:now+600};
  const id=await this.snap.capturePrimary({request,base,cursorKeyId:keys.currentKid,selectors,guard,config,now});
  await buildSnapshot({store:this.snap,snapshotId:id,cursorKey:keys.keys.get(keys.currentKid),cursorKeyId:keys.currentKid,config,recordConfig:{dependencies:this.registry.dependencies,recognisedEpochs:new Set(epochs.map(e=>e.epoch))},now,clock:this.runtime.clock,digestStreamFactory:this.runtime.digestStreamFactory});
  return serveSnapshotPage({store:this.snap,request,config,cursorKey:keys.keys.get(keys.currentKid),cursorKeyId:keys.currentKid,now:this.runtime.clock()});
 }

 receiver(request){
  const config={env:this.runtime.config.env,recipientApp:this.runtime.app,snapshotSchema:this.runtime.settings.raw.snapshotSchema};validateReconcileRequest(request,config);
  requireThat(child(this.runtime.app)&&request.recipientApp===this.runtime.app,'RECONCILE_DIRECTION_CONFLICT',403);
  const entries=this.registry.streams.filter(s=>s.targetApp===this.runtime.app&&s.stream===request.stream),genesis=entries.filter(s=>s.genesis);
  requireThat(genesis.length===1&&(request.ownerEpoch===null||entries.some(s=>s.ownerEpoch===request.ownerEpoch)),'RECONCILE_EPOCH_NOT_CONFIGURED',409);
  const bridges=new Map(this.registry.bridges.filter(b=>b.targetApp===this.runtime.app&&b.stream===request.stream).map(b=>[b.ownerEpoch,{predecessorEpoch:b.predecessorEpoch,coveredThrough:b.coveredThrough,denialsIncluded:b.denialsIncluded}]));
  return new SnapshotReceiver({store:this.snap,config,trust:{stream:request.stream,currentEpoch:request.ownerEpoch,genesisEpoch:genesis[0].ownerEpoch,bridges},recordConfig:{dependencies:this.registry.dependencies,recognisedEpochs:new Set(entries.map(s=>s.ownerEpoch))},digestStreamFactory:this.runtime.digestStreamFactory,clock:this.runtime.clock});
 }
 async registerReconcileRequest(request){
  const receiver=this.receiver(request),initial={...request,pageToken:null},old=await this.store.first('SELECT * FROM jwt_v2_receive_requests WHERE request_id=?',request.requestId);
  if(old){requireThat(old.request_binding===requestBinding(request),'RECONCILE_REQUEST_CONFLICT',409);requireThat(old.status!=='CANCELLED','RECONCILE_REQUEST_CANCELLED',409);return receiver;}
  requireThat(request.pageToken===null,'UNKNOWN_SNAPSHOT_CONTINUATION',409);
  const epoch=request.ownerEpoch??receiver.trust.genesisEpoch,local=await this.ledger(this.runtime.app,request.stream,epoch);
  requireThat(request.contiguousThrough===local.contiguous_through,'RECONCILE_LOCAL_CURSOR_CHANGED',409);
  if(request.ownerEpoch===null){const prior=await this.store.first("SELECT 1 FROM jwt_v2_receive_requests WHERE json_extract(request_json,'$.stream')=? LIMIT 1",request.stream);requireThat(!prior&&local.contiguous_through===0,'GENESIS_ALREADY_REQUESTED',409);}
  else{
   const baselineRequest=receiver.config.snapshotSchema===4&&request.stream==='account-security'&&request.missingRanges.length===0;
   requireThat(baselineRequest||local.highest_seen>local.contiguous_through&&request.missingRanges.every(([first])=>first>request.contiguousThrough),'RECONCILE_EVIDENCE_REQUIRED',409);
  }
  requireThat(request.missingRanges.every(([,last])=>last<=local.highest_seen),'RECONCILE_RANGE_NOT_OBSERVED',409);
  await receiver.registerRequest(initial);return receiver;
 }
 async receiveReconcileReply(request,raw,peer){
  requireThat(peer.sourceApp==='academy'&&peer.targetApp===this.runtime.app,'RECONCILE_REPLY_OWNER_CONFLICT',401);
  const receiver=this.receiver(request),pending=await this.store.first('SELECT * FROM jwt_v2_receive_requests WHERE request_id=?',request.requestId);
  requireThat(pending&&pending.request_binding===requestBinding(request)&&['PENDING','COMPLETE'].includes(pending.status),'UNREQUESTED_RECONCILIATION_REPLY',409);
  const reply=strictJSON(raw),options=await this.eventOptions(peer);
  if(reply.mode==='EVENTS'){
   const verified=await verifyEventReplay({raw,request,config:receiver.config,streams:options.streams,dependencies:this.registry.dependencies});
   if(verified.events.length){const batch={schema:2,env:this.runtime.config.env,sourceApp:'academy',targetApp:this.runtime.app,batchId:request.requestId,events:verified.events};await receiveBatch({body:canonical(batch),config:this.runtime.config,store:this.store,...options});}
   // No cursor is assigned from coveredThrough; only receiveBatch's individually
   // published APPLIED facts advance existing contiguous coverage.
   await this.store.stmt("UPDATE jwt_v2_receive_requests SET status='COMPLETE' WHERE request_id=? AND status='PENDING'",request.requestId).run();return {mode:'EVENTS',automaticCoverage:false};
  }
  requireThat(reply.mode==='SNAPSHOT','UNKNOWN_RECONCILE_MODE',409);
  const staged=await receiver.stage(raw,{now:this.runtime.clock()});
  // A signed source watermark can hold local admission while effects are
  // pending. Only finishApplied may advance contiguous coverage.
  await this.store.stmt(`UPDATE jwt_v2_event_streams SET highest_seen=max(highest_seen,?)
   WHERE source_app='academy' AND target_app=? AND stream=? AND owner_epoch=?`,
   reply.coveredThrough,this.runtime.app,reply.stream,reply.ownerEpoch).run();
  return staged;
 }
 async advanceReconcileSnapshot(requestId){
  requireThat(uuid(requestId)&&child(this.runtime.app),'INVALID_SNAPSHOT_CONTINUATION',409);
  const [[pending],[capture]]=await this.store.readBatch([
   ['SELECT * FROM jwt_v2_receive_requests WHERE request_id=?',requestId],
   ['SELECT snapshot_id,status FROM jwt_v2_receive_snapshots WHERE request_id=?',requestId]
  ]);
  requireThat(pending&&['PENDING','COMPLETE'].includes(pending.status)&&capture&&['VERIFIED','APPLIED'].includes(capture.status),
   'SNAPSHOT_CONTINUATION_REQUIRED',409);
  const request=strictJSON(pending.request_json),receiver=this.receiver(request);
  requireThat(pending.request_binding===requestBinding(request),'RECONCILE_REQUEST_CONFLICT',409);
  const {snapshot_id:snapshotId}=capture;
  if(capture.status==='APPLIED'){
   await receiver.verify(snapshotId,{now:this.runtime.clock()});
   return {mode:'SNAPSHOT',status:'APPLIED',publicationPending:false,snapshotId};
  }
  await receiver.applyRecords(snapshotId,{now:this.runtime.clock(),limit:2,planEffect:async({record,snapshotId,offset,metadata})=>{
   const workId=snapshotId+':'+offset;
   if(record.type==='accountBaseline')return sharedAccountBaselinePlan(this.store,{record,metadata,workId,now:this.runtime.clock()});
   const scoped=snapshotEffect(record);
   return {workId,statements:await this.effectPlan(workId,scoped.target,{sub:scoped.scopeSub})};
  }});
  const pendingEffect=await this.store.first(`SELECT e.work_id FROM jwt_v2_snapshot_effects e JOIN jwt_v2_worksets w USING(work_id)
   WHERE e.snapshot_id=? AND w.state='PENDING' ORDER BY e.record_offset LIMIT 1`,snapshotId);
  if(pendingEffect)await this.publishWork(pendingEffect.work_id,{budget:{remaining:1}});
  return receiver.finishApplied(snapshotId,{now:this.runtime.clock()});
 }
 async publishPending({limit=20}={}){
  requireThat(safeInt(limit,1)&&limit<=20,'INVALID_PUBLICATION_PUMP',503);const works=await this.store.all("SELECT work_id FROM jwt_v2_worksets WHERE state='PENDING' ORDER BY created_at,work_id LIMIT ?",limit),budget={remaining:20};let applied=0;
  for(const work of works){try{if(await this.publishWork(work.work_id,{budget}))applied++;}catch{/* Retry durable work later; never claim an unavailable target covered. */}}
  return {attempted:works.length,applied};
 }
}
export async function runtimeServices(runtime){
 let service=instances.get(runtime);if(!service){service=new RuntimeServices(runtime);instances.set(runtime,service);}return service;
}
export const runtimeServiceBoundary=Object.freeze({registry:'Only explicit source/target/dependency/epoch registries; no public request creates sender or inbox genesis.',capture:'Actual retained sender events, fixed split/watermark guard and immutable bounded replay/snapshot captures; unavailable history fails closed.',publication:'Operational facts and all required durable cache barriers precede APPLIED. Child local report floors retain original selectors and canonical acceptance remains distinct from global application.'});
