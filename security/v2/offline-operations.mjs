import {registryControlPlan,sourceControlPlan} from './control-publication.mjs';
import {ascii,requireThat,safeInt,strictJSON,uuid} from './codec.mjs';
import {serviceFetch} from './http-service.mjs';
import {deliverOutbox} from './outbox.mjs';
import {runtimeServices} from './runtime-service.mjs';
import {
 prepareUpdateBoundary,listUpdateSubjects,revokeOfflineAcademyAccount,publishUpdateSessions,verifyUpdateBoundary,requireVerifiedUpdateBoundary
} from './update-boundary.mjs';

async function deliver(runtime,limit=4){
 requireThat(runtime.app==='academy'&&safeInt(limit,1)&&limit<=8,'INVALID_OFFLINE_DELIVERY',400);
 const services=await runtimeServices(runtime);
 return deliverOutbox(runtime.store,{now:runtime.clock(),limit,async sendAuthenticated(event){
  const ledger=await services.ledger(event.targetApp,event.stream,event.ownerEpoch);
  requireThat(event.sequence<ledger.next_sequence,'OFFLINE_UNCOMMITTED_EVENT',503);
  const batchId=crypto.randomUUID();
  return serviceFetch(runtime,{targetApp:event.targetApp,path:'/internal/auth/v2/events',operationId:batchId,
   body:{schema:2,env:runtime.config.env,sourceApp:'academy',targetApp:event.targetApp,batchId,events:[event]}});
 }});
}

async function reconcile(runtime,{requestId,pageToken=null}){
 requireThat(['studio','hifz'].includes(runtime.app)&&runtime.settings.raw.snapshotSchema===4&&uuid(requestId)
  &&(pageToken===null||ascii(pageToken,4096)),'INVALID_OFFLINE_RECONCILIATION',400);
 const store=runtime.store;
 const saved=await store.first('SELECT request_json FROM jwt_v2_receive_requests WHERE request_id=?',requestId);
 const stream='account-security';
 let body;
 if(saved){
  body={...strictJSON(saved.request_json),pageToken};
 }else{
  requireThat(pageToken===null,'UNKNOWN_SNAPSHOT_CONTINUATION',409);
  const streams=(await runtimeServices(runtime)).registry.streams.filter(entry=>
   entry.sourceApp==='academy'&&entry.targetApp===runtime.app&&entry.stream===stream);
  const ownerEpoch=runtime.settings.raw.sharedChildEntry?.ownerEpoch;
  requireThat(streams.some(entry=>entry.ownerEpoch===ownerEpoch),'RECONCILE_EPOCH_NOT_CONFIGURED',503);
  const current=await store.first('SELECT contiguous_through,highest_seen FROM jwt_v2_event_streams WHERE source_app=? AND target_app=? AND stream=? AND owner_epoch=?',
   'academy',runtime.app,stream,ownerEpoch);
  requireThat(current,'OFFLINE_RECONCILIATION_GENESIS_REQUIRED',503);
  body={schema:2,env:runtime.config.env,sourceApp:runtime.app,targetApp:'academy',requestId,ownerApp:'academy',
   recipientApp:runtime.app,stream,ownerEpoch,contiguousThrough:current.contiguous_through,missingRanges:[],knownFloorsDigest:null,pageToken};
 }
 const page=await serviceFetch(runtime,{targetApp:'academy',path:'/internal/auth/v2/reconcile',operationId:requestId,body});
 requireThat(page.schema===4&&uuid(page.snapshotId),'OFFLINE_BASELINE_SNAPSHOT_REQUIRED',503);
 const ready=await store.first("SELECT status FROM jwt_v2_receive_snapshots WHERE snapshot_id=?",page.snapshotId);
 return {snapshotId:page.snapshotId,nextPageToken:page.nextPageToken,applied:ready?.status==='APPLIED'};
}

async function publishSharedRegistry(runtime,generation){
 await requireVerifiedUpdateBoundary(runtime);
 const registry=runtime.settings.sharedAcademy;
 requireThat(registry?.revision===1&&(runtime.app==='academy'
  ?runtime.settings.sharedAcademySessions===true&&registry.signingKey
  :runtime.settings.raw.sharedChildEntry&&registry.signingKey===null),'SHARED_KEY_REGISTRY_REQUIRED',503);
 const suffix='control/app',store=runtime.store;
 const target=await store.first('SELECT projection_json FROM jwt_v2_control_targets WHERE app=? AND env=? AND suffix=?',
  runtime.app,runtime.config.env,suffix);
 requireThat(target,'CONTROL_SOURCE_NOT_COMMITTED',503);
 const current=strictJSON(target.projection_json),receiptRef='offline-shared-registry-'+generation;
 let next=current;
 if(current.sharedAcademyRegistryRevision===undefined){
  next={...current,cr:current.cr+1,sharedAcademyRegistryRevision:registry.revision,withdrawnSharedAcademyKids:[]};
  const update=await registryControlPlan(store,{registry:next,receiptRef,
   predecessor:{epoch:current.keyRegistryEpoch,revision:current.keyRegistryRevision}});
  await store.batch(update.statements);
  const commit=await sourceControlPlan(store,{suffix,projection:next,expectedCR:current.cr,commitRef:receiptRef});
  await store.batch(commit.statements);
 }else requireThat(current.sharedAcademyRegistryRevision===registry.revision
  &&Array.isArray(current.withdrawnSharedAcademyKids)&&!current.withdrawnSharedAcademyKids.includes(registry.kid),
  'SHARED_KEY_REGISTRY_CONFLICT',409);
 await runtime.cache.publish(suffix,async()=>next);
 const published=await runtime.appControl();
 requireThat(published.cr===next.cr&&published.sharedAcademyRegistryRevision===registry.revision
  &&!published.withdrawnSharedAcademyKids.includes(registry.kid),'SHARED_KEY_REGISTRY_NOT_PUBLISHED',503);
 return {status:'VERIFIED',revision:registry.revision,controlRevision:published.cr};
}

// This function is called only by the named, binding-only Worker entrypoint.
export async function runOfflineUpdateStep(runtime,command){
 const pinned=runtime.settings.raw.offlineUpdate,generation=command?.generation;
 requireThat(runtime.env.UAA_V111_CUTOVER==='held'&&pinned&&generation===pinned.generation
  &&command.releaseId===pinned.releaseId,'OFFLINE_UPDATE_HOLD_REQUIRED',409);
 switch(command.action){
  case 'publishSharedRegistry':return publishSharedRegistry(runtime,generation);
  case 'prepare':return prepareUpdateBoundary(runtime,pinned);
  case 'inventory':return listUpdateSubjects(runtime,{generation,after:command.after,limit:command.limit});
  case 'revokeAccount':{
   requireThat(ascii(command.subject,180),'OFFLINE_UPDATE_ACCOUNT_UNAVAILABLE',400);
   const {status,receipt}=await revokeOfflineAcademyAccount(runtime,{generation,sub:command.subject});
   return {status,receipt};
  }
  case 'publishSessions':return publishUpdateSessions(runtime,{generation,limit:command.limit});
  case 'deliverCutoffs':return deliver(runtime,command.limit);
  case 'reconcileBaselines':return reconcile(runtime,command);
  case 'verifyRevocations':return verifyUpdateBoundary(runtime,generation);
  default:requireThat(false,'INVALID_OFFLINE_UPDATE_ACTION',400);
 }
}
