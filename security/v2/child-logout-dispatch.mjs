import {DurableObject} from 'cloudflare:workers';
import {requireThat,uuid} from './codec.mjs';
import {heldForV111Cutover,requireV111CutoverOpen} from './cutover-state.mjs';
import {childLogoutProgress,logoutDispatchEnabled,logoutDispatchScope} from './logout-dispatch.mjs';
import {runtimeFor} from './runtime.mjs';
import {runtimeServices} from './runtime-service.mjs';
import {requireVerifiedUpdateBoundary} from './update-boundary.mjs';

const key='logout';
const commitWindowSeconds=120;
const retryMs=60_000;
const promptMs=2_000;

export class HifzLogoutDispatcher extends DurableObject {
 async arm(operationId){
  requireV111CutoverOpen(this.env);
  requireThat(logoutDispatchEnabled(this.env)&&uuid(operationId)&&this.ctx.id.name===operationId,
   'LOGOUT_DISPATCH_UNAVAILABLE',503);
  const runtime=await runtimeFor(this.env,{app:'hifz'});
  await requireVerifiedUpdateBoundary(runtime);
  const scope=logoutDispatchScope(runtime);
  return this.ctx.storage.transaction(async transaction=>{
   const previous=await transaction.get(key);
   requireThat(!previous||previous.scope===scope,'LOGOUT_DISPATCH_SCOPE_CHANGED',503);
   if(previous){
    if(await transaction.getAlarm()===null)await transaction.setAlarm(Date.now());
    return previous.expiresAt;
   }
   const expiresAt=runtime.clock()+commitWindowSeconds;
   await transaction.put(key,{operationId,scope,expiresAt});
   await transaction.setAlarm(Date.now());
   return expiresAt;
  });
 }

 async alarm(){
  const pending=await this.ctx.storage.get(key);
  if(!pending)return;
  // Persist a retry before crossing a Worker, D1 or R2 boundary.
  await this.ctx.storage.setAlarm(Date.now()+retryMs);
  if(heldForV111Cutover(this.env)||!logoutDispatchEnabled(this.env))return;
  const runtime=await runtimeFor(this.env,{app:'hifz'});
  await requireVerifiedUpdateBoundary(runtime);
  if(pending.scope!==logoutDispatchScope(runtime))return;
  const {operationId,expiresAt}=pending;
  let progress=await childLogoutProgress(runtime,operationId,expiresAt);
  if(!progress.operation_id){
   if(progress.expired)await this.#finish();
   else await this.ctx.storage.setAlarm(Date.now()+promptMs);
   return;
  }

  if(progress.local_state!=='APPLIED'||progress.report_state!=='ACKNOWLEDGED'){
   await (await runtimeServices(runtime)).continueLocalLogout(operationId);
   progress=await childLogoutProgress(runtime,operationId,expiresAt);
  }
  if(progress.local_state==='APPLIED'&&progress.report_state==='ACKNOWLEDGED'){
   await this.#finish();
   return;
  }
  const delay=progress.local_state!=='APPLIED'||progress.next_delivery===null
   ?promptMs:Math.max(promptMs,progress.next_delivery*1000-Date.now());
  await this.ctx.storage.setAlarm(Date.now()+delay);
 }

 async #finish(){
  await this.ctx.storage.transaction(async transaction=>{
   await transaction.delete(key);
   await transaction.deleteAlarm();
  });
 }
}
