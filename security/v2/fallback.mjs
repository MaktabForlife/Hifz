import {requireThat,canonical,vectorDigest,digest,safeInt} from './codec.mjs';
import {verifyToken} from './tokens.mjs';
import {coherentCapture} from './cache.mjs';
export async function primaryTransportFallback({store,cache,token,sid,config,keys,now,loadPrimaryAppControl,readFence,readVector,loadRights,resourceKeys=[],action,loadPrimaryResource}){
 // Caller invokes only for SECURITY_TRANSPORT_UNAVAILABLE. Proven ACTIVE loss is never fallback-eligible.
 const [appLife,sessionLife]=await Promise.all([store.lifecycle(cache.key('control/app')),store.lifecycle(cache.key('security/session/'+sid))]);
 requireThat(appLife?.state==='ACTIVE'&&sessionLife?.state==='ACTIVE','SECURITY_CONTROL_UNAVAILABLE',503);
 const app=await loadPrimaryAppControl();requireThat(app&&app.app===config.app&&app.env===config.env&&Array.isArray(app.withdrawnKids),'PRIMARY_APP_CONTROL_UNAVAILABLE',503);
 const f=await store.family(sid);requireThat(f&&f.state==='UNLOCKED'&&f.authority_ready===1&&now<Math.min(f.deadline,f.idle_until,f.s_exp),'SESSION_NOT_AUTHORISED');
 const binding=JSON.parse(f.binding_json);
 const current=await store.first("SELECT 1 FROM jwt_v2_accounts a JOIN jwt_v2_parents p ON p.sub=a.sub JOIN jwt_v2_browsers b ON b.bsid=p.bsid WHERE a.sub=? AND a.active=1 AND a.ce=? AND a.ae=? AND a.le=? AND p.psid=? AND p.state='UNLOCKED' AND p.bv=? AND p.bsid=? AND p.ce=? AND p.ae=? AND p.s_iat=? AND p.s_exp=? AND b.bv=p.bv AND b.sub=a.sub AND b.psid=p.psid AND b.cancelled_through<p.bv",f.sub,f.ce,f.ae,f.le,f.psid,f.bv,f.bsid,f.ce,f.ae,f.s_iat,f.s_exp);
 requireThat(current,'SESSION_ENDED');
 const projection=JSON.parse(f.projection_json);
 requireThat(projection.timedUntil===undefined||safeInt(projection.timedUntil),'PRIMARY_TIMED_AUTHORITY_UNAVAILABLE',503);
 const timedUntil=Math.min(f.s_exp,projection.timedUntil??f.s_exp);
 requireThat(projection.policyEpoch===app.policyEpoch&&projection.policyRevision===app.policyRevision&&projection.inactivityMinutes===app.inactivityMinutes&&projection.keyRegistryEpoch===app.keyRegistryEpoch&&projection.keyRegistryRevision===app.keyRegistryRevision,'PRIMARY_POLICY_RECONCILIATION_REQUIRED',503);
 requireThat(typeof action==='string'&&action.length>0&&Array.isArray(projection.deniedActions),'ACTION_CONTEXT_REQUIRED',503);
 requireThat(!projection.deniedActions.includes(action),'ACCESS_DENIED',403);
 requireThat(f.idle_until<=Math.min(f.s_exp,f.last_refresh+app.inactivityMinutes*60),'PRIMARY_POLICY_NOT_APPLIED',503);
 if(resourceKeys.length)requireThat(typeof loadPrimaryResource==='function','PRIMARY_RESOURCE_CHECKS_REQUIRED',503);
 for(const key of resourceKeys){
  const life=await store.lifecycle(cache.key('control/resource/'+key));requireThat(life?.state==='ACTIVE','SECURITY_CONTROL_UNAVAILABLE',503);
  const policy=await loadPrimaryResource(key);
  requireThat(policy&&policy.resourceId===key&&Array.isArray(policy.deniedActions),'PRIMARY_RESOURCE_UNAVAILABLE',503);
  requireThat(!policy.deniedActions.includes(action),'ACCESS_DENIED',403);
 }
 const claims=await verifyToken(token,{config,keys,withdrawn:new Set(app.withdrawnKids),projection:binding,now,idleUntil:f.idle_until,timedUntil:Math.min(f.deadline,timedUntil),initial:JSON.parse(f.projection_json).initialIssuance===true});
 requireThat(claims.ver>=app.migrationFloor&&claims.exp<=f.deadline,'TOKEN_FORMAT_RETIRED');
 const captured=await coherentCapture({readFence,readVector,loadRights,committedLease:{vat:f.vat,deadline:f.deadline},now});
 requireThat(binding.pv===await vectorDigest(captured.vector),'PERMISSIONS_REFRESH_REQUIRED',503);
 requireThat(projection.rightsHash===await digest(captured.rights),'COMMITTED_RIGHTS_MISMATCH',503);
 // D1 may have been unavailable when an earlier loss sealed the R2 app.
 // A current ACTIVE app witness is required; full-bucket outages therefore fail closed.
 const witness=(await cache.read('control/app')).value;
 for(const field of ['app','env','policyEpoch','policyRevision','inactivityMinutes','keyRegistryEpoch','keyRegistryRevision','migrationFloor'])requireThat(witness[field]===app[field],'PRIMARY_APP_CONTROL_CHANGED',503);
 requireThat(canonical(witness.withdrawnKids)===canonical(app.withdrawnKids),'PRIMARY_APP_CONTROL_CHANGED',503);
 const after=await store.family(sid);requireThat(after&&after.cr===f.cr&&after.binding_json===f.binding_json&&after.state==='UNLOCKED','AUTHORITY_CHANGED_DURING_CAPTURE',503);
 return {binding,rights:captured.rights,deadline:Math.min(f.deadline,f.idle_until,f.s_exp,timedUntil),vat:f.vat,mode:'BOUNDED_PRIMARY_TRANSPORT_FALLBACK'};
}
export async function authoriseWithFallback(options){
 try{return await options.cache.authorise(options);}
 catch(error){if(error.code!=='SECURITY_TRANSPORT_UNAVAILABLE')throw error;return primaryTransportFallback({...options,...options.fallback,sid:options.sessionKey});}
}
