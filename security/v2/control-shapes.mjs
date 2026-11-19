import {requireThat,safeInt,uuid} from './codec.mjs';
import {BINDING} from './tokens.mjs';
export function controlShape(suffix,value,prefix){
 const parts=prefix.split('/'),app=parts[3],env=parts[2];
 requireThat(value.app===app&&value.env===env,'MALFORMED_CONTROL_NAMESPACE',503);
 if(suffix==='control/app'){
  requireThat(typeof value.policyEpoch==='string'&&value.policyEpoch.length>0&&typeof value.keyRegistryEpoch==='string'&&value.keyRegistryEpoch.length>0&&safeInt(value.policyRevision,1)&&safeInt(value.keyRegistryRevision,1)&&safeInt(value.migrationFloor,1)&&safeInt(value.inactivityMinutes,15)&&value.inactivityMinutes<=200,'MALFORMED_APP_CONTROL',503);
  requireThat(Array.isArray(value.withdrawnKids)&&value.withdrawnKids.every(k=>/^[A-Za-z0-9._-]{1,64}$/.test(k))&&new Set(value.withdrawnKids).size===value.withdrawnKids.length,'MALFORMED_KEY_REGISTRY',503);
 }else if(suffix.startsWith('security/session/')){
  requireThat(value.binding&&Object.keys(value.binding).length===BINDING.length&&BINDING.every(k=>Object.hasOwn(value.binding,k))&&uuid(value.binding.sid)&&value.binding.sid===suffix.slice(17),'MALFORMED_SESSION_BINDING',503);
  requireThat(['ADMITTED_LOCKED','UNLOCKED','LOCKED','REVOKED','EXPIRED'].includes(value.localState)&&typeof value.authorityReady==='boolean','MALFORMED_SESSION_STATE',503);
  for(const name of ['validationDeadline','idleUntil','s_exp'])requireThat(safeInt(value[name]),'MALFORMED_SESSION_DEADLINE',503);
  requireThat(value.s_exp===value.binding.s_exp&&value.validationDeadline<=Math.min(value.binding.vat+900,value.idleUntil,value.s_exp),'MALFORMED_SESSION_LEASE',503);
  if(value.localState==='UNLOCKED'&&value.authorityReady){
   requireThat(Array.isArray(value.deniedActions)&&value.deniedActions.every(a=>typeof a==='string'&&a.length>0)&&typeof value.policyEpoch==='string'&&typeof value.keyRegistryEpoch==='string'&&safeInt(value.policyRevision,1)&&safeInt(value.keyRegistryRevision,1)&&safeInt(value.timedUntil)&&Array.isArray(value.ownerVector),'MALFORMED_SESSION_AUTHORITY',503);
   requireThat(typeof value.rightsKey==='string'&&value.rightsKey.startsWith(prefix+'rights/')&&/^[0-9a-f]{64}$/.test(value.rightsHash),'MALFORMED_RIGHTS_REFERENCE',503);
  }
 }else{
  requireThat(value.resourceId===suffix.slice('control/resource/'.length)&&typeof value.ownerEpoch==='string'&&safeInt(value.revision,1)&&Array.isArray(value.deniedActions)&&value.deniedActions.every(a=>typeof a==='string'&&a.length>0),'MALFORMED_RESOURCE_CONTROL',503);
 }
 return value;
}
