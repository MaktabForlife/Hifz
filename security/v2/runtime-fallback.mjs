import {canonical,strictJSON,requireThat,bytes,sha256,hex,equal} from './codec.mjs';
import {primaryTransportFallback} from './fallback.mjs';
import {assertCommittedControl} from './control-publication.mjs';
import {nativeFence} from './capture.mjs';
import {vectorFromGuards} from './capture-receipt.mjs';
async function sourceControl(runtime,suffix){
 const row=await runtime.store.first('SELECT projection_json FROM jwt_v2_control_targets WHERE app=? AND env=? AND suffix=?',runtime.app,runtime.config.env,suffix);
 requireThat(row,'PRIMARY_CONTROL_SOURCE_UNAVAILABLE',503);
 const value=strictJSON(row.projection_json);await assertCommittedControl(runtime.store,suffix,value);return value;
}
async function vector(runtime,sub){
 const refs=runtime.settings.dependenciesFor(sub),rows=await runtime.store.all("SELECT d.id,d.scope,d.owner_epoch,d.revision FROM json_each(?) j JOIN jwt_v2_dependencies d ON d.id=json_extract(j.value,'$.id') AND d.scope=json_extract(j.value,'$.scope') ORDER BY d.id,d.scope",canonical(refs));
 requireThat(rows.length===refs.length&&rows.every(row=>refs.some(ref=>ref.id===row.id&&ref.scope===row.scope&&ref.ownerEpoch===row.owner_epoch)),'NATIVE_OWNER_EPOCH_RECONCILIATION_REQUIRED',503);
 return vectorFromGuards(rows.map(r=>[r.id,r.scope,r.owner_epoch,r.revision]));
}
function freeze(value){if(value&&typeof value==='object'){for(const v of Object.values(value))freeze(v);Object.freeze(value);}return value;}
export async function recoverRuntimeAuthority(runtime,{token,sid,resourceKeys,action,error}){
 requireThat(['SECURITY_TRANSPORT_UNAVAILABLE','RIGHTS_PAYLOAD_UNAVAILABLE','RIGHTS_PAYLOAD_CORRUPT','RIGHTS_PAYLOAD_TRANSPORT_UNAVAILABLE'].includes(error.code),'AUTHORITY_RECOVERY_NOT_ALLOWED',503);
 // Proven security-control loss/fencing is never an eligible input.
 let binding;
 const result=await primaryTransportFallback({store:runtime.store,cache:runtime.cache,token,sid,config:runtime.config,keys:runtime.settings.apiKeys,now:runtime.clock(),resourceKeys,action,
  loadPrimaryAppControl:()=>sourceControl(runtime,'control/app'),
  loadPrimaryResource:key=>sourceControl(runtime,'control/resource/'+key),
  readFence:()=>nativeFence(runtime.settings.db.withSession('first-primary'),{academy:runtime.app==='academy'}),
  readVector:async()=>{if(!binding){const f=await runtime.store.family(sid);requireThat(f,'SESSION_ENDED',401);binding=JSON.parse(f.binding_json);}return vector(runtime,binding.sub);},
  loadRights:async()=>{const capture=await runtime.native.capture({binding});return capture.rights;}
 });
 if(error.code.startsWith('RIGHTS_PAYLOAD_')){
  const f=await runtime.store.family(sid),saved=JSON.parse(f.projection_json),raw=canonical(result.rights);
  requireThat(f.binding_json===canonical(result.binding)&&runtime.clock()<result.deadline&&equal(hex(await sha256(bytes(raw))),saved.rightsHash),'COMMITTED_RIGHTS_MISMATCH',503);
  requireThat(typeof saved.rightsKey==='string'&&saved.rightsKey.startsWith(runtime.settings.prefix+'rights/'),'INVALID_RIGHTS_REFERENCE',503);
  let existing;
  try{existing=await runtime.settings.bucket.get(saved.rightsKey);}catch{return {...result,rights:freeze(result.rights)};}
  const condition=existing?{etagMatches:existing.etag}:new Headers({'If-None-Match':'*'});
  requireThat(!existing||existing.etag,'RIGHTS_CACHE_ETAG_REQUIRED',503);
  // This cache is not an authority control. A failed/lost write cannot extend
  // authority; the already-verified primary result remains bounded by its old lease.
  try{await runtime.settings.bucket.put(saved.rightsKey,raw,{onlyIf:condition,httpMetadata:{contentType:'application/json',cacheControl:'private, no-store'}});}catch{}
 }
 return {...result,rights:freeze(result.rights)};
}
