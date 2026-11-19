import {assertCommittedControl} from './control-publication.mjs';
import {coversFloor} from './floors.mjs';
import {canonical,strictJSON,requireThat,reject,safeInt,uuid,sha256,hex,bytes,vectorDigest,equal,digest} from './codec.mjs';
import {controlShape} from './control-shapes.mjs';
import {verifyToken,preverifyAPI,BINDING} from './tokens.mjs';
export const MAX_CONTROL_BYTES=16384;
const verifiedPayloads=new WeakMap();
function immutable(value){if(value&&typeof value==='object'){for(const item of Object.values(value))immutable(item);Object.freeze(value);}return value;}
export class SecurityCache {
 constructor({bucket,store,prefix,generation}){
  requireThat(/^auth-private\/v2\/(?:production|feature)\/(?:academy|studio|hifz)\/[A-Za-z0-9_-]+\/$/.test(prefix)&&prefix.endsWith('/'+generation+'/'),'INVALID_SECURITY_NAMESPACE',503);
  requireThat(store.controlKey('control/app')===prefix+'control/app','SECURITY_NAMESPACE_MISMATCH',503);
  this.bucket=bucket;this.store=store;this.prefix=prefix;this.generation=generation;this.metrics={controlReads:0,payloadReads:0,conditionalWrites:0};
 }
 key(suffix){requireThat(/^(?:control\/app|security\/session\/[a-zA-Z0-9_-]+|control\/resource\/[a-zA-Z0-9_-]+)$/.test(suffix),'INVALID_SECURITY_KEY',503);return this.prefix+suffix;}
 async seed(suffix){
  const key=this.key(suffix),incarnation=crypto.randomUUID(),nonce=crypto.randomUUID();
  const first=await this.store.claimSeed({key,incarnation,generation:this.generation,nonce});
  if(!first)return {created:false};
  const value={schema:2,generation:this.generation,incarnation,state:'SEED',cr:0,publicationNonce:nonce};
  // This is the sole create attempt. Even a lost PUT response never permits a second create.
  this.metrics.conditionalWrites++;
  await this.bucket.put(key,canonical(value),{onlyIf:new Headers({'If-None-Match':'*'}),httpMetadata:{contentType:'application/json',cacheControl:'private, no-store'}});
  const found=await this.bucket.get(key);
  requireThat(found,'SECURITY_SEED_UNCONFIRMED',503);
  requireThat(!Number.isFinite(found.size)||found.size<=MAX_CONTROL_BYTES,'CONTROL_PARTITION_REQUIRED',503);
   const body=strictJSON(await found.arrayBuffer(),{maxBytes:MAX_CONTROL_BYTES});
  requireThat(body.incarnation===incarnation&&body.publicationNonce===nonce&&body.state==='SEED','SECURITY_SEED_CONFLICT',503);
  await this.store.seedObserved(key,nonce);return {created:true};
 }
 async noteLoss(suffix){
  const key=this.key(suffix),appKey=this.key('control/app');
  await this.store.lost(key).catch(()=>{});
  // Seal the existing app control with an ETag-only denial. This globally holds the
  // old generation on the same ordinary two-control path, even if a late session
  // publisher completes. No missing key is ever created here.
  await this.store.lost(appKey).catch(()=>{});
  for(let attempt=0;attempt<2;attempt++){
   let object;try{object=await this.bucket.get(appKey);}catch{return;}
   if(!object||!object.etag)return;
   let value;try{value=strictJSON(await object.arrayBuffer(),{maxBytes:MAX_CONTROL_BYTES});}catch{value=null;}
   if(value?.state==='FENCED')return;
   const life=await this.store.lifecycle(appKey).catch(()=>null);
   const incarnation=life?.incarnation||value?.incarnation;
   if(!uuid(incarnation))return;
   const cr=safeInt(value?.cr,1)?Math.min(Number.MAX_SAFE_INTEGER,value.cr+1):Math.max(1,life?.semantic_revision||1);
   const hold={schema:2,generation:this.generation,incarnation,state:'FENCED',cr,publicationNonce:crypto.randomUUID(),app:this.prefix.split('/')[3],env:this.prefix.split('/')[2]};
   try{if(await this.bucket.put(appKey,canonical(hold),{onlyIf:{etagMatches:object.etag},httpMetadata:{contentType:'application/json',cacheControl:'private, no-store'}}))return;}catch{return;}
  }
 }
 async read(suffix){
  const key=this.key(suffix);let object;
  this.metrics.controlReads++;
  try{object=await this.bucket.get(key);}catch{reject('SECURITY_TRANSPORT_UNAVAILABLE',503);}
  if(!object){const life=await this.store.lifecycle(key);if(!life)reject('SESSION_ENDED',401);if(life.state==='SEED')reject('SECURITY_PUBLICATION_PENDING',503);await this.noteLoss(suffix);reject('SECURITY_CONTROL_UNAVAILABLE',503);}
  if(Number.isFinite(object.size)&&object.size>MAX_CONTROL_BYTES){await this.noteLoss(suffix);reject('SECURITY_CONTROL_UNAVAILABLE',503);}
  let raw;try{raw=await object.arrayBuffer();}catch{reject('SECURITY_TRANSPORT_UNAVAILABLE',503);}
  let value;try{requireThat(raw.byteLength<=MAX_CONTROL_BYTES,'CONTROL_TOO_LARGE',503);value=strictJSON(raw,{maxBytes:MAX_CONTROL_BYTES});}catch{await this.noteLoss(suffix);reject('SECURITY_CONTROL_UNAVAILABLE',503);}
  if(value?.state==='SEED'){
   const life=await this.store.lifecycle(key);
   if(life?.state==='SEED'&&value.schema===2&&value.generation===this.generation&&life.generation===value.generation&&value.incarnation===life.incarnation&&value.publicationNonce===life.seed_nonce&&value.cr===0)reject('SECURITY_PUBLICATION_PENDING',503);
   await this.noteLoss(suffix);reject('SECURITY_CONTROL_UNAVAILABLE',503);
  }
  if(value.schema!==2||value.generation!==this.generation||value.state!=='ACTIVE'||!uuid(value.incarnation)||!safeInt(value.cr,1)||!uuid(value.publicationNonce)){
   await this.noteLoss(suffix);reject('SECURITY_CONTROL_UNAVAILABLE',503);
  }
  try{controlShape(suffix,value,this.prefix);}catch{await this.noteLoss(suffix);reject('SECURITY_CONTROL_UNAVAILABLE',503);}
  requireThat(typeof object.etag==='string'&&object.etag.length>0,'SECURITY_ETAG_REQUIRED',503);
  return {value,etag:object.etag};
 }
 async publish(suffix,buildCommitted){
  const key=this.key(suffix),life=await this.store.lifecycle(key);
  requireThat(life&&['SEED','ACTIVE'].includes(life.state)&&life.seed_observed===1&&life.generation===this.generation,'SECURITY_OBJECT_FENCED',503);
  const object=await this.bucket.get(key);
  if(!object){await this.noteLoss(suffix);reject('SECURITY_CONTROL_UNAVAILABLE',503);}
  if(Number.isFinite(object.size)&&object.size>MAX_CONTROL_BYTES){await this.noteLoss(suffix);reject('SECURITY_CONTROL_UNAVAILABLE',503);}
  let readBody;try{readBody=await object.arrayBuffer();}catch{reject('SECURITY_TRANSPORT_UNAVAILABLE',503);}
  let current;try{requireThat(readBody.byteLength<=MAX_CONTROL_BYTES,'CONTROL_TOO_LARGE',503);current=strictJSON(readBody,{maxBytes:MAX_CONTROL_BYTES});}catch{await this.noteLoss(suffix);reject('SECURITY_CONTROL_UNAVAILABLE',503);}
  if(current.incarnation!==life.incarnation||current.generation!==this.generation||!['SEED','ACTIVE'].includes(current.state)){await this.noteLoss(suffix);reject('SECURITY_CONTROL_UNAVAILABLE',503);}
  if(current.state==='SEED'&&(current.cr!==0||current.publicationNonce!==life.seed_nonce)){await this.noteLoss(suffix);reject('SECURITY_CONTROL_UNAVAILABLE',503);}
  requireThat(object.etag,'SECURITY_ETAG_REQUIRED',503);
  if(current.state==='ACTIVE')try{controlShape(suffix,current,this.prefix);}catch{await this.noteLoss(suffix);reject('SECURITY_CONTROL_UNAVAILABLE',503);}
  const committed=await buildCommitted();
  controlShape(suffix,committed,this.prefix);
  requireThat(safeInt(committed.cr,1)&&committed.cr>=life.semantic_revision,'STALE_PUBLISHER',409);
  if(suffix.startsWith('security/session/')){
   const primary=await this.store.family(suffix.slice('security/session/'.length));
   requireThat(primary&&primary.cr===committed.cr&&primary.binding_json===canonical(committed.binding)&&primary.state===committed.localState&&primary.deadline===committed.validationDeadline&&primary.idle_until===committed.idleUntil&&Boolean(primary.authority_ready)===committed.authorityReady,'UNCOMMITTED_SECURITY_PROJECTION',409);
   if(committed.localState==='UNLOCKED'&&committed.authorityReady){
    const saved=JSON.parse(primary.projection_json);
    requireThat(safeInt(committed.timedUntil)&&committed.timedUntil<=Math.min(primary.s_exp,saved.timedUntil??primary.s_exp),'UNCOMMITTED_TIMED_BOUND',409);
    for(const field of ['ownerVector','rightsHash','deniedActions','policyEpoch','policyRevision','keyRegistryEpoch','keyRegistryRevision'])requireThat(saved[field]!==undefined&&committed[field]!==undefined&&canonical(saved[field])===canonical(committed[field]),'UNCOMMITTED_PERMISSION_PROJECTION',409);
   }
   if(current.state==='ACTIVE'){
    requireThat(current.s_exp===committed.s_exp,'IMMUTABLE_ORIGINAL_EXPIRY',409);
    requireThat(!['REVOKED','EXPIRED'].includes(current.localState)||current.localState===committed.localState,'TERMINAL_SECURITY_PROJECTION',409);
    for(const target of current.enforcedTargets||[])requireThat((committed.enforcedTargets||[]).some(t=>coversFloor(t,target)),'PUBLISHED_FLOOR_OMITTED',409);
   }
  }
  if(current.cr>committed.cr)reject('STALE_PUBLISHER',409);
  if(current.cr===committed.cr&&current.state==='ACTIVE'){
   const semantic=value=>Object.fromEntries(Object.entries(value).filter(([k])=>!['publicationNonce','incarnation','generation','schema','state'].includes(k)));
   requireThat(canonical(semantic(current))===canonical(semantic(committed)),'PUBLICATION_CONFLICT',409);
   if(suffix.startsWith('control/'))await assertCommittedControl(this.store,suffix,committed);
   await this.store.published(key,current.cr,{cr:current.cr,nonce:current.publicationNonce,incarnation:current.incarnation,generation:current.generation,digest:await digest(current),etag:object.etag});return current;
  }
  if(suffix.startsWith('control/'))await assertCommittedControl(this.store,suffix,committed);
  const candidate={...committed,schema:2,generation:this.generation,incarnation:life.incarnation,state:'ACTIVE',publicationNonce:crypto.randomUUID()};
  const encoded=canonical(candidate);requireThat(bytes(encoded).length<=MAX_CONTROL_BYTES,'CONTROL_PARTITION_REQUIRED',503);
   const latest=await this.store.lifecycle(key);requireThat(latest&&['SEED','ACTIVE'].includes(latest.state)&&latest.incarnation===life.incarnation&&latest.generation===life.generation,'SECURITY_OBJECT_FENCED',503);
  this.metrics.conditionalWrites++;
  const written=await this.bucket.put(key,encoded,{onlyIf:{etagMatches:object.etag},httpMetadata:{contentType:'application/json',cacheControl:'private, no-store'}});
  requireThat(written,'PUBLICATION_RETRY',409);
  await this.store.published(key,candidate.cr,{cr:candidate.cr,nonce:candidate.publicationNonce,incarnation:candidate.incarnation,generation:candidate.generation,digest:await digest(candidate),etag:written.etag});return candidate;
 }
 async authorise({token,sessionKey,config,keys,now,rightsMemo=new Map(),resourceKeys=[],action}){
  const verified=await preverifyAPI(token,{config,keys,now});
  requireThat(verified.sid===sessionKey,'SECURITY_SELECTOR_MISMATCH');
  const app=(await this.read('control/app')).value;
  requireThat(!app.withdrawnKids.includes(verified.kid),'UNTRUSTED_KEY');
  const session=(await this.read('security/session/'+sessionKey)).value;
  requireThat(app.app===config.app&&app.env===config.env&&session.app===config.app&&session.env===config.env,'WRONG_SECURITY_NAMESPACE');
  requireThat(session.localState==='UNLOCKED','SESSION_NOT_UNLOCKED',['LOCKED','ADMITTED_LOCKED'].includes(session.localState)?423:401);
  requireThat(session.authorityReady,'PERMISSIONS_REFRESH_REQUIRED',503);
  requireThat(typeof action==='string'&&action.length>0,'ACTION_CONTEXT_REQUIRED',503);
  requireThat(Array.isArray(session.deniedActions)&&session.deniedActions.every(a=>typeof a==='string'),'MALFORMED_SESSION_DENIALS',503);
  requireThat(!session.deniedActions.includes(action),'ACCESS_DENIED',403);
  requireThat(now<Math.min(session.validationDeadline,session.idleUntil,session.s_exp),'LEASE_EXPIRED');
  requireThat(session.policyEpoch===app.policyEpoch&&session.policyRevision===app.policyRevision&&session.keyRegistryEpoch===app.keyRegistryEpoch&&session.keyRegistryRevision===app.keyRegistryRevision,'SECURITY_RECONCILIATION_REQUIRED',503);
  const claims=await verifyToken(token,{config,keys,preverified:verified,withdrawn:new Set(app.withdrawnKids||[]),projection:session.binding,now,idleUntil:session.idleUntil,timedUntil:session.timedUntil,initial:session.initialIssuance===true});
  requireThat(claims.ver>=app.migrationFloor,'TOKEN_FORMAT_RETIRED');
  requireThat(claims.exp<=session.validationDeadline,'INVALID_VALIDATION_DEADLINE');
  requireThat(session.binding.pv===await vectorDigest(session.ownerVector),'VECTOR_MISMATCH');
  for(const key of resourceKeys){const policy=(await this.read('control/resource/'+key)).value;requireThat(!policy.deniedActions.includes(action),'ACCESS_DENIED',403);}
  const memoKey=canonical([config.env,config.app,session.binding.sub,session.ownerVector,session.rightsKey,session.rightsHash]);
  let rights=rightsMemo.get(memoKey);
  if(!rights||typeof rights!=='object'||verifiedPayloads.get(rights)!==memoKey)rights=null;
  if(!rights){
   requireThat(typeof session.rightsKey==='string'&&session.rightsKey.startsWith(this.prefix+'rights/')&&/^[0-9a-f]{64}$/.test(session.rightsHash),'INVALID_RIGHTS_REFERENCE',503);
   this.metrics.payloadReads++;const object=await this.bucket.get(session.rightsKey);requireThat(object&&object.size<=2*1024*1024,'RIGHTS_PAYLOAD_UNAVAILABLE',503);
   const raw=new Uint8Array(await object.arrayBuffer());requireThat(equal(hex(await sha256(raw)),session.rightsHash),'RIGHTS_PAYLOAD_CORRUPT',503);
   rights=immutable(strictJSON(raw,{maxBytes:2*1024*1024}));requireThat(rights&&typeof rights==='object','INVALID_RIGHTS_PAYLOAD',503);verifiedPayloads.set(rights,memoKey);rightsMemo.set(memoKey,rights);
  }
  // Memoised bytes do not confer a lease: controls and deadlines were checked above on every request.
  return {binding:session.binding,rights,deadline:Math.min(session.validationDeadline,session.idleUntil,session.timedUntil,session.s_exp)};
 }
}
export async function coherentCapture({readFence,readVector,loadRights,committedLease,now}){
 requireThat(committedLease&&now<committedLease.deadline,'LEASE_EXPIRED');
 for(let attempt=0;attempt<2;attempt++){
  const before=await readFence();requireThat(!before.pending,'SPLIT_RECOVERY_PENDING',503);
  const vectorBefore=canonical(await readVector()),rights=await loadRights();
  const after=await readFence(),vectorAfter=canonical(await readVector());
  if(!after.pending&&canonical(before)===canonical(after)&&vectorBefore===vectorAfter)return {rights,vat:committedLease.vat,deadline:committedLease.deadline,vector:JSON.parse(vectorAfter)};
 }
 reject('AUTHORITY_CHANGED_DURING_CAPTURE',503);
}
