import {strictJSON,exact,canonical,requireThat,reject,ascii,safeInt,uuid,digest,sha256,hex,hmac,b64u,unb64u,equal,opaque,bytes} from './codec.mjs';
const EVENT='schema env sourceApp targetApp eventId operationId stream ownerEpoch sequence sub kind target committedAt commitRef digest'.split(' ');
const KINDS={'credential-epoch-advanced':'credentialEpoch','account-revoked':'accountCutoff','parent-revoked':'parent','browser-superseded':'browser','authority-updated':'dependency','policy-updated':'policy','key-withdrawn':'key'};
const TARGETS={accountCutoff:'type sub maxCe maxAe reason incidentId',credentialEpoch:'type sub newCe reason',parent:'type sub psid bsid bv ce ae',browser:'type bsid maxBv',dependency:'type id ownerEpoch revision effect deniedActions',policy:'type policyId ownerEpoch revision inactivityMinutes',key:'type purpose kid registryRevision'};
export const BUCKETS=['accountCutoffs','credentialFloors','parentCutoffs','browserCutoffs','localCutoffs','keyWithdrawals','policies','dependencyFloors'];
const REASONS=['VOLUNTARY_LOGOUT','VERIFIED_REFRESH_REUSE','SUSPICIOUS_ACTIVITY','CONFIRMED_KEY_COMPROMISE','ACCOUNT_DISABLED'];
export function validateTarget(target,{sub,dependencies=new Map(),ownerEpoch,targetApp}={}){
 requireThat(TARGETS[target?.type],'UNKNOWN_TARGET',400);exact(target,TARGETS[target.type].split(' '));
 for(const [k,v] of Object.entries(target)){
  if(['maxCe','maxAe','newCe','bv','ce','ae','maxBv','revision','registryRevision'].includes(k))requireThat(safeInt(v,1),'INVALID_COUNTER',400);
  if(['psid','bsid'].includes(k))requireThat(uuid(v),'INVALID_UUID',400);
 }
 if(Object.hasOwn(target,'sub'))requireThat(typeof sub==='string'&&target.sub===sub,'SUBJECT_CONFLICT',409);
 switch(target.type){
  case 'accountCutoff':requireThat(REASONS.includes(target.reason)&&(target.incidentId===null||uuid(target.incidentId)),'INVALID_CUTOFF',400);break;
  case 'credentialEpoch':requireThat(['ADMIN_PIN_RESET','PASSWORD_RESET'].includes(target.reason),'INVALID_CREDENTIAL_REASON',400);break;
  case 'dependency':{
   const rule=dependencies.get(target.id);requireThat(rule&&rule.ownerApp==='academy'&&rule.recipients?.includes(targetApp)&&target.ownerEpoch===rule.epoch&&['INVALIDATE','DENY'].includes(target.effect),'DEPENDENCY_CONFLICT',409);
   requireThat(Array.isArray(target.deniedActions)&&new Set(target.deniedActions).size===target.deniedActions.length,'INVALID_ACTIONS',400);
   requireThat(target.deniedActions.every((a,i)=>rule.actions.includes(a)&&(i===0||target.deniedActions[i-1]<a)),'INVALID_ACTIONS',400);
   requireThat(target.effect==='INVALIDATE'?target.deniedActions.length===0:target.deniedActions.length>0,'INVALID_EFFECT',400);break;
  }
  case 'policy':requireThat(sub===null&&target.policyId==='session-inactivity'&&target.ownerEpoch===ownerEpoch&&safeInt(target.inactivityMinutes,15)&&target.inactivityMinutes<=200,'INVALID_POLICY',400);break;
  case 'key':requireThat(sub===null&&target.purpose==='academy-handoff'&&/^[A-Za-z0-9._-]{1,64}$/.test(target.kid),'INVALID_KEY_TARGET',400);break;
 }
 return target;
}
export async function validateEvent(e,{env,targetApp,streams,dependencies=new Map()}){
 exact(e,EVENT);requireThat(e.schema===2&&e.env===env&&e.sourceApp==='academy'&&['studio','hifz'].includes(e.targetApp)&&e.targetApp===targetApp,'EVENT_DIRECTION_CONFLICT',409);
 requireThat(uuid(e.eventId)&&uuid(e.operationId)&&ascii(e.stream)&&ascii(e.ownerEpoch)&&ascii(e.commitRef)&&safeInt(e.sequence,1)&&safeInt(e.committedAt),'INVALID_EVENT',400);
 requireThat(e.sub===null||typeof e.sub==='string'&&bytes(e.sub).length>0&&bytes(e.sub).length<=180&&!/[\u0000-\u0020\u007f]/.test(e.sub),'INVALID_SUBJECT',400);
 requireThat(streams.get(e.stream)?.has(e.ownerEpoch),'RECONCILIATION_REQUIRED',409);
 requireThat(KINDS[e.kind]===e.target?.type,'EVENT_KIND_CONFLICT',409);
 validateTarget(e.target,{sub:e.sub,ownerEpoch:e.ownerEpoch,targetApp:e.targetApp,dependencies});
 if(['accountCutoff','credentialEpoch','parent'].includes(e.target.type))requireThat(e.sub!==null,'SUBJECT_CONFLICT',409);
 const unsigned=Object.fromEntries(Object.entries(e).filter(([k])=>k!=='digest'));requireThat(/^[0-9a-f]{64}$/.test(e.digest)&&equal(await digest(unsigned),e.digest),'EVENT_DIGEST_CONFLICT',409);
 return e;
}
function packet({method,path,env,sourceApp,targetApp,time,nonce,bodyDigest}){
 requireThat(['POST'].includes(method)&&/^\/internal\/auth\/v2\/[a-z-]+$/.test(path),'INVALID_SERVICE_PATH',401);
 return ['uaa-service-v2',method,path,env,sourceApp,targetApp,String(time),nonce,bodyDigest].join('\n');
}
export async function serviceHeaders({keyId,key,method='POST',path,env,sourceApp,targetApp,now,body}){
 const nonce=b64u(crypto.getRandomValues(new Uint8Array(16))),bodyDigest=hex(await sha256(body));
 const signature=b64u(await hmac(key,packet({method,path,env,sourceApp,targetApp,time:now,nonce,bodyDigest})));
 return {'X-UAA-Service-Key':keyId,'X-UAA-Service-Source':sourceApp,'X-UAA-Service-Target':targetApp,'X-UAA-Service-Time':String(now),'X-UAA-Service-Nonce':nonce,'X-UAA-Service-Signature':signature};
}
export async function authenticateService({request,body,config,registry,store,now}){
 const url=new URL(request.url);requireThat(!url.search&&url.origin===config.serviceOrigin,'WRONG_SERVICE_ORIGIN',401);
 const headers=request.headers,keyId=headers.get('X-UAA-Service-Key'),entry=registry.get(keyId);
 requireThat(entry&&entry.env===config.env&&entry.targetApp===config.app&&entry.sourceApp===headers.get('X-UAA-Service-Source')&&entry.targetApp===headers.get('X-UAA-Service-Target')&&entry.paths.includes(url.pathname),'SERVICE_KEY_NOT_ALLOWED',401);
 const text=headers.get('X-UAA-Service-Time');requireThat(/^(?:0|[1-9][0-9]*)$/.test(text||''),'INVALID_SERVICE_TIME',401);
 const time=Number(text);requireThat(safeInt(time)&&Math.abs(time-now)<=30,'SERVICE_TIME_SKEW',401);
 const nonce=headers.get('X-UAA-Service-Nonce');unb64u(nonce,16);const sig=unb64u(headers.get('X-UAA-Service-Signature'),32);
 const signed=packet({method:request.method,path:url.pathname,env:config.env,sourceApp:entry.sourceApp,targetApp:entry.targetApp,time,nonce,bodyDigest:hex(await sha256(body))});
 requireThat(equal(sig,await hmac(entry.key,signed)),'INVALID_SERVICE_SIGNATURE',401);
 try{await store.stmt('INSERT INTO jwt_v2_nonces VALUES(?,?,?,?)',entry.sourceApp,keyId,nonce,now+120).run();}catch{reject('SERVICE_NONCE_REUSED',401);}
 return entry;
}
async function advance(store,e){
 let stream=await store.first('SELECT * FROM jwt_v2_event_streams WHERE source_app=? AND target_app=? AND stream=? AND owner_epoch=?',e.sourceApp,e.targetApp,e.stream,e.ownerEpoch);
 if(!stream)return;
 let through=stream.contiguous_through;
 for(let count=0;count<256&&through<Number.MAX_SAFE_INTEGER;count++){
  const next=await store.first("SELECT 1 FROM jwt_v2_events WHERE source_app=? AND target_app=? AND stream=? AND owner_epoch=? AND sequence=? AND state='APPLIED'",e.sourceApp,e.targetApp,e.stream,e.ownerEpoch,through+1);if(!next)break;through++;
 }
 if(through>stream.contiguous_through)await store.stmt('UPDATE jwt_v2_event_streams SET contiguous_through=max(contiguous_through,?) WHERE source_app=? AND target_app=? AND stream=? AND owner_epoch=?',through,e.sourceApp,e.targetApp,e.stream,e.ownerEpoch).run();
}
export async function receiveBatch({body,config,store,streams,dependencies,planEffect,publishAndCovered}){
 // Call only after authenticateService; no endpoint/router exports an unauthenticated transport.
 const raw=typeof body==='string'?bytes(body):body;requireThat(raw.byteLength<=65536,'BODY_TOO_LARGE',413);
 const batch=exact(strictJSON(raw),['schema','env','sourceApp','targetApp','batchId','events']);
 requireThat(batch.schema===2&&batch.env===config.env&&batch.sourceApp==='academy'&&batch.targetApp===config.app&&['studio','hifz'].includes(config.app)&&uuid(batch.batchId)&&Array.isArray(batch.events)&&batch.events.length>=1&&batch.events.length<=20,'INVALID_BATCH',400);
 const results=[];
 for(const event of batch.events){
  let state='CONFLICT',reason=null,appliedRef=null;
  try{
   await validateEvent(event,{env:config.env,targetApp:config.app,streams,dependencies});
   let known=await store.first('SELECT * FROM jwt_v2_events WHERE event_id=? OR (source_app=? AND target_app=? AND stream=? AND owner_epoch=? AND sequence=?)',event.eventId,event.sourceApp,event.targetApp,event.stream,event.ownerEpoch,event.sequence);
   requireThat(!known||known.event_id===event.eventId&&known.digest===event.digest,'CONFLICTING_EVENT_RECEIPT',409);
   if(!known){
    const effects=await planEffect(event);
    await store.batch([
     store.stmt("INSERT INTO jwt_v2_event_streams(source_app,target_app,stream,owner_epoch,highest_seen) VALUES(?,?,?,?,?) ON CONFLICT(source_app,target_app,stream,owner_epoch) DO UPDATE SET highest_seen=max(highest_seen,excluded.highest_seen)",event.sourceApp,event.targetApp,event.stream,event.ownerEpoch,event.sequence),
     store.stmt("INSERT INTO jwt_v2_events VALUES(?,?,?,?,?,?,?,?,'CAPTURED',NULL)",event.eventId,event.sourceApp,event.targetApp,event.stream,event.ownerEpoch,event.sequence,event.digest,canonical(event)),...effects
    ]);
    known={state:'CAPTURED'};
   }
   state=known.state;
   if(state!=='APPLIED')await publishAndCovered(event);
   const barrier=await store.first("SELECT state FROM jwt_v2_worksets WHERE work_id=?",event.eventId);
   if(state!=='APPLIED'&&barrier?.state==='APPLIED'){
    appliedRef=event.eventId;await store.stmt("UPDATE jwt_v2_events SET state='APPLIED',applied_ref=? WHERE event_id=? AND digest=?",appliedRef,event.eventId,event.digest).run();state='APPLIED';
   }else if(state==='APPLIED')appliedRef=known.applied_ref;
   if(state==='APPLIED')await advance(store,event);
  }catch(error){reason=error.code||'CAPTURE_FAILED';if(error.status>=500||!error.status){const captured=event?.eventId&&await store.first('SELECT state FROM jwt_v2_events WHERE event_id=?',event.eventId);state=captured?'CAPTURED':'CONFLICT';}}
  const stream=event?.stream&&await store.first('SELECT * FROM jwt_v2_event_streams WHERE source_app=? AND target_app=? AND stream=? AND owner_epoch=?',batch.sourceApp,batch.targetApp,event.stream,event.ownerEpoch);
  results.push({eventId:event?.eventId||null,digest:event?.digest||null,status:state,reason,appliedRef,stream:event?.stream||null,ownerEpoch:event?.ownerEpoch||null,contiguousThrough:stream?.contiguous_through??0,highestSeen:stream?.highest_seen??0,gapPending:stream?stream.contiguous_through<stream.highest_seen:false,retryAfterSeconds:state==='CAPTURED'?1:0});
 }
 return {schema:2,batchId:batch.batchId,results};
}

export async function handleEventsRequest(options){
 const {request}=options;let size=0,chunks=[];const reader=request.body?.getReader();if(reader){for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>65536){await reader.cancel();reject('BODY_TOO_LARGE',413);}chunks.push(value);}}
 const body=new Uint8Array(size);let offset=0;for(const chunk of chunks){body.set(chunk,offset);offset+=chunk.length;}
 await authenticateService({...options,body});return receiveBatch({...options,body});
}
