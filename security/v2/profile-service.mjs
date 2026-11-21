import {canonical,strictJSON,exact,requireThat,safeInt,ascii,uuid,bytes,digest,hmac,b64u,unb64u,equal} from './codec.mjs';
import {ORIGINS} from './tokens.mjs';
import {dependencyScope} from './issuance-floors.mjs';
export const PROFILE_PATH='/internal/academy/profile-sync',PROFILE_ID='academy:native:hifz_profile_sync',PROFILE_PURPOSE='hifz-profile-projection';
const verifiedProfiles=new WeakMap();
export function authenticatedProfileProjection(packet){const proof=verifiedProfiles.get(packet);requireThat(proof,'AUTHENTICATED_PROFILE_PROJECTION_REQUIRED',403);return proof;}
const profileFields=['academyUserId','revision','pinResetVersion','name','loginId','whatsappNumber','role','active','credentialEpoch'];
export function validateNativeProfile(value){
 exact(value,profileFields);dependencyScope(value.academyUserId);
 const text=(v,max,empty=false)=>typeof v==='string'&&v===v.trim()&&(empty||v.length>0)&&bytes(v).length<=max&&!/[\u0000-\u001f\u007f]/.test(v);
 requireThat(text(value.name,160)&&text(value.loginId,160)&&text(value.whatsappNumber,32,true)&&['student','teacher','admin'].includes(value.role)&&[0,1].includes(value.active)&&safeInt(value.revision,1)&&safeInt(value.pinResetVersion)&&safeInt(value.credentialEpoch,1),'INVALID_HIFZ_PROFILE_PROJECTION',400);return value;
}
export function profileKeys(runtime,now){
 const ring=strictJSON(runtime.env.UAA_V2_PROFILE_KEYS_JSON,{maxBytes:65536});exact(ring,['schema','currentKid','keys']);
 requireThat(ring.schema===1&&ascii(ring.currentKid,64)&&Array.isArray(ring.keys)&&ring.keys.length>0&&ring.keys.length<=20,'PROFILE_KEY_REGISTRY_REQUIRED',503);
 const keys=new Map();
 for(const value of ring.keys){exact(value,['kid','key','notBefore','notAfter','disabled']);requireThat(ascii(value.kid,64)&&/^[A-Za-z0-9._-]+$/.test(value.kid)&&!keys.has(value.kid)&&safeInt(value.notBefore)&&safeInt(value.notAfter)&&value.notBefore<value.notAfter&&typeof value.disabled==='boolean','PROFILE_KEY_REGISTRY_INVALID',503);const key=unb64u(value.key,32);if(!value.disabled&&value.notBefore<=now&&now<value.notAfter)keys.set(value.kid,{...value,key});}
 requireThat(keys.has(ring.currentKid),'PROFILE_SIGNER_UNAVAILABLE',503);return {currentKid:ring.currentKid,keys};
}
export async function validateProfilePacket(value,runtime){
 exact(value,['schema','purpose','env','sourceApp','targetApp','operationId','dependency','commitRef','projectionDigest','profile']);
 requireThat(value.schema===2&&value.purpose===PROFILE_PURPOSE&&value.env===runtime.config.env&&value.sourceApp==='academy'&&value.targetApp==='hifz'&&uuid(value.operationId)&&ascii(value.commitRef,128),'INVALID_PROFILE_PACKET',400);
 validateNativeProfile(value.profile);const t=exact(value.dependency,['type','id','ownerEpoch','revision','effect','deniedActions']);
 requireThat(t.type==='dependency'&&t.id===PROFILE_ID&&ascii(t.ownerEpoch)&&safeInt(t.revision,1)&&t.effect==='INVALIDATE'&&Array.isArray(t.deniedActions)&&t.deniedActions.length===0&&value.projectionDigest===await digest(value.profile),'PROFILE_SOURCE_BINDING_CONFLICT',409);return value;
}
const signed=(label,{env,keyId,time,nonce,bodyDigest})=>canonical({purpose:label,method:'POST',path:PROFILE_PATH,env,sourceApp:label.endsWith('-request')?'academy':'hifz',targetApp:label.endsWith('-request')?'hifz':'academy',keyId,time,nonce,bodyDigest});
export async function profileHeaders(runtime,body,{reply=false,now=runtime.clock()}={}){
 const ring=profileKeys(runtime,now),key=ring.keys.get(ring.currentKid),nonce=b64u(crypto.getRandomValues(new Uint8Array(16))),bodyDigest=await digest(strictJSON(body)),label='uaa-native-profile-v2-'+(reply?'reply':'request');
 return {'Content-Type':'application/json','X-UAA-Profile-Key':key.kid,'X-UAA-Profile-Time':String(now),'X-UAA-Profile-Nonce':nonce,'X-UAA-Profile-MAC':b64u(await hmac(key.key,signed(label,{env:runtime.config.env,keyId:key.kid,time:now,nonce,bodyDigest})))};
}
export async function verifyProfileMAC(runtime,headers,body,{reply=false,now=runtime.clock()}={}){
 const keyId=headers.get('X-UAA-Profile-Key'),key=profileKeys(runtime,now).keys.get(keyId),text=headers.get('X-UAA-Profile-Time');requireThat(key&&/^(?:0|[1-9][0-9]*)$/.test(text||''),'PROFILE_KEY_NOT_ALLOWED',401);
 const time=Number(text),nonce=headers.get('X-UAA-Profile-Nonce');unb64u(nonce,16);requireThat(safeInt(time)&&Math.abs(now-time)<=30,'PROFILE_TIME_SKEW',401);
 const label='uaa-native-profile-v2-'+(reply?'reply':'request'),mac=unb64u(headers.get('X-UAA-Profile-MAC'),32);
 requireThat(equal(mac,await hmac(key.key,signed(label,{env:runtime.config.env,keyId,time,nonce,bodyDigest:await digest(strictJSON(body))}))),'PROFILE_MAC_INVALID',401);
 try{await runtime.store.stmt('INSERT INTO jwt_v2_nonces VALUES(?,?,?,?)',reply?'hifz':'academy','profile:'+keyId,nonce,now+120).run();}catch{requireThat(false,'PROFILE_NONCE_REUSED',401);}
}
export async function readProfileBody(response,maxBytes=16384){
 const reader=response.body?.getReader();requireThat(reader,'PROFILE_BODY_REQUIRED',400);const chunks=[];let size=0,timer;
 const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>{const error=new Error('PROFILE_BODY_TIMEOUT');error.code='PROFILE_BODY_TIMEOUT';error.status=408;reject(error);},10000);});
 try{for(;;){const {value,done}=await Promise.race([reader.read(),timeout]);if(done)break;size+=value.length;requireThat(size<=maxBytes,'PROFILE_BODY_TOO_LARGE',413);chunks.push(value);}}
 catch(error){reader.cancel().catch(()=>{});throw error;}finally{clearTimeout(timer);reader.releaseLock();}
 const out=new Uint8Array(size);let i=0;for(const chunk of chunks){out.set(chunk,i);i+=chunk.length;}return out;
}
export async function sendNativeProfile(runtime,packet,{fetcher=globalThis.fetch}={}){
 requireThat(runtime.app==='academy','PROFILE_WRONG_OWNER',403);await validateProfilePacket(packet,runtime);const body=canonical(packet);requireThat(bytes(body).length<=16384,'PROFILE_BODY_TOO_LARGE',413);
 const peer=runtime.env.UAA_V2_PEERS?.hifz,transport=peer?.fetch?peer.fetch.bind(peer):fetcher;requireThat(typeof transport==='function','PROFILE_TRANSPORT_REQUIRED',503);
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),10000);
 try{
  const response=await transport(new Request(ORIGINS.hifz+PROFILE_PATH,{method:'POST',headers:await profileHeaders(runtime,body),body,redirect:'manual',signal:controller.signal}));
  requireThat(response instanceof Response&&!response.redirected&&response.status===200,'PROFILE_DELIVERY_UNAVAILABLE',503);const raw=await readProfileBody(response,4096);await verifyProfileMAC(runtime,response.headers,raw,{reply:true});const reply=exact(strictJSON(raw),['schema','status','operationId','sub','dependency','commitRef','projectionDigest','nativeReceiptDigest']);
  requireThat(reply.schema===2&&reply.status==='COMMITTED'&&reply.operationId===packet.operationId&&reply.sub===packet.profile.academyUserId&&canonical(reply.dependency)===canonical(packet.dependency)&&reply.commitRef===packet.commitRef&&reply.projectionDigest===packet.projectionDigest&&/^[0-9a-f]{64}$/.test(reply.nativeReceiptDigest),'PROFILE_COMMIT_RECEIPT_CONFLICT',409);return reply;
 }finally{clearTimeout(timer);}
}
export async function handleNativeProfile(runtime,request){
 requireThat(runtime.app==='hifz'&&runtime.env.UAA_V2_ENABLED==='1','PROFILE_WRONG_OWNER',403);const url=new URL(request.url);
 requireThat(url.origin===ORIGINS.hifz&&url.pathname===PROFILE_PATH&&!url.search&&!url.hash&&request.method==='POST'&&!request.headers.has('Origin')&&!request.headers.has('Cookie')&&request.headers.get('Content-Type')?.split(';')[0].trim()==='application/json','PROFILE_REQUEST_FORBIDDEN',403);
 const raw=await readProfileBody(request);await verifyProfileMAC(runtime,request.headers,raw);const packet=await validateProfilePacket(strictJSON(raw),runtime);verifiedProfiles.set(packet,Object.freeze({profile:packet.profile,target:packet.dependency,commitRef:packet.commitRef,projectionDigest:packet.projectionDigest}));
 requireThat(typeof runtime.native.applyProfileProjection==='function','PROFILE_NATIVE_INTAKE_REQUIRED',503);const result=await runtime.native.applyProfileProjection(packet),reply={schema:2,status:'COMMITTED',operationId:packet.operationId,sub:packet.profile.academyUserId,dependency:packet.dependency,commitRef:packet.commitRef,projectionDigest:packet.projectionDigest,nativeReceiptDigest:result.nativeReceiptDigest};
 requireThat(/^[0-9a-f]{64}$/.test(reply.nativeReceiptDigest),'PROFILE_NATIVE_RECEIPT_REQUIRED',503);const body=canonical(reply);return new Response(body,{status:200,headers:{...await profileHeaders(runtime,body,{reply:true}),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
}
