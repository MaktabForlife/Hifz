import {canonical,strictJSON,requireThat,ascii,safeInt,bytes,digest,hmac,b64u,unb64u,equal,opaque} from './codec.mjs';
import {ORIGINS} from './tokens.mjs';
export const portalPath='/internal/academy/portal/v2',portalReturnPath='/internal/website/portal-return/v2';
const verifiedPeers=new WeakMap();
export const isVerifiedPortalPeer=peer=>Boolean(peer&&verifiedPeers.get(peer)===canonical(peer.body));
const operations=new Set(['stage-manifest','stage-page','summary','join','admin-read','admin','admin-cover','source-return']);
const limit=operation=>operation==='admin-cover'?1016384:operation==='admin'||operation==='admin-read'?270336:65536;
const replyLimit=(operation,input)=>operation==='admin-read'&&input?.command?.action==='mou-playlist-cover-preview'?1000000:270336;
const packet=(reply,kid,time,nonce,hash,{sourceApp='academy',targetApp='studio',path=portalPath}={})=>({purpose:reply?'uaa-root-portal-reply-v2':'uaa-root-portal-request-v2',env:'production',sourceApp:reply?targetApp:sourceApp,targetApp:reply?sourceApp:targetApp,method:'POST',path,kid,time,nonce,bodyDigest:hash});
export function portalKeys(env,now){
 const ring=strictJSON(env.UAA_V2_PORTAL_RPC_KEYS_JSON??'null',{maxBytes:65536});
 requireThat(ring?.schema===1&&ascii(ring.currentKid,64)&&Array.isArray(ring.keys)&&ring.keys.length>0&&ring.keys.length<=20,'PORTAL_KEYS_REQUIRED',503);
 const keys=new Map();
 for(const row of ring.keys){
  requireThat(row&&Object.keys(row).sort().join(',')==='disabled,key,kid,notAfter,notBefore,operations'&&ascii(row.kid,64)&&/^[A-Za-z0-9._-]+$/.test(row.kid)&&!keys.has(row.kid)&&typeof row.disabled==='boolean'&&safeInt(row.notBefore)&&safeInt(row.notAfter)&&row.notBefore<row.notAfter&&Array.isArray(row.operations)&&row.operations.length>0&&new Set(row.operations).size===row.operations.length&&row.operations.every(v=>operations.has(v)),'PORTAL_KEYS_INVALID',503);
  const key=unb64u(row.key,32);requireThat(![...keys.values()].some(e=>equal(e.key,key)),'PORTAL_KEY_REUSED',503);keys.set(row.kid,{...row,key});
 }
 const current=keys.get(ring.currentKid);requireThat(current&&!current.disabled&&current.notBefore<=now&&now<current.notAfter,'PORTAL_SIGNER_UNAVAILABLE',503);return {keys,current};
}
export async function portalJSON(input,maxBytes=1016384){
 const reader=input.body?.getReader();requireThat(reader,'PORTAL_BODY_REQUIRED',400);let size=0;const chunks=[];
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maxBytes){await reader.cancel();requireThat(false,'PORTAL_BODY_TOO_LARGE',413);}chunks.push(value);}}finally{reader.releaseLock();}
 const raw=new Uint8Array(size);let at=0;for(const value of chunks){raw.set(value,at);at+=value.length;}return strictJSON(raw,{maxBytes});
}
export async function verifyPortalEnvelope(envelope,{env,app,now}){
 const {body,keyId:kid,issuedAt:time,nonce,mac}=envelope,targetApp=app,sourceApp=app==='studio'?'academy':'studio',path=app==='studio'?portalPath:portalReturnPath,route={sourceApp,targetApp,path};
 requireThat(['academy','studio'].includes(app),'PORTAL_DIRECTION_INVALID',403);
 const row=portalKeys(env,now).keys.get(kid);
 requireThat(row&&!row.disabled&&row.notBefore<=now&&now<row.notAfter&&safeInt(time)&&time<=now+5&&now<time+10&&typeof nonce==='string'&&/^[A-Za-z0-9_-]{43}$/.test(nonce),'PORTAL_AUTH_REQUIRED',401);
 requireThat(body?.schema===2&&body.env==='production'&&body.sourceApp===sourceApp&&body.targetApp===targetApp&&(app==='academy'?body.operation==='source-return':body.operation!=='source-return')&&operations.has(body.operation)&&row.operations.includes(body.operation)&&bytes(canonical(body)).length<=limit(body.operation)&&body.issuedAt===time&&safeInt(body.expiresAt)&&time<body.expiresAt&&body.expiresAt<=time+10&&now<body.expiresAt,'PORTAL_PROOF_INVALID',403);
 let supplied;try{supplied=unb64u(mac,32);}catch{requireThat(false,'PORTAL_MAC_INVALID',401);}
 requireThat(equal(supplied,await hmac(row.key,canonical(packet(false,kid,time,nonce,await digest(body),route)))),'PORTAL_MAC_INVALID',401);
 const peer={body,kid,time,nonce,key:row.key,...route};verifiedPeers.set(peer,canonical(body));return peer;
}
export async function verifyPortalRequest(request,runtime){
 const u=new URL(request.url),targetApp=runtime.app,path=targetApp==='studio'?portalPath:portalReturnPath;
 requireThat(['studio','academy'].includes(targetApp)&&u.origin===ORIGINS[targetApp]&&u.pathname===path&&!u.search&&request.method==='POST','PORTAL_ROUTE_INVALID',404);
 const peer=await verifyPortalEnvelope({body:await portalJSON(request),keyId:request.headers.get('X-UAA-Portal-Key'),issuedAt:Number(request.headers.get('X-UAA-Portal-Time')),nonce:request.headers.get('X-UAA-Portal-Nonce'),mac:request.headers.get('X-UAA-Portal-MAC')},{env:runtime.env,app:runtime.app,now:runtime.clock()});
 try{await runtime.store.stmt('INSERT INTO jwt_v2_nonces VALUES(?,?,?,?)',peer.sourceApp,'portal:'+peer.kid,peer.nonce,peer.body.expiresAt).run();}catch{requireThat(false,'PORTAL_NONCE_REUSED',401);}return peer;
}
export async function portalReply(runtime,peer,value,status=200){
 // Native business DTOs use normal JSON omission semantics (for example a
 // deliberately omitted private object key). Sign exactly the strict JSON
 // value that crosses the wire, never an in-memory undefined property.
 const maximum=replyLimit(peer.body.operation,peer.body.input),wire=JSON.stringify(value);
 requireThat(typeof wire==='string'&&bytes(wire).length<=maximum,'PORTAL_REPLY_TOO_LARGE',503);
 value=strictJSON(wire,{maxBytes:maximum});const encoded=canonical(value);requireThat(bytes(encoded).length<=maximum,'PORTAL_REPLY_TOO_LARGE',503);const time=runtime.clock();
 return new Response(encoded,{status,headers:{'Content-Type':'application/json','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','X-UAA-Portal-Key':peer.kid,'X-UAA-Portal-Time':String(time),'X-UAA-Portal-Nonce':peer.nonce,'X-UAA-Portal-MAC':b64u(await hmac(peer.key,canonical(packet(true,peer.kid,time,peer.nonce,await digest(value),peer)))) }});
}
export async function portalFetch(runtime,proof,operation,input){
 requireThat((runtime.app==='academy'&&operation!=='source-return'||runtime.app==='studio'&&operation==='source-return')&&operations.has(operation),'PORTAL_DIRECTION_INVALID',503);const targetApp=runtime.app==='academy'?'studio':'academy',path=targetApp==='studio'?portalPath:portalReturnPath,route={sourceApp:runtime.app,targetApp,path},now=runtime.clock(),entry=portalKeys(runtime.env,now).current;requireThat(entry.operations.includes(operation),'PORTAL_OPERATION_NOT_ALLOWED',503);
 const expiresAt=Math.min(now+10,proof.expiresAt??Number.MAX_SAFE_INTEGER,proof.deadline,proof.binding.s_exp),nonce=opaque(),body={schema:2,env:'production',sourceApp:runtime.app,targetApp,operation,issuedAt:now,expiresAt,delegationId:proof.delegationId,binding:proof.binding,deadline:proof.deadline,head:proof.head,input};
 requireThat(expiresAt>now,'PORTAL_LEASE_EXPIRED',401);const encoded=canonical(body);requireThat(bytes(encoded).length<=limit(operation),'PORTAL_BODY_TOO_LARGE',413);
 const headers={'Content-Type':'application/json','X-UAA-Portal-Key':entry.kid,'X-UAA-Portal-Time':String(now),'X-UAA-Portal-Nonce':nonce,'X-UAA-Portal-MAC':b64u(await hmac(entry.key,canonical(packet(false,entry.kid,now,nonce,await digest(body),route))))},peer=runtime.env.UAA_V2_PEERS?.[targetApp],transport=peer?.fetch?peer.fetch.bind(peer):globalThis.fetch;
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),Math.max(1,(expiresAt-now)*1000));
 try{
  const response=await transport(new Request(ORIGINS[targetApp]+path,{method:'POST',headers,body:encoded,redirect:'manual',signal:controller.signal}));
  requireThat(response instanceof Response&&!response.redirected&&(response.status<300||response.status>=400),'PORTAL_REPLY_INVALID',503);
  const value=await portalJSON(response,replyLimit(operation,input)),time=Number(response.headers.get('X-UAA-Portal-Time'));
  requireThat(response.headers.get('X-UAA-Portal-Key')===entry.kid&&response.headers.get('X-UAA-Portal-Nonce')===nonce&&safeInt(time)&&time<=runtime.clock()+5&&runtime.clock()<time+10,'PORTAL_REPLY_INVALID',503);
  requireThat(equal(unb64u(response.headers.get('X-UAA-Portal-MAC'),32),await hmac(entry.key,canonical(packet(true,entry.kid,time,nonce,await digest(value),route)))),'PORTAL_REPLY_INVALID',503);
  requireThat(response.ok&&value.success!==false,typeof value.code==='string'?value.code:'PORTAL_UNAVAILABLE',response.status>=500?503:response.status);return value;
 }catch(error){if(error.code)throw error;requireThat(false,'PORTAL_TRANSPORT_UNAVAILABLE',503);}finally{clearTimeout(timer);}
}
export const portalBusinessBoundary=Object.freeze({authority:'Explicit Academy parent business delegation; never a Studio cookie, SID, bearer token or admission receipt.',limits:'Authentication C19 remains64KiB. Separate existing native business DTO limits cover bounded playlist documents/artwork; profile packets stay64KiB.',retry:'No automatic replay of a business mutation.'});
