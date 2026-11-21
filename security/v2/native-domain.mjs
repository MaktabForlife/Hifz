import {canonical,strictJSON,requireThat,uuid,safeInt,ascii,bytes,digest,hmac,b64u,unb64u,opaque} from './codec.mjs';
import {ORIGINS} from './tokens.mjs';
const commands=new Set(['dashboard','lesson-join','media-teachers','course-playlist-placements','identity'].map(c=>'/internal/website/'+c));
const purpose='uaa-native-business-v2';
export function nativeRPCSigner(runtime,command,now){
 const ring=strictJSON(runtime.env.UAA_V2_NATIVE_RPC_KEYS_JSON,{maxBytes:65536});
 requireThat(ring?.schema===1&&Array.isArray(ring.keys)&&ring.keys.length<=20,'NATIVE_RPC_REGISTRY_REQUIRED',503);
 const ids=new Set(),eligible=[];
 for(const entry of ring.keys){
  requireThat(entry&&Object.keys(entry).sort().join(',')==='commands,disabled,key,kid,notAfter,notBefore,sourceApp,targetApp'&&ascii(entry.kid,64)&&/^[A-Za-z0-9._-]+$/.test(entry.kid)&&!ids.has(entry.kid)&&entry.sourceApp==='studio'&&entry.targetApp==='academy'&&typeof entry.disabled==='boolean'&&safeInt(entry.notBefore)&&safeInt(entry.notAfter)&&entry.notBefore<entry.notAfter&&Array.isArray(entry.commands)&&entry.commands.length>0&&new Set(entry.commands).size===entry.commands.length&&entry.commands.every(c=>commands.has(c)),'NATIVE_RPC_REGISTRY_INVALID',503);
  ids.add(entry.kid);const key=unb64u(entry.key,32);
  if(!entry.disabled&&entry.notBefore<=now&&now<entry.notAfter&&entry.commands.includes(command))eligible.push({...entry,key});
 }
 const selected=runtime.settings.raw.nativeRPCSigningKid;
 const signer=selected?eligible.find(k=>k.kid===selected):eligible.length===1?eligible[0]:null;
 requireThat(signer,'NATIVE_RPC_SIGNER_UNAVAILABLE',503);return signer;
}
async function readReply(response){
 requireThat(response?.body,'NATIVE_RPC_REPLY_UNAVAILABLE',503);
 const reader=response.body.getReader(),chunks=[];let size=0;
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>65536){await reader.cancel();requireThat(false,'NATIVE_RPC_REPLY_TOO_LARGE',503);}chunks.push(value);}}
 finally{reader.releaseLock();}
 const raw=new Uint8Array(size);let offset=0;for(const c of chunks){raw.set(c,offset);offset+=c.length;}return strictJSON(raw,{maxBytes:65536});
}
export async function nativeDomainCommand(runtime,cap,{command,input,operationId=crypto.randomUUID(),resource=null}){
 requireThat(runtime.app==='studio'&&commands.has(command)&&uuid(operationId)&&input&&typeof input==='object'&&!Array.isArray(input),'NATIVE_RPC_COMMAND_REQUIRED',403);
 const trusted=runtime.businessCapability(cap);
 requireThat(typeof runtime.native.businessAuthority==='function','NATIVE_RPC_AUTHORITY_PROJECTION_REQUIRED',503);
 const authority=await runtime.native.businessAuthority(trusted.rights,{command,input,resource,binding:trusted.binding});
 const now=runtime.clock(),signer=nativeRPCSigner(runtime,command,now),expiresAt=Math.min(now+60,trusted.deadline,trusted.binding.s_exp);
 requireThat(expiresAt>now,'NATIVE_RPC_LEASE_EXPIRED',401);
 const body={schema:2,env:runtime.config.env,sourceApp:'studio',targetApp:'academy',operationId,issuedAt:now,expiresAt,binding:trusted.binding,rightsHash:await digest(trusted.rights),authority,command,input,resource};
 const encoded=canonical(body);requireThat(bytes(encoded).length<=65536,'NATIVE_RPC_SCOPE_PARTITION_REQUIRED',503);
 const nonce=opaque(),packet={purpose,method:'POST',path:command,env:runtime.config.env,sourceApp:'studio',targetApp:'academy',keyId:signer.kid,issuedAt:now,nonce,bodyDigest:await digest(body)};
 const headers={'Content-Type':'application/json','X-UAA-Native-Key':signer.kid,'X-UAA-Native-Time':String(now),'X-UAA-Native-Nonce':nonce,'X-UAA-Native-MAC':b64u(await hmac(signer.key,canonical(packet)))};
 // Writes additionally recheck the owning child tuple before entering the
 // source-owned business transaction. No unrelated V1 session is fabricated.
 if(command.endsWith('/identity')){const guard=runtime.writeGuard(cap,{sensitive:true});await runtime.store.batch([...guard.before,...guard.after]);}
 const peer=runtime.env.UAA_V2_PEERS?.academy,transport=peer?.fetch?peer.fetch.bind(peer):globalThis.fetch;
 requireThat(typeof transport==='function','NATIVE_RPC_TRANSPORT_UNAVAILABLE',503);
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),Math.min(10000,(expiresAt-now)*1000));
 try{
  const response=await transport(new Request(ORIGINS.academy+command,{method:'POST',headers,body:encoded,redirect:'manual',signal:controller.signal}));
  requireThat(response instanceof Response&&!response.redirected&&(response.status<300||response.status>=400),'NATIVE_RPC_REPLY_UNAVAILABLE',503);
  const result=await readReply(response);
  if(!response.ok){const code=typeof result.code==='string'&&/^[A-Z][A-Z0-9_]{0,80}$/.test(result.code)?result.code:'NATIVE_RPC_UNAVAILABLE';requireThat(false,code,response.status>=500?503:response.status);}
  runtime.assertCapability(cap);return result;
 }catch(error){if(error.code)throw error;requireThat(false,'NATIVE_RPC_TRANSPORT_UNAVAILABLE',503);}
 finally{clearTimeout(timer);}
}
export const nativeRPCBoundary=Object.freeze({purpose,commands:[...commands],authority:'Exact validated cached scope can only be narrowed by fresh source-owned business checks. RPC is not an auth checkpoint or a V1 session.',retry:'No automatic business replay after an uncertain result.'});
