import {bytes,canonical,strictJSON,exact,requireThat,safeInt,uuid,ascii} from './codec.mjs';
import {serviceHeaders,authenticateService,receiveBatch} from './events.mjs';
import {ORIGINS} from './tokens.mjs';
import {runtimeServices} from './runtime-service.mjs';

const peers=new WeakMap(),paths=new Set(['transactions','redeem','events','reconcile','incidents','logout'].map(v=>'/internal/auth/v2/'+v));
const child=app=>app==='studio'||app==='hifz';
const direction=(path,source,target)=>path.endsWith('/events')?source==='academy'&&child(target):child(source)&&target==='academy';
export const servicePeer=request=>peers.get(request)??null;
export function serviceSigner(runtime,{sourceApp=runtime.app,targetApp,path}){
 const entries=[...runtime.settings.serviceKeys.values()].filter(k=>k.env===runtime.config.env&&k.sourceApp===sourceApp&&k.targetApp===targetApp&&k.paths.includes(path));
 const selected=runtime.settings.raw.serviceSigningKids?.[targetApp]?.[path];
 const key=selected?entries.find(k=>k.kid===selected):entries.length===1?entries[0]:null;
 requireThat(key&&ascii(key.kid,64),'SERVICE_SIGNER_NOT_CONFIGURED',503);return key;
}
async function boundedBody(source,{limit=65536,timeoutMs=10000}={}){
 const reader=source.body?.getReader();requireThat(reader,'MISSING_SERVICE_BODY',400);let count=0,chunks=[],timer;
 const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>{reader.cancel().catch(()=>{});reject(Object.assign(new Error('SERVICE_BODY_TIMEOUT'),{code:'SERVICE_BODY_TIMEOUT',status:408}));},timeoutMs);});
 try{for(;;){const part=await Promise.race([reader.read(),timeout]);if(part.done)break;count+=part.value.byteLength;if(count>limit){await reader.cancel();requireThat(false,'BODY_TOO_LARGE',413);}chunks.push(part.value);}}
 finally{clearTimeout(timer);reader.releaseLock();}
 const raw=new Uint8Array(count);let at=0;for(const part of chunks){raw.set(part,at);at+=part.length;}return raw;
}
const response=(value,headers={})=>new Response(typeof value==='string'?value:canonical(value),{status:200,headers:{'Content-Type':'application/json','Cache-Control':'private, no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',...headers}});
export async function handleServiceHTTP(runtime,request,ctx){
 const url=new URL(request.url),path=url.pathname;
 requireThat(paths.has(path),'UNKNOWN_SERVICE_PATH',404);requireThat(request.method==='POST','METHOD_NOT_ALLOWED',405);
 requireThat(!request.headers.has('Origin')&&!request.headers.has('Cookie'),'SERVICE_TRANSPORT_ONLY',401);
 requireThat(/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('Content-Type')||''),'JSON_SERVICE_BODY_REQUIRED',415);
 const raw=await boundedBody(request),now=runtime.clock();requireThat(safeInt(now),'SERVICE_CLOCK_UNAVAILABLE',503);
 const peer=await authenticateService({request,body:raw,config:{...runtime.config,serviceOrigin:runtime.config.origin},registry:runtime.settings.serviceKeys,store:runtime.store,now});
 requireThat(direction(path,peer.sourceApp,peer.targetApp),'SERVICE_DIRECTION_DENIED',403);
 peers.set(request,Object.freeze({sourceApp:peer.sourceApp,targetApp:peer.targetApp,env:peer.env,path,keyId:peer.kid}));
 const body=strictJSON(raw);
 if(path.endsWith('/transactions')){
  exact(body,['tx','purpose','targetApp','expected','stateHash','challenge','callback','returnTo',...(body&&Object.hasOwn(body,'expiresAt')?['expiresAt']:[])]);
  requireThat(runtime.app==='academy'&&body.targetApp===peer.sourceApp,'CEREMONY_SERVICE_DIRECTION',403);
  const ceremonies=runtime.getCeremonies?await runtime.getCeremonies():await runtime.ceremonies;requireThat(ceremonies?.register,'CEREMONY_SERVICE_UNAVAILABLE',503);
  return response(await ceremonies.register({request,...body}));
 }
 if(path.endsWith('/redeem')){
  exact(body,['tx','targetApp','purpose','operationId','code','verifier']);
  requireThat(runtime.app==='academy'&&body.targetApp===peer.sourceApp,'CEREMONY_SERVICE_DIRECTION',403);
  const ceremonies=runtime.getCeremonies?await runtime.getCeremonies():await runtime.ceremonies;requireThat(ceremonies?.redeem,'CEREMONY_SERVICE_UNAVAILABLE',503);
  return response(await ceremonies.redeem({request,...body}));
 }
 const services=await runtimeServices(runtime);
 if(path.endsWith('/events'))return response(await receiveBatch({body:raw,config:runtime.config,store:runtime.store,...await services.eventOptions(peer)}));
 if(path.endsWith('/reconcile')){
  const signer=serviceSigner(runtime,{targetApp:peer.sourceApp,path});
  const reply=await services.reconcileOwner(body,peer),encoded=typeof reply==='string'?reply:canonical(reply);
  requireThat(bytes(encoded).length<=65536&&canonical(strictJSON(encoded))===encoded,'INVALID_RECONCILE_REPLY',503);
  const headers=await serviceHeaders({keyId:signer.kid,key:signer.key,path,env:runtime.config.env,sourceApp:runtime.app,targetApp:peer.sourceApp,now:runtime.clock(),body:bytes(encoded)});
  return response(encoded,headers);
 }
 return response(await services.acceptReport(body,peer,{kind:path.endsWith('/logout')?'logout':'incidents'}));
}
export async function serviceFetch(runtime,{targetApp,path,body,operationId}){
 requireThat(ORIGINS[targetApp]&&paths.has(path)&&direction(path,runtime.app,targetApp)&&uuid(operationId),'INVALID_SERVICE_OPERATION',400);
 if(Object.hasOwn(body??{},'operationId'))requireThat(body.operationId===operationId,'SERVICE_OPERATION_CONFLICT',409);
 const encoded=canonical(body);requireThat(bytes(encoded).length<=65536,'BODY_TOO_LARGE',413);
 const signer=serviceSigner(runtime,{targetApp,path}),headers=await serviceHeaders({keyId:signer.kid,key:signer.key,path,env:runtime.config.env,sourceApp:runtime.app,targetApp,now:runtime.clock(),body:bytes(encoded)});
 headers['Content-Type']='application/json';headers['Cache-Control']='no-store';
 if(path.endsWith('/reconcile'))await (await runtimeServices(runtime)).registerReconcileRequest(body);
 const binding=runtime.env.UAA_V2_PEERS?.[targetApp];requireThat(binding===undefined||typeof binding.fetch==='function','SERVICE_PEER_BINDING_INVALID',503);
 const transport=binding?binding.fetch.bind(binding):globalThis.fetch;requireThat(typeof transport==='function','SERVICE_TRANSPORT_UNAVAILABLE',503);
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort('SERVICE_DEADLINE'),10000);
 let result,raw;
 try{result=await transport(new Request(ORIGINS[targetApp]+path,{method:'POST',headers,body:encoded,redirect:'manual',signal:controller.signal}));requireThat(result instanceof Response&&!result.redirected&&result.ok,'SERVICE_REPLY_UNAVAILABLE',503);raw=await boundedBody(result);}
 catch(error){if(error?.code)throw error;throw Object.assign(new Error('SERVICE_TRANSPORT_UNAVAILABLE'),{code:'SERVICE_TRANSPORT_UNAVAILABLE',status:503});}
 finally{clearTimeout(timer);}
 if(path.endsWith('/reconcile')){
  const replyRequest=new Request(ORIGINS[runtime.app]+path,{method:'POST',headers:result.headers,body:raw});
  const peer=await authenticateService({request:replyRequest,body:raw,config:{...runtime.config,serviceOrigin:runtime.config.origin},registry:runtime.settings.serviceKeys,store:runtime.store,now:runtime.clock()});
  requireThat(peer.sourceApp===targetApp&&peer.targetApp===runtime.app,'RECONCILE_REPLY_OWNER_CONFLICT',401);
  const services=await runtimeServices(runtime);await services.receiveReconcileReply(body,raw,peer);
 }
 return strictJSON(raw);
}
export const serviceHTTPBoundary=Object.freeze({requests:'Closed C19 directions, fixed peer origins, exact bytes HMAC/nonces, strict schemas, bounded time/body and no automatic retry.',reconciliation:'Responses have fresh owner-to-recipient authentication and request-bound durable verification; a source watermark is never coverage.',credentials:'No PIN hashes, user cookies, payloads or service secrets are logged.'});
