import {allowedReturn} from './return-routes.mjs';
import {canonical,requireThat,uuid,unb64u,digest,strictJSON,bytes} from './codec.mjs';
import {LocalCeremonyConsumer,digestState} from './ceremonies.mjs';
import {HTTPTransactions} from './http-transactions.mjs';
import {selector,requireExpected} from './http-context.mjs';
import {childTransition} from './http-families.mjs';
import {serviceFetch} from './http-service.mjs';

const pendingAuth=new WeakMap();
async function installed(runtime,request){
 try{const c=await runtime.currentFamily(request);const f=await runtime.observeState(c.family);return ['REVOKED','EXPIRED'].includes(f.state)?null:{app:runtime.app,...JSON.parse(f.binding_json),fingerprint:c.fingerprint};}
 catch(error){if(error.code==='SESSION_ENDED')return null;throw error;}
}
async function consumer(runtime,request){
 return new LocalCeremonyConsumer({store:runtime.store,config:runtime.config,keys:runtime.settings.handoffKeys,clock:runtime.clock,policyMinutes:(await runtime.appControl()).inactivityMinutes,
  authoriseRequest:async(req,tx)=>{const auth=pendingAuth.get(req);return auth?.tx===tx?auth:null;},
  readInstalled:req=>installed(runtime,req),
  mappingGuard:claims=>runtime.native.mappingGuard(claims),
  prepareTransition:args=>childTransition(runtime,args),
  prepareAuthority:typeof runtime.native.ensureColdSourceAuthority==='function'?args=>runtime.native.ensureColdSourceAuthority({runtime,...args}):null
 });
}
export async function journeyBootstrap(runtime,request,body,current){
 requireThat(runtime.app!=='academy','CHILD_CEREMONY_ONLY',403);
 const transactions=new HTTPTransactions(runtime),context=current?selector(JSON.parse(current.family.binding_json),runtime.app):null;
 let row;
 if(body.purpose.endsWith('/finalize')){
  row=await transactions.get(body.tx);
  requireThat(row&&row.kind===body.purpose&&row.operation_id===body.observedOperationId&&row.status==='PENDING'&&runtime.clock()<row.expires_at,'BROWSER_TRANSACTION_EXPIRED',409);
  if(row.expected_json)requireExpected(context,JSON.parse(row.expected_json));else requireThat(!context,'OPERATION_SUPERSEDED',409);
 }else{
  if(body.purpose==='unlock/start')requireThat(current&&['LOCKED','ADMITTED_LOCKED'].includes(current.family.state),'UNLOCK_CONTEXT_REQUIRED',409);
  row=await transactions.create({kind:body.purpose,sub:context?.sub||null,expected:context,payload:{}});
 }
 const state=current?await runtime.stateDTO(current.family):{contractVersion:2,success:true,state:'SIGNED_OUT',context:null,serverNowMs:runtime.clock()*1000};
 return runtime.json({...state,...await transactions.dto(row,body.purpose)});
}
export async function startJourney(runtime,request,body,purpose){
 const transactions=new HTTPTransactions(runtime),auth=await transactions.verify(request,body,purpose+'/start');
 requireThat(/^[0-9a-f]{64}$/.test(body.stateHash),'INVALID_STATE_HASH',400);unb64u(body.challenge,32);
 requireThat(body.callback===runtime.config.origin+'/auth/v2/'+purpose+'/callback','UNREGISTERED_CALLBACK',400);
 requireThat(typeof body.returnTo==='string'&&body.returnTo.startsWith('/')&&!body.returnTo.startsWith('//')&&!/[#\r\n]/.test(body.returnTo),'UNREGISTERED_RETURN',400);
 const returnTo=runtime.config.origin+body.returnTo;
 requireThat(allowedReturn(runtime.settings.callbacks,runtime.app,returnTo),'UNREGISTERED_RETURN',400);
 const tx=crypto.randomUUID(),operationId=crypto.randomUUID(),expiresAt=runtime.clock()+300,expected=auth.row.expected_json&&JSON.parse(auth.row.expected_json);
 const stateHash=body.stateHash;
 const final=await transactions.create({kind:purpose+'/finalize',sub:expected?.sub||null,expected,tx,operationId,expiresAt,payload:{purpose,stateHash,challenge:body.challenge,returnTo:body.returnTo}});
 const finalProof=await transactions.proof(final);
 pendingAuth.set(request,{tx,csrfHash:await digest(finalProof)});
 const local=await consumer(runtime,request);
 await local.registerPending({request,tx,purpose,expected,operationId,expiresAt});
 const reply=await serviceFetch(runtime,{targetApp:'academy',path:'/internal/auth/v2/transactions',operationId:auth.row.operation_id,body:{tx,purpose,targetApp:runtime.app,expected,stateHash,challenge:body.challenge,callback:body.callback,returnTo,expiresAt}});
 requireThat(reply.tx===tx&&reply.expiresAt<=expiresAt,'CEREMONY_SERVICE_CONFLICT',503);
 const [g,c]=transactions.guard(auth.row);
 await runtime.store.batch([g,runtime.store.stmt("UPDATE jwt_v2_http_transactions SET status='COMMITTED',result_json=? WHERE tx=?",canonical({tx,operationId}),auth.row.tx),c]);
 return runtime.json({success:true,tx,operationId,expiresAtMs:Math.min(expiresAt,reply.expiresAt)*1000,navigateUrl:runtime.config.academyOrigin+'/auth/v2/'+purpose+'?tx='+tx});
}
export async function finalizeJourney(runtime,request,body,purpose){
 const auth=await new HTTPTransactions(runtime).verify(request,body,purpose+'/finalize',{allowCommitted:true});
 if(auth.row.status==='COMMITTED')return runtime.json({success:true,state:'UNCONFIRMED',context:null,outcome:'SUPERSEDED',operationId:body.operationId});
 unb64u(body.code,32);unb64u(body.verifier,32);
 const reply=await serviceFetch(runtime,{targetApp:'academy',path:'/internal/auth/v2/redeem',operationId:body.operationId,body:{tx:auth.row.tx,targetApp:runtime.app,purpose,operationId:body.operationId,code:body.code,verifier:body.verifier}});
 requireThat(reply.tx===body.tx&&reply.operationId===body.operationId&&typeof reply.proof==='string','CEREMONY_SERVICE_CONFLICT',503);
 // The consumer verifies the signed grant before any source installation or
 // native identity mapping. No unverified JWT payload selects native authority.
 pendingAuth.set(request,{tx:body.tx,csrfHash:auth.csrfHash});
 const local=await consumer(runtime,request),result=await local.consume({request,tx:body.tx,operationId:body.operationId,proof:reply.proof});
 if(!result.winner)return runtime.json({success:true,state:'UNCONFIRMED',context:null,outcome:'SUPERSEDED',operationId:body.operationId});
 // The atomic consume receipt wins before a secret can leave this process.
 await runtime.store.stmt("UPDATE jwt_v2_http_transactions SET status='COMMITTED',result_json=? WHERE tx=? AND status='PENDING'",canonical(result.result),body.tx).run();
 let priorPending=false;if(purpose==='admission'){
  const original=auth.row.expected_json&&JSON.parse(auth.row.expected_json);
  if(original&&original.sid!==result.result.sid)try{await runtime.publishFamily(original.sid);}catch{priorPending=true;}
 }
 const publication=await runtime.publishWinningFamily(result.result.sid,{initial:purpose==='admission'});if(priorPending)publication.cachePublication='PENDING';
 const family=await runtime.store.family(result.result.sid),payload=JSON.parse(auth.row.payload_json);
 return runtime.cookieResponse(family,result.credentials.refresh,{...await runtime.stateDTO(family),operationId:body.operationId,outcome:'COMMITTED',returnTo:payload.returnTo,...publication});
}
const escaped=s=>s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;');
export function callbackForm({callback,tx,stateHash,code}){
 const destination=new URL(callback);requireThat(destination.protocol==='https:'&&!destination.search&&!destination.hash,'UNREGISTERED_CALLBACK',503);
 // User activates an ordinary POST form; no credential appears in a URL.
 const html='<!doctype html><html><meta charset="utf-8"><meta name="referrer" content="strict-origin"><title>Continue sign-in</title><form method="post" action="'+escaped(callback)+'">'+Object.entries({tx,stateHash,code}).map(([name,value])=>'<input type="hidden" name="'+name+'" value="'+escaped(value)+'">').join('')+'<button type="submit">Continue</button></form><script type="module" src="/auth/v2/post.mjs"></script></html>';
 return new Response(html,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'private, no-store','Referrer-Policy':'strict-origin','Content-Security-Policy':"default-src 'none'; script-src 'self'; form-action "+destination.origin+"; base-uri 'none'; frame-ancestors 'none'"}});
}
export async function callbackRelay(runtime,request,purpose){
 requireThat(runtime.app!=='academy'&&request.method==='POST'&&request.headers.get('Origin')===runtime.config.academyOrigin,'INVALID_CALLBACK_ORIGIN',403);
 requireThat(/^application\/x-www-form-urlencoded(?:;|$)/i.test(request.headers.get('Content-Type')||''),'CALLBACK_FORM_REQUIRED',415);
 const raw=await request.text();requireThat(bytes(raw).length<=4096,'BODY_TOO_LARGE',413);
 const form=new URLSearchParams(raw),names=[...form.keys()];
 requireThat(names.length===3&&new Set(names).size===3&&names.every(n=>['tx','stateHash','code'].includes(n)),'INVALID_CALLBACK_FORM',400);
 const value=Object.fromEntries(form);requireThat(uuid(value.tx),'INVALID_BROWSER_TRANSACTION',400);requireThat(/^[0-9a-f]{64}$/.test(value.stateHash),'INVALID_STATE_HASH',400);unb64u(value.code,32);
 const row=await new HTTPTransactions(runtime).get(value.tx);
 requireThat(row?.kind===purpose+'/finalize'&&row.status==='PENDING'&&runtime.clock()<row.expires_at,'BROWSER_TRANSACTION_EXPIRED',409);
 const data=canonical({...value,purpose}).replaceAll('<','\\u003c');
 return new Response('<!doctype html><html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Completing sign-in</title><p id="status">Completing sign-in…</p><script id="callback" type="application/json">'+data+'</script><script type="module" src="/auth/v2/relay.mjs"></script></html>',{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'private, no-store','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"}});
}
export function relayModule(runtime){
 const modulePath=runtime.app==='hifz'?'/js/v111/browser-session.mjs':'/v111/browser-session.mjs';
 const source="import {createBrowserSession} from '"+modulePath+"';\nconst payload=JSON.parse(document.getElementById('callback').textContent);const session=createBrowserSession({app:"+JSON.stringify(runtime.app)+",origin:location.origin,academyOrigin:"+JSON.stringify(runtime.config.academyOrigin)+",fetch:globalThis.fetch.bind(globalThis),crypto:globalThis.crypto,sessionStorage:globalThis.sessionStorage,locks:globalThis.navigator.locks,indexedDB:globalThis.indexedDB,BroadcastChannel:globalThis.BroadcastChannel,onMask:()=>{}});try{const result=await session.completeCallback(payload);history.replaceState(null,'',result.returnTo);location.replace(result.returnTo);}catch(error){document.getElementById('status').textContent='Sign-in could not be confirmed. Return to the app to try again.';}\n";
 return new Response(source,{headers:{'Content-Type':'text/javascript; charset=utf-8','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'}});
}
