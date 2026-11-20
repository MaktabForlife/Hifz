import {canonical,requireThat,uuid} from './codec.mjs';
import {verifyBootstrap,browserBody} from './browser-security.mjs';
import {clearCookies} from './tokens.mjs';
import {selector,expectedContext,requireExpected} from './http-context.mjs';
import {HTTPTransactions} from './http-transactions.mjs';
import {rotateFamily,browserOutboxPlan} from './http-families.mjs';
import {pinBootstrap,submitPIN} from './http-pin.mjs';
import {journeyBootstrap,startJourney,finalizeJourney,callbackRelay,relayModule} from './http-journeys.mjs';
import {restrictionPlan} from './publication.mjs';
const STABLE='app sub sid psid bsid bv ce ae le'.split(' ');
const sameStable=(a,b)=>a&&b&&STABLE.every(k=>a[k]===b[k]);
function clear(runtime,response){for(const cookie of clearCookies(runtime.app))response.headers.append('Set-Cookie',cookie);return response;}
async function current(runtime,request,{spent=false}={}){try{return await runtime.currentFamily(request,{allowSpent:spent});}catch(error){if(error.code==='SESSION_ENDED')return null;throw error;}}
async function bootstrap(runtime,request,body){
 const purpose=body.purpose||'refresh';requireThat(typeof purpose==='string','INVALID_AUTH_PURPOSE',400);
 if(['pin','pin/setup'].includes(purpose))return pinBootstrap(runtime,request,body);
 let c=await current(runtime,request,{spent:true});
 if(c?.historical)return runtime.json({success:true,state:'SIGNED_OUT',context:null,outcome:'SUPERSEDED'});
 if(c){c.family=await runtime.observeState(c.family);if(['REVOKED','EXPIRED'].includes(c.family.state))c=null;}
 const supplied=expectedContext(request,body),context=c?selector(JSON.parse(c.family.binding_json),runtime.app):null;
 if(supplied&&context&&!sameStable(supplied,context))return runtime.json({success:true,state:'SIGNED_OUT',context:null,outcome:'SUPERSEDED'});
 if(purpose==='status'&&!c)return runtime.json({success:true,state:'SIGNED_OUT',context:null,outcome:'UNCONFIRMED'});
 if(['admission/start','admission/finalize','unlock/start','unlock/finalize'].includes(purpose))return journeyBootstrap(runtime,request,body,c);
 if(purpose==='admission/proceed'){const {proceedAcademy}=await import('./http-shells.mjs');return proceedAcademy(runtime,request,body,c);}
 if(purpose==='browser-clear'&&!c){const transactions=new HTTPTransactions(runtime),row=await transactions.create({kind:'browser-clear',payload:{}});return runtime.json({success:true,state:'SIGNED_OUT',context:null,...await transactions.dto(row)});}
 if(!c)return runtime.json({success:true,state:'SIGNED_OUT',context:null});
 return runtime.json(await runtime.stateDTO(c.family,{purpose}));
}
async function status(runtime,request,body){
 requireThat(uuid(body.observedOperationId),'INVALID_OBSERVED_OPERATION',400);
 const c=await current(runtime,request,{spent:true});
 if(!c||c.historical||!c.family||['REVOKED','EXPIRED'].includes(c.family.state)||runtime.clock()>=c.family.s_exp)return runtime.json({success:true,state:'SIGNED_OUT',context:null,outcome:'UNCONFIRMED',operationId:body.operationId});
 const context=selector(JSON.parse(c.family.binding_json),runtime.app);requireExpected(context,expectedContext(request,body));
 await runtime.intents.verify(request,{operationId:body.operationId,purpose:'status',context});
 if(body.historicalContext)requireThat(sameStable(context,body.historicalContext),'STATUS_CONTEXT_CONFLICT',409);
 const intent=await runtime.store.first('SELECT * FROM jwt_v2_intents WHERE intent_id=?',body.observedOperationId);
 const transaction=await runtime.store.first('SELECT * FROM jwt_v2_http_transactions WHERE operation_id=?',body.observedOperationId);
 const consumed=await runtime.store.first('SELECT * FROM jwt_v2_ceremony_consumed WHERE operation_id=?',body.observedOperationId);
 let committed=null;
 if(intent?.state==='COMMITTED')committed=intent.result_json&&JSON.parse(intent.result_json);
 if(transaction?.status==='COMMITTED')committed=transaction.result_json&&JSON.parse(transaction.result_json);
 if(consumed)committed=JSON.parse(consumed.result_json);
 const installed=committed?.sid===c.family.sid&&(committed.sv===undefined||committed.sv===c.family.sv)&&['UNLOCKED','LOCKED','ADMITTED_LOCKED'].includes(c.family.state);
 return runtime.json({...await runtime.stateDTO(c.family),operationId:body.operationId,outcome:installed?'INSTALLED_CURRENT':intent||transaction||consumed?'SUPERSEDED':'UNCONFIRMED'});
}
async function exit(runtime,request,body,kind){
 const c=await current(runtime,request,{spent:true});requireThat(c&&!c.historical&&c.family,'CURRENT_REFRESH_REQUIRED',401);
 const f=c.family,context=selector(JSON.parse(f.binding_json),runtime.app);requireExpected(context,expectedContext(request,body));await runtime.intents.verify(request,{operationId:body.operationId,purpose:kind,context});
 requireThat(runtime.clock()<f.s_exp&&!['REVOKED','EXPIRED'].includes(f.state),'SESSION_ENDED',401);
 let outcome,canonicalAccepted=false,globalConfirmed=false;
 if(kind==='logout'&&runtime.app==='academy'){
  const result=await runtime.store.acceptCutoff({sub:f.sub,ce:f.ce,ae:f.ae,operationId:body.operationId,kind:'VOLUNTARY_LOGOUT',now:runtime.clock()});requireThat(['ACCEPTED','ALREADY_COVERED'].includes(result.status),'LOGOUT_RECONCILIATION_REQUIRED',503);
  requireThat(await runtime.publishPending(result.receipt),'LOGOUT_PUBLICATION_PENDING',503);outcome='ACCEPTED_PENDING';canonicalAccepted=true;
 }else if(kind==='logout'){
  const {runtimeServices}=await import('./runtime-service.mjs'),services=await runtimeServices(runtime),result=await services.queueReport({binding:JSON.parse(f.binding_json),kind:'logout',operationId:body.operationId,now:runtime.clock()});outcome=result?.outcome||'GLOBAL_UNCONFIRMED';canonicalAccepted=result?.canonicalAccepted===true;globalConfirmed=result?.globalConfirmed===true;
 }else{
  const now=runtime.clock(),target=runtime.app==='academy'?{type:'browser',bsid:f.bsid,maxBv:f.bv}:{type:'parent',sub:f.sub,psid:f.psid,bsid:f.bsid,bv:f.bv,ce:f.ce,ae:f.ae};
  const plan=await restrictionPlan(runtime.store,{workId:body.operationId,target,now,sub:f.sub}),[g,cl]=runtime.store.guard("SELECT 1 FROM jwt_v2_families WHERE sid=? AND fingerprint=? AND binding_json=? AND state NOT IN('REVOKED','EXPIRED')",[f.sid,c.fingerprint,f.binding_json]);
  await runtime.store.batch([g,...plan,...(runtime.app==='academy'?[runtime.store.stmt('UPDATE jwt_v2_browsers SET cancelled_through=max(cancelled_through,?) WHERE bsid=?',f.bv,f.bsid),...await browserOutboxPlan(runtime,{target,sub:f.sub,operationId:body.operationId,now})]:[]),runtime.store.stmt("UPDATE jwt_v2_http_transactions SET status='CANCELLED' WHERE sub=? AND status='PENDING'",f.sub),cl]);
  requireThat(await runtime.publishPending(body.operationId),'SWITCH_PUBLICATION_PENDING',503);outcome=runtime.app==='academy'?'BROWSER_CANCELLED':'LOCAL_SIGNED_OUT';
 }
 return clear(runtime,runtime.json({success:true,state:'SIGNED_OUT',context:null,outcome,canonicalAccepted,globalConfirmed,operationId:body.operationId,...(kind==='switch'?{navigateUrl:runtime.config.academyOrigin+'/auth/v2/signin?switch=1'}:{})}));
}
export async function handleAuthHTTP(runtime,request,ctx){
 const url=new URL(request.url),path=url.pathname;
 if(path.startsWith('/internal/auth/v2/')){const {handleServiceHTTP}=await import('./http-service.mjs');return handleServiceHTTP(runtime,request,ctx);}
 if(request.method==='GET'){
  if(path==='/auth/v2/relay.mjs')return relayModule(runtime);
  if(path==='/auth/v2/browser-session.mjs'||path==='/auth/v2/browser-drafts.mjs'){
   requireThat(['GET','HEAD'].includes(request.method),'METHOD_NOT_ALLOWED',405);
   const assets=await import('./browser-assets.mjs'),source=path.endsWith('/browser-session.mjs')?assets.browserSessionSource:assets.browserDraftsSource;
   return new Response(request.method==='HEAD'?null:source,{headers:{'Content-Type':'text/javascript','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'}});
  }
  if(path==='/auth/v2/post.mjs')return new Response('document.querySelector("form")?.requestSubmit();',{headers:{'Content-Type':'text/javascript','Cache-Control':'private, no-store'}});
  const {authShell}=await import('./http-shells.mjs');return authShell(runtime,request);
 }
 requireThat(request.method==='POST'&&!url.search,'METHOD_NOT_ALLOWED',405);
 for(const purpose of ['admission','unlock'])if(path==='/auth/v2/'+purpose+'/callback')return callbackRelay(runtime,request,purpose);
 verifyBootstrap(request,runtime.config);requireThat(/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('Content-Type')||''),'JSON_BODY_REQUIRED',415);
 const body=await browserBody(request);requireThat(body&&typeof body==='object'&&!Array.isArray(body),'INVALID_AUTH_BODY',400);
 if(path==='/auth/v2/bootstrap')return bootstrap(runtime,request,body);
 if(path==='/auth/v2/admission/start'&&runtime.app==='academy'){const {continueAcademy}=await import('./http-shells.mjs');return continueAcademy(runtime,request,body);}
 if(path==='/auth/v2/refresh')return rotateFamily(runtime,request,body);
 if(path==='/auth/v2/status')return status(runtime,request,body);
 if(path==='/auth/v2/pin')return submitPIN(runtime,request,body);
 if(path==='/auth/v2/pin/setup')return submitPIN(runtime,request,body,{setup:true});
 if(path==='/auth/v2/logout'||path==='/auth/v2/switch')return exit(runtime,request,body,path.split('/').at(-1));
 for(const purpose of ['admission','unlock']){if(path==='/auth/v2/'+purpose+'/start')return startJourney(runtime,request,body,purpose);if(path==='/auth/v2/'+purpose+'/finalize')return finalizeJourney(runtime,request,body,purpose);}
 if(path==='/auth/v2/draft-key'){const {releaseDraftKey}=await import('./http-drafts.mjs');return releaseDraftKey(runtime,request,body);}
 if(path==='/auth/v2/browser-clear'){
  const c=await current(runtime,request);
  if(c){const context=selector(JSON.parse(c.family.binding_json),runtime.app);requireExpected(context,expectedContext(request,body));await runtime.intents.verify(request,{operationId:body.operationId,purpose:'browser-clear',context});}
  else {const transactions=new HTTPTransactions(runtime),auth=await transactions.verify(request,body,'browser-clear'),[g,cl]=transactions.guard(auth.row);await runtime.store.batch([g,runtime.store.stmt("UPDATE jwt_v2_http_transactions SET status='COMMITTED' WHERE tx=?",auth.row.tx),cl]);}
  return clear(runtime,runtime.json({success:true,state:'SIGNED_OUT',context:null,operationId:body.operationId,outcome:'LOCAL_COOKIES_CLEARED'}));
 }
 requireThat(false,'UNKNOWN_AUTH_PATH',404);
}
