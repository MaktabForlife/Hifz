import {canonical,digest,equal,exact,requireThat,safeInt,strictJSON,unb64u} from './codec.mjs';
import {allowedReturn} from './return-routes.mjs';
import {expectedContext,requireExpected,selector} from './http-context.mjs';
import {HTTPTransactions} from './http-transactions.mjs';
import {admissionBarrier,s256,digestState} from './ceremonies.mjs';
import {childTransition} from './http-families.mjs';
import {sharedPredecessor,sharedRetirementPlan,publishSharedRetirements,isSharedRetired,hasSharedPredecessor} from './shared-entry-recovery.mjs';
import {readCookies,readSharedAcademyAccess,verifyToken} from './tokens.mjs';
import {admissionFloorGuard} from './publication.mjs';
import {issuanceFloorGuard} from './issuance-floors.mjs';
import {assertCaptureReceipt} from './capture-receipt.mjs';
import {familyPolicyRegistrationPlan} from './policy.mjs';

import {serviceFetch} from './http-service.mjs';
import {accountGate} from './signin-account-proof.mjs';
import {sharedEntryClientSource} from './shared-entry-client-source.mjs';

const purpose='shared-entry';
const destinations={tafseer:'/studio/?view=collections&collection=tafseer',mothers:'/studio/?classroom=mothers',courses:'/studio/?view=collections&collection=courses',hifz:'/'};

// The current Academy baseline comes from verified account and stream evidence.
// Presenting a shared access cookie cannot update that baseline.
export {sharedEntrySchemaSQL} from './shared-account-baselines.mjs';

function configuration(runtime){
 const mode=runtime.settings.raw.sharedChildEntry;
 requireThat(['studio','hifz'].includes(runtime.app)&&mode&&runtime.settings.sharedAcademy,'UNKNOWN_AUTH_PATH',404);
 requireThat(typeof mode.ownerEpoch==='string'&&safeInt(mode.notBefore,1)&&runtime.settings.raw.serviceStreams?.some(entry=>entry.sourceApp==='academy'&&entry.targetApp===runtime.app&&entry.stream==='account-security'&&entry.ownerEpoch===mode.ownerEpoch),'SHARED_ENTRY_CONFIGURATION_REQUIRED',503);
 return mode;
}

async function currentChild(runtime,request){
 try{
  const current=await runtime.currentFamily(request),family=await runtime.observeState(current.family);
  return ['REVOKED','EXPIRED'].includes(family.state)?null:family;
 }catch(error){if(error.code==='SESSION_ENDED')return null;throw error;}
}

// An access-only request may still have usable local authority. It cannot
 // claim loss of both credentials or bypass the installed-holder check.
async function requireNoUnpairedAuthority(runtime,request){
 if(readCookies(request.headers.get('Cookie'),runtime.app).access){
  const check=new Request(runtime.config.origin+'/auth/v2/shared-entry',{headers:{Cookie:request.headers.get('Cookie')}});
  let eligible=false;
  try{eligible=Boolean(await runtime.authorise(check,{action:'read'}));}
  catch(error){if(![401,423].includes(error.status))throw error;}
  requireThat(!eligible,'SHARED_CHILD_REFRESH_MISSING',409);
 }
}

async function academyIdentity(runtime,request,appControl,mode){
 const token=readSharedAcademyAccess(request.headers.get('Cookie')),registry=runtime.settings.sharedAcademy;
 if(!token)return null;
 requireThat(appControl.sharedAcademyRegistryRevision===registry.revision&&Array.isArray(appControl.withdrawnSharedAcademyKids),'CHILD_AUTHORITY_PENDING',503);
 try{
  const claims=await verifyToken(token,{profile:'shared',config:runtime.config,keys:registry.keys,withdrawn:new Set(appControl.withdrawnSharedAcademyKids),now:runtime.clock(),idleUntil:Number.MAX_SAFE_INTEGER,initial:'PRECHECK'});
  if(claims.s_iat<mode.notBefore)return null;
  const {kid}=strictJSON(unb64u(token.split('.')[0]),{maxBytes:512});
  return {claims,kid};
 }catch(error){if(error.status>=500)throw error;return null;}
}

export async function startSharedEntry(runtime,request,body){
 const mode=configuration(runtime);
 exact(body,['destination','challenge','expectedContext']);
 unb64u(body.challenge,32);
 requireThat(Object.hasOwn(destinations,body.destination)&&(runtime.app==='hifz')===(body.destination==='hifz'),'UNREGISTERED_RETURN',400);
 const returnTo=destinations[body.destination];
 requireThat(allowedReturn(runtime.settings.callbacks,runtime.app,runtime.config.origin+returnTo),'UNREGISTERED_RETURN',400);
 const current=await currentChild(runtime,request),context=current?selector(JSON.parse(current.binding_json),runtime.app):null;
 if(!current)await requireNoUnpairedAuthority(runtime,request);
 const expected=expectedContext(request,body);
 if(context)requireExpected(context,expected);else requireThat(expected===null,'OPERATION_SUPERSEDED',409);
 const identity=await academyIdentity(runtime,request,await runtime.appControl(),mode);
 const expiresAt=Math.min(runtime.clock()+300,identity?.claims.s_exp??Infinity,current?.s_exp??Infinity);
 const transactions=new HTTPTransactions(runtime);
 const row=await transactions.create({kind:purpose,sub:context?.sub||null,expected:context,expiresAt,payload:{returnTo,challenge:body.challenge}});
 return runtime.json({success:true,operationId:row.operation_id,expiresAtMs:row.expires_at*1000,...await transactions.dto(row)});
}

export function validateSharedChildSource(binding,source,mode){
 requireThat(binding.s_iat>=mode.notBefore&&source?.issuer==='https://ummabbadacademy.app'&&source.env==='production'
  &&['sub','psid','bsid','bv'].every(field=>source[field]===binding[field])&&typeof source.kid==='string','SESSION_ENDED',401);
}


export async function requireSharedChildRenewal(runtime,family){
 const mode=configuration(runtime),binding=JSON.parse(family.binding_json),source=JSON.parse(family.projection_json).sharedAcademyAdmission;
 validateSharedChildSource(binding,source,mode);
 const app=await runtime.appControl(),gate=accountGate(runtime,mode,binding);
 requireThat(app.sharedAcademyRegistryRevision===runtime.settings.sharedAcademy.revision&&!app.withdrawnSharedAcademyKids?.includes(source.kid)&&await runtime.store.first(gate.sql,...gate.args),'CHILD_AUTHORITY_PENDING',503);
 return gate;
}

export async function continueSharedBookmark(runtime,request,body){
 const mode=configuration(runtime);
 const hasMode=Object.hasOwn(body,'mode');
 exact(body,['tx','operationId','expectedContext','verifier','stateHash',...(hasMode?['mode']:[])]);
 const returnMode=hasMode?body.mode:'continue';
 requireThat(['continue','select','renew'].includes(returnMode),'UNREGISTERED_RETURN',400);
 const transactions=new HTTPTransactions(runtime),{row}=await transactions.verify(request,body,purpose);
 const payload=JSON.parse(row.payload_json);
 const current=await currentChild(runtime,request);
 const actual=current?selector(JSON.parse(current.binding_json),runtime.app):null;
 if(row.expected_json)requireExpected(actual,JSON.parse(row.expected_json));
 else requireThat(!current,'OPERATION_SUPERSEDED',409);
 const verified=await academyIdentity(runtime,request,await runtime.appControl(),mode);
 if(returnMode==='select'){
  const fields=['sub','psid','bsid','bv','ce','ae','s_iat','s_exp'];
  requireThat(current&&verified&&payload.accountChoice
   &&equal(await digest(fields.map(key=>verified.claims[key])),payload.accountChoice),'ACCOUNT_SELECTION_REQUIRED',409);
 }else if(returnMode==='renew'){
  requireThat(!current&&verified&&await hasSharedPredecessor(runtime.store,verified.claims),'OPERATION_SUPERSEDED',409);
 }else requireThat(!verified,'OPERATION_SUPERSEDED',409);
 requireThat(equal(await s256(body.verifier),payload.challenge)&&/^[0-9a-f]{64}$/.test(body.stateHash),'STATE_CONFLICT',403);
 requireThat(!payload.stateHash||payload.stateHash===body.stateHash&&payload.returnMode===returnMode,'STATE_CONFLICT',403);
 const [guard,clear]=runtime.store.guard("SELECT 1 FROM jwt_v2_http_transactions WHERE tx=? AND status='PENDING' AND expires_at>unixepoch() AND payload_json=?",
  [row.tx,row.payload_json]);
 await runtime.store.batch([guard,
  runtime.store.stmt("UPDATE jwt_v2_http_transactions SET payload_json=? WHERE tx=?",canonical({...payload,stateHash:body.stateHash,returnMode}),row.tx),
  clear]);
 const callback=runtime.config.origin+'/auth/v2/shared-entry/callback';
 const reply=await serviceFetch(runtime,{targetApp:'academy',path:'/internal/auth/v2/transactions',operationId:row.operation_id,
  body:{tx:row.tx,purpose:'shared-entry-return',targetApp:runtime.app,stateHash:body.stateHash,challenge:payload.challenge,callback,expiresAt:row.expires_at,...(returnMode==='continue'?{}:{mode:returnMode})}});
 requireThat(reply.success===true&&reply.tx===row.tx&&reply.expiresAt===row.expires_at,'CEREMONY_CONFLICT',409);
 return runtime.json({success:true,tx:row.tx,operationId:row.operation_id});
}

const relayHeaders={'Cache-Control':'private, no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff',
 'Content-Security-Policy':"default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"};

export async function sharedBookmarkCallback(runtime,request){
 configuration(runtime);
 requireThat(request.headers.get('Origin')===runtime.config.academyOrigin,'INVALID_CALLBACK_ORIGIN',403);
 requireThat(/^application\/x-www-form-urlencoded(?:;|$)/i.test(request.headers.get('Content-Type')||''),'CALLBACK_FORM_REQUIRED',415);
 const chunks=[],reader=request.body?.getReader();
 requireThat(reader,'CALLBACK_FORM_REQUIRED',400);
 let length=0;
 for(;;){
  const {value,done}=await reader.read();
  if(done)break;
  length+=value.length;
  if(length>512){await reader.cancel();requireThat(false,'BODY_TOO_LARGE',413);}
  chunks.push(...value);
 }
 const form=new URLSearchParams(new TextDecoder().decode(Uint8Array.from(chunks))),pairs=[...form];
 requireThat(pairs.length===2&&form.has('tx')&&form.has('state'),'INVALID_CALLBACK_FORM',400);
 const tx=form.get('tx'),state=form.get('state'),row=await new HTTPTransactions(runtime).get(tx);
 const payload=row?.payload_json&&JSON.parse(row.payload_json);
 requireThat(row?.kind===purpose&&payload?.stateHash&&equal(await digestState(state),payload.stateHash),'STATE_CONFLICT',403);
 return Response.json({success:true,tx,state,expired:runtime.clock()>=row.expires_at},{
  headers:{...relayHeaders,'Access-Control-Allow-Origin':runtime.config.academyOrigin,Vary:'Origin'}});
}

export function sharedBookmarkCallbackShell(runtime){
 configuration(runtime);
 return new Response('<!doctype html><meta charset="utf-8"><title>Opening programme</title><p id="status" role="status">Opening your programme…</p><a id="academy-link" href="https://ummabbadacademy.app/?workspace=learn" hidden>Open Academy</a><script type="module" src="/auth/v2/shared-entry/return.mjs"></script>',
  {headers:{...relayHeaders,'Content-Type':'text/html; charset=utf-8'}});
}

export function sharedBookmarkClient(runtime){
 configuration(runtime);
 const source="import {resumeChildEntry} from '/auth/v2/shared-entry-client.mjs';\n"
  +"const status=document.getElementById('status');const handled=await resumeChildEntry(status);\n"
  +"if(!handled)status.textContent='This sign-in could not be confirmed.';";
 return new Response(source,{headers:{...relayHeaders,'Content-Type':'text/javascript'}});
}

async function checkedSharedEntry(runtime,request,body,{allowConfirmation=false}={}){
 const mode=configuration(runtime),transactions=new HTTPTransactions(runtime);
 exact(body,['tx','operationId','expectedContext','verifier',...(Object.hasOwn(body,'returnState')?['returnState']:[]),...(allowConfirmation&&Object.hasOwn(body,'confirmAcademyAccount')?['confirmAcademyAccount']:[])]);
 if(Object.hasOwn(body,'confirmAcademyAccount'))requireThat(body.confirmAcademyAccount===true,'ACCOUNT_SELECTION_REQUIRED',409);
 const {row}=await transactions.verify(request,body,purpose,{allowCommitted:true});
 const payload=JSON.parse(row.payload_json);
 requireThat(equal(await s256(body.verifier),payload.challenge),'CSRF_INVALID',403);
 requireThat(payload.stateHash?equal(await digestState(body.returnState),payload.stateHash):!Object.hasOwn(body,'returnState'),'STATE_CONFLICT',403);
 return {mode,transactions,row,payload};
}

export async function observeSharedEntry(runtime,request,body){
 const {row,payload}=await checkedSharedEntry(runtime,request,body);
 const response=(outcome,extra={})=>runtime.json({success:true,context:null,operationId:row.operation_id,outcome,...extra});
 if(row.status!=='COMMITTED')return response('PENDING');
 const receipt=row.result_json&&JSON.parse(row.result_json);
 if(!receipt?.sid)return response('UNCONFIRMED');
 if(await isSharedRetired(runtime.store,receipt.sid))return response('SUPERSEDED');
 let installed;
 try{installed=await runtime.currentFamily(request);}
 catch(error){if(error.code!=='SESSION_ENDED')throw error;}
 if(!installed)return response('UNCONFIRMED');
 if(installed.family.sid!==receipt.sid)return response('SUPERSEDED');
 const check=new Request(runtime.config.origin+'/auth/v2/shared-entry/status',{headers:{Cookie:request.headers.get('Cookie')||''}});
 try{
  const cap=await runtime.authorise(check,{action:'read'});
  requireExpected(selector(JSON.parse(installed.family.binding_json),runtime.app),cap.context);
  return response('INSTALLED_CURRENT',{state:'UNLOCKED',context:cap.context,returnTo:payload.returnTo});
 }catch(error){
  if(error.status>=500)throw error;
  return response('UNCONFIRMED');
 }
}

export async function completeSharedEntry(runtime,request,body){
 const {mode,transactions,row,payload}=await checkedSharedEntry(runtime,request,body,{allowConfirmation:true}),store=runtime.store;
 requireThat(payload.returnMode!=='select','OPERATION_SUPERSEDED',409);
 if(row.status==='COMMITTED')return runtime.json({success:true,state:'UNCONFIRMED',outcome:'SUPERSEDED',context:null,operationId:row.operation_id});
 const current=await currentChild(runtime,request);
 if(row.expected_json)requireExpected(current?selector(JSON.parse(current.binding_json),runtime.app):null,JSON.parse(row.expected_json));
 else requireThat(!current,'OPERATION_SUPERSEDED',409);
 const app=await runtime.appControl(),verified=await academyIdentity(runtime,request,app,mode);
 let selectedCurrent=null;
 if(current){
  requireThat(current.state==='UNLOCKED','PIN_REQUIRED',423);
  const binding=JSON.parse(current.binding_json);
  requireThat(verified,'ACADEMY_SIGN_IN_REQUIRED',401);
  const check=new Request(runtime.config.origin+'/auth/v2/shared-entry',{headers:{Cookie:request.headers.get('Cookie')}});
  const cap=await runtime.authorise(check,{action:'read'});
  requireExpected(selector(binding,runtime.app),cap.context);
  const identityFields=['sub','psid','bsid','bv','ce','ae','s_iat','s_exp'];
  const conflicts=verified&&!identityFields.every(key=>binding[key]===verified.claims[key]);
  if(!conflicts){
   requireThat(!body.confirmAcademyAccount&&!payload.accountChoice,'ACCOUNT_SELECTION_REQUIRED',409);
   return runtime.json({success:true,...await runtime.stateDTO(current),returnTo:payload.returnTo,operationId:row.operation_id});
  }
  const choice=await digest(identityFields.map(key=>verified.claims[key]));
  if(!body.confirmAcademyAccount){
   const [guard,clear]=store.guard(
    "SELECT 1 FROM jwt_v2_http_transactions WHERE tx=? AND payload_json=? AND status='PENDING' AND expires_at>unixepoch()",
    [row.tx,row.payload_json]
   );
   await store.batch([guard,
    store.stmt('UPDATE jwt_v2_http_transactions SET payload_json=? WHERE tx=?',canonical({...payload,accountChoice:choice}),row.tx),
    clear
   ]);
   requireThat(false,'ACCOUNT_SELECTION_REQUIRED',409);
  }
  requireThat(payload.accountChoice&&equal(payload.accountChoice,choice),'ACCOUNT_SELECTION_REQUIRED',409);
  selectedCurrent=current;
 }
 requireThat(!body.confirmAcademyAccount||selectedCurrent,'ACCOUNT_SELECTION_REQUIRED',409);
 requireThat(verified,'ACADEMY_SIGN_IN_REQUIRED',401);
 if(!current)await requireNoUnpairedAuthority(runtime,request);
 const {claims,kid}=verified,gate=accountGate(runtime,mode,claims);
 requireThat(await store.first(gate.sql,...gate.args),'CHILD_AUTHORITY_PENDING',503);
 let mapping;
 try{mapping=await runtime.native.mappingGuard(claims);}
 catch(error){
  if(error.code==='HIFZ_PROFILE_REQUIRED'||error.code==='HIFZ_PROFILE_INACTIVE'||error.code==='STUDIO_ACCOUNT_INACTIVE')requireThat(false,'ACCESS_DENIED',403);
  throw error;
 }
 const predecessor=await sharedPredecessor(runtime,claims);
 const {exactParent,prior,priorBarrier}=predecessor;
 const now=runtime.clock(),barrier=admissionBarrier({
  existing:priorBarrier&&{lastRefresh:priorBarrier.last_refresh,idleUntil:priorBarrier.idle_until,locked:Boolean(priorBarrier.locked)},
  afg:claims.afg,now,policyMinutes:app.inactivityMinutes,s_exp:claims.s_exp
 });
 if(priorBarrier)barrier.idleUntil=Math.min(barrier.idleUntil,priorBarrier.idle_until);
 const provenance={issuer:claims.iss,env:claims.env,kid,sub:claims.sub,psid:claims.psid,bsid:claims.bsid,bv:claims.bv};
 const plan=await childTransition(runtime,{claims,purpose:'admission',installed:null,barrier,now,operationId:row.operation_id,sharedAcademyAdmission:provenance});
 const guards=[
  transactions.guard(row),
  store.guard("SELECT 1 FROM jwt_v2_http_transactions WHERE tx=? AND payload_json=? AND status='PENDING'",[row.tx,row.payload_json]),
  store.guard(gate.sql,gate.args),store.guard(mapping.sql,mapping.args),
  admissionFloorGuard(store,plan.binding),
  store.guard('SELECT 1 WHERE ?>unixepoch() AND ?>unixepoch()',[claims.exp,row.expires_at]),
  ...predecessor.guards,
  ...(selectedCurrent?[store.guard("SELECT 1 FROM jwt_v2_families WHERE sid=? AND cr=? AND state='UNLOCKED'",[selectedCurrent.sid,selectedCurrent.cr])]:[]),
  store.guard("SELECT 1 FROM jwt_v2_control_targets WHERE app=? AND env=? AND suffix='control/app' AND cr=? AND json_extract(projection_json,'$.sharedAcademyRegistryRevision')=? AND NOT EXISTS(SELECT 1 FROM json_each(projection_json,'$.withdrawnSharedAcademyKids') WHERE value=?)",[runtime.app,runtime.config.env,app.cr,app.sharedAcademyRegistryRevision,kid]),
  store.guard("SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_restrictions WHERE json_extract(target_json,'$.type')='key' AND json_extract(target_json,'$.purpose')='academy-shared-access' AND json_extract(target_json,'$.kid')=?)",[kid]),
 ];
 let issuance=[];
 if(barrier.state==='UNLOCKED'){
  await assertCaptureReceipt({capture:plan.capture,binding:plan.binding,projection:plan.projection,guards:plan.vectorGuards,manifest:store.dependencyManifest(claims.sub),app:runtime.app,env:runtime.config.env,now});
  issuance=issuanceFloorGuard(store,{binding:plan.binding,projection:plan.projection,vectorGuards:plan.vectorGuards,now});
 }
 const result={...plan.result,operationId:row.operation_id},policy=familyPolicyRegistrationPlan(store,{sid:result.sid,ownerEpoch:plan.projection.policyEpoch,revision:plan.projection.policyRevision,minutes:plan.projection.inactivityMinutes,now});
 const retired=[prior,selectedCurrent].filter(Boolean);
 const retirements=sharedRetirementPlan(store,retired,result.sid,row.operation_id);
 try{
  await store.batch([
  ...guards.map(pair=>pair[0]),...plan.statements,...policy,...issuance.slice(0,1),...retirements,
  store.stmt('INSERT INTO jwt_v2_ceremony_barriers VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(psid,bsid,bv,sub) DO UPDATE SET last_refresh=excluded.last_refresh,idle_until=excluded.idle_until,locked=excluded.locked,revision=revision+1',...exactParent,barrier.lastRefresh,barrier.idleUntil,Number(barrier.locked)),
  store.stmt('INSERT INTO jwt_v2_shared_entry_families(sid,tx) VALUES(?,?)',result.sid,row.tx),
  store.stmt("UPDATE jwt_v2_http_transactions SET status='COMMITTED',result_json=? WHERE tx=?",canonical(result),row.tx),
  store.stmt('INSERT INTO jwt_v2_ceremony_consumed VALUES(?,?,?,?,?,?)',claims.jti,row.tx,row.operation_id,await digest(claims),canonical(result),now),
  ...issuance.slice(1),...guards.map(pair=>pair[1])
  ]);
 }catch(error){
  const latest=await transactions.get(row.tx);
  if(latest?.status==='COMMITTED')return runtime.json({success:true,state:'UNCONFIRMED',outcome:'SUPERSEDED',context:null,operationId:row.operation_id});
  if(await store.first('SELECT 1 FROM jwt_v2_ceremony_consumed WHERE jti=?',claims.jti))requireThat(false,'OPERATION_SUPERSEDED',409);
  throw error;
 }
 await publishSharedRetirements(runtime,result.sid);
 const publication=await runtime.publishWinningFamily(result.sid,{initial:true});
 requireThat(publication.cachePublication==='READY','CHILD_AUTHORITY_PENDING',503);
 const appAfter=await runtime.appControl();
 const [[family],[ready],[mapped]]=await store.readBatch([
  ['SELECT * FROM jwt_v2_families WHERE sid=?',result.sid],
  [gate.sql,...gate.args],
  [mapping.sql,...mapping.args]
 ]);
 const pair=family&&JSON.parse(family.projection_json).sharedAcademyAdmission;
 requireThat(pair?.kid===kid&&family.cr===1&&family.state===barrier.state&&appAfter.sharedAcademyRegistryRevision===app.sharedAcademyRegistryRevision&&!appAfter.withdrawnSharedAcademyKids?.includes(kid)&&ready&&mapped,'CHILD_AUTHORITY_PENDING',503);
 if(barrier.locked){
  const response=await runtime.cookieResponse(family,plan.credentials.refresh,{...await runtime.stateDTO(family),code:'PIN_REQUIRED',operationId:row.operation_id,returnTo:payload.returnTo,...publication});
  return new Response(response.body,{status:423,headers:response.headers});
 }
 return runtime.cookieResponse(family,plan.credentials.refresh,{...await runtime.stateDTO(family),operationId:row.operation_id,outcome:'COMMITTED',returnTo:payload.returnTo,...publication});
}

export function sharedEntryPage(runtime,request){
 configuration(runtime);
 const url=new URL(request.url),entries=[...url.searchParams];
 const headers={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','Content-Security-Policy':"default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"};
 if(url.pathname==='/auth/v2/shared-entry-client.mjs'){
  requireThat(!entries.length,'UNREGISTERED_RETURN',400);
  return new Response(sharedEntryClientSource,{headers:{...headers,'Content-Type':'text/javascript; charset=utf-8'}});
 }
 const area=entries[0]?.[1];
 requireThat(entries.length===1&&entries[0][0]==='area'&&Object.hasOwn(destinations,area)&&(runtime.app==='hifz')===(area==='hifz'),'UNREGISTERED_RETURN',400);
 return new Response('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Opening programme</title><main data-shared-entry-area="'+area+'"><p id="entry-status" role="status">Opening your programme…</p><a id="academy-link" href="https://ummabbadacademy.app/?workspace=learn" hidden>Open Academy</a></main><script type="module" src="/auth/v2/shared-entry-client.mjs"></script>',{headers:{...headers,'Content-Type':'text/html; charset=utf-8'}});
}
