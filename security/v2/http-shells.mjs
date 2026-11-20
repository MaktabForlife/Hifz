import {canonical,requireThat,uuid,digest} from './codec.mjs';
import {HTTPTransactions} from './http-transactions.mjs';
import {academyCeremonies,markPINRequest} from './http-pin.mjs';
import {selector,requireExpected} from './http-context.mjs';
import {callbackForm} from './http-journeys.mjs';
export async function proceedAcademy(runtime,request,body,current){
 requireThat(runtime.app==='academy'&&uuid(body.tx),'ACADEMY_CEREMONY_REQUIRED',400);
 const c=await runtime.store.first('SELECT * FROM jwt_v2_ceremonies WHERE tx=?',body.tx);
 requireThat(c&&c.status==='PENDING'&&runtime.clock()<c.expires_at,'CEREMONY_EXPIRED',409);
 if(!current)return runtime.json({success:true,state:'SIGNED_OUT',context:null,action:'SIGNIN',journeyTx:c.tx});
 const family=await runtime.observeState(current.family),context=selector(JSON.parse(family.binding_json),runtime.app);
 const transactions=new HTTPTransactions(runtime),row=await transactions.create({kind:'admission/proceed',sub:family.sub,expected:context,payload:{journeyTx:c.tx}});
 const proof=await transactions.proof(row);markPINRequest(request,{tx:c.tx,csrfHash:await digest(proof)});
 const ceremonies=await academyCeremonies(runtime),pinRequired=c.purpose==='unlock';
 await ceremonies.bindParent({request,tx:c.tx,sub:family.sub,pinRequired});
 if(typeof runtime.native.prepareAdmissionAuthority==='function'){
  const ceremony=await runtime.store.first('SELECT * FROM jwt_v2_ceremonies WHERE tx=?',c.tx),parent=await runtime.store.first('SELECT * FROM jwt_v2_parents WHERE psid=?',family.psid);
  const prepared=await runtime.native.prepareAdmissionAuthority({runtime,ceremony,parent,operationId:c.tx});
  requireThat(typeof prepared?.ready==='boolean','NATIVE_AUTHORITY_PREPARATION_INVALID',503);
  if(!prepared.ready){
   const done=prepared.progress?.completedPages,total=prepared.progress?.totalPages;
   requireThat(Number.isSafeInteger(done)&&done>=0&&Number.isSafeInteger(total)&&total>=done&&total<=128,'NATIVE_AUTHORITY_PREPARATION_INVALID',503);
   return runtime.json({...await runtime.stateDTO(family),...await transactions.dto(row),journeyTx:c.tx,action:'PREPARE',preparationExpiresAtMs:c.expires_at*1000,retryAfterMs:250,progress:'Preparing secure connection ('+done+'/'+total+').'});
  }
 }

 return runtime.json({...await runtime.stateDTO(family),...await transactions.dto(row),journeyTx:c.tx,action:pinRequired?'PIN':'CONTINUE'});
}
export async function continueAcademy(runtime,request,body){
 const transactions=new HTTPTransactions(runtime),auth=await transactions.verify(request,body,'admission/proceed');
 const payload=JSON.parse(auth.row.payload_json),c=await runtime.store.first('SELECT * FROM jwt_v2_ceremonies WHERE tx=?',payload.journeyTx);
 requireThat(c?.purpose==='admission'&&c.pin_required===0,'FRESH_PIN_REQUIRED',423);
 const current=await runtime.currentFamily(request),family=await runtime.observeState(current.family);
 requireThat(['UNLOCKED','LOCKED'].includes(family.state),'PARENT_INELIGIBLE',401);
 requireExpected(selector(JSON.parse(family.binding_json),runtime.app),JSON.parse(auth.row.expected_json));
 markPINRequest(request,{tx:c.tx,csrfHash:auth.csrfHash});
 const code=await(await academyCeremonies(runtime)).issueCode({request,tx:c.tx,stateHash:c.state_hash,operationId:body.operationId});
 requireThat(code.winner,'OPERATION_SUPERSEDED',409);
 return runtime.json({success:true,state:family.state,context:selector(JSON.parse(family.binding_json),runtime.app),operationId:body.operationId,post:{callback:code.callback,tx:code.tx,stateHash:code.stateHash,code:code.code}});
}
const esc=s=>s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;');
export async function authShell(runtime,request){
 requireThat(runtime.app==='academy','UNKNOWN_AUTH_PATH',404);
 const url=new URL(request.url),path=url.pathname,allowed=['/auth/v2/signin','/auth/v2/pin','/auth/v2/admission','/auth/v2/unlock'];
 if(path==='/auth/v2/control.mjs')return new Response(controlModule(),{headers:{'Content-Type':'text/javascript','Cache-Control':'private, no-store'}});
 requireThat(allowed.includes(path),'UNKNOWN_AUTH_PATH',404);
 const query=[...url.searchParams.entries()];
 requireThat(query.every(([k,v])=>k==='tx'&&uuid(v)||path==='/auth/v2/signin'&&k==='switch'&&v==='1')&&new Set(query.map(([k])=>k)).size===query.length,'INVALID_AUTH_ROUTE',400);
 const tx=url.searchParams.get('tx');
 if(['admission','unlock'].includes(path.split('/').at(-1))){const c=tx&&await runtime.store.first('SELECT expires_at,purpose,status FROM jwt_v2_ceremonies WHERE tx=?',tx);requireThat(c&&c.purpose===path.split('/').at(-1)&&c.status==='PENDING'&&runtime.clock()<c.expires_at,'CEREMONY_EXPIRED',409);}
 const data=canonical({tx,switchAccount:url.searchParams.get('switch')==='1',app:'academy'}).replaceAll('<','\\u003c');
 const html='<!doctype html><html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="strict-origin"><title>Academy sign-in</title><main><h1>Academy</h1><p id="status">Checking sign-in…</p><form id="pin" hidden><label>Unique ID <input name="loginId" autocomplete="username" required maxlength="180"></label><label>PIN <input name="pin" type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" autocomplete="current-password" required></label><label id="confirm-label" hidden>Confirm PIN <input name="confirmation" type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" autocomplete="new-password"></label><button>Continue</button></form><button id="continue" hidden>Continue</button></main><script id="config" type="application/json">'+data+'</script><script type="module" src="/auth/v2/control.mjs"></script></html>';
 return new Response(html,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'private, no-store','Referrer-Policy':'strict-origin','Content-Security-Policy':"default-src 'none'; script-src 'self'; connect-src 'self'; form-action "+runtime.config.academyOrigin+' '+Object.values(runtime.settings.callbacks).map(c=>c.origin).join(' ')+"; base-uri 'none'; frame-ancestors 'none'"}});
}
function controlModule(){return [
"import {createBrowserSession} from '/auth/v2/browser-session.mjs';",
"const settings=JSON.parse(document.getElementById('config').textContent), status=document.getElementById('status'), form=document.getElementById('pin'), next=document.getElementById('continue');",
"const session=createBrowserSession({app:'academy',origin:location.origin,fetch:fetch.bind(globalThis),crypto,sessionStorage,locks:navigator.locks,indexedDB,BroadcastChannel,onMask:()=>{}});let journey=settings.tx, setup=false, proof=null;",
"function post(p){const f=document.createElement('form');f.method='post';f.action=p.callback;for(const k of ['tx','stateHash','code']){const i=document.createElement('input');i.type='hidden';i.name=k;i.value=p[k];f.append(i);}document.body.append(f);f.requestSubmit();}",
"async function begin(){if(settings.switchAccount)await session.switchAccount();if(journey){const dto=await session.prepareJourneyAuthority({tx:journey,onProgress:value=>{status.textContent=value.progress||'Preparing secure connection.';}});proof=dto;if(dto.action==='CONTINUE'){next.hidden=false;status.textContent='Continue to your app.';return;}if(dto.action==='PIN'){form.elements.loginId.hidden=true;form.elements.loginId.required=false;status.textContent='Enter your PIN to continue.';form.hidden=false;return;}}status.textContent='Enter your Unique ID and PIN.';form.hidden=false;}",
"next.addEventListener('click',async()=>{next.disabled=true;try{const r=await fetch('/auth/v2/admission/start',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json','X-UAA-Request':'2','X-UAA-CSRF':proof.csrf},body:JSON.stringify({tx:proof.tx,operationId:proof.intent.id,expectedContext:proof.context})});const d=await r.json();if(!r.ok||!d.post)throw Error('Could not confirm sign-in');post(d.post);}catch(e){status.textContent=e.message;next.disabled=false;}});",
"form.addEventListener('submit',async event=>{event.preventDefault();const values=Object.fromEntries(new FormData(form));form.querySelector('button').disabled=true;try{const input={loginId:values.loginId,...(journey&&proof?.action==='PIN'?{journeyTx:journey}:{})};const result=setup?await session.setupPin({...input,pin:values.pin,confirmation:values.confirmation}):await session.submitPin({...input,pin:values.pin});values.pin='';form.elements.pin.value='';form.elements.confirmation.value='';if(result.post){post(result.post);return;}if(journey){await begin();return;}location.replace('/');}catch(e){if(e.code==='PIN_SETUP_REQUIRED'){setup=true;document.getElementById('confirm-label').hidden=false;form.elements.confirmation.required=true;status.textContent='Choose and confirm a four-digit PIN.';}else status.textContent='Sign-in could not be confirmed: '+(e.code||'unavailable');}finally{form.querySelector('button').disabled=false;}});",
"begin().catch(e=>{status.textContent='Sign-in is unavailable: '+(e.code||'unavailable');});"
].join('\n');}
