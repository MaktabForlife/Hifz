import {AcademyCeremonies} from './ceremonies.mjs';
import {HTTPTransactions} from './http-transactions.mjs';
import {canonical,requireThat,digest,uuid} from './codec.mjs';
import {selector,requireExpected,expectedContext} from './http-context.mjs';
import {beginRootFamily,initialBinding} from './http-families.mjs';
import {assertCaptureReceipt} from './capture-receipt.mjs';
import {issuanceFloorGuard} from './issuance-floors.mjs';
import {admissionFloorGuard} from './publication.mjs';

const pinRequests=new WeakMap(),services=new WeakMap();
export function markPINRequest(request,{tx,csrfHash}){pinRequests.set(request,{tx,csrfHash});}
export async function academyCeremonies(runtime){
 if(services.has(runtime))return services.get(runtime);
 requireThat(runtime.app==='academy','ACADEMY_PIN_ONLY',403);
 const store=runtime.store;
 const parentEligibility=async({request,sub,tx,purpose,expected})=>{
  const app=await runtime.appControl();
  const life=await store.lifecycle(runtime.cache.key('control/app'));
  requireThat(life?.state==='ACTIVE'&&!(app.withdrawnHandoffKids||[]).includes(runtime.settings.handoffKid),'HANDOFF_AUTHORITY_HELD',503);
  const {servicePeer}=await import('./http-service.mjs');const peer=servicePeer(request);
  let parent;
  if(peer){const ceremony=await store.first('SELECT parent_json FROM jwt_v2_ceremonies WHERE tx=?',tx);const pinned=ceremony?.parent_json&&JSON.parse(ceremony.parent_json);requireThat(pinned,'PARENT_INELIGIBLE',401);parent=await store.first('SELECT * FROM jwt_v2_parents WHERE psid=?',pinned.psid);}
  else {const current=await runtime.currentFamily(request);const family=await runtime.observeState(current.family);requireThat(family.sub===sub,'PARENT_INELIGIBLE',401);parent=await store.first('SELECT * FROM jwt_v2_parents WHERE psid=?',family.psid);}
  const account=await store.first('SELECT * FROM jwt_v2_accounts WHERE sub=?',sub),browser=parent&&await store.first('SELECT * FROM jwt_v2_browsers WHERE bsid=?',parent.bsid);
  requireThat(parent&&account?.active===1&&parent.sub===sub&&parent.ce===account.ce&&parent.ae===account.ae&&runtime.clock()<parent.s_exp&&browser&&browser.psid===parent.psid&&browser.bv===parent.bv&&browser.cancelled_through<parent.bv&&['UNLOCKED','LOCKED'].includes(parent.state),'PARENT_INELIGIBLE',401);
  
  if(expected)for(const k of ['sub','psid','bsid','bv','ce','ae'])requireThat(expected[k]===parent[k],'PARENT_CHANGED',409);
  return {...parent,afg:parent.foreground_at};
 };
 const service=new AcademyCeremonies({
  store,config:runtime.config,callbacks:runtime.settings.callbacks,clock:runtime.clock,
  credentialSnapshot:runtime.native.credentialSnapshot,credentialGuard:runtime.native.credentialGuard,verifyPin:runtime.native.verifyPin,
  setupPlan:runtime.native.setupCredentialPlan,
  authorisePinRequest:async(request,tx)=>{const p=pinRequests.get(request);return p?.tx===tx?p:null;},
  attestedSource:async request=>{
   if(typeof runtime.env.UAA_V2_PLATFORM_SOURCE==='function')return runtime.env.UAA_V2_PLATFORM_SOURCE(request);
   requireThat(request.cf&&typeof request.cf.colo==='string','SOURCE_ADDRESS_UNAVAILABLE',503);
   return {kind:'platform',address:request.headers.get('CF-Connecting-IP')};
  },
  authoriseChild:async(request,targetApp)=>{const {servicePeer}=await import('./http-service.mjs');const p=servicePeer(request);return p&&p.sourceApp===targetApp&&p.targetApp==='academy'&&['/internal/auth/v2/transactions','/internal/auth/v2/redeem'].includes(p.path);},
  parentEligibility,
  assertCodeAuthority:typeof runtime.native.assertCodeAuthority==='function'?args=>runtime.native.assertCodeAuthority({runtime,...args}):null,
  parentGuard:p=>({sql:"SELECT 1 FROM jwt_v2_parents p JOIN jwt_v2_accounts a ON a.sub=p.sub JOIN jwt_v2_browsers b USING(bsid) WHERE p.psid=? AND p.sub=? AND p.bsid=? AND p.bv=? AND p.ce=? AND p.ae=? AND p.s_iat=? AND p.s_exp=? AND p.state IN('LOCKED','UNLOCKED') AND p.s_exp>? AND a.active=1 AND a.ce=p.ce AND a.ae=p.ae AND b.bv=p.bv AND b.psid=p.psid AND b.cancelled_through<p.bv AND EXISTS(SELECT 1 FROM jwt_v2_objects WHERE object_key=? AND state='ACTIVE') AND NOT EXISTS(SELECT 1 FROM jwt_v2_control_targets t,json_each(t.projection_json,'$.withdrawnHandoffKids') k WHERE t.object_key=? AND k.value=?)",args:[p.psid,p.sub,p.bsid,p.bv,p.ce,p.ae,p.s_iat,p.s_exp,runtime.clock(),runtime.cache.key('control/app'),runtime.cache.key('control/app'),runtime.settings.handoffKid]}),
  signingKey:runtime.settings.handoffSigningKey,kid:runtime.settings.handoffKid
 });
 services.set(runtime,service);return service;
}

export async function pinBootstrap(runtime,request,body){
 requireThat(runtime.app==='academy','ACADEMY_PIN_ONLY',403);
 const transactions=new HTTPTransactions(runtime),ceremonies=await academyCeremonies(runtime);
 let current=null;try{current=await runtime.currentFamily(request);}catch(error){if(error.code!=='SESSION_ENDED')throw error;}
 if(current){current.family=await runtime.observeState(current.family);if(['REVOKED','EXPIRED'].includes(current.family.state)||runtime.clock()>=current.family.s_exp)current=null;}
 const supplied=expectedContext(request,body);
 if(supplied&&current){const actual=selector(JSON.parse(current.family.binding_json),runtime.app);requireThat('app sub sid psid bsid bv ce ae le'.split(' ').every(k=>actual[k]===supplied[k]),'OPERATION_SUPERSEDED',409);}
 let transaction=body.tx?await transactions.get(body.tx):null;
 let journey=null;
 if(body.journeyTx){requireThat(uuid(body.journeyTx),'INVALID_CEREMONY',400);journey=await runtime.store.first('SELECT * FROM jwt_v2_ceremonies WHERE tx=?',body.journeyTx);requireThat(journey&&journey.status==='PENDING'&&runtime.clock()<journey.expires_at&&current,'PARENT_INELIGIBLE',401);}
 if(transaction){
  requireThat(transaction.kind===body.purpose&&transaction.status==='PENDING'&&runtime.clock()<transaction.expires_at,'BROWSER_TRANSACTION_EXPIRED',409);
  if(transaction.expected_json)requireExpected(selector(JSON.parse(current?.family.binding_json||'null'),runtime.app),JSON.parse(transaction.expected_json));
 }else{
  let credential;
  if(current&&['LOCKED','ADMITTED_LOCKED'].includes((await runtime.observeState(current.family)).state))credential=await runtime.native.credentialSnapshot(current.family.sub);
  else credential=await runtime.native.selection(body.loginId);
  requireThat(credential.active,'ACCOUNT_INACTIVE',401);
  await runtime.store.stmt('INSERT INTO jwt_v2_accounts VALUES(?,?,1,0,1,1) ON CONFLICT(sub) DO NOTHING',credential.sub,credential.ce).run();
  const account=await runtime.store.first('SELECT * FROM jwt_v2_accounts WHERE sub=?',credential.sub);
  requireThat(account.ce===credential.ce&&account.active===1,'CREDENTIAL_RECONCILIATION_REQUIRED',503);
  const expected=current?selector(JSON.parse(current.family.binding_json),runtime.app):null;
  transaction=await transactions.create({kind:body.purpose,sub:credential.sub,expected,expiresAt:Math.min(runtime.clock()+300,journey?.expires_at??Number.MAX_SAFE_INTEGER),payload:{ae:account.ae,ce:credential.ce,setupComplete:credential.setupComplete,mode:journey?'child':current&&['LOCKED','ADMITTED_LOCKED'].includes(current.family.state)?'unlock':'signin',journeyTx:journey?.tx||null}});
 }
 const proof=await transactions.proof(transaction);
 const pinTx=journey?.tx||JSON.parse(transaction.payload_json).journeyTx||transaction.tx;
 markPINRequest(request,{tx:pinTx,csrfHash:await digest(proof)});
 if(journey)await ceremonies.bindParent({request,tx:journey.tx,sub:transaction.sub,pinRequired:true});
 else await ceremonies.startRootPin({request,tx:transaction.tx,sub:transaction.sub,returnTo:runtime.config.origin+'/'});
 const attempt=await ceremonies.issueAttempt({request,tx:pinTx});
 const state=current?await runtime.stateDTO(current.family):{contractVersion:2,success:true,serverNowMs:runtime.clock()*1000,state:'SIGNED_OUT',context:null};
 return runtime.json({...state,...await transactions.dto(transaction),attemptId:attempt.attemptId,setupRequired:!JSON.parse(transaction.payload_json).setupComplete});
}

export async function submitPIN(runtime,request,body,{setup=false}={}){
 const transactions=new HTTPTransactions(runtime),auth=await transactions.verify(request,body,setup?'pin/setup':'pin',{allowCommitted:true});
 const transaction=auth.row;
 let installed=null;try{installed=await runtime.currentFamily(request);}catch(error){if(error.code!=='SESSION_ENDED')throw error;}
 if(installed&&(['REVOKED','EXPIRED'].includes(installed.family.state)||runtime.clock()>=installed.family.s_exp))installed=null;
 const expected=transaction.expected_json&&JSON.parse(transaction.expected_json);
 if(expected){requireThat(installed,'OPERATION_SUPERSEDED',409);requireExpected(selector(JSON.parse(installed.family.binding_json),runtime.app),expected);}
 else requireThat(!installed,'OPERATION_SUPERSEDED',409);
 if(transaction.status==='COMMITTED')return runtime.json({success:true,state:'UNCONFIRMED',context:null,outcome:'SUPERSEDED',operationId:body.operationId});
 const payload=JSON.parse(transaction.payload_json),pinTx=payload.journeyTx||transaction.tx;
 const ceremonies=await academyCeremonies(runtime);markPINRequest(request,{tx:pinTx,csrfHash:auth.csrfHash});
 requireThat(uuid(body.attemptId),'UNISSUED_PIN_ATTEMPT',403);
 const pending=await runtime.store.first("SELECT * FROM jwt_v2_ceremony_attempts WHERE tx=? AND attempt_id=?",pinTx,body.attemptId);
 requireThat(pending,'UNISSUED_PIN_ATTEMPT',403);
 const result=await ceremonies.verify({request,tx:pinTx,attemptId:pending.attempt_id,pin:body.pin,confirmation:body.confirmation,setup});
 if(result.status!=='VERIFIED')return runtime.json({success:false,code:result.status,pausedUntilMs:(result.pausedUntil||0)*1000},result.status==='PIN_PAUSED'?429:401);
 const credential=await runtime.native.credentialSnapshot(transaction.sub),attempt=await runtime.store.first('SELECT * FROM jwt_v2_ceremony_attempts WHERE attempt_id=?',pending.attempt_id);
 let current=null;try{current=await runtime.currentFamily(request);}catch(error){if(error.code!=='SESSION_ENDED')throw error;}
 if(current&&(['REVOKED','EXPIRED'].includes(current.family.state)||runtime.clock()>=current.family.s_exp))current=null;
 if(expected){requireThat(current,'OPERATION_SUPERSEDED',409);requireExpected(selector(JSON.parse(current.family.binding_json),runtime.app),expected);}else requireThat(!current,'OPERATION_SUPERSEDED',409);
 let committed;
 if(payload.mode==='child'){
  requireThat(!setup,'CHILD_PIN_SETUP_REQUIRES_NEW_PARENT',409);
  const ceremony=await runtime.store.first('SELECT * FROM jwt_v2_ceremonies WHERE tx=?',pinTx);
  const code=await ceremonies.issueCode({request,tx:pinTx,stateHash:ceremony.state_hash,operationId:transaction.operation_id});
  requireThat(code.winner,'OPERATION_SUPERSEDED',409);
  await runtime.store.stmt("UPDATE jwt_v2_http_transactions SET status='COMMITTED',result_json=? WHERE tx=?",canonical({status:'CODE_ISSUED',tx:transaction.tx,operationId:body.operationId}),transaction.tx).run();
  return runtime.json({...await runtime.stateDTO(current.family),operationId:body.operationId,post:{callback:code.callback,tx:code.tx,stateHash:code.stateHash,code:code.code}});
 }
 if(payload.mode==='unlock'){requireThat(!setup,'FRESH_PARENT_REQUIRED',409);committed=await unlockAcademy(runtime,{transaction,attempt,credential,current});}
 else committed=await beginRootFamily(runtime,{transaction,attempt,credential,current});
 const state=await runtime.stateDTO(committed.family);
 return runtime.cookieResponse(committed.family,committed.refresh,{...state,operationId:body.operationId,outcome:'COMMITTED',cachePublication:committed.cachePublication||'READY'});
}

async function unlockAcademy(runtime,{transaction,attempt,credential,current}){
 const store=runtime.store,now=runtime.clock(),proof=JSON.parse(attempt.result_json);
 requireThat(current&&proof.status==='VERIFIED'&&now<proof.expiresAt&&credential.active&&credential.ce===attempt.credential_epoch,'FRESH_PIN_REQUIRED',423);
 const old=await runtime.observeState(current.family),original=JSON.parse(old.binding_json);
 requireExpected(selector(original,runtime.app),JSON.parse(transaction.expected_json));
 requireThat(['LOCKED','ADMITTED_LOCKED'].includes(old.state)&&now<old.s_exp,'UNLOCK_CONTEXT_CONFLICT',409);
 const capture=await runtime.nativeCapture(original),binding={...original,sv:old.sv+1,ue:old.ue+1,pv:capture.pv,vat:capture.vat};
 const projection=await runtime.buildProjection(binding,capture,{previous:JSON.parse(old.projection_json)}),idleUntil=Math.min(old.s_exp,now+projection.inactivityMinutes*60),deadline=Math.min(binding.vat+900,idleUntil,projection.timedUntil),refresh=(await import('./codec.mjs')).opaque(),fp=await (await import('./codec.mjs')).fingerprint(refresh,runtime.config);
 await assertCaptureReceipt({capture,binding,projection,guards:capture.vectorGuards,manifest:runtime.settings.dependenciesFor(binding.sub),app:runtime.app,env:runtime.config.env,now});
 const native=runtime.native.credentialGuard(credential),[ng,nc]=store.guard(native.sql,native.args),[tg,tc]=new HTTPTransactions(runtime).guard(transaction);
 const [g,c]=store.guard("SELECT 1 FROM jwt_v2_families f JOIN jwt_v2_accounts a USING(sub) JOIN jwt_v2_browsers b USING(bsid) WHERE f.sid=? AND f.fingerprint=? AND f.binding_json=? AND f.state IN('LOCKED','ADMITTED_LOCKED') AND f.s_exp>? AND a.active=1 AND a.ce=f.ce AND a.ae=f.ae AND a.le=f.le AND b.bv=f.bv AND b.cancelled_through<f.bv",[old.sid,current.fingerprint,old.binding_json,now]);
 const floor=admissionFloorGuard(store,binding),issuance=issuanceFloorGuard(store,{binding,projection,vectorGuards:capture.vectorGuards,existingSid:old.sid,now});
 const vectors=capture.vectorGuards.map(args=>store.guard('SELECT 1 FROM jwt_v2_dependencies WHERE id=? AND scope=? AND owner_epoch=? AND revision=?',args));
 const safe={status:'COMMITTED',sid:old.sid,sv:binding.sv,ue:binding.ue,le:binding.le,s_exp:binding.s_exp,state:'UNLOCKED',operationId:transaction.operation_id};
 await store.batch([tg,ng,g,floor[0],...vectors.map(v=>v[0]),
  store.stmt("INSERT INTO jwt_v2_ceremony_pending(tx,purpose,expected_json,sub,expires_at,csrf_hash,operation_id,status) VALUES(?,'unlock',?,?,?,?,?,'COMMITTED')",transaction.tx,canonical(selector(original,runtime.app)),old.sub,transaction.expires_at,attempt.csrf_hash,transaction.operation_id),
  store.stmt('INSERT INTO jwt_v2_refresh_history VALUES(?,?,?,?,?,1,?,?,?)',old.fingerprint,old.sid,old.fingerprint_generation,old.binding_json,attempt.csrf_hash,now,transaction.operation_id,old.s_exp),
  store.stmt("UPDATE jwt_v2_families SET state='UNLOCKED',authority_ready=1,sv=sv+1,ue=ue+1,cr=cr+1,vat=?,deadline=?,idle_until=?,last_refresh=?,policy_minutes=?,fingerprint=?,fingerprint_generation=fingerprint_generation+1,binding_json=?,projection_json=? WHERE sid=?",binding.vat,deadline,idleUntil,now,projection.inactivityMinutes,fp,canonical(binding),canonical(projection),old.sid),
  store.stmt("UPDATE jwt_v2_parents SET state='UNLOCKED',foreground_at=? WHERE psid=? AND state='LOCKED'",now,old.psid),
  store.stmt("UPDATE jwt_v2_intents SET state='CANCELLED',superseding_operation=? WHERE sid=? AND state='ISSUED'",transaction.operation_id,old.sid),
  store.stmt('INSERT INTO jwt_v2_ceremony_consumed VALUES(?,?,?,?,?,?)',crypto.randomUUID(),transaction.tx,transaction.operation_id,await digest({attemptId:attempt.attempt_id,binding:original}),canonical(safe),now),
  store.stmt("UPDATE jwt_v2_http_transactions SET status='COMMITTED',result_json=? WHERE tx=?",canonical(safe),transaction.tx),
  store.stmt('INSERT INTO jwt_v2_ceremony_barriers VALUES(?,?,?,?,?,?,0,1) ON CONFLICT(psid,bsid,bv,sub) DO UPDATE SET last_refresh=excluded.last_refresh,idle_until=excluded.idle_until,locked=0,revision=revision+1',old.psid,old.bsid,old.bv,old.sub,now,idleUntil),issuance[0],issuance[1],...vectors.map(v=>v[1]),floor[1],c,nc,tc]);
 const publication=await runtime.publishWinningFamily(old.sid);return {family:await store.family(old.sid),refresh,...publication};
}
