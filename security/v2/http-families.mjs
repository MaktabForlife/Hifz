import {canonical,requireThat,opaque,fingerprint,uuid,digest} from './codec.mjs';
import {assertCaptureReceipt} from './capture-receipt.mjs';
import {admissionFloorGuard,restrictionPlan} from './publication.mjs';
import {issuanceFloorGuard} from './issuance-floors.mjs';
import {selector,requireExpected} from './http-context.mjs';

export function initialBinding(runtime,{sub,ce,ae,le=0,psid,sid=psid,bsid,bv,s_iat,s_exp,sv=1,ue=0,capture}){
 return {ver:2,env:runtime.config.env,iss:runtime.config.origin,aud:'urn:uaa:'+runtime.config.env+':'+runtime.app+':api:v2',sub,sid,psid,bsid,bv,ce,ae,le,sv,ue,pv:capture.pv,vat:capture.vat,s_iat,s_exp};
}
export async function rotateFamily(runtime,request,body){
 const current=await runtime.currentFamily(request,{allowSpent:true}),f=await runtime.observeState(current.family);
 const expected=body.expectedContext;requireThat(expected,'EXPECTED_CONTEXT_REQUIRED',409);
 const original=current.historical?JSON.parse(current.history.binding_json):JSON.parse(f.binding_json);
 requireExpected(selector(original,runtime.app),expected);
 const auth=await runtime.intents.verify(request,{operationId:body.operationId,purpose:'refresh',context:expected,allowHistorical:current.historical});
 if(current.historical){
  const classification=await runtime.store.classifyReuse({fingerprint:current.fingerprint,intentId:body.operationId,binding:original,csrfHash:auth.csrfHash,now:runtime.clock()});
  if(classification.incidentEligible)await runtime.reportIncident?.({...classification,operationId:crypto.randomUUID()});
  return runtime.json({success:true,state:['LOCKED','ADMITTED_LOCKED'].includes(f.state)?f.state:'UNCONFIRMED',context:null,outcome:'SUPERSEDED',operationId:body.operationId});
 }
 requireThat(f.state==='UNLOCKED','PIN_REQUIRED',423);
 requireThat(typeof body.qualifyingActivity==='boolean','ACTIVITY_CLASSIFICATION_REQUIRED',400);
 const capture=await runtime.nativeCapture(original),next={...original,sv:original.sv+1,pv:capture.pv,vat:capture.vat};
 const now=runtime.clock(),idleUntil=Math.min(f.s_exp,(body.qualifyingActivity?now:f.last_refresh)+f.policy_minutes*60);
 const projection=await runtime.buildProjection(next,capture,{previous:JSON.parse(f.projection_json)});
 const deadline=Math.min(capture.vat+900,idleUntil,f.s_exp,projection.timedUntil),refresh=opaque();
 const result=await runtime.store.rotate({sid:f.sid,fingerprint:current.fingerprint,intentId:body.operationId,csrfHash:auth.csrfHash,expectedBinding:original,successorFingerprint:await fingerprint(refresh,runtime.config),nextBinding:next,nextProjection:projection,now,idleUntil,deadline,vectorGuards:capture.vectorGuards,qualifyingActivity:body.qualifyingActivity,capture,requireBarrier:runtime.app!=='academy'});
 requireThat(result.winner,'OPERATION_SUPERSEDED',409);
 const publication=await runtime.publishWinningFamily(f.sid);
 const family=await runtime.store.family(f.sid);
 return runtime.cookieResponse(family,refresh,{...await runtime.stateDTO(family),operationId:body.operationId,outcome:'COMMITTED',...publication});
}

export async function childTransition(runtime,{claims,purpose,installed,barrier,now,operationId}){
 const store=runtime.store,old=purpose==='unlock'?await store.family(claims.sid):null;
 const account=await store.first('SELECT * FROM jwt_v2_accounts WHERE sub=?',claims.sub);
 const le=old?.le??account?.le??0,sid=old?.sid||crypto.randomUUID();
 const skeleton={...claims,le,sid},capture=await runtime.nativeCapture(skeleton);
 const binding=initialBinding(runtime,{...claims,le,sid,sv:old?old.sv+1:1,ue:old?old.ue+1:0,capture});
 const projection=await runtime.buildProjection(binding,capture,{initialIssuance:false});
 const deadline=Math.min(binding.vat+900,barrier.idleUntil,claims.s_exp,projection.timedUntil),refresh=opaque(),fp=await fingerprint(refresh,runtime.config);
 const [ag,ac]=store.guard("SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_accounts WHERE sub=? AND (ce>? OR (ce=? AND ae>?) OR active=0))",[claims.sub,claims.ce,claims.ce,claims.ae]);
 const [pg,pc]=store.guard("SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_parents WHERE psid=? AND (sub<>? OR bsid<>? OR bv<>? OR ce<>? OR ae<>? OR s_iat<>? OR s_exp<>? OR state IN('REVOKED','EXPIRED')))",[claims.psid,claims.sub,claims.bsid,claims.bv,claims.ce,claims.ae,claims.s_iat,claims.s_exp]);
 const [bg,bc]=store.guard("SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_browsers WHERE bsid=? AND (bv>? OR cancelled_through>=?))",[claims.bsid,claims.bv,claims.bv]);
 const statements=[ag,pg,bg,
  store.stmt('INSERT INTO jwt_v2_accounts VALUES(?,?,?, ?,1,1) ON CONFLICT(sub) DO UPDATE SET ce=excluded.ce,ae=excluded.ae,revision=revision+1',claims.sub,claims.ce,claims.ae,le),
  store.stmt("INSERT INTO jwt_v2_parents VALUES(?,?,?,?,?,?,?,?,?,'UNLOCKED') ON CONFLICT(psid) DO NOTHING",claims.psid,claims.sub,claims.bsid,claims.bv,claims.ce,claims.ae,claims.s_iat,claims.s_exp,claims.afg??now),
  store.stmt('INSERT INTO jwt_v2_browsers VALUES(?,?,?,?,0) ON CONFLICT(bsid) DO UPDATE SET bv=excluded.bv,sub=excluded.sub,psid=excluded.psid',claims.bsid,claims.bv,claims.sub,claims.psid)
 ];
 if(installed&&installed.sid!==sid)statements.push(store.stmt("UPDATE jwt_v2_families SET state='REVOKED',cr=cr+1 WHERE sid=? AND state NOT IN('REVOKED','EXPIRED')",installed.sid));
 if(old){
  statements.push(store.stmt('UPDATE jwt_v2_families SET sv=?,ue=?,cr=cr+1,state=?,vat=?,deadline=?,idle_until=?,last_refresh=?,fingerprint=?,fingerprint_generation=fingerprint_generation+1,binding_json=?,projection_json=?,authority_ready=? WHERE sid=?',binding.sv,binding.ue,barrier.state,binding.vat,deadline,barrier.idleUntil,barrier.lastRefresh,fp,canonical(binding),canonical(projection),Number(barrier.state==='UNLOCKED'),sid));
 }else statements.push(store.stmt('INSERT INTO jwt_v2_families(sid,sub,psid,bsid,bv,ce,ae,le,sv,ue,cr,state,s_iat,s_exp,vat,deadline,idle_until,last_refresh,policy_minutes,fingerprint,fingerprint_generation,binding_json,projection_json,authority_ready) VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,1,?,?,?)',sid,binding.sub,binding.psid,binding.bsid,binding.bv,binding.ce,binding.ae,binding.le,binding.sv,binding.ue,barrier.state,binding.s_iat,binding.s_exp,binding.vat,deadline,barrier.idleUntil,barrier.lastRefresh,projection.inactivityMinutes,fp,canonical(binding),canonical(projection),Number(barrier.state==='UNLOCKED')));
 statements.push(bc,pc,ac);
 return {statements,binding,projection,capture,vectorGuards:capture.vectorGuards,result:{sid,sv:binding.sv,ue:binding.ue,le,s_exp:binding.s_exp,state:barrier.state},credentials:{refresh}};
}

export async function beginRootFamily(runtime,{transaction,attempt,credential,current=null}){
 const store=runtime.store,now=runtime.clock(),payload=JSON.parse(transaction.payload_json),result=JSON.parse(attempt.result_json);
 requireThat(result.status==='VERIFIED'&&now<result.expiresAt&&attempt.tx===transaction.tx&&attempt.sub===credential.sub&&credential.active,'FRESH_PIN_REQUIRED',423);
 requireThat(credential.ce===(result.setup?result.setupCommittedCe:attempt.credential_epoch),'CREDENTIAL_CHANGED',409);
 const account=await store.first('SELECT * FROM jwt_v2_accounts WHERE sub=?',credential.sub);
 requireThat(account&&account.ce===credential.ce&&account.ae===payload.ae&&account.active===1,'ROOT_CONTEXT_CHANGED',409);
 const sid=crypto.randomUUID(),bsid=current?.family.bsid||crypto.randomUUID(),bv=current?current.family.bv+1:1;
 const capture=await runtime.nativeCapture({sub:credential.sub,ce:credential.ce}),signedAt=runtime.clock();
 const binding=initialBinding(runtime,{sub:credential.sub,ce:credential.ce,ae:account.ae,le:account.le,psid:sid,bsid,bv,s_iat:signedAt,s_exp:signedAt+604800,capture});
 const projection=await runtime.buildProjection(binding,capture,{initialIssuance:true}),idleUntil=Math.min(binding.s_exp,signedAt+projection.inactivityMinutes*60),deadline=Math.min(capture.vat+900,idleUntil,projection.timedUntil,binding.s_exp),refresh=opaque();
 const [tg,tc]=store.guard("SELECT 1 FROM jwt_v2_http_transactions WHERE tx=? AND status='PENDING' AND operation_id=? AND expires_at>?",[transaction.tx,transaction.operation_id,now]);
 const cg=runtime.native.credentialGuard(credential),[ng,nc]=store.guard(cg.sql,cg.args);
 const [ag,ac]=store.guard('SELECT 1 FROM jwt_v2_accounts WHERE sub=? AND ce=? AND ae=? AND active=1',[binding.sub,binding.ce,binding.ae]);
 const before=[tg,ng,ag],after=[ac,nc,tc];
 if(current){
  const old=current.family;
  const [og,oc]=store.guard("SELECT 1 FROM jwt_v2_families f JOIN jwt_v2_browsers b ON b.bsid=f.bsid WHERE f.sid=? AND f.fingerprint=? AND f.binding_json=? AND f.state IN('UNLOCKED','LOCKED','ADMITTED_LOCKED') AND b.bv=f.bv AND b.sub=f.sub AND b.psid=f.psid AND b.cancelled_through<f.bv",[old.sid,current.fingerprint,old.binding_json]);before.push(og);
  const target={type:'browser',bsid:old.bsid,maxBv:old.bv};
  before.push(...await restrictionPlan(store,{workId:transaction.operation_id,target,now,sub:old.sub}));
  before.push(store.stmt('UPDATE jwt_v2_browsers SET cancelled_through=max(cancelled_through,?) WHERE bsid=?',old.bv,old.bsid));
  before.push(...await browserOutboxPlan(runtime,{target,sub:old.sub,operationId:transaction.operation_id,now}));after.unshift(oc);
 }
 before.push(store.stmt("INSERT INTO jwt_v2_parents VALUES(?,?,?,?,?,?,?,?,?,'UNLOCKED')",sid,binding.sub,bsid,bv,binding.ce,binding.ae,signedAt,binding.s_exp,signedAt));
 before.push(store.stmt('INSERT INTO jwt_v2_browsers VALUES(?,?,?,?,0) ON CONFLICT(bsid) DO UPDATE SET bv=excluded.bv,sub=excluded.sub,psid=excluded.psid',bsid,bv,binding.sub,sid));
 after.unshift(store.stmt("UPDATE jwt_v2_http_transactions SET status='COMMITTED',result_json=? WHERE tx=?",canonical({status:'COMMITTED',sid,operationId:transaction.operation_id,s_exp:binding.s_exp}),transaction.tx));
 await store.createFamily({binding,projection,capture,fingerprint:await fingerprint(refresh,runtime.config),now:signedAt,deadline,idleUntil,policyMinutes:projection.inactivityMinutes,vectorGuards:capture.vectorGuards},{before,after});
 let priorPending=false;if(current)try{priorPending=!await runtime.publishPending(transaction.operation_id);}catch{priorPending=true;}const publication=await runtime.publishWinningFamily(sid,{initial:true});if(priorPending)publication.cachePublication='PENDING';return {family:await store.family(sid),refresh,...publication};
}
export async function browserOutboxPlan(runtime,{target,sub,operationId,now}){
 const store=runtime.store,items=[];
 requireThat(runtime.app==='academy','ACADEMY_OWNER_REQUIRED',503);
 for(const targetApp of ['studio','hifz']){
  const stream=await store.first("SELECT * FROM jwt_v2_sender_streams WHERE target_app=? AND stream='account-security'",targetApp);requireThat(stream,'OUTBOX_STREAM_UNAVAILABLE',503);
  const event={schema:2,env:runtime.config.env,sourceApp:'academy',targetApp,eventId:crypto.randomUUID(),operationId,stream:stream.stream,ownerEpoch:stream.owner_epoch,sequence:stream.next_sequence,sub,kind:'browser-superseded',target,committedAt:now,commitRef:operationId};event.digest=await digest(event);
  const [g,c]=store.guard('SELECT 1 FROM jwt_v2_sender_streams WHERE target_app=? AND stream=? AND owner_epoch=? AND next_sequence=?',[targetApp,stream.stream,stream.owner_epoch,stream.next_sequence]);
  items.push(g,store.stmt('UPDATE jwt_v2_sender_streams SET next_sequence=next_sequence+1 WHERE target_app=? AND stream=?',targetApp,stream.stream),store.stmt('INSERT INTO jwt_v2_outbox(event_id,event_json,digest,target_app) VALUES(?,?,?,?)',event.eventId,canonical(event),event.digest,targetApp),c);
 }
 return items;
}
