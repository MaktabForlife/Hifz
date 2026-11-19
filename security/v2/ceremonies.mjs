import {assertCaptureReceipt} from './capture-receipt.mjs';
import {issuanceFloorGuard} from './issuance-floors.mjs';
import {familyPolicyRegistrationPlan} from './policy.mjs';
import {strictJSON,canonical,requireThat,reject,safeInt,uuid,ascii,opaque,fingerprint,digest,domainDigest,sha256,bytes,b64u,unb64u,equal} from './codec.mjs';
import {admissionFloorGuard} from './publication.mjs';
import {issueToken,verifyToken,ownOrigin,profileConfig} from './tokens.mjs';
export const ceremonySchemaSQL = [
 "CREATE TABLE IF NOT EXISTS jwt_v2_ceremonies(tx TEXT PRIMARY KEY,purpose TEXT NOT NULL,target_app TEXT NOT NULL,sub TEXT,expected_json TEXT,state_hash TEXT NOT NULL,challenge TEXT NOT NULL,callback TEXT NOT NULL,return_to TEXT NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,parent_json TEXT,pin_required INTEGER NOT NULL DEFAULT 0,pin_attempt TEXT,code_hash TEXT,code_expires INTEGER,grant_json TEXT,issue_operation TEXT,redemption_operation TEXT,status TEXT NOT NULL DEFAULT 'PENDING');",
 "CREATE TABLE IF NOT EXISTS jwt_v2_ceremony_attempts(attempt_id TEXT PRIMARY KEY,tx TEXT NOT NULL,sub TEXT NOT NULL,credential_epoch INTEGER NOT NULL,gate_generation INTEGER NOT NULL,csrf_hash TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN('ISSUED','RESERVED','DONE','CANCELLED')),result_json TEXT,expires_at INTEGER NOT NULL);",
 "CREATE TABLE IF NOT EXISTS jwt_v2_ceremony_budgets(kind TEXT NOT NULL,budget_key TEXT NOT NULL,tokens_milli INTEGER NOT NULL,last_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,PRIMARY KEY(kind,budget_key));",
 "CREATE TABLE IF NOT EXISTS jwt_v2_ceremony_reservations(attempt_id TEXT PRIMARY KEY,source_key TEXT NOT NULL,sub TEXT NOT NULL,expires_at INTEGER NOT NULL);",
 "CREATE INDEX IF NOT EXISTS jwt_v2_ceremony_source_capacity ON jwt_v2_ceremony_reservations(source_key,expires_at);",
 "CREATE TABLE IF NOT EXISTS jwt_v2_ceremony_pending(tx TEXT PRIMARY KEY,purpose TEXT NOT NULL,expected_json TEXT,sub TEXT,expires_at INTEGER NOT NULL,csrf_hash TEXT NOT NULL,operation_id TEXT NOT NULL UNIQUE,status TEXT NOT NULL DEFAULT 'PENDING');",
 "CREATE TABLE IF NOT EXISTS jwt_v2_ceremony_barriers(psid TEXT NOT NULL,bsid TEXT NOT NULL,bv INTEGER NOT NULL,sub TEXT NOT NULL,last_refresh INTEGER NOT NULL,idle_until INTEGER NOT NULL,locked INTEGER NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(psid,bsid,bv,sub));",
 "CREATE TABLE IF NOT EXISTS jwt_v2_ceremony_consumed(jti TEXT PRIMARY KEY,tx TEXT NOT NULL UNIQUE,operation_id TEXT NOT NULL UNIQUE,grant_digest TEXT NOT NULL,result_json TEXT NOT NULL,consumed_at INTEGER NOT NULL);"
].join('\n');
const TYPES=['admission','unlock'];
const APP=['studio','hifz'];
const FIELDS='app sub sid psid bsid bv ce ae le sv ue'.split(' ');
const BIND='sub psid bsid bv ce ae s_iat s_exp'.split(' ');
const noCookies=result=>({...result,winner:false,cookies:false});
const resultJSON=result=>canonical(result);
const atLeast=(value,min=0)=>requireThat(safeInt(value,min),'INVALID_COUNTER',400);
export function normalizePlatformAddress(address){
 requireThat(typeof address==='string'&&address.length<=64,'SOURCE_ADDRESS_UNAVAILABLE',503);
 if(address.includes(':')){
  let host;try{host=new URL('http://['+address+']/').hostname;}catch{reject('SOURCE_ADDRESS_UNAVAILABLE',503);}
  requireThat(host.startsWith('[')&&host.endsWith(']'),'SOURCE_ADDRESS_UNAVAILABLE',503);return host.slice(1,-1);
 }
 const parts=address.split('.');requireThat(parts.length===4&&parts.every(p=>/^(?:0|[1-9][0-9]{0,2})$/.test(p)&&Number(p)<=255),'SOURCE_ADDRESS_UNAVAILABLE',503);
 return parts.join('.');
}
export const s256=async verifier=>{unb64u(verifier,32);return b64u(await sha256(bytes(verifier)));};
export function pinPauseSeconds(failures){atLeast(failures);return failures<5?0:failures===5?900:failures===6?1800:3600;}
export function admissionBarrier({existing,afg,now,policyMinutes,s_exp}){
 atLeast(now);atLeast(afg);requireThat(safeInt(policyMinutes,15)&&policyMinutes<=200&&safeInt(s_exp)&&afg<=now,'INVALID_ADMISSION_CLOCK',400);
 const lastRefresh=existing?existing.lastRefresh:afg;
 requireThat(safeInt(lastRefresh)&&lastRefresh<=now,'INVALID_ADMISSION_CLOCK',400);
 // Existing expiry/lock is tested before applying any new policy or crediting a visit.
 const elapsed=existing&&(existing.locked||now>=Math.min(existing.idleUntil,s_exp));
 const idleUntil=Math.min(s_exp,lastRefresh+policyMinutes*60);
 return {lastRefresh,idleUntil,locked:Boolean(elapsed||now>=idleUntil),state:elapsed||now>=idleUntil?'ADMITTED_LOCKED':'UNLOCKED'};
}
function exactSelector(value,app){
 requireThat(value&&Object.keys(value).length===FIELDS.length&&FIELDS.every(k=>Object.hasOwn(value,k))&&value.app===app,'INVALID_EXPECTED_CONTEXT',400);
 requireThat(typeof value.sub==='string'&&bytes(value.sub).length>0&&bytes(value.sub).length<=180&&['sid','psid','bsid'].every(k=>uuid(value[k]))&&['bv','ce','ae','sv'].every(k=>safeInt(value[k],1))&&['le','ue'].every(k=>safeInt(value[k])),'INVALID_EXPECTED_CONTEXT',400);
 return value;
}
function sameBinding(a,b,fields=BIND){return fields.every(k=>a?.[k]===b?.[k]);}
function callbackAllowed(registry,app,value,key){
 const list=registry[app]?.[key];requireThat(Array.isArray(list)&&list.includes(value),'UNREGISTERED_CALLBACK',400);
 const u=new URL(value);requireThat(u.origin===registry[app].origin&&!u.username&&!u.password&&!u.hash&&!u.search,'UNREGISTERED_CALLBACK',400);
}
function accountSnapshot(s){
 requireThat(s&&typeof s.sub==='string'&&safeInt(s.ce,1)&&safeInt(s.generation,1)&&typeof s.active==='boolean'&&typeof s.setupComplete==='boolean'&&ascii(String(s.revision)),'CREDENTIAL_UNAVAILABLE',503);
 return s;
}
export class AcademyCeremonies {
 constructor({store,config,callbacks,clock,credentialSnapshot,credentialGuard,verifyPin,setupPlan,authorisePinRequest,attestedSource,authoriseChild,parentEligibility,parentGuard,signingKey,kid}){
  requireThat(store.app==='academy'&&config.app==='academy','ACADEMY_PIN_ONLY',503);
  for(const cb of [clock,credentialSnapshot,credentialGuard,verifyPin,authorisePinRequest,attestedSource,authoriseChild,parentEligibility,parentGuard])requireThat(typeof cb==='function','CEREMONY_ADAPTER_REQUIRED',503);
  Object.assign(this,{store,config,callbacks,clock,credentialSnapshot,credentialGuard,verifyPin,setupPlan,authorisePinRequest,attestedSource,authoriseChild,parentEligibility,parentGuard,signingKey,kid});
 }
 async pinRequest(request,tx){
  ownOrigin(request,this.config);requireThat(request.headers.get('X-UAA-Request')==='2','CEREMONY_HEADER_REQUIRED',403);
  const authorisation=await this.authorisePinRequest(request,tx);
  requireThat(authorisation&&/^[0-9a-f]{64}$/.test(authorisation.csrfHash),'CEREMONY_CSRF',403);return authorisation;
 }
 async register({request,tx,purpose,targetApp,expected=null,stateHash,challenge,callback,returnTo}){
  const now=this.clock();atLeast(now);requireThat(uuid(tx)&&TYPES.includes(purpose)&&APP.includes(targetApp),'INVALID_CEREMONY',400);
  requireThat(await this.authoriseChild(request,targetApp),'CHILD_SERVICE_AUTH_REQUIRED',401);
  requireThat(/^[0-9a-f]{64}$/.test(stateHash),'INVALID_STATE_HASH',400);unb64u(challenge,32);
  callbackAllowed(this.callbacks,targetApp,callback,'callbacks');callbackAllowed(this.callbacks,targetApp,returnTo,'returns');
  if(expected!==null)exactSelector(expected,targetApp);
  if(purpose==='unlock')requireThat(expected,'UNLOCK_CONTEXT_REQUIRED',400);
  const record={tx,purpose,targetApp,expected,stateHash,challenge,callback,returnTo,createdAt:now,expiresAt:now+300};
  const old=await this.store.first('SELECT * FROM jwt_v2_ceremonies WHERE tx=?',tx);
  if(old){
   requireThat(old.purpose===purpose&&old.target_app===targetApp&&old.expected_json===(expected===null?null:canonical(expected))&&old.state_hash===stateHash&&old.challenge===challenge&&old.callback===callback&&old.return_to===returnTo,'CEREMONY_CONFLICT',409);
   return {tx,expiresAt:old.expires_at,status:old.status};
  }
  await this.store.stmt('INSERT INTO jwt_v2_ceremonies(tx,purpose,target_app,expected_json,state_hash,challenge,callback,return_to,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)',tx,purpose,targetApp,expected===null?null:canonical(expected),stateHash,challenge,callback,returnTo,now,now+300).run();
  return {tx,expiresAt:now+300,status:'PENDING'};
 }
 async bindParent({request,tx,sub,pinRequired}){
  await this.pinRequest(request,tx);const now=this.clock(),ceremony=await this.store.first('SELECT * FROM jwt_v2_ceremonies WHERE tx=?',tx);
  requireThat(ceremony&&ceremony.status==='PENDING'&&now<ceremony.expires_at,'CEREMONY_EXPIRED',409);
  const credential=accountSnapshot(await this.credentialSnapshot(sub)),parent=await this.parentEligibility({request,sub,tx,purpose:ceremony.purpose,targetApp:ceremony.target_app,expected:ceremony.expected_json&&JSON.parse(ceremony.expected_json)});
  requireThat(credential.active&&parent&&parent.sub===sub&&parent.ce===credential.ce&&safeInt(parent.ae,1)&&uuid(parent.psid)&&uuid(parent.bsid)&&safeInt(parent.bv,1)&&safeInt(parent.s_iat)&&parent.s_exp===parent.s_iat+604800&&now<parent.s_exp&&safeInt(parent.afg)&&parent.s_iat<=parent.afg&&parent.afg<=now,'PARENT_INELIGIBLE',401);
  requireThat(typeof pinRequired==='boolean'&&(ceremony.purpose!=='unlock'||pinRequired),'INVALID_PIN_REQUIREMENT',400);
  if(ceremony.purpose==='unlock')requireThat(sameBinding(JSON.parse(ceremony.expected_json),parent,['sub','psid','bsid','bv','ce','ae']),'UNLOCK_CONTEXT_CONFLICT',409);
  if(ceremony.sub)requireThat(ceremony.sub===sub&&sameBinding(JSON.parse(ceremony.parent_json),parent)&&ceremony.pin_required===Number(pinRequired),'CEREMONY_CONTEXT_CHANGED',409);
  const pinned=ceremony.parent_json?JSON.parse(ceremony.parent_json):parent;
  const [g,clear]=this.store.guard("SELECT 1 FROM jwt_v2_ceremonies WHERE tx=? AND status='PENDING' AND expires_at>? AND (sub IS NULL OR (sub=? AND parent_json=? AND pin_required=?))",[tx,now,sub,canonical(pinned),Number(pinRequired)]);
  const native=this.credentialGuard(credential),pg=this.parentGuard(parent);
  const [cg,cc]=this.store.guard(native.sql,native.args),[pguard,pc]=this.store.guard(pg.sql,pg.args);
  await this.store.batch([g,cg,pguard,this.store.stmt('UPDATE jwt_v2_ceremonies SET sub=?,parent_json=?,pin_required=?,expires_at=min(expires_at,?) WHERE tx=?',sub,canonical(pinned),Number(pinRequired),parent.s_exp,tx),pc,cc,clear]);
  return {tx,expiresAt:Math.min(ceremony.expires_at,parent.s_exp),pinRequired};
 }
 async issueAttempt({request,tx}){
  const auth=await this.pinRequest(request,tx),now=this.clock(),ceremony=await this.store.first('SELECT * FROM jwt_v2_ceremonies WHERE tx=?',tx);
  requireThat(ceremony&&ceremony.status==='PENDING'&&ceremony.sub&&now<ceremony.expires_at,'CEREMONY_EXPIRED',409);
  const c=accountSnapshot(await this.credentialSnapshot(ceremony.sub));requireThat(c.active,'ACCOUNT_INACTIVE',401);
  await this.store.stmt('INSERT INTO jwt_v2_pin_gates(sub,generation) VALUES(?,?) ON CONFLICT(sub) DO NOTHING',c.sub,c.generation).run();
  const gate=await this.store.first('SELECT * FROM jwt_v2_pin_gates WHERE sub=?',c.sub);
  requireThat(gate.generation===c.generation,'CREDENTIAL_CHANGED',409);
  const id=crypto.randomUUID(),expires=Math.min(ceremony.expires_at,now+300);
  await this.store.stmt("INSERT INTO jwt_v2_ceremony_attempts VALUES(?,?,?,?,?,?,'ISSUED',NULL,?)",id,tx,c.sub,c.ce,c.generation,auth.csrfHash,expires).run();
  return {attemptId:id,expiresAt:expires};
 }
 async verify({request,tx,attemptId,pin,confirmation,setup=false}){
  requireThat(uuid(attemptId)&&typeof pin==='string'&&/^[0-9]{4}$/.test(pin),'INVALID_PIN_FORMAT',400);
  if(setup)requireThat(typeof confirmation==='string'&&/^[0-9]{4}$/.test(confirmation)&&pin===confirmation,'PIN_CONFIRMATION_MISMATCH',400);
  const auth=await this.pinRequest(request,tx);let now=this.clock();atLeast(now);
  let attempt=await this.store.first('SELECT * FROM jwt_v2_ceremony_attempts WHERE attempt_id=?',attemptId);
  requireThat(attempt&&attempt.tx===tx&&equal(attempt.csrf_hash,auth.csrfHash),'UNISSUED_PIN_ATTEMPT',403);
  if(attempt.status==='DONE')return JSON.parse(attempt.result_json);
  requireThat(attempt.status!=='CANCELLED','CREDENTIAL_CHANGED',409);
  requireThat(attempt.status==='ISSUED'&&now<attempt.expires_at,'PIN_BUSY',503);
  let ceremony=await this.store.first('SELECT * FROM jwt_v2_ceremonies WHERE tx=?',tx);
  requireThat(ceremony&&ceremony.status==='PENDING'&&ceremony.sub===attempt.sub&&now<ceremony.expires_at,'CEREMONY_EXPIRED',409);
  const c=accountSnapshot(await this.credentialSnapshot(attempt.sub));
  requireThat(c.active&&c.ce===attempt.credential_epoch&&c.generation===attempt.gate_generation,'CREDENTIAL_CHANGED',409);
  requireThat(setup?!c.setupComplete:c.setupComplete,setup?'PIN_SETUP_NOT_ELIGIBLE':'PIN_SETUP_REQUIRED',409);
  if(setup)requireThat(typeof this.setupPlan==='function','PIN_SETUP_ADAPTER_REQUIRED',503);
  let gate=await this.store.first('SELECT * FROM jwt_v2_pin_gates WHERE sub=?',attempt.sub);
  requireThat(gate&&gate.generation===c.generation,'CREDENTIAL_CHANGED',409);
  requireThat(now>=gate.paused_until,'PIN_PAUSED',429);
  requireThat(!gate.reservation||now>=gate.reservation_until,'PIN_BUSY',503);
  const attested=await this.attestedSource(request);
  requireThat(attested?.kind==='platform','SOURCE_ADDRESS_UNAVAILABLE',503);
  const sourceKey=await domainDigest('uaa-pin-source-v2',{env:this.config.env,address:normalizePlatformAddress(attested.address)});
  const capacity=await this.store.first('SELECT count(*) n FROM jwt_v2_ceremony_reservations WHERE source_key=? AND expires_at>?',sourceKey,now);
  requireThat(capacity.n<2,'REQUEST_RATE_LIMITED',429);
  for(const [kind,key,limit] of [['source',sourceKey,10000],['ceremony',tx,5000]])await this.store.stmt('INSERT INTO jwt_v2_ceremony_budgets VALUES(?,?,?,?,?) ON CONFLICT(kind,budget_key) DO NOTHING',kind,key,limit,now,now+120).run();
  const [g,clear]=this.store.guard("SELECT 1 FROM jwt_v2_pin_gates g JOIN jwt_v2_ceremony_attempts a ON a.sub=g.sub JOIN jwt_v2_ceremonies c ON c.tx=a.tx WHERE g.sub=? AND g.generation=? AND g.paused_until<=? AND (g.reservation IS NULL OR g.reservation_until<=?) AND a.attempt_id=? AND a.status='ISSUED' AND a.expires_at>? AND c.status='PENDING' AND c.expires_at>? AND (SELECT count(*) FROM jwt_v2_ceremony_reservations WHERE source_key=? AND expires_at>?)<2 AND (SELECT min(10000,tokens_milli+max(0,?-last_at)*1000) FROM jwt_v2_ceremony_budgets WHERE kind='source' AND budget_key=?)>=1000 AND (SELECT min(5000,tokens_milli+max(0,?-last_at)*100) FROM jwt_v2_ceremony_budgets WHERE kind='ceremony' AND budget_key=?)>=1000",[attempt.sub,c.generation,now,now,attemptId,now,now,sourceKey,now,now,sourceKey,now,tx]);
  const native=this.credentialGuard(c),[cg,cc]=this.store.guard(native.sql,native.args);
  try{
   await this.store.batch([g,cg,
    this.store.stmt("UPDATE jwt_v2_ceremony_budgets SET tokens_milli=min(10000,tokens_milli+max(0,?-last_at)*1000)-1000,last_at=?,expires_at=? WHERE kind='source' AND budget_key=?",now,now,now+120,sourceKey),
    this.store.stmt("UPDATE jwt_v2_ceremony_budgets SET tokens_milli=min(5000,tokens_milli+max(0,?-last_at)*100)-1000,last_at=?,expires_at=? WHERE kind='ceremony' AND budget_key=?",now,now,now+120,tx),
    this.store.stmt('DELETE FROM jwt_v2_ceremony_reservations WHERE expires_at<=?',now),
    this.store.stmt('INSERT INTO jwt_v2_ceremony_reservations VALUES(?,?,?,?)',attemptId,sourceKey,attempt.sub,now+5),
    this.store.stmt('UPDATE jwt_v2_pin_gates SET reservation=?,reservation_until=? WHERE sub=?',attemptId,now+5,attempt.sub),
    this.store.stmt("UPDATE jwt_v2_ceremony_attempts SET status='RESERVED' WHERE attempt_id=?",attemptId),cc,clear
   ]);
  }catch(error){
   gate=await this.store.first('SELECT * FROM jwt_v2_pin_gates WHERE sub=?',attempt.sub);
   if(gate?.paused_until>now)reject('PIN_PAUSED',429);
   if(gate?.generation!==c.generation)reject('CREDENTIAL_CHANGED',409);
   if(gate?.reservation&&gate.reservation_until>now)reject('PIN_BUSY',503);
   reject('REQUEST_RATE_LIMITED',429);
  }
  gate=await this.store.first('SELECT * FROM jwt_v2_pin_gates WHERE sub=?',attempt.sub);
  let verified=false,setupStatements=[];
  try{
   const fresh=accountSnapshot(await this.credentialSnapshot(attempt.sub));
   requireThat(canonical(fresh)===canonical(c),'CREDENTIAL_CHANGED',409);
   if(setup){const plan=await this.setupPlan({credential:c,pin});requireThat(plan&&Array.isArray(plan.statements),'PIN_SETUP_ADAPTER_REQUIRED',503);setupStatements=plan.statements;verified=true;}
   else verified=await this.verifyPin(pin,c);
   requireThat(typeof verified==='boolean','PIN_VERIFIER_UNAVAILABLE',503);
  }catch(error){
   await this.finishUnavailable({attempt,c,now:this.clock(),code:error.code||'PIN_VERIFIER_UNAVAILABLE'});
   throw error;
  }
  now=this.clock();
  const fresh=accountSnapshot(await this.credentialSnapshot(attempt.sub));requireThat(canonical(fresh)===canonical(c),'CREDENTIAL_CHANGED',409);
  requireThat(safeInt(gate.failures)&&safeInt(gate.failures+1),'PIN_COUNTER_EXHAUSTED',503);
  const wrong=gate.failures+1,pause=verified?0:pinPauseSeconds(wrong);
  const result=verified?{status:'VERIFIED',attemptId,tx,verifiedAt:now,expiresAt:Math.min(now+60,ceremony.expires_at),setup}:{status:pause?'PIN_PAUSED':'WRONG_PIN',attemptId,failures:wrong,pausedUntil:pause?now+pause:0};
  const currentParent=ceremony.parent_json?await this.parentEligibility({request,sub:attempt.sub,tx,purpose:ceremony.purpose,targetApp:ceremony.target_app,expected:ceremony.expected_json&&JSON.parse(ceremony.expected_json)}):null;
  if(ceremony.parent_json)requireThat(sameBinding(currentParent,JSON.parse(ceremony.parent_json))&&now<currentParent.s_exp,'PARENT_CHANGED',409);
  const grant=verified&&TYPES.includes(ceremony.purpose)?this.grantClaims(ceremony,currentParent,now):null;
  const credentialCas=this.credentialGuard(c),[fg,fc]=this.store.guard("SELECT 1 FROM jwt_v2_pin_gates g JOIN jwt_v2_ceremony_attempts a ON a.sub=g.sub JOIN jwt_v2_ceremonies c ON c.tx=a.tx WHERE g.sub=? AND g.generation=? AND g.reservation=? AND g.reservation_until>? AND g.paused_until<=? AND a.attempt_id=? AND a.status='RESERVED' AND c.status='PENDING' AND c.expires_at>?",[attempt.sub,c.generation,attemptId,now,now,attemptId,now]);
  const [ng,nc]=this.store.guard(credentialCas.sql,credentialCas.args);
  const parentCas=currentParent?this.parentGuard(currentParent):null;
  const parentChecks=parentCas?this.store.guard(parentCas.sql,parentCas.args):[];
  try{
   await this.store.batch([fg,ng,...(parentChecks.length?[parentChecks[0]]:[]),...setupStatements,
    this.store.stmt('UPDATE jwt_v2_pin_gates SET failures=?,paused_until=?,reservation=NULL,reservation_until=NULL WHERE sub=?',verified?0:wrong,verified?0:result.pausedUntil,attempt.sub),
    this.store.stmt("UPDATE jwt_v2_ceremony_attempts SET status='DONE',result_json=? WHERE attempt_id=?",resultJSON(result),attemptId),
    this.store.stmt('DELETE FROM jwt_v2_ceremony_reservations WHERE attempt_id=?',attemptId),
    ...(verified?[this.store.stmt('UPDATE jwt_v2_ceremonies SET pin_attempt=?,grant_json=? WHERE tx=?',attemptId,grant===null?null:canonical(grant),tx)]:[]),...(parentChecks.length?[parentChecks[1]]:[]),nc,fc
   ]);
   return result;
  }catch(error){await this.finishUnavailable({attempt,c,now,code:'PIN_RESULT_NOT_COMMITTED'});reject('PIN_RESULT_NOT_COMMITTED',503);}
 }
 async finishUnavailable({attempt,c,now,code}){
  const result={status:'UNAVAILABLE',attemptId:attempt.attempt_id,code};
  await this.store.batch([
   this.store.stmt("UPDATE jwt_v2_ceremony_attempts SET status='DONE',result_json=? WHERE attempt_id=? AND status='RESERVED'",resultJSON(result),attempt.attempt_id),
   this.store.stmt('UPDATE jwt_v2_pin_gates SET reservation=NULL,reservation_until=NULL WHERE sub=? AND generation=? AND reservation=?',attempt.sub,c.generation,attempt.attempt_id),
   this.store.stmt('DELETE FROM jwt_v2_ceremony_reservations WHERE attempt_id=?',attempt.attempt_id)
  ]);
 }
 async pruneAbuseMetadata(){
  const now=this.clock();
  await this.store.batch([this.store.stmt('DELETE FROM jwt_v2_ceremony_budgets WHERE expires_at<=?',now),this.store.stmt('DELETE FROM jwt_v2_ceremony_reservations WHERE expires_at<=?',now)]);
 }
 resetPlan({sub,newGeneration,newCe,operationId}){
  requireThat(uuid(operationId)&&safeInt(newGeneration,1)&&safeInt(newCe,1),'INVALID_RESET_PLAN',400);
  // Compose these statements inside the existing authorised native reset/epoch/outbox batch.
  return [
   this.store.stmt('INSERT INTO jwt_v2_pin_gates(sub,generation) VALUES(?,?) ON CONFLICT(sub) DO UPDATE SET generation=excluded.generation,failures=0,paused_until=0,reservation=NULL,reservation_until=NULL WHERE generation<excluded.generation',sub,newGeneration),
   this.store.stmt("UPDATE jwt_v2_ceremonies SET status='CANCELLED' WHERE sub=? AND status IN('PENDING','CODE_ISSUED','GRANTED')",sub),
   this.store.stmt("UPDATE jwt_v2_ceremony_attempts SET status='CANCELLED' WHERE sub=? AND status IN('ISSUED','RESERVED')",sub),
   this.store.stmt('DELETE FROM jwt_v2_ceremony_reservations WHERE sub=?',sub),
   this.store.stmt("UPDATE jwt_v2_families SET state='REVOKED',cr=cr+1 WHERE sub=? AND ce<? AND state NOT IN('REVOKED','EXPIRED')",sub,newCe),
   this.store.stmt("UPDATE jwt_v2_parents SET state='REVOKED' WHERE sub=? AND ce<?",sub,newCe),
   this.store.stmt("UPDATE jwt_v2_intents SET state='CANCELLED',superseding_operation=? WHERE state='ISSUED' AND sid IN(SELECT sid FROM jwt_v2_families WHERE sub=? AND ce<?)",operationId,sub,newCe)
  ];
 }

 async startRootPin({request,tx,sub,returnTo}){
  requireThat(uuid(tx),'INVALID_CEREMONY',400);await this.pinRequest(request,tx);
  const c=accountSnapshot(await this.credentialSnapshot(sub));requireThat(c.active,'ACCOUNT_INACTIVE',401);
  requireThat(this.callbacks.academy?.returns?.includes(returnTo),'UNREGISTERED_RETURN',400);
  const now=this.clock(),old=await this.store.first('SELECT * FROM jwt_v2_ceremonies WHERE tx=?',tx);
  if(old){requireThat(old.sub===sub&&old.purpose==='signin'&&old.return_to===returnTo,'CEREMONY_CONFLICT',409);return {tx,expiresAt:old.expires_at};}
  await this.store.stmt("INSERT INTO jwt_v2_ceremonies(tx,purpose,target_app,sub,state_hash,challenge,callback,return_to,created_at,expires_at,pin_required) VALUES(?,'signin','academy',?,'','',?,?,?, ?,1)",tx,sub,this.config.origin+'/auth/v2/pin',returnTo,now,now+300).run();
  return {tx,expiresAt:now+300};
 }
 grantClaims(ceremony,parent,now){
  requireThat(parent&&now<parent.s_exp,'PARENT_EXPIRED',401);
  const c={ver:2,env:this.config.env,iss:this.config.origin,aud:'urn:uaa:'+this.config.env+':'+ceremony.target_app+':'+ceremony.purpose+':v2',sub:parent.sub,psid:parent.psid,bsid:parent.bsid,bv:parent.bv,ce:parent.ce,ae:parent.ae,s_iat:parent.s_iat,s_exp:parent.s_exp,tx:ceremony.tx,jti:crypto.randomUUID(),iat:now,exp:Math.min(now+60,parent.s_exp)};
  if(ceremony.purpose==='admission')c.afg=parent.afg;
  else{const expected=JSON.parse(ceremony.expected_json);for(const key of ['sid','le','sv','ue'])c[key]=expected[key];}
  return c;
 }
 async issueCode({request,tx,state,operationId}){
  requireThat(uuid(operationId),'UNISSUED_OPERATION',400);await this.pinRequest(request,tx);unb64u(state,32);
  const now=this.clock(),c=await this.store.first('SELECT * FROM jwt_v2_ceremonies WHERE tx=?',tx);
  requireThat(c&&TYPES.includes(c.purpose)&&c.sub&&now<c.expires_at,'CEREMONY_EXPIRED',409);
  requireThat(equal(await digestState(state),c.state_hash),'STATE_CONFLICT',403);
  if(c.status!=='PENDING')return noCookies({status:'CODE_ALREADY_ISSUED',tx});
  const parent=await this.parentEligibility({request,sub:c.sub,tx,purpose:c.purpose,targetApp:c.target_app,expected:c.expected_json&&JSON.parse(c.expected_json)});
  requireThat(sameBinding(parent,JSON.parse(c.parent_json))&&now<parent.s_exp,'PARENT_CHANGED',401);
  let grant=c.grant_json&&JSON.parse(c.grant_json);
  if(c.pin_required){
   const attempt=c.pin_attempt&&await this.store.first('SELECT * FROM jwt_v2_ceremony_attempts WHERE attempt_id=?',c.pin_attempt);
   const result=attempt?.result_json&&JSON.parse(attempt.result_json);
   requireThat(attempt?.status==='DONE'&&result?.status==='VERIFIED'&&result.tx===tx&&now<result.expiresAt&&grant&&now<grant.exp,'FRESH_PIN_REQUIRED',423);
  }else grant=grant||this.grantClaims(c,parent,now);
  requireThat(sameBinding(grant,parent),'GRANT_BINDING_CONFLICT',409);
  const code=opaque(),codeHash=await domainDigest('uaa-code-v2',{env:this.config.env,target:c.target_app,code}),deadline=Math.min(now+60,c.expires_at,parent.s_exp,grant.exp);
  const [g,clear]=this.store.guard("SELECT 1 FROM jwt_v2_ceremonies WHERE tx=? AND status='PENDING' AND expires_at>? AND parent_json=?",[tx,now,c.parent_json]);
  const credential=accountSnapshot(await this.credentialSnapshot(c.sub));requireThat(credential.active&&credential.ce===grant.ce,'CREDENTIAL_CHANGED',409);
  const pg=this.parentGuard(parent),cg=this.credentialGuard(credential),[pguard,pc]=this.store.guard(pg.sql,pg.args),[cguard,cc]=this.store.guard(cg.sql,cg.args);
  try{
   await this.store.batch([g,pguard,cguard,this.store.stmt("UPDATE jwt_v2_ceremonies SET code_hash=?,code_expires=?,grant_json=?,issue_operation=?,status='CODE_ISSUED' WHERE tx=?",codeHash,deadline,canonical(grant),operationId,tx),cc,pc,clear]);
  }catch(error){
   const current=await this.store.first('SELECT status FROM jwt_v2_ceremonies WHERE tx=?',tx);
   if(['CODE_ISSUED','GRANTED'].includes(current?.status))return noCookies({status:'CODE_ALREADY_ISSUED',tx});
   throw error;
  }
  return {winner:true,cookies:false,tx,code,state,callback:c.callback,expiresAt:deadline};
 }
 async redeem({request,tx,targetApp,purpose,operationId,code,verifier}){
  requireThat(uuid(operationId)&&TYPES.includes(purpose)&&APP.includes(targetApp),'INVALID_REDEMPTION',400);
  requireThat(await this.authoriseChild(request,targetApp),'CHILD_SERVICE_AUTH_REQUIRED',401);unb64u(code,32);unb64u(verifier,32);
  const now=this.clock(),c=await this.store.first('SELECT * FROM jwt_v2_ceremonies WHERE tx=?',tx);
  requireThat(c&&c.purpose===purpose&&c.target_app===targetApp&&['CODE_ISSUED','GRANTED'].includes(c.status)&&now<c.expires_at&&now<c.code_expires,'CODE_EXPIRED',409);
  requireThat(equal(await s256(verifier),c.challenge)&&equal(await domainDigest('uaa-code-v2',{env:this.config.env,target:targetApp,code}),c.code_hash),'CODE_BINDING_CONFLICT',403);
  const grant=JSON.parse(c.grant_json);requireThat(now<grant.exp,'GRANT_EXPIRED',409);
  const parent=await this.parentEligibility({request,sub:c.sub,tx,purpose,targetApp,expected:c.expected_json&&JSON.parse(c.expected_json)});
  requireThat(sameBinding(parent,grant)&&now<parent.s_exp,'PARENT_CHANGED',401);
  const credential=accountSnapshot(await this.credentialSnapshot(c.sub));requireThat(credential.active&&credential.ce===grant.ce,'CREDENTIAL_CHANGED',409);
  if(c.redemption_operation)requireThat(c.redemption_operation===operationId,'CODE_ALREADY_CONSUMED',409);
  const [g,clear]=this.store.guard("SELECT 1 FROM jwt_v2_ceremonies WHERE tx=? AND purpose=? AND target_app=? AND code_hash=? AND grant_json=? AND code_expires>? AND expires_at>? AND status IN('CODE_ISSUED','GRANTED') AND (redemption_operation IS NULL OR redemption_operation=?)",[tx,purpose,targetApp,c.code_hash,c.grant_json,now,now,operationId]);
  const pg=this.parentGuard(parent),cg=this.credentialGuard(credential),[pguard,pc]=this.store.guard(pg.sql,pg.args),[cguard,cc]=this.store.guard(cg.sql,cg.args);
  try{
   await this.store.batch([g,pguard,cguard,this.store.stmt("UPDATE jwt_v2_ceremonies SET redemption_operation=?,status='GRANTED' WHERE tx=?",operationId,tx),cc,pc,clear]);
  }catch(error){
   const current=await this.store.first('SELECT redemption_operation FROM jwt_v2_ceremonies WHERE tx=?',tx);
   if(current?.redemption_operation&&current.redemption_operation!==operationId)reject('CODE_ALREADY_CONSUMED',409);
   throw error;
  }
  const childConfig=profileConfig({app:targetApp,env:this.config.env,origin:this.callbacks[targetApp].origin,academyOrigin:this.config.origin});
  const proof=await issueToken(grant,{profile:purpose,config:childConfig,key:this.signingKey,kid:this.kid,now});
  return {proof,tx,operationId,grantId:grant.jti,expiresAt:grant.exp};
 }

}

export const digestState=async state=>{unb64u(state,32);return Array.from(await sha256(bytes(state)),v=>v.toString(16).padStart(2,'0')).join('');};
/**
 * Guarded child primitive. HTTP authentication/CSRF/native identity and authority
 * readers remain required adapters; this class never verifies a child's PIN.
 * prepareTransition must be pure planning, returning D1 statements, safe result,
 * and transient credentials. Grant consumption and the native transition share
 * one batch. No raw proof, code, refresh or successor is stored here.
 */
export class LocalCeremonyConsumer {
 constructor({store,config,keys,clock,authoriseRequest,readInstalled,mappingGuard,prepareTransition,policyMinutes=90}){
  requireThat(APP.includes(store.app)&&store.app===config.app&&TYPES.every(Boolean),'CHILD_CONSUMER_ONLY',503);
  for(const cb of [clock,authoriseRequest,readInstalled,mappingGuard,prepareTransition])requireThat(typeof cb==='function','CEREMONY_ADAPTER_REQUIRED',503);
  requireThat(safeInt(policyMinutes,15)&&policyMinutes<=200,'INVALID_POLICY',503);
  Object.assign(this,{store,config,keys,clock,authoriseRequest,readInstalled,mappingGuard,prepareTransition,policyMinutes});
 }
 async request(request,tx){
  ownOrigin(request,this.config);requireThat(request.headers.get('X-UAA-Request')==='2','CEREMONY_HEADER_REQUIRED',403);
  const r=await this.authoriseRequest(request,tx);requireThat(r&&/^[0-9a-f]{64}$/.test(r.csrfHash),'CEREMONY_CSRF',403);return r;
 }
 async registerPending({request,tx,purpose,expected=null,operationId,expiresAt}){
  const a=await this.request(request,tx),now=this.clock();requireThat(uuid(tx)&&uuid(operationId)&&TYPES.includes(purpose)&&safeInt(expiresAt)&&expiresAt>now&&expiresAt<=now+300,'INVALID_PENDING_CEREMONY',400);
  if(expected!==null)exactSelector(expected,this.config.app);
  const installed=await this.readInstalled(request);
  requireThat(expected===null?!installed:installed&&FIELDS.every(k=>installed[k]===expected[k]),'INSTALLED_CONTEXT_CONFLICT',409);
  if(purpose==='unlock')requireThat(installed&&expected&&uuid(expected.sid),'UNLOCK_CONTEXT_REQUIRED',409);
  const existing=await this.store.first('SELECT * FROM jwt_v2_ceremony_pending WHERE tx=?',tx);
  if(existing){requireThat(existing.expected_json===(expected===null?null:canonical(expected))&&existing.operation_id===operationId&&existing.purpose===purpose&&equal(existing.csrf_hash,a.csrfHash),'PENDING_CEREMONY_CONFLICT',409);return {tx,expiresAt:existing.expires_at};}
  const intentPlan=[];
  if(purpose==='unlock'){
   const family=await this.store.family(installed.sid);
   requireThat(family&&family.fingerprint===installed.fingerprint&&['LOCKED','ADMITTED_LOCKED'].includes(family.state),'UNLOCK_CONTEXT_CONFLICT',409);
   intentPlan.push(this.store.stmt("INSERT INTO jwt_v2_intents(intent_id,sid,kind,binding_json,csrf_hash,generation,state,expires_at) VALUES(?,?,'unlock',?,?,?,'ISSUED',?)",operationId,installed.sid,family.binding_json,a.csrfHash,family.fingerprint_generation,Math.min(expiresAt,family.s_exp)));
  }
  await this.store.batch([...intentPlan,this.store.stmt("INSERT INTO jwt_v2_ceremony_pending(tx,purpose,expected_json,sub,expires_at,csrf_hash,operation_id) VALUES(?,?,?,?,?,?,?)",tx,purpose,expected===null?null:canonical(expected),expected?.sub||null,expiresAt,a.csrfHash,operationId)]);
  return {tx,expiresAt};
 }
 async consume({request,tx,operationId,proof}){
  const auth=await this.request(request,tx),now=this.clock(),pending=await this.store.first('SELECT * FROM jwt_v2_ceremony_pending WHERE tx=?',tx);
  requireThat(pending&&pending.operation_id===operationId&&equal(auth.csrfHash,pending.csrf_hash),'UNISSUED_OPERATION',403);
  const known=await this.store.first('SELECT * FROM jwt_v2_ceremony_consumed WHERE tx=?',tx);
  const handoffHeader=strictJSON(unb64u(proof.split('.')[0]));
 const claims=await verifyToken(proof,{profile:pending.purpose,config:this.config,keys:this.keys,now,allowExpired:Boolean(known)});
  requireThat(claims.tx===tx,'GRANT_TRANSACTION_CONFLICT',403);const hash=await digest(claims);
  if(known){requireThat(known.grant_digest===hash&&known.operation_id===operationId,'GRANT_CONFLICT',409);return noCookies({status:'OPERATION_SUPERSEDED',operationId});}
  try{
  requireThat(pending.status==='PENDING'&&now<pending.expires_at,'CEREMONY_EXPIRED',409);
  const installed=await this.readInstalled(request),expected=pending.expected_json&&JSON.parse(pending.expected_json);
  requireThat(expected===null?!installed:installed&&FIELDS.every(k=>installed[k]===expected[k]),'INSTALLED_CONTEXT_CONFLICT',409);
  if(pending.purpose==='unlock')requireThat(installed&&FIELDS.filter(k=>k!=='app').every(k=>claims[k]===installed[k]),'UNLOCK_CONTEXT_CONFLICT',403);
  const prior=await this.store.first('SELECT * FROM jwt_v2_ceremony_barriers WHERE psid=? AND bsid=? AND bv=? AND sub=?',claims.psid,claims.bsid,claims.bv,claims.sub);
  if(!prior){
   const ever=await this.store.first('SELECT 1 FROM jwt_v2_families WHERE psid=? AND bsid=? AND bv=? AND sub=? LIMIT 1',claims.psid,claims.bsid,claims.bv,claims.sub);
   requireThat(!ever,'CHILD_BARRIER_UNAVAILABLE',503);
  }
  const barrier=pending.purpose==='unlock'?{lastRefresh:now,idleUntil:Math.min(now+this.policyMinutes*60,claims.s_exp),locked:false,state:'UNLOCKED'}:admissionBarrier({existing:prior?{lastRefresh:prior.last_refresh,idleUntil:prior.idle_until,locked:Boolean(prior.locked)}:null,afg:claims.afg,now,policyMinutes:this.policyMinutes,s_exp:claims.s_exp});
  const plan=await this.prepareTransition({claims,purpose:pending.purpose,expected,installed,barrier,now,operationId});
  requireThat(plan&&Array.isArray(plan.statements)&&plan.statements.length>0&&plan.result,'LOCAL_TRANSITION_PLAN_REQUIRED',503);
  const result=plan.result;
  requireThat(uuid(result.sid)&&safeInt(result.sv,1)&&safeInt(result.ue)&&safeInt(result.le)&&result.s_exp===claims.s_exp&&result.state===barrier.state,'INVALID_LOCAL_TRANSITION',503);
  if(pending.purpose==='unlock')requireThat(result.sid===claims.sid&&result.sv===claims.sv+1&&result.ue===claims.ue+1&&result.le===claims.le,'INVALID_UNLOCK_TRANSITION',503);
  else if(installed)requireThat(result.sid!==installed.sid,'ADMISSION_MUST_REPLACE_SID',503);
  requireThat(plan.binding&&plan.projection&&Array.isArray(plan.vectorGuards)&&canonical(plan.projection.binding)===canonical(plan.binding)&&plan.binding.sid===result.sid,'LOCAL_CAPTURE_PLAN_REQUIRED',503);
  if(result.state==='UNLOCKED')await assertCaptureReceipt({capture:plan.capture,binding:plan.binding,projection:plan.projection,guards:plan.vectorGuards,manifest:typeof this.store.dependencyManifest==='function'?this.store.dependencyManifest(claims.sub):this.store.dependencyManifest,app:this.config.app,env:this.config.env,now});
  const issuance=result.state==='UNLOCKED'?issuanceFloorGuard(this.store,{binding:plan.binding,projection:plan.projection,vectorGuards:plan.vectorGuards,existingSid:pending.purpose==='unlock'?result.sid:null,now}):[null,null];
  const policyRegistration=pending.purpose==='admission'?familyPolicyRegistrationPlan(this.store,{sid:result.sid,ownerEpoch:plan.projection.policyEpoch,revision:plan.projection.policyRevision,minutes:plan.projection.inactivityMinutes,now}):[];
  const [keyGuard,keyClear]=this.store.guard("SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_restrictions WHERE json_extract(target_json,'$.type')='key' AND json_extract(target_json,'$.purpose')='academy-handoff' AND json_extract(target_json,'$.kid')=?)",[handoffHeader.kid]);
  const safeResult={status:'COMMITTED',sid:result.sid,sv:result.sv,ue:result.ue,s_exp:result.s_exp,state:result.state,le:result.le,operationId};
  const [g,clear]=this.store.guard("SELECT 1 FROM jwt_v2_ceremony_pending WHERE tx=? AND operation_id=? AND status='PENDING' AND expires_at>?",[tx,operationId,now]);
  const mapping=this.mappingGuard(claims),[mg,mc]=this.store.guard(mapping.sql,mapping.args),[floor,fc]=admissionFloorGuard(this.store,{...claims,app:this.config.app,le:result.le});
  const [barrierGuard,barrierClear]=prior?this.store.guard('SELECT 1 FROM jwt_v2_ceremony_barriers WHERE psid=? AND bsid=? AND bv=? AND sub=? AND revision=?',[claims.psid,claims.bsid,claims.bv,claims.sub,prior.revision]):this.store.guard('SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_ceremony_barriers WHERE psid=? AND bsid=? AND bv=? AND sub=?)',[claims.psid,claims.bsid,claims.bv,claims.sub]);
  const bindingColumns='sid sub psid bsid bv ce ae le sv ue vat s_iat s_exp'.split(' ');
  const jsonBindingCheck=bindingColumns.map(k=>" AND json_extract(f.binding_json,'$."+k+"')=f."+k).join('');
  const [projectionGuard,projectionClear]=this.store.guard('SELECT 1 FROM jwt_v2_families WHERE sid=? AND projection_json=? AND authority_ready=? AND (?<>\'UNLOCKED\' OR deadline<=json_extract(projection_json,\'$.timedUntil\'))',[result.sid,canonical(plan.projection),Number(result.state==='UNLOCKED'),result.state]);
  const [final,finalClear]=this.store.guard("SELECT 1 FROM jwt_v2_families f JOIN jwt_v2_accounts a ON a.sub=f.sub JOIN jwt_v2_parents p ON p.psid=f.psid JOIN jwt_v2_browsers b ON b.bsid=f.bsid WHERE f.sid=? AND f.sub=? AND f.psid=? AND f.bsid=? AND f.bv=? AND f.ce=? AND f.ae=? AND f.s_iat=? AND f.s_exp=? AND f.state=? AND f.sv=? AND f.ue=? AND f.le=? AND f.last_refresh=? AND f.idle_until=? AND a.active=1 AND a.ce=f.ce AND a.ae=f.ae AND a.le=f.le AND p.sub=f.sub AND p.bsid=f.bsid AND p.bv=f.bv AND p.ce=f.ce AND p.ae=f.ae AND p.s_iat=f.s_iat AND p.s_exp=f.s_exp AND p.state IN('UNLOCKED','LOCKED') AND b.sub=f.sub AND b.psid=f.psid AND b.bv=f.bv AND b.cancelled_through<f.bv AND f.vat>=f.s_iat AND f.vat<=?"+jsonBindingCheck,[result.sid,claims.sub,claims.psid,claims.bsid,claims.bv,claims.ce,claims.ae,claims.s_iat,claims.s_exp,result.state,result.sv,result.ue,result.le,barrier.lastRefresh,barrier.idleUntil,now]);
  const cancelSid=installed?.sid,unlockFamily=pending.purpose==='unlock'?await this.store.family(installed.sid):null;
  const historyPlan=[];
  if(unlockFamily){
   requireThat(['LOCKED','ADMITTED_LOCKED'].includes(unlockFamily.state)&&unlockFamily.fingerprint===installed.fingerprint,'UNLOCK_CONTEXT_CONFLICT',409);
   const [uGuard,uClear]=this.store.guard("SELECT 1 FROM jwt_v2_intents i JOIN jwt_v2_families f ON f.sid=i.sid WHERE i.intent_id=? AND i.kind='unlock' AND i.state='ISSUED' AND i.binding_json=f.binding_json AND i.generation=f.fingerprint_generation AND f.fingerprint=? AND f.state IN('LOCKED','ADMITTED_LOCKED')",[operationId,installed.fingerprint]);
   historyPlan.push(uGuard,this.store.stmt('INSERT INTO jwt_v2_refresh_history(fingerprint,sid,generation,binding_json,csrf_hash,complete,spent_at,intent_id,s_exp) VALUES(?,?,?,?,?,1,?,?,?)',unlockFamily.fingerprint,unlockFamily.sid,unlockFamily.fingerprint_generation,unlockFamily.binding_json,auth.csrfHash,now,operationId,unlockFamily.s_exp),uClear);
  }
  const [oldGuard,oldClear]=cancelSid&&cancelSid!==result.sid?this.store.guard("SELECT 1 FROM jwt_v2_families WHERE sid=? AND state IN('REVOKED','EXPIRED')",[cancelSid]):[null,null];
  try{
   await this.store.batch([g,mg,floor,keyGuard,barrierGuard,...historyPlan,...plan.statements,
    ...(pending.purpose==='unlock'?[this.store.stmt("UPDATE jwt_v2_parents SET state='UNLOCKED',foreground_at=? WHERE psid=? AND sub=? AND bsid=? AND bv=? AND ce=? AND ae=? AND state IN('UNLOCKED','LOCKED')",now,claims.psid,claims.sub,claims.bsid,claims.bv,claims.ce,claims.ae)]:[]),
    this.store.stmt('INSERT INTO jwt_v2_ceremony_barriers VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(psid,bsid,bv,sub) DO UPDATE SET last_refresh=excluded.last_refresh,idle_until=excluded.idle_until,locked=excluded.locked,revision=revision+1',claims.psid,claims.bsid,claims.bv,claims.sub,barrier.lastRefresh,barrier.idleUntil,Number(barrier.locked)),
    ...(cancelSid?[this.store.stmt("UPDATE jwt_v2_intents SET state=CASE WHEN intent_id=? THEN 'COMMITTED' ELSE 'CANCELLED' END,superseding_operation=?,result_json=? WHERE sid=? AND state='ISSUED'",operationId,operationId,canonical(safeResult),cancelSid)]:[]),
    ...policyRegistration,...(issuance[0]?[issuance[0]]:[]),...(oldGuard?[oldGuard]:[]),projectionGuard,final,this.store.stmt('INSERT INTO jwt_v2_ceremony_consumed VALUES(?,?,?,?,?,?)',claims.jti,tx,operationId,hash,canonical(safeResult),now),
    this.store.stmt("UPDATE jwt_v2_ceremony_pending SET status='COMMITTED' WHERE tx=?",tx),finalClear,projectionClear,...(issuance[1]?[issuance[1]]:[]),...(oldClear?[oldClear]:[]),barrierClear,keyClear,fc,mc,clear
   ]);
  }catch(error){
   const winner=await this.store.first('SELECT * FROM jwt_v2_ceremony_consumed WHERE tx=?',tx);
   if(winner&&winner.grant_digest===hash&&winner.operation_id===operationId)return noCookies({status:'OPERATION_SUPERSEDED',operationId});
   throw error;
  }
  return {winner:true,cookies:Boolean(plan.credentials),result:safeResult,...(plan.credentials?{credentials:plan.credentials}:{})};
  }catch(error){
   const completed=await this.store.first('SELECT * FROM jwt_v2_ceremony_consumed WHERE tx=?',tx);
   if(completed&&completed.grant_digest===hash&&completed.operation_id===operationId)return noCookies({status:'OPERATION_SUPERSEDED',operationId});
   throw error;
  }
 }
}
