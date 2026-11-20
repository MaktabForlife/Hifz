import {privateStreamDeadline} from './stream-deadline.mjs';
import {compactFloors} from './floors.mjs';
import {RightsMemo} from './rights-memo.mjs';
import {primaryWriteCondition} from './primary-write-guard.mjs';
import {canonical,strictJSON,requireThat,reject,uuid,safeInt,unb64u,bytes,digest,opaque,fingerprint,hex,sha256} from './codec.mjs';
import {loadRuntimeConfiguration} from './runtime-config.mjs';
import {PrimaryStore} from './store.mjs';
import {SecurityCache} from './cache.mjs';
import {issueToken,readCookies,cookiePair,refreshOnlyCookie} from './tokens.mjs';
import {privateJSON,browserBody,verifyBootstrap} from './browser-security.mjs';
import {HTTPIntents,selector,expectedContext,requireExpected,decorateResponse} from './http-context.mjs';
import {admissionFloorGuard,markSessionCovered,worksetApplied} from './publication.mjs';

const instances=new WeakMap(),capabilities=new WeakMap();
const safeActions=new Set(['read','write','sensitive','media']);
const parseBinding=f=>JSON.parse(f.binding_json);
function accessSID(token){const parts=typeof token==='string'&&token.split('.');requireThat(parts&&parts.length===3,'SESSION_ENDED',401);const claims=strictJSON(unb64u(parts[1]),{maxBytes:2048});requireThat(uuid(claims.sid),'SESSION_ENDED',401);return claims.sid;}
function accessKid(token){const h=strictJSON(unb64u(token.split('.')[0]),{maxBytes:512});requireThat(typeof h.kid==='string','SESSION_ENDED',401);return h.kid;}
export class AppRuntime {
 constructor({settings,clock=()=>Math.floor(Date.now()/1000),env,native}){
  this.settings=settings;this.config=settings.config;this.app=settings.config.app;this.clock=clock;this.env=env;this.native=native;
  this.store=new PrimaryStore(settings.db,{app:this.app,env:this.config.env,dependencyManifest:settings.dependenciesFor,dependencyRegistry:settings.dependencies,securityPrefix:settings.prefix});
  this.cache=new SecurityCache({bucket:settings.bucket,store:this.store,prefix:settings.prefix,generation:settings.raw.generation});
  Object.defineProperty(this,'ceremonies',{get:async()=>{const {academyCeremonies}=await import('./http-pin.mjs');return academyCeremonies(this);}});
  this.intents=new HTTPIntents({store:this.store,config:this.config,csrf:settings.csrf,clock});this.rightsMemo=new RightsMemo();
 }
 async ensureDependencies(sub){
  const refs=this.settings.dependenciesFor(sub);
  // Initial counters describe the current scoped native facts, including empty
  // tables. Native writers race through the same captured primary transaction.
  // Unknown/absent optional tables are never present in the installed manifest.
  await this.store.batch(refs.map(r=>this.store.stmt('INSERT INTO jwt_v2_dependencies(id,scope,owner_epoch,revision) VALUES(?,?,?,1) ON CONFLICT(id,scope) DO NOTHING',r.id,r.scope,r.ownerEpoch)));
  return refs;
 }
 async nativeCapture(binding){
  await this.ensureDependencies(binding.sub);
  const capture=await this.native.capture({binding});
  requireThat(capture.sub===binding.sub&&(capture.credentialEpoch??capture.sourceCredentialEpoch)===binding.ce,'NATIVE_CAPTURE_BINDING_CONFLICT',409);return capture;
 }
 async appControl(){return (await this.cache.read('control/app')).value;}
 async buildProjection(binding,capture,{initialIssuance=false,previous={}}={}){
  const app=await this.appControl(),rightsHash=await digest(capture.rights),subjectHash=await digest({env:this.config.env,app:this.app,sub:binding.sub});
  requireThat(!app.withdrawnKids.includes(this.settings.apiKid),'CURRENT_SIGNING_KEY_WITHDRAWN',503);
  const rightsKey=this.settings.prefix+'rights/'+subjectHash+'/'+binding.pv+'/'+rightsHash;
  const raw=canonical(capture.rights);requireThat(bytes(raw).length<=2*1024*1024,'RIGHTS_PARTITION_REQUIRED',503);
  const prior=await this.settings.bucket.get(rightsKey);
  if(!prior)await this.settings.bucket.put(rightsKey,raw,{onlyIf:new Headers({'If-None-Match':'*'}),httpMetadata:{contentType:'application/json',cacheControl:'private, no-store'}});
  const stored=prior||await this.settings.bucket.get(rightsKey);
  requireThat(stored&&stored.size<=2*1024*1024,'RIGHTS_PAYLOAD_UNAVAILABLE',503);
  const persisted=new Uint8Array(await stored.arrayBuffer());
  requireThat(hex(await sha256(persisted))===rightsHash,'RIGHTS_PAYLOAD_CORRUPT',503);
  return {...previous,binding,ownerVector:capture.ownerVector,rightsKey,rightsHash,deniedActions:previous.deniedActions||[],timedUntil:Math.min(binding.s_exp,capture.timedUntil),policyEpoch:app.policyEpoch,policyRevision:app.policyRevision,inactivityMinutes:app.inactivityMinutes,keyRegistryEpoch:app.keyRegistryEpoch,keyRegistryRevision:app.keyRegistryRevision,handoffRegistryRevision:app.handoffRegistryRevision??0,withdrawnHandoffKids:app.withdrawnHandoffKids||[],initialIssuance};
 }
 async publishFamily(sid,{initial=false}={}){
  const f=await this.store.family(sid);requireThat(f,'SESSION_ENDED',401);
  const saved=JSON.parse(f.projection_json),suffix='security/session/'+sid;
  // The workset watermark records exactly which pre-existing SIDs a change
  // must cover. New SIDs pass the atomic issuance-floor guard instead. Do not
  // copy unrelated historical browser/account revocations into every control.
  const restrictions=await this.store.all('SELECT w.target_json FROM jwt_v2_publications p JOIN jwt_v2_worksets w ON w.work_id=p.work_id WHERE p.sid=?',sid);
  const enforcedTargets=compactFloors([...(saved.enforcedTargets||[]),...restrictions.map(r=>JSON.parse(r.target_json))]);
  if(!await this.store.lifecycle(this.cache.key(suffix))){requireThat(initial&&f.sv===1&&f.fingerprint_generation===1&&f.cr===1,'SECURITY_INITIAL_PUBLICATION_REQUIRED',503);await this.cache.seed(suffix);}
  return this.cache.publish(suffix,async()=>({...saved,enforcedTargets,app:this.app,env:this.config.env,cr:f.cr,binding:parseBinding(f),localState:f.state,authorityReady:Boolean(f.authority_ready),validationDeadline:f.deadline,idleUntil:f.idle_until,lastRefresh:f.last_refresh,s_exp:f.s_exp,inactivityMinutes:f.policy_minutes}));
 }
 async pendingPublication(sid){const life=await this.store.lifecycle(this.cache.key('security/session/'+sid)),f=await this.store.family(sid);return Boolean(life&&f&&(life.state==='SEED'||life.semantic_revision<f.cr));}
 async publishWinningFamily(sid,{initial=false}={}){try{await this.publishFamily(sid,{initial});return {cachePublication:'READY'};}catch(error){if(error.code&&!['SECURITY_TRANSPORT_UNAVAILABLE','PUBLICATION_RETRY','SECURITY_SEED_UNCONFIRMED'].includes(error.code))throw error;return {cachePublication:'PENDING'};}}
 async currentFamily(request,{allowSpent=false}={}){
  const cookies=readCookies(request.headers.get('Cookie'),this.app);
  requireThat(cookies.refresh,'SESSION_ENDED',401);
  const fp=await fingerprint(cookies.refresh,this.config);
  const family=await this.store.first('SELECT * FROM jwt_v2_families WHERE fingerprint=?',fp);
  if(family)return {family,fingerprint:fp,cookies,historical:false};
  if(allowSpent){
   const history=await this.store.first('SELECT * FROM jwt_v2_refresh_history WHERE fingerprint=? AND s_exp>?',fp,this.clock());
   if(history)return {family:await this.store.family(history.sid),fingerprint:fp,cookies,historical:true,history};
  }
  reject('SESSION_ENDED',401);
 }
 async authorise(request,{action='read',resourceKeys=[],authPurpose=null,operationId=null}={}){
  requireThat(safeActions.has(action)&&new URL(request.url).origin===this.config.origin,'WRONG_PUBLIC_ORIGIN',403);
  const cookies=readCookies(request.headers.get('Cookie'),this.app);requireThat(cookies.access,'ACCESS_REFRESH_REQUIRED',401);
  const sid=accessSID(cookies.access);
  let verified;
  try{verified=await this.cache.authorise({token:cookies.access,sessionKey:sid,config:this.config,keys:this.settings.apiKeys,now:this.clock(),rightsMemo:this.rightsMemo,resourceKeys,action});}
  catch(error){
   const transportPending=error.code==='SECURITY_TRANSPORT_UNAVAILABLE'&&await this.pendingPublication(sid);
   if(transportPending||['SECURITY_PUBLICATION_PENDING','SECURITY_BINDING_CHANGED','INVALID_VALIDATION_TIME','INVALID_LEASE','LEASE_EXPIRED','SESSION_NOT_UNLOCKED','PERMISSIONS_REFRESH_REQUIRED','SECURITY_RECONCILIATION_REQUIRED','ACCESS_DENIED'].includes(error.code)){const {recoverPendingAuthority}=await import('./runtime-pending.mjs');verified=await recoverPendingAuthority(this,{token:cookies.access,sid,resourceKeys,action});}
   else if(!['SECURITY_TRANSPORT_UNAVAILABLE','RIGHTS_PAYLOAD_UNAVAILABLE','RIGHTS_PAYLOAD_CORRUPT','RIGHTS_PAYLOAD_TRANSPORT_UNAVAILABLE'].includes(error.code))throw error;
   else {const {recoverRuntimeAuthority}=await import('./runtime-fallback.mjs');verified=await recoverRuntimeAuthority(this,{token:cookies.access,sid,resourceKeys,action,error});}
  }
  requireThat(this.clock()<Math.min(verified.deadline,verified.binding.s_exp),'LEASE_EXPIRED',401);
  const context=selector(verified.binding,this.app),expected=expectedContext(request);
  if(expected)requireExpected(context,expected);
  const unsafe=!['GET','HEAD','OPTIONS'].includes(request.method);
  let csrfValid=false;
  if(authPurpose){
   requireThat(authPurpose==='draft-key','INVALID_AUTH_CAPABILITY_PURPOSE',403);
   const current=await this.currentFamily(request);requireExpected(context,selector(parseBinding(current.family),this.app));
   await this.intents.verify(request,{operationId,purpose:authPurpose,context});csrfValid=true;
  }else if(request.headers.get('X-UAA-CSRF'))csrfValid=await this.intents.verifyBusiness(request,context);
  if(unsafe||action==='write'||action==='sensitive')requireThat(csrfValid,'BUSINESS_CSRF_REQUIRED',403);
  const cap=Object.freeze({binding:Object.freeze({...verified.binding}),rights:verified.rights,deadline:verified.deadline,context:Object.freeze(context)});
  capabilities.set(cap,{runtime:this,csrfValid,action,kid:accessKid(cookies.access),request});return cap;
 }
 assertCapability(cap){
  const meta=capabilities.get(cap);requireThat(meta?.runtime===this&&this.clock()<Math.min(cap.deadline,cap.binding.s_exp),'V2_CAPABILITY_EXPIRED',401);return meta;
 }
 writeGuard(cap,{sensitive=false}={}){
  const meta=this.assertCapability(cap);requireThat(meta.csrfValid,'BUSINESS_CSRF_REQUIRED',403);
  const b=cap.binding,now=this.clock();
  const {sql,args}=primaryWriteCondition({binding:b,app:this.app,env:this.config.env,now,kid:meta.kid}),pair=this.store.guard(sql,args);
  return {sql,args,before:[pair[0]],after:[pair[1]],sensitive:Boolean(sensitive)};
 }
 businessCapability(cap){const meta=this.assertCapability(cap);requireThat(meta.csrfValid,'BUSINESS_CSRF_REQUIRED',403);return {binding:cap.binding,rights:cap.rights,deadline:cap.deadline,kid:meta.kid};}
 coordinatorCapability(cap){const meta=this.assertCapability(cap);return {binding:cap.binding,rights:cap.rights,deadline:cap.deadline,kid:meta.kid};}
 decorate(response,cap){if(cap){this.assertCapability(cap);response=privateStreamDeadline(response,{deadline:Math.min(cap.deadline,cap.binding.vat+900,cap.binding.s_exp),clock:this.clock});}return decorateResponse(response,cap?.context,this.clock()*1000);}
 json(value,status=200,cap=null){return this.decorate(privateJSON({contractVersion:2,serverNowMs:this.clock()*1000,...value},status),cap);}
 async observeState(family){
  const now=this.clock();
  if(['REVOKED','EXPIRED'].includes(family.state))return family;
  if(now<family.s_exp&&(family.state==='LOCKED'||family.state==='ADMITTED_LOCKED'||now<family.idle_until))return family;
  const state=now>=family.s_exp?'EXPIRED':'LOCKED';
  const [guard,clear]=this.store.guard("SELECT 1 FROM jwt_v2_families WHERE sid=? AND binding_json=? AND state NOT IN('REVOKED','EXPIRED')",[family.sid,family.binding_json]);
  await this.store.batch([guard,
   this.store.stmt("UPDATE jwt_v2_families SET state=?,cr=cr+1 WHERE sid=? AND state NOT IN('REVOKED','EXPIRED')",state,family.sid),
   this.store.stmt("UPDATE jwt_v2_intents SET state='CANCELLED' WHERE sid=? AND state='ISSUED'",family.sid),
   this.store.stmt("INSERT INTO jwt_v2_ceremony_barriers VALUES(?,?,?,?,?,?,1,1) ON CONFLICT(psid,bsid,bv,sub) DO UPDATE SET locked=1,revision=revision+1",family.psid,family.bsid,family.bv,family.sub,family.last_refresh,family.idle_until),
   ...(this.app==='academy'?[this.store.stmt("UPDATE jwt_v2_parents SET state=? WHERE psid=? AND state IN('UNLOCKED','LOCKED')",state,family.psid)]:[]),clear]);
  await this.publishFamily(family.sid);return this.store.family(family.sid);
 }
 async publishPending(workId){
  const rows=await this.store.all('SELECT sid FROM jwt_v2_publications WHERE work_id=? AND published_cr IS NULL AND covered_by_expiry=0',workId);
  for(const row of rows){const projection=await this.publishFamily(row.sid);await markSessionCovered(this.store,{workId,sid:row.sid,projection,controlKey:this.cache.key('security/session/'+row.sid),now:this.clock()});}
  return worksetApplied(this.store,workId);
 }
 async stateDTO(family,{purpose='refresh'}={}){
  family=await this.observeState(family);
  const now=this.clock(),context=selector(parseBinding(family),this.app),terminal=['REVOKED','EXPIRED'].includes(family.state)||now>=family.s_exp;
  if(terminal)return {contractVersion:2,success:false,state:'ENDED',serverNowMs:now*1000,context:null};
  const state=family.state==='ADMITTED_LOCKED'?'ADMITTED_LOCKED':now>=family.idle_until||family.state!=='UNLOCKED'?'LOCKED':'UNLOCKED';
  const auth=await this.intents.issue(family,purpose);
  const business=state==='UNLOCKED'&&now<Math.min(family.deadline,family.idle_until,family.s_exp)?await this.intents.issue(family,'business'):null;
  return {contractVersion:2,success:true,serverNowMs:now*1000,state,authorityReady:Boolean(family.authority_ready),replacementRequired:state==='UNLOCKED'&&!family.authority_ready,context,expectedContext:context,env:this.config.env,draftGeneration:1,originalExpiresAtMs:family.s_exp*1000,idleUntilMs:family.idle_until*1000,validatedAtMs:family.vat*1000,validationDeadlineMs:family.deadline*1000,...auth,...(business?{csrfByPurpose:{business:business.csrf},businessIntent:business.intent}: {})};
 }
 async cookieResponse(family,refresh,value){
  let app;if(value.cachePublication==='PENDING'){const {validateWinningPair}=await import('./runtime-pending.mjs');const eligible=await validateWinningPair(this,{family,refresh});family=eligible.family;app=eligible.app;}else app=await this.appControl();const now=this.clock(),binding=parseBinding(family),saved=JSON.parse(family.projection_json);
  if(family.state==='ADMITTED_LOCKED'){const response=this.json(value);response.headers.append('Set-Cookie',refreshOnlyCookie({app:this.app,refresh,now,originalExpires:family.s_exp}));return response;}
  requireThat(family.state==='UNLOCKED'&&family.authority_ready===1&&now<Math.min(family.deadline,family.idle_until,saved.timedUntil,family.s_exp)&&!app.withdrawnKids.includes(this.settings.apiKid),'TOKEN_ISSUANCE_UNAVAILABLE',503);
  const access=await issueToken({...binding,iat:now,exp:family.deadline,jti:crypto.randomUUID()},{config:this.config,key:this.settings.apiSigningKey,kid:this.settings.apiKid,now,idleUntil:family.idle_until,timedUntil:saved.timedUntil,initial:saved.initialIssuance===true});
  const response=this.json(value);
  for(const cookie of cookiePair({app:this.app,access,refresh,now,accessExpires:family.deadline,originalExpires:family.s_exp}))response.headers.append('Set-Cookie',cookie);
  return response;
 }
 async domainCommand(cap,request){this.assertCapability(cap);const {nativeDomainCommand}=await import('./native-domain.mjs');return nativeDomainCommand(this,cap,request);}
 async handle(request,ctx){
  const path=new URL(request.url).pathname;
  if(!path.startsWith('/auth/v2/')&&!path.startsWith('/internal/auth/v2/'))return null;
  try{
   requireThat(new URL(request.url).origin===this.config.origin,'WRONG_PUBLIC_ORIGIN',403);
   const {handleAuthHTTP}=await import('./http-auth.mjs');
   return await handleAuthHTTP(this,request,ctx);
  }catch(error){
   const status=Number.isInteger(error.status)&&error.status>=400&&error.status<=599?error.status:503;
   const code=typeof error.code==='string'&&/^[A-Z][A-Z0-9_]{0,80}$/.test(error.code)?error.code:'AUTHORITY_UNAVAILABLE';
   return this.json({success:false,code,retryable:status===503||status===429},status);
  }
 }
}
export async function createAppRuntime({settings,env,nativeFactory,clock}){
 const runtime=new AppRuntime({settings,env,clock,native:null});
 requireThat(typeof nativeFactory==='function','NATIVE_RUNTIME_FACTORY_REQUIRED',503);
 runtime.native=await nativeFactory({env,store:runtime.store,clock:runtime.clock,dependenciesFor:settings.dependenciesFor,ensureDependencies:sub=>runtime.ensureDependencies(sub)});
 requireThat(runtime.native&&['identity','mappingGuard','capture','draftGuard'].every(k=>typeof runtime.native[k]==='function'),'NATIVE_RUNTIME_ADAPTER_REQUIRED',503);
 return runtime;
}
export async function runtimeFor(env,{app,nativeFactory,clock}={}){
 requireThat(env&&typeof env==='object','V2_RUNTIME_CONFIGURATION_REQUIRED',503);
 let map=instances.get(env);if(!map){map=new Map();instances.set(env,map);}
 if(!map.has(app)){
  const promise=(async()=>{const settings=await loadRuntimeConfiguration(env,app);const factory=nativeFactory||(await import('./native-runtime.mjs')).createNativeRuntime;return createAppRuntime({settings,env,nativeFactory:factory,clock});})();
  map.set(app,promise);promise.catch(()=>map.delete(app));
 }
 return map.get(app);
}
