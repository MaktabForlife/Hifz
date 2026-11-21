// Standalone browser-only V111 client. Cookies and JWTs never enter JavaScript.
const FIELDS=['app','sub','sid','psid','bsid','bv','ce','ae','le','sv','ue'],STABLE=FIELDS.filter(k=>!['sv','ue'].includes(k));
const encoder=new TextEncoder(),decoder=new TextDecoder('utf-8',{fatal:true}),SESSION_PREFIX='uaa-ceremony-v2:';
export class BrowserSessionError extends Error{constructor(code,detail={}){super(code);this.code=code;Object.assign(this,detail);}}
const need=(v,c,d)=>{if(!v)throw new BrowserSessionError(c,d);};
const same=(a,b,fields=FIELDS)=>a===null&&b===null||Boolean(a&&b&&fields.every(k=>a[k]===b[k]));
const uuid=v=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v);
function checkedContext(c,app){
 if(c===null)return null;
 need(c&&Object.keys(c).length===FIELDS.length&&FIELDS.every(k=>Object.hasOwn(c,k))&&c.app===app,'INVALID_BROWSER_CONTEXT');
 need(typeof c.sub==='string'&&encoder.encode(c.sub).length>0&&encoder.encode(c.sub).length<=180&&!/[\u0000-\u0020\u007f]/.test(c.sub),'INVALID_BROWSER_CONTEXT');
 for(const k of ['sid','psid','bsid'])need(uuid(c[k]),'INVALID_BROWSER_CONTEXT');
 for(const k of ['bv','ce','ae','sv'])need(Number.isSafeInteger(c[k])&&c[k]>=1,'INVALID_BROWSER_CONTEXT');
 for(const k of ['le','ue'])need(Number.isSafeInteger(c[k])&&c[k]>=0,'INVALID_BROWSER_CONTEXT');
 return Object.freeze({...c});
}
const encode=bytes=>btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
function decode(value){need(typeof value==='string'&&/^[A-Za-z0-9_-]+$/.test(value),'INVALID_BROWSER_ENCODING');let b;try{b=Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')+'='.repeat((4-value.length%4)%4)),c=>c.charCodeAt(0));}catch{throw new BrowserSessionError('INVALID_BROWSER_ENCODING');}need(encode(b)===value,'INVALID_BROWSER_ENCODING');return b;}
const contextHeader=c=>encode(encoder.encode(JSON.stringify(c)));
const random=crypto=>encode(crypto.getRandomValues(new Uint8Array(32)));
const request=r=>new Promise((resolve,reject)=>{r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error||Error('COORDINATION_UNAVAILABLE'));});
export function createIndexedDBLeaderStore(indexedDB,{name='uaa-browser-control-v2'}={}){
 let connection;
 async function transaction(fn){
  need(indexedDB?.open,'COORDINATION_UNAVAILABLE');
  if(!connection)connection=new Promise((resolve,reject)=>{const r=indexedDB.open(name,1);r.onupgradeneeded=()=>{if(!r.result.objectStoreNames.contains('leases'))r.result.createObjectStore('leases',{keyPath:'name'});};r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);r.onblocked=()=>reject(Error('COORDINATION_UNAVAILABLE'));});
  const db=await connection;
  return new Promise((resolve,reject)=>{const tx=db.transaction('leases','readwrite'),s=tx.objectStore('leases');let result;tx.oncomplete=()=>resolve(result);tx.onabort=tx.onerror=()=>reject(tx.error||Error('COORDINATION_UNAVAILABLE'));Promise.resolve().then(()=>fn({get:key=>request(s.get(key)),put:row=>request(s.put(row))})).then(v=>{result=v;}).catch(e=>{try{tx.abort();}catch{}reject(e);});});
 }
 return {
  claim:({name,owner,now,leaseMs})=>transaction(async s=>{const old=await s.get(name);if(old&&old.owner!==owner&&old.expiresAtMs>now)return null;const fence=(old?.fence||0)+1;need(Number.isSafeInteger(fence),'COORDINATION_FENCE_EXHAUSTED');const row={name,owner,fence,expiresAtMs:now+leaseMs};await s.put(row);return row;}),
  current:({name,owner,fence,now})=>transaction(async s=>{const row=await s.get(name);return Boolean(row&&row.owner===owner&&row.fence===fence&&row.expiresAtMs>now);}),
  release:({name,owner,fence})=>transaction(async s=>{const row=await s.get(name);if(row?.owner===owner&&row.fence===fence)await s.put({...row,owner:null,expiresAtMs:0});})
 };
}
export function createBrowserSession(options){return new BrowserSession(options);}
export class BrowserSession{
 #app;#origin;#academy;#fetch;#crypto;#ss;#ls;#locks;#leader;#channel;#clock;#mono;#maskView;#onState;#checkpoint;#drafts;#context=null;#state='UNAVAILABLE';#generation=0;#controlVersion=0;#dto=null;#credentials=new Map();#anchorServer=0;#anchorLocal=0;#masked=true;#serial=Promise.resolve();#owner;#unconfirmed=false;#activity=false;#timer=null;#setTimer;#clearTimer;#rememberGeneration=0;#deadlineTimer=null;#refreshPromise=null;#needsBootstrap=true;#hidden=false;#playback=false;#serviceWorker;#workerListener;#workerBlocked=false;#bootstrapFlights=new Map();#preparationCancels=new Set();#responses=new WeakMap();
 constructor({app,origin=globalThis.location?.origin,academyOrigin='https://ummabbadacademy.app',fetch=globalThis.fetch?.bind(globalThis),crypto=globalThis.crypto,sessionStorage=globalThis.sessionStorage,localStorage=globalThis.localStorage,locks=globalThis.navigator?.locks,indexedDB=globalThis.indexedDB,leaderStore,BroadcastChannel=globalThis.BroadcastChannel,clock=()=>Date.now(),monotonicClock=()=>globalThis.performance?.now()??Date.now(),onMask=()=>{},onState=()=>{},drafts=null,checkpoint=async()=>{},serviceWorker=globalThis.navigator?.serviceWorker,setTimer=(fn,ms)=>{const id=setTimeout(fn,ms);id.unref?.();return id;},clearTimer=id=>clearTimeout(id)}={}){
  need(['academy','studio','hifz'].includes(app)&&typeof fetch==='function'&&crypto?.subtle,'BROWSER_ADAPTER_REQUIRED');
  for(const value of [origin,academyOrigin]){let u;try{u=new URL(value);}catch{throw new BrowserSessionError('INVALID_BROWSER_ORIGIN');}need(u.protocol==='https:'&&u.origin===value,'INVALID_BROWSER_ORIGIN');}
  Object.assign(this,{});
  this.#app=app;this.#origin=origin;this.#academy=academyOrigin;this.#fetch=fetch;this.#crypto=crypto;this.#ss=sessionStorage;this.#ls=localStorage;this.#locks=locks;this.#clock=clock;this.#mono=monotonicClock;this.#maskView=onMask;this.#onState=onState;this.#drafts=drafts;this.#checkpoint=checkpoint;this.#setTimer=setTimer;this.#clearTimer=clearTimer;this.#owner=crypto.randomUUID();if(app==='academy'){try{const g=Number(localStorage?.getItem('uaa-account-hint-generation-v2')??0);if(Number.isSafeInteger(g)&&g>=0)this.#rememberGeneration=g;}catch{}}
  if(BroadcastChannel){try{this.#channel=new BroadcastChannel('uaa-browser-v2:'+app);this.#channel.addEventListener?.('message',e=>this.#message(e.data));if(!this.#channel.addEventListener)this.#channel.onmessage=e=>this.#message(e.data);}catch{this.#channel=null;}}
  if(this.#channel&&(leaderStore||indexedDB))this.#leader=leaderStore||createIndexedDBLeaderStore(indexedDB);
  this.#serviceWorker=serviceWorker;this.#workerListener=()=>{try{this.#guardWorker();}catch{}};serviceWorker?.addEventListener?.('controllerchange',this.#workerListener);this.#mask('STARTUP');try{this.#guardWorker();}catch{}
 }
 #guardWorker(){let controlled=false;try{controlled=Boolean(this.#serviceWorker?.controller);}catch{controlled=true;}if(!controlled){this.#workerBlocked=false;return;}if(!this.#workerBlocked){this.#workerBlocked=true;this.#cancelPreparation();this.#controlVersion++;this.#generation++;this.#needsBootstrap=true;this.#state='UNAVAILABLE';this.#credentials.clear();this.#activity=false;this.#playback=false;if(this.#timer)this.#clearTimer(this.#timer);this.#timer=null;if(this.#deadlineTimer)this.#clearTimer(this.#deadlineTimer);this.#deadlineTimer=null;this.#drafts?.lock();this.#mask('UNVERIFIED_SERVICE_WORKER');this.#emit();}throw new BrowserSessionError('UNVERIFIED_SERVICE_WORKER',{message:'An older offline version controls this tab. Reopen the current app.'});}
 #cancelPreparation(){for(const cancel of [...this.#preparationCancels])cancel();}
 #preparationPause(ms){return new Promise((resolve,reject)=>{let id;const finish=()=>{this.#preparationCancels.delete(cancel);resolve();},cancel=()=>{this.#clearTimer(id);this.#preparationCancels.delete(cancel);reject(new BrowserSessionError('PREPARATION_CANCELLED'));};this.#preparationCancels.add(cancel);id=this.#setTimer(finish,ms);id?.ref?.();});}
 #mask(reason){this.#masked=true;this.#maskView(true,{reason,context:this.getContext(),...reason==='UNVERIFIED_SERVICE_WORKER'?{message:'An older offline version controls this tab. Reopen the current app.'}:{}});}
 #emit(){this.#onState(this.getState());}
 #now(){return this.#anchorServer?this.#anchorServer+Math.max(0,this.#mono()-this.#anchorLocal):this.#clock();}
 getServerNowMs(){return Math.floor(this.#now());}
 getContext(){return this.#context?Object.freeze({...this.#context}):null;}
 checkCurrentContext(expected){return same(this.#context,expected);}
 getState(){return Object.freeze({viewVersion:this.#generation,suspended:this.#hidden,validationRequired:this.#needsBootstrap,state:this.#state,context:this.getContext(),masked:this.#masked,globalUnconfirmed:this.#unconfirmed,originalExpiresAtMs:this.#dto?.originalExpiresAtMs??null,idleUntilMs:this.#dto?.idleUntilMs??null,validationDeadlineMs:this.#dto?.validationDeadlineMs??null,validatedAtMs:this.#dto?.validatedAtMs??null,authorityReady:this.#dto?.authorityReady??null,replacementRequired:this.#dto?.replacementRequired===true,draftGeneration:this.#dto?.draftGeneration??null,unverifiedServiceWorker:this.#workerBlocked});}
 attachDrafts(drafts){this.#drafts=drafts;this.#bindDrafts();return this;}
 #bindDrafts(){if(this.#drafts&&this.#context&&Number.isSafeInteger(this.#dto?.draftGeneration))this.#drafts.bindContext({context:this.#context,env:this.#dto.env||'production',draftGeneration:this.#dto.draftGeneration,originalExpiresAtMs:this.#dto.originalExpiresAtMs});}
 reveal(expected){this.#guardWorker();need(!this.#hidden&&!this.#needsBootstrap&&this.checkCurrentContext(expected)&&this.#state==='UNLOCKED'&&this.#dto.authorityReady!==false&&this.#dto.replacementRequired!==true&&this.#now()<Math.min(this.#dto.originalExpiresAtMs,this.#dto.idleUntilMs,this.#dto.validationDeadlineMs),'PRIVATE_VIEW_NOT_CURRENT');this.#masked=false;this.#maskView(false,{context:this.getContext()});}
 #deadline(){if(this.#deadlineTimer)this.#clearTimer(this.#deadlineTimer);this.#deadlineTimer=null;if(!this.#context||this.#state!=='UNLOCKED')return;const deadline=Math.min(this.#dto.originalExpiresAtMs,this.#dto.idleUntilMs,this.#dto.validationDeadlineMs);const expected=this.getContext();this.#deadlineTimer=this.#setTimer(()=>{if(this.checkCurrentContext(expected)){this.#needsBootstrap=true;this.#mask('LEASE_EXPIRED');this.#drafts?.lock();}},Math.max(0,deadline-this.#now()));}
 #message(data){if(data?.type==='uaa-cancel-v2'&&data.app===this.#app&&same(data.context,this.#context,STABLE))this.clearAvailable({reason:'REMOTE_CONTEXT_CANCELLED',broadcast:false}).catch(()=>{});else if(data?.type==='uaa-cookie-changed-v2'&&data.app===this.#app&&same(data.context,this.#context,STABLE)){this.#controlVersion++;this.#generation++;this.#mask('COOKIE_RECONCILIATION_REQUIRED');this.#needsBootstrap=true;this.#credentials.clear();}}
 #broadcast(type,context){try{this.#channel?.postMessage({type,app:this.#app,context});}catch{}}
 #url(path){need(typeof path==='string'&&path.startsWith('/')&&!path.startsWith('//'),'INVALID_BROWSER_PATH');const u=new URL(path,this.#origin);need(u.origin===this.#origin,'CROSS_ORIGIN_BROWSER_REQUEST');return u.href;}
 #authDTO(dto){
  need(dto&&dto.contractVersion===2&&typeof dto.success==='boolean'&&Number.isSafeInteger(dto.serverNowMs)&&dto.serverNowMs>=0,'INVALID_AUTH_RESPONSE');
  for(const forbidden of ['jwt','token','accessToken','refreshToken','refreshSecret','accessCookie','refreshCookie'])need(!Object.hasOwn(dto,forbidden),'BROWSER_CREDENTIAL_EXPOSURE');
  if(Object.hasOwn(dto,'validatedAtMs'))need(Number.isSafeInteger(dto.validatedAtMs)&&dto.validatedAtMs>=0&&dto.validatedAtMs<=dto.serverNowMs,'INVALID_VALIDATION_TIME');if(Object.hasOwn(dto,'context'))checkedContext(dto.context,this.#app);return dto;
 }
 #calibrate(serverNowMs){const current=this.#now();this.#anchorServer=Math.max(serverNowMs,this.#anchorServer?current:0);this.#anchorLocal=this.#mono();}
 async #raw(path,body,{csrf=null,version=this.#generation,expected=this.#context,guard=true}={}){
  this.#guardWorker();
  const headers={'Content-Type':'application/json','X-UAA-Request':'2'};if(csrf)headers['X-UAA-CSRF']=csrf;if(expected)headers['X-UAA-Expected-Context']=contextHeader(expected);
  let response;try{response=await this.#fetch(this.#url(path),{method:'POST',credentials:'include',mode:'same-origin',cache:'no-store',redirect:'error',referrerPolicy:'same-origin',referrer:this.#origin+'/',headers,body:JSON.stringify(body)});}catch(cause){throw new BrowserSessionError('AUTH_TRANSPORT_UNAVAILABLE',{cause});}
  this.#guardWorker();if(guard)need(version===this.#generation&&same(expected,this.#context),'STALE_BROWSER_RESPONSE');
  need(!response.redirected,'AUTH_REDIRECT_REJECTED');let dto;try{dto=JSON.parse(await response.text());}catch{throw new BrowserSessionError('INVALID_AUTH_RESPONSE');}this.#authDTO(dto);
  this.#guardWorker();if(guard)need(version===this.#generation&&same(expected,this.#context),'STALE_BROWSER_RESPONSE');
  this.#calibrate(dto.serverNowMs);
  if(!response.ok||dto.success===false)throw new BrowserSessionError(dto.code||dto.error?.code||'AUTH_REQUEST_FAILED',{status:response.status,dto});return dto;
 }
 #accept(dto,{transition=null,previous=this.#context,operationId=null}={}){
  this.#authDTO(dto);const next=checkedContext(dto.context??null,this.#app);for(const field of ['authorityReady','replacementRequired'])if(Object.hasOwn(dto,field))need(typeof dto[field]==='boolean','INVALID_AUTH_READINESS');
  need(['UNLOCKED','LOCKED','ADMITTED_LOCKED','SIGNED_OUT','ENDED','UNAVAILABLE','GLOBAL_UNCONFIRMED'].includes(dto.state),'INVALID_AUTH_STATE');
  if(operationId!==null)need(dto.operationId===operationId,'AUTH_OPERATION_MISMATCH');
  if(next){
   for(const field of ['originalExpiresAtMs','idleUntilMs','validationDeadlineMs'])need(Number.isSafeInteger(dto[field])&&dto[field]>=0,'INVALID_AUTH_DEADLINE');
   need(dto.idleUntilMs<=dto.originalExpiresAtMs&&dto.validationDeadlineMs<=Math.min(dto.idleUntilMs,dto.originalExpiresAtMs),'INVALID_AUTH_DEADLINE');
   if(previous&&same(previous,next,STABLE)&&this.#dto)need(dto.originalExpiresAtMs===this.#dto.originalExpiresAtMs,'ORIGINAL_EXPIRY_CHANGED');
   if(previous&&same(previous,next)&&this.#dto){need(dto.validationDeadlineMs<=this.#dto.validationDeadlineMs,'UNCOMMITTED_LEASE_EXTENSION');if(Number.isSafeInteger(dto.validatedAtMs)&&Number.isSafeInteger(this.#dto.validatedAtMs))need(dto.validatedAtMs<=this.#dto.validatedAtMs,'UNCOMMITTED_VALIDATION_TIME');}
   if(transition==='refresh')need(previous&&same(previous,next,STABLE)&&next.sv===previous.sv+1&&next.ue===previous.ue,'REFRESH_CONTEXT_CHANGED');
   if(transition==='unlock')need(previous&&same(previous,next,STABLE)&&next.sv===previous.sv+1&&next.ue===previous.ue+1,'UNLOCK_CONTEXT_CHANGED');
  }
  const changed=!same(this.#context,next);if(changed){this.#generation++;this.#mask('CONTEXT_VALIDATION');if(this.#context&&!same(this.#context,next,STABLE))this.#drafts?.discardSession().catch(()=>{});}
  this.#context=next;this.#state=dto.state;this.#dto=Object.freeze({...dto,context:next});this.#calibrate(dto.serverNowMs);this.#bindDrafts();
  if(dto.intent&&dto.csrf)this.#rememberCredentials(dto.intent.kind,dto);
  if(dto.businessIntent&&dto.csrfByPurpose?.business)this.#rememberCredentials('business',{...dto,intent:dto.businessIntent,csrf:dto.csrfByPurpose.business,csrfExpiresAtMs:dto.businessIntent.expiresAtMs});
  if(dto.state!=='UNLOCKED'||!next||dto.authorityReady===false||dto.replacementRequired===true||this.#now()>=Math.min(dto.originalExpiresAtMs,dto.idleUntilMs,dto.validationDeadlineMs)){this.#mask(dto.state);this.#drafts?.lock();}
  this.#needsBootstrap=false;this.#deadline();this.#emit();return dto;
 }
 #rememberCredentials(purpose,dto){
  const i=dto.intent;need(i&&uuid(i.id)&&typeof purpose==='string'&&Number.isSafeInteger(i.expiresAtMs)&&i.expiresAtMs>this.#now()&&Number.isSafeInteger(dto.csrfExpiresAtMs)&&dto.csrfExpiresAtMs>this.#now()&&typeof dto.csrf==='string'&&dto.csrf.length>0,'INVALID_ISSUED_INTENT');
  if(['pin','pin/setup'].includes(purpose))need(uuid(dto.tx)&&uuid(dto.attemptId),'INVALID_ISSUED_PIN_ATTEMPT');
  this.#credentials.set(purpose,{intent:{...i},csrf:dto.csrf,csrfExpiresAtMs:dto.csrfExpiresAtMs,context:this.getContext(),tx:dto.tx,attemptId:dto.attemptId});
 }
 bootstrap({purpose='refresh',...input}={}){
  const expected=this.getContext(),version=this.#generation,key=JSON.stringify([purpose,expected,version,input]);if(this.#bootstrapFlights.has(key))return this.#bootstrapFlights.get(key);
  const run=async()=>{const dto=await this.#raw('/auth/v2/bootstrap',{purpose,expectedContext:expected,...input},{expected,version});if(purpose==='status'&&['SUPERSEDED','UNCONFIRMED','ENDED'].includes(dto.outcome)&&!dto.intent){this.#mask('INSTALLATION_UNCONFIRMED');this.#drafts?.lock();return dto;}this.#accept(dto);return dto;};
  const pending=run().finally(()=>{if(this.#bootstrapFlights.get(key)===pending)this.#bootstrapFlights.delete(key);});this.#bootstrapFlights.set(key,pending);return pending;
 }

 async prepareJourneyAuthority({tx,onProgress=()=>{}}={}){
  need(this.#app==='academy'&&uuid(tx)&&typeof onProgress==='function','INVALID_PREPARATION_JOURNEY');this.#guardWorker();need(!this.#hidden,'PREPARATION_CANCELLED');
  let generation=this.#generation,expected=this.getContext(),deadline=null;
  for(;;){this.#guardWorker();need(generation===this.#generation&&!this.#hidden&&same(expected,this.#context),'PREPARATION_CANCELLED');if(deadline!==null)need(this.#now()<deadline,'PREPARATION_EXPIRED');
   const dto=await this.bootstrap({purpose:'admission/proceed',tx});if(expected===null&&dto.context!==null&&dto.context!==undefined&&this.#generation===generation+1&&same(dto.context,this.#context)){expected=this.getContext();generation=this.#generation;}need(generation===this.#generation&&!this.#hidden&&same(expected,this.#context),'PREPARATION_CANCELLED');
   need(dto.journeyTx===tx,'PREPARATION_TRANSACTION_CHANGED');if(dto.action!=='PREPARE')return dto;need(expected!==null,'INVALID_PREPARATION_RESPONSE');
   need(Number.isSafeInteger(dto.preparationExpiresAtMs)&&dto.preparationExpiresAtMs>this.#now()&&Number.isSafeInteger(dto.retryAfterMs)&&dto.retryAfterMs>=1&&dto.retryAfterMs<=5000&&(dto.progress===undefined||typeof dto.progress==='string'&&encoder.encode(dto.progress).length<=200),'INVALID_PREPARATION_RESPONSE');
   if(deadline===null)deadline=dto.preparationExpiresAtMs;else need(dto.preparationExpiresAtMs===deadline,'PREPARATION_DEADLINE_CHANGED');onProgress(Object.freeze({progress:dto.progress||'',preparationExpiresAtMs:deadline,retryAfterMs:dto.retryAfterMs}));
   await this.#preparationPause(Math.min(dto.retryAfterMs,Math.max(1,deadline-this.#now())));
  }
 }
 async #for(purpose,input={}){
  await this.bootstrap({purpose,...input});const c=this.#credentials.get(purpose);
  need(c&&same(c.context,this.#context)&&c.intent.expiresAtMs>this.#now()&&c.csrfExpiresAtMs>this.#now(),'OPERATION_PROOF_UNAVAILABLE');return c;
 }
 #coordinate(fn){
  const controlVersion=this.#controlVersion,version=this.#generation,guard=()=>need(controlVersion===this.#controlVersion&&version===this.#generation,'BROWSER_CONTROL_SUPERSEDED');
  const run=async()=>{
   this.#guardWorker();if(this.#locks?.request){let entered=false;try{return await this.#locks.request('uaa-cookie-v2:'+this.#app,{mode:'exclusive'},async()=>{entered=true;guard();return fn();});}catch(e){if(entered||e instanceof BrowserSessionError)throw e;if(!this.#leader){this.#mask('COORDINATION_UNAVAILABLE');throw new BrowserSessionError('COORDINATION_UNAVAILABLE',{cause:e});}}}
   need(this.#leader&&this.#channel,'COORDINATION_UNAVAILABLE');const name='uaa-cookie-v2:'+this.#app,row=await this.#leader.claim({name,owner:this.#owner,now:this.#clock(),leaseMs:10000});need(row,'COORDINATION_BUSY');
   try{guard();const result=await fn();need(await this.#leader.current({name,owner:this.#owner,fence:row.fence,now:this.#clock()}),'COORDINATION_LOST');return result;}finally{await this.#leader.release({name,owner:this.#owner,fence:row.fence}).catch(()=>{});}
  };
  const p=this.#serial.catch(()=>{}).then(run);this.#serial=p;return p.catch(e=>{const obsolete=controlVersion!==this.#controlVersion||version!==this.#generation&&['STALE_BROWSER_RESPONSE','DRAFT_CONTEXT_CHANGED','BROWSER_CONTROL_SUPERSEDED'].includes(e.code);if(!obsolete){this.#needsBootstrap=true;this.#credentials.clear();this.#mask(e.code||'COORDINATION_UNAVAILABLE');this.#drafts?.lock();}throw e;});
 }
 async ensureFresh({activeWork=true}={}){
  this.#guardWorker();
  if(this.#needsBootstrap||!this.#dto||!this.#credentials.size)await this.bootstrap();
  need(!this.#unconfirmed,'GLOBAL_LOGOUT_UNCONFIRMED');need(this.#context&&this.#state==='UNLOCKED','PIN_REQUIRED');
  if(this.#now()>=Math.min(this.#dto.idleUntilMs,this.#dto.originalExpiresAtMs)){this.#mask('PIN_REQUIRED');this.#drafts?.lock();throw new BrowserSessionError('PIN_REQUIRED');}
  if(this.#dto.replacementRequired===true||this.#now()>=this.#dto.validationDeadlineMs-60000){need(activeWork||this.#dto.replacementRequired===true,'RENEWAL_REQUIRES_ACTIVE_WORK');await this.refresh({activeWork});}
  return this.getState();
 }
 async prepareBusiness({activeWork=true}={}){
  this.#guardWorker();need(!this.#hidden,'BUSINESS_ACTION_SUSPENDED');const previous=this.getContext();await this.bootstrap({purpose:'business'});need(!previous||same(previous,this.#context,STABLE),'BUSINESS_CONTEXT_CHANGED');await this.ensureFresh({activeWork});need(!this.#hidden&&!this.#needsBootstrap&&this.#state==='UNLOCKED'&&(!previous||same(previous,this.#context,STABLE)),'BUSINESS_CONTEXT_CHANGED');return this.getState();
 }
 async prepareSensitive({activeWork=true}={}){
  this.#guardWorker();need(!this.#hidden,'SENSITIVE_ACTION_SUSPENDED');await this.prepareBusiness({activeWork});
  const age=Number.isSafeInteger(this.#dto?.validatedAtMs)?this.#now()-this.#dto.validatedAtMs:Infinity;
  if(age<0||age>=55000)await this.refresh({activeWork});
  need(!this.#hidden&&!this.#needsBootstrap&&this.#state==='UNLOCKED'&&Number.isSafeInteger(this.#dto?.validatedAtMs)&&this.#now()>=this.#dto.validatedAtMs&&this.#now()-this.#dto.validatedAtMs<60000,'SENSITIVE_FRESHNESS_UNAVAILABLE');return this.getState();
 }
 async refresh({activeWork=true}={}){
  this.#guardWorker();
  if(this.#refreshPromise)return this.#refreshPromise;
  const requested=this.getContext(),controlVersion=this.#controlVersion;let observedOperationId=null,historicalContext=null;
  const run=async()=>{await this.#drafts?.flush();return this.#coordinate(async()=>{
   const boot=await this.bootstrap({purpose:'refresh'}),proof=this.#credentials.get('refresh'),previous=this.getContext();need(proof&&same(proof.context,previous),'OPERATION_PROOF_UNAVAILABLE');need(previous&&this.#state==='UNLOCKED'&&this.#now()<Math.min(this.#dto.idleUntilMs,this.#dto.originalExpiresAtMs),'PIN_REQUIRED');
   if(requested&&same(requested,previous,STABLE)&&previous.sv>requested.sv)return {...boot,outcome:'INSTALLED_CURRENT'};
   observedOperationId=proof.intent.id;historicalContext=previous;
   try{const dto=await this.#raw('/auth/v2/refresh',{operationId:proof.intent.id,expectedContext:previous,qualifyingActivity:Boolean(activeWork&&!this.#hidden&&(this.#activity||this.#playback))},{csrf:proof.csrf});this.#accept(dto,{transition:'refresh',previous,operationId:proof.intent.id});this.#activity=false;this.#broadcast('uaa-cookie-changed-v2',this.getContext());return dto;}
   catch(error){if(controlVersion!==this.#controlVersion||error.code==='STALE_BROWSER_RESPONSE')throw error;this.#needsBootstrap=true;this.#mask('REFRESH_RECONCILIATION');await this.status(proof.intent.id,{historicalContext:previous}).catch(()=>{});throw error;}
  });};
  this.#refreshPromise=run().catch(async error=>{if(error.code==='COORDINATION_LOST'&&observedOperationId)await this.status(observedOperationId,{historicalContext}).catch(()=>{});throw error;}).finally(()=>{this.#refreshPromise=null;});return this.#refreshPromise;
 }
 async status(observedOperationId,{historicalContext=this.getContext()}={}){
  need(uuid(observedOperationId),'INVALID_OBSERVED_OPERATION');const boot=await this.bootstrap({purpose:'status',observedOperationId,historicalContext});
  if(['SUPERSEDED','UNCONFIRMED','ENDED'].includes(boot.outcome)&&!boot.intent)return boot;
  const proof=this.#credentials.get('status');need(proof&&same(proof.context,this.#context),'OPERATION_PROOF_UNAVAILABLE');
  const dto=await this.#raw('/auth/v2/status',{operationId:proof.intent.id,observedOperationId,expectedContext:this.getContext(),historicalContext},{csrf:proof.csrf});
  if(dto.outcome==='INSTALLED_CURRENT'&&dto.context&&historicalContext&&same(dto.context,historicalContext,STABLE))this.#accept(dto);else this.#mask('INSTALLATION_UNCONFIRMED');return dto;
 }
 responseProvenance(response){const proof=this.#responses.get(response);if(!proof||proof.viewVersion!==this.#generation||!this.checkCurrentContext(proof.context))return null;return Object.freeze({context:Object.freeze({...proof.context}),viewVersion:proof.viewVersion,renewedFrom:proof.renewedFrom?Object.freeze({context:Object.freeze({...proof.renewedFrom.context}),viewVersion:proof.renewedFrom.viewVersion}):null});}
 async protectedFetch(path,init={}, {readOnly=false}={}){return this.#protectedRead(path,init,readOnly,false,null);}
 async #protectedRead(path,init,readOnly,retried,renewedFrom){
  this.#guardWorker();
  await this.ensureFresh();let proof=this.#credentials.get('business');
  if(!proof||!same(proof.context,this.#context)||proof.intent.expiresAtMs<=this.#now()||proof.csrfExpiresAtMs<=this.#now())proof=await this.#for('business');
  const expected=this.getContext(),version=this.#generation,controlVersion=this.#controlVersion,headers=new Headers(init.headers);headers.set('X-UAA-Request','2');headers.set('X-UAA-CSRF',proof.csrf);headers.set('X-UAA-Business-Intent',proof.intent.id);headers.set('X-UAA-Expected-Context',contextHeader(expected));
  let response;try{response=await this.#fetch(this.#url(path),{...init,headers,credentials:'include',mode:'same-origin',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer'});}catch(cause){throw new BrowserSessionError('BUSINESS_OUTCOME_UNAVAILABLE',{cause,requestMayHaveExecuted:true});}
  this.#guardWorker();need(version===this.#generation&&this.checkCurrentContext(expected),'STALE_BROWSER_RESPONSE');
  if([401,403,409,423,503].includes(response.status))this.#needsBootstrap=true;
  if([401,403,409,423,503].includes(response.status)){this.#mask('AUTHORITY_UNAVAILABLE');if(response.status===423)this.#drafts?.lock();}
  if(!response.ok&&response.status!==304){let contextVerified=false;if(response.headers.get('X-UAA-Contract')==='2'){let metadata;try{metadata={context:JSON.parse(decoder.decode(decode(response.headers.get('X-UAA-Context')))),serverNowMs:Number(response.headers.get('X-UAA-Server-Now-Ms'))};}catch{throw new BrowserSessionError('PROTECTED_CONTEXT_UNAVAILABLE',{status:response.status});}need(Number.isSafeInteger(metadata.serverNowMs)&&same(checkedContext(metadata.context,this.#app),expected)&&version===this.#generation&&this.checkCurrentContext(expected),'STALE_BROWSER_RESPONSE');this.#calibrate(metadata.serverNowMs);contextVerified=true;}const failure=new BrowserSessionError('PROTECTED_REQUEST_FAILED',{status:response.status,...contextVerified?{response}:{},requestMayHaveExecuted:true,contextVerified,responseContext:contextVerified?expected:null,responseViewVersion:contextVerified?version:null});const method=String(init.method||'GET').toUpperCase(),safe=method==='GET'||method==='HEAD'||readOnly===true&&method==='POST';if(!retried&&safe&&[401,403,409,423,503].includes(response.status)&&!this.#hidden){try{await this.bootstrap({purpose:'business'});await this.ensureFresh({activeWork:false});this.#guardWorker();need(controlVersion===this.#controlVersion&&!this.#hidden&&same(expected,this.#context,STABLE)&&this.#context.sv>expected.sv&&this.#context.ue===expected.ue,'READ_RENEWAL_UNAVAILABLE');return this.#protectedRead(path,init,readOnly,true,{context:expected,viewVersion:version});}catch(error){if(error.code==='UNVERIFIED_SERVICE_WORKER'||error.code==='STALE_BROWSER_RESPONSE')throw error;if(controlVersion===this.#controlVersion&&same(expected,this.#context,STABLE)){this.#needsBootstrap=true;this.#mask('AUTHORITY_UNAVAILABLE');}throw failure;}}throw failure;}
  let metadata;
  try{if(response.headers.get('X-UAA-Contract')==='2')metadata={contractVersion:2,context:JSON.parse(decoder.decode(decode(response.headers.get('X-UAA-Context')))),serverNowMs:Number(response.headers.get('X-UAA-Server-Now-Ms'))};else metadata=await response.clone().json();}catch{throw new BrowserSessionError('PROTECTED_CONTEXT_UNAVAILABLE');}
  need(metadata.contractVersion===2&&Number.isSafeInteger(metadata.serverNowMs)&&same(checkedContext(metadata.context,this.#app),expected)&&version===this.#generation&&this.checkCurrentContext(expected),'STALE_BROWSER_RESPONSE');this.#calibrate(metadata.serverNowMs);this.#responses.set(response,{context:expected,viewVersion:version,renewedFrom});return response;
 }
 recordActivity({kind,manual=true}={}){if(!this.#hidden&&manual&&['keyboard','pointer','touch','scroll'].includes(kind))this.#activity=true;}
 playbackActivity({recordingId,optIn,userStarted,progressing,paused=false,ended=false,stalled=false,autoplay=false,repeat=false}={}){this.#playback=Boolean(!this.#hidden&&typeof recordingId==='string'&&optIn&&userStarted&&progressing&&!paused&&!ended&&!stalled&&!autoplay&&!repeat);}
 scheduleRenewal({activeWork=true,jitterMs=0}={}){
  need(Number.isSafeInteger(jitterMs)&&jitterMs>=0&&jitterMs<=5000,'INVALID_RENEWAL_JITTER');if(this.#timer)this.#clearTimer(this.#timer);if(this.#hidden||!activeWork||!this.#dto||this.#state!=='UNLOCKED')return null;
  const at=Math.min(this.#dto.validationDeadlineMs,this.#dto.idleUntilMs,this.#dto.originalExpiresAtMs)-60000-jitterMs,delay=Math.max(0,at-this.#now());const controlVersion=this.#controlVersion;this.#timer=this.#setTimer(()=>{this.#timer=null;this.refresh().catch(()=>{if(controlVersion===this.#controlVersion)this.#mask('RENEWAL_UNAVAILABLE');});},delay);return at;
 }
 async prepareJourney(){const controlVersion=this.#controlVersion;this.#guardWorker();this.#mask('AUTH_JOURNEY');try{await this.#checkpoint();this.#guardWorker();await this.#drafts?.flush();this.#guardWorker();this.#drafts?.lock();return {checkpointed:true};}catch(e){if(controlVersion===this.#controlVersion)this.#mask('DRAFT_CHECKPOINT_FAILED');throw e;}}
 #navigate(url){const u=new URL(url);need(u.origin===this.#academy&&u.protocol==='https:'&&![...u.searchParams.keys()].some(k=>['code','state','verifier','pin','token','jwt'].includes(k.toLowerCase()))&&!u.hash,'UNTRUSTED_AUTH_NAVIGATION');return u.href;}
 async #begin(purpose,{returnTo='/'}={}){
  need(this.#app!=='academy'&&!this.#unconfirmed,'CHILD_CEREMONY_UNAVAILABLE');need(typeof returnTo==='string'&&returnTo.startsWith('/')&&!returnTo.startsWith('//')&&!/[#\r\n]/.test(returnTo),'INVALID_RETURN_ROUTE');await this.prepareJourney();
  return this.#coordinate(async()=>{
   const proof=await this.#for(purpose+'/start'),expected=this.getContext(),state=random(this.#crypto),verifier=random(this.#crypto),challenge=encode(new Uint8Array(await this.#crypto.subtle.digest('SHA-256',encoder.encode(verifier))));
   const stateHash=Array.from(new Uint8Array(await this.#crypto.subtle.digest('SHA-256',encoder.encode(state))),v=>v.toString(16).padStart(2,'0')).join('');
   const dto=await this.#raw('/auth/v2/'+purpose+'/start',{operationId:proof.intent.id,expectedContext:expected,stateHash,challenge,callback:this.#origin+'/auth/v2/'+purpose+'/callback',returnTo},{csrf:proof.csrf});
   need(uuid(dto.tx)&&uuid(dto.operationId)&&Number.isSafeInteger(dto.expiresAtMs)&&dto.expiresAtMs>this.#now()&&dto.expiresAtMs<=this.#now()+300000,'INVALID_CEREMONY_START');
   const entry={contractVersion:2,purpose,tx:dto.tx,state,verifier,expiresAtMs:dto.expiresAtMs,expectedContext:expected,operationId:dto.operationId,returnTo};try{need(this.#ss?.setItem,'CEREMONY_STORAGE_UNAVAILABLE');this.#ss.setItem(SESSION_PREFIX+dto.tx,JSON.stringify(entry));need(this.#ss.getItem(SESSION_PREFIX+dto.tx)!==null,'CEREMONY_STORAGE_UNAVAILABLE');}catch{this.#mask('CEREMONY_STORAGE_UNAVAILABLE');throw new BrowserSessionError('CEREMONY_STORAGE_UNAVAILABLE');}
   return {...dto,navigateUrl:this.#navigate(dto.navigateUrl)};
  });
 }
 beginAdmission(options){return this.#begin('admission',options);}startAdmission(options){return this.beginAdmission(options);}
 beginUnlock(options){return this.#begin('unlock',options);}startUnlock(options){return this.beginUnlock(options);}
 async completeCallback({tx,stateHash,code,purpose='admission'}){
  need(uuid(tx)&&['admission','unlock'].includes(purpose)&&typeof stateHash==='string'&&/^[a-f0-9]{64}$/.test(stateHash)&&typeof code==='string'&&code.length>0,'INVALID_CEREMONY_CALLBACK');
  let entry;try{entry=JSON.parse(this.#ss?.getItem(SESSION_PREFIX+tx)||'null');}catch{throw new BrowserSessionError('CEREMONY_STORAGE_UNAVAILABLE');}
  need(entry&&entry.tx===tx&&entry.purpose===purpose&&typeof entry.state==='string'&&/^[A-Za-z0-9_-]{43}$/.test(entry.state)&&Number.isSafeInteger(entry.expiresAtMs)&&entry.expiresAtMs>0&&/^[A-Za-z0-9_-]{43}$/.test(entry.verifier),'CEREMONY_STATE_MISMATCH');
  const expectedStateHash=Array.from(new Uint8Array(await this.#crypto.subtle.digest('SHA-256',encoder.encode(entry.state))),v=>v.toString(16).padStart(2,'0')).join('');need(expectedStateHash===stateHash,'CEREMONY_STATE_MISMATCH');
  return this.#coordinate(async()=>{
   const proof=await this.#for(purpose+'/finalize',{tx,observedOperationId:entry.operationId});need(entry.expiresAtMs>this.#now(),'CEREMONY_EXPIRED');need(same(entry.expectedContext,this.#context)&&proof.intent.id===entry.operationId,'CEREMONY_CONTEXT_CHANGED');
   try{const dto=await this.#raw('/auth/v2/'+purpose+'/finalize',{operationId:entry.operationId,expectedContext:entry.expectedContext,tx,code,verifier:entry.verifier},{csrf:proof.csrf});this.#accept(dto,{transition:purpose==='unlock'?'unlock':null,previous:entry.expectedContext,operationId:entry.operationId});this.#ss.removeItem(SESSION_PREFIX+tx);this.#broadcast('uaa-cookie-changed-v2',this.getContext());return {...dto,returnTo:typeof dto.returnTo==='string'?this.#url(dto.returnTo):this.#url(entry.returnTo)};}
   catch(e){this.#mask('FINALIZE_RECONCILIATION');await this.status(entry.operationId,{historicalContext:entry.expectedContext}).catch(()=>{});throw e;}
  });
 }
 completeAdmission(args){return this.completeCallback({...args,purpose:'admission'});}completeUnlock(args){return this.completeCallback({...args,purpose:'unlock'});}
 async draftKey({resource,draftGeneration,originalExpiresAtMs,capsule,context:expected}){
  need(this.checkCurrentContext(expected),'DRAFT_CONTEXT_CHANGED');
  return this.#coordinate(async()=>{const proof=await this.#for('draft-key');need(!this.#hidden&&!this.#needsBootstrap&&this.checkCurrentContext(expected)&&this.#state==='UNLOCKED','DRAFT_CONTEXT_CHANGED');need(this.#dto?.authorityReady!==false&&this.#dto?.replacementRequired!==true,'DRAFT_AUTHORITY_REFRESH_REQUIRED');return this.#raw('/auth/v2/draft-key',{operationId:proof.intent.id,expectedContext:expected,resource,draftGeneration,originalExpiresAtMs,capsule},{csrf:proof.csrf});});
 }
 async submitPin({pin,...input}){need(this.#app==='academy'&&/^\d{4}$/.test(pin),'ACADEMY_PIN_ONLY');return this.#coordinate(async()=>{const proof=await this.#for('pin',input),dto=await this.#raw('/auth/v2/pin',{...input,pin,tx:proof.tx,attemptId:proof.attemptId,operationId:proof.intent.id,expectedContext:this.getContext()},{csrf:proof.csrf});if(dto.state)this.#accept(dto,{operationId:proof.intent.id});return dto;});}
 async setupPin({pin,confirmation,...input}){need(this.#app==='academy'&&/^\d{4}$/.test(pin)&&pin===confirmation,'PIN_CONFIRMATION_REQUIRED');return this.#coordinate(async()=>{const proof=await this.#for('pin/setup',input),dto=await this.#raw('/auth/v2/pin/setup',{...input,pin,confirmation,tx:proof.tx,attemptId:proof.attemptId,operationId:proof.intent.id,expectedContext:this.getContext()},{csrf:proof.csrf});if(dto.state)this.#accept(dto,{operationId:proof.intent.id});return dto;});}
 clearAvailable({reason='LOGOUT',broadcast=true}={}){
  this.#cancelPreparation();
  const previous=this.getContext();this.#controlVersion++;this.#generation++;this.#mask(reason);this.#context=null;this.#state='SIGNED_OUT';this.#dto=null;this.#credentials.clear();this.#activity=false;this.#playback=false;this.#needsBootstrap=true;if(this.#deadlineTimer)this.#clearTimer(this.#deadlineTimer);this.#deadlineTimer=null;if(this.#timer)this.#clearTimer(this.#timer);this.#timer=null;
  if(broadcast&&previous)this.#broadcast('uaa-cancel-v2',previous);
  try{if(this.#ss)for(let i=this.#ss.length-1;i>=0;i--){const key=this.#ss.key(i);if(key?.startsWith(SESSION_PREFIX))this.#ss.removeItem(key);}}catch{}
  this.#emit();return this.#drafts?.discardSession()??Promise.resolve();
 }
 async #exit(kind,input={}){
  const previous=this.getContext();this.clearAvailable({reason:kind.toUpperCase()}).catch(()=>{});
  try{const boot=await this.#raw('/auth/v2/bootstrap',{purpose:kind,expectedContext:previous},{expected:previous,guard:false});need(boot.context&&(!previous||same(boot.context,previous,STABLE))&&boot.intent&&boot.csrf,'EXIT_CONTEXT_CHANGED');const dto=await this.#raw('/auth/v2/'+kind,{...input,operationId:boot.intent.id,expectedContext:boot.context},{expected:boot.context,csrf:boot.csrf,guard:false});this.#unconfirmed=dto.outcome==='GLOBAL_UNCONFIRMED';return dto;}
  catch(error){this.#unconfirmed=true;this.#mask('GLOBAL_UNCONFIRMED');return {contractVersion:2,success:false,state:'SIGNED_OUT',outcome:'GLOBAL_UNCONFIRMED',code:error.code||'EXIT_UNAVAILABLE'};}
 }
 logout(){return this.#exit('logout');}switchAccount(input){return this.#exit('switch',input);}
 async pageshow(){this.#hidden=false;this.#controlVersion++;this.#generation++;this.#needsBootstrap=true;this.#mask('RESTORED_PAGE');this.#drafts?.lock();return this.bootstrap();}
 pagehide(){this.#cancelPreparation();if(this.#timer)this.#clearTimer(this.#timer);this.#timer=null;this.#hidden=true;this.#activity=false;this.#playback=false;this.#controlVersion++;this.#generation++;this.#needsBootstrap=true;this.#mask('HISTORY_SUSPENSION');this.#drafts?.lock();}
 async browserClear({tx,operationId,csrf,expiresAtMs,expectedContext}){
  need(uuid(tx)&&uuid(operationId)&&typeof csrf==='string'&&Number.isSafeInteger(expiresAtMs)&&this.#now()<expiresAtMs&&expiresAtMs<=this.#now()+60000,'INVALID_BROWSER_CONTROL');
  if(!this.checkCurrentContext(expectedContext))return {cleared:false,outcome:'CONTEXT_CHANGED'};
  return this.#coordinate(async()=>{need(this.checkCurrentContext(expectedContext),'BROWSER_CONTROL_SUPERSEDED');const dto=await this.#raw('/auth/v2/browser-clear',{tx,operationId,expectedContext},{csrf});this.clearAvailable({reason:'BROWSER_CLEAR'}).catch(()=>{});return dto;});
 }
 rememberSelection({selection,optIn=false,serverNowMs,hintGeneration}={}){
  need(this.#app==='academy','ACADEMY_HINT_ONLY');if(!optIn)return;need(hintGeneration===this.getHintGeneration()&&Number.isSafeInteger(serverNowMs)&&selection&&typeof selection.uniqueId==='string'&&typeof selection.displayName==='string','STALE_ACCOUNT_HINT');this.#ls?.setItem('uaa-account-selection-v2',JSON.stringify({selection:{uniqueId:selection.uniqueId,displayName:selection.displayName},signedAtMs:serverNowMs,expiresAtMs:serverNowMs+30*86400000,generation:hintGeneration}));
 }
 getHintGeneration(){try{const g=Number(this.#ls?.getItem('uaa-account-hint-generation-v2')??this.#rememberGeneration);if(Number.isSafeInteger(g)&&g>=this.#rememberGeneration)this.#rememberGeneration=g;}catch{}return this.#rememberGeneration;}
 getRememberedSelection(){if(this.#app!=='academy')return null;try{const r=JSON.parse(this.#ls?.getItem('uaa-account-selection-v2')||'null');return r&&r.generation===this.getHintGeneration()&&this.#now()<r.expiresAtMs?r.selection:null;}catch{return null;}}
 forgetSelection(){this.#rememberGeneration=this.getHintGeneration()+1;try{this.#ls?.setItem('uaa-account-hint-generation-v2',String(this.#rememberGeneration));this.#ls?.removeItem('uaa-account-selection-v2');}catch{}return this.#rememberGeneration;}
 dispose(){this.#serviceWorker?.removeEventListener?.('controllerchange',this.#workerListener);if(this.#deadlineTimer)this.#clearTimer(this.#deadlineTimer);if(this.#timer)this.#clearTimer(this.#timer);this.#channel?.close();this.pagehide();}
}
