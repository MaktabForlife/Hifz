// Browser-only V111 encrypted draft storage. No server modules, bearer tokens or providers.
const FIELDS=['app','sub','sid','psid','bsid','bv','ce','ae','le','sv','ue'];
const STABLE=['app','sub','sid','psid','bsid','bv','ce','ae','le'];
const encoder=new TextEncoder(),decoder=new TextDecoder('utf-8',{fatal:true});
const fail=(code)=>{const e=new Error(code);e.code=code;throw e;};
const need=(v,c)=>{if(!v)fail(c);};
const canonical=v=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
const same=(a,b,fields=FIELDS)=>Boolean(a&&b&&fields.every(k=>a[k]===b[k]));
const uuid=v=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v);
function context(c){
 need(c&&Object.keys(c).length===FIELDS.length&&FIELDS.every(k=>Object.hasOwn(c,k))&&['academy','studio','hifz'].includes(c.app),'INVALID_DRAFT_CONTEXT');
 need(typeof c.sub==='string'&&encoder.encode(c.sub).length>0&&encoder.encode(c.sub).length<=180&&!/[\u0000-\u0020\u007f]/.test(c.sub),'INVALID_DRAFT_CONTEXT');
 for(const k of ['sid','psid','bsid'])need(uuid(c[k]),'INVALID_DRAFT_CONTEXT');
 for(const k of ['bv','ce','ae','sv'])need(Number.isSafeInteger(c[k])&&c[k]>=1,'INVALID_DRAFT_CONTEXT');
 for(const k of ['le','ue'])need(Number.isSafeInteger(c[k])&&c[k]>=0,'INVALID_DRAFT_CONTEXT');
 return Object.freeze({...c});
}
function resourceId(r){need(typeof r==='string'||r&&typeof r==='object'&&!Array.isArray(r)&&[Object.prototype,null].includes(Object.getPrototypeOf(r))&&Object.keys(r).length>0&&Object.keys(r).length<=16&&Object.values(r).every(v=>v===null||typeof v==='string'||typeof v==='boolean'||Number.isSafeInteger(v)),'INVALID_DRAFT_RESOURCE');const key=typeof r==='string'?r:canonical(r);need(encoder.encode(key).length>0&&encoder.encode(key).length<=1024&&!/[\u0000-\u001f\u007f]/.test(key),'INVALID_DRAFT_RESOURCE');return key;}
const resourceSnapshot=r=>{resourceId(r);return typeof r==='string'?r:Object.freeze({...r});};
function decodeKey(value){
 need(typeof value==='string'&&/^[A-Za-z0-9_-]{43}$/.test(value),'INVALID_DRAFT_KEY');
 let raw;try{raw=Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')+'='),c=>c.charCodeAt(0));}catch{fail('INVALID_DRAFT_KEY');}
 need(raw.length===32&&encode64(raw)===value,'INVALID_DRAFT_KEY');return raw;
}
const encode64=raw=>btoa(String.fromCharCode(...raw)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
const request=r=>new Promise((resolve,reject)=>{r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error||Error('DRAFT_STORAGE_UNAVAILABLE'));});
export function createIndexedDBDraftStore(indexedDB,{name='uaa-private-drafts-v2'}={}){
 let connection;
 async function open(){
  need(indexedDB&&typeof indexedDB.open==='function','DRAFT_STORAGE_UNAVAILABLE');
  if(!connection)connection=new Promise((resolve,reject)=>{let r;try{r=indexedDB.open(name,1);}catch(e){reject(e);return;}r.onupgradeneeded=()=>{if(!r.result.objectStoreNames.contains('drafts'))r.result.createObjectStore('drafts',{keyPath:'id'});};r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error||Error('DRAFT_STORAGE_UNAVAILABLE'));r.onblocked=()=>reject(Error('DRAFT_STORAGE_BLOCKED'));});
  return connection;
 }
 return {async transaction(mode,fn){
  const db=await open();return new Promise((resolve,reject)=>{
   let tx,result;try{tx=db.transaction('drafts',mode);}catch(e){reject(e);return;}
   tx.oncomplete=()=>resolve(result);tx.onerror=()=>reject(tx.error||Error('DRAFT_STORAGE_UNAVAILABLE'));tx.onabort=()=>reject(tx.error||Error('DRAFT_STORAGE_UNAVAILABLE'));
   const s=tx.objectStore('drafts'),api={get:id=>request(s.get(id)),all:()=>request(s.getAll()),put:value=>request(s.put(value)),delete:id=>request(s.delete(id))};
   Promise.resolve().then(()=>fn(api)).then(v=>{result=v;}).catch(e=>{try{tx.abort();}catch{}reject(e);});
  });
 }};
}
export function createBrowserDrafts(options){return new BrowserDrafts(options);}
export class BrowserDrafts{
 #crypto;#store;#clock;#release;#unavailable;#binding=null;#key=null;#capsule=null;#version=0;#pending=new Map();#verifiedResources=new Set();#writes=Promise.resolve();#tabId;#failed=null;
 constructor({crypto=globalThis.crypto,indexedDB=globalThis.indexedDB,store,clock=()=>Date.now(),releaseCapsule,onUnavailable=()=>{},tabId,sessionStorage=globalThis.sessionStorage,perResourceBytes=2*1024*1024,perSessionBytes=16*1024*1024}={}){
  need(crypto?.subtle&&typeof crypto.getRandomValues==='function'&&typeof releaseCapsule==='function','DRAFT_ADAPTER_REQUIRED');
  need(perResourceBytes===2*1024*1024&&perSessionBytes===16*1024*1024,'UNAPPROVED_DRAFT_BUDGET');
  if(!tabId){try{tabId=sessionStorage?.getItem('uaa-draft-tab-v2');if(!tabId){tabId=crypto.randomUUID();sessionStorage?.setItem('uaa-draft-tab-v2',tabId);need(sessionStorage?.getItem('uaa-draft-tab-v2')===tabId,'DRAFT_STORAGE_UNAVAILABLE');}}catch{fail('DRAFT_STORAGE_UNAVAILABLE');}}need(uuid(tabId),'INVALID_DRAFT_TAB');this.#tabId=tabId;
  this.#crypto=crypto;this.#store=store||createIndexedDBDraftStore(indexedDB);this.#clock=clock;this.#release=releaseCapsule;this.#unavailable=onUnavailable;this.perResourceBytes=perResourceBytes;this.perSessionBytes=perSessionBytes;
 }
 bindContext({context:selector,env='production',draftGeneration,originalExpiresAtMs}){
  const c=context(selector);need(['production','feature'].includes(env)&&Number.isSafeInteger(draftGeneration)&&draftGeneration>=1&&Number.isSafeInteger(originalExpiresAtMs)&&originalExpiresAtMs>this.#clock(),'INVALID_DRAFT_BINDING');
  const next={context:c,env,draftGeneration,originalExpiresAtMs},sameFamily=this.#binding&&same(this.#binding.context,c,STABLE)&&this.#binding.env===env&&this.#binding.draftGeneration===draftGeneration&&this.#binding.originalExpiresAtMs===originalExpiresAtMs;
  if(sameFamily&&same(this.#binding.context,c))return this;
  this.#version++;this.#verifiedResources.clear();
  this.#key=null;if(!sameFamily){this.#capsule=null;}this.#binding=Object.freeze(next);return this;
 }
 getContext(){return this.#binding?{...this.#binding,context:{...this.#binding.context}}:null;}
 checkCurrentContext(expected){return Boolean(this.#binding&&same(this.#binding.context,expected));}
 #current(){need(this.#binding,'DRAFT_CONTEXT_UNAVAILABLE');need(this.#clock()<this.#binding.originalExpiresAtMs,'DRAFT_SESSION_EXPIRED');return this.#binding;}
 #family(b=this.#current()){return canonical({env:b.env,...Object.fromEntries(STABLE.map(k=>[k,b.context[k]])),draftGeneration:b.draftGeneration,originalExpiresAtMs:b.originalExpiresAtMs});}
 #id(resource,b=this.#current()){return this.#family(b)+'\0'+this.#tabId+'\0'+resourceId(resource);}
 #track(p,version=this.#version){this.#pending.set(p,version);p.catch(e=>{if(version!==this.#version)return;this.#failed=e;this.lock();this.#unavailable({code:e.code||'DRAFT_RECOVERY_FAILED'});}).finally(()=>this.#pending.delete(p)).catch(()=>{});return p;}
 #enqueue(fn){const version=this.#version,p=this.#writes.catch(()=>{}).then(()=>{need(version===this.#version,'DRAFT_CONTEXT_CHANGED');return fn(version);});this.#writes=p;return this.#track(p,version);}
 async #storage(mode,fn){const version=this.#version;try{return await this.#store.transaction(mode,fn);}catch(e){if(version===this.#version){this.#failed=e;this.lock();this.#unavailable({code:e.code||'DRAFT_STORAGE_UNAVAILABLE'});}throw e;}}
 async #obtainKey(resource,capsule=null){
  const b=this.#current(),version=this.#version;resourceId(resource);
  await this.#storage('readonly',s=>s.all());need(version===this.#version&&same(this.#binding?.context,b.context),'DRAFT_CONTEXT_CHANGED');
  if(this.#key&&this.#verifiedResources.has(resourceId(resource)))return this.#key;
  const response=await this.#release({resource,context:{...b.context},draftGeneration:b.draftGeneration,originalExpiresAtMs:b.originalExpiresAtMs,capsule:capsule??this.#capsule});
  need(version===this.#version&&same(this.#binding?.context,b.context),'DRAFT_CONTEXT_CHANGED');
  need(response?.contractVersion===2&&response.success!==false&&same(response.context,b.context)&&response.draftGeneration===b.draftGeneration&&response.originalExpiresAtMs===b.originalExpiresAtMs&&response.capsule!==undefined,'DRAFT_KEY_CONTEXT_CHANGED');
  need(encoder.encode(canonical(response.capsule)).length<=16384,'DRAFT_CAPSULE_TOO_LARGE');
  const expectedCapsule=capsule??this.#capsule;if(expectedCapsule!==null)need(canonical(expectedCapsule)===canonical(response.capsule),'DRAFT_CAPSULE_CHANGED');
  const raw=decodeKey(response.key);let key;
  try{key=await this.#crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);}finally{raw.fill(0);}
  need(version===this.#version&&same(this.#binding?.context,b.context),'DRAFT_CONTEXT_CHANGED');
  this.#key=key;this.#capsule=structuredClone(response.capsule);this.#verifiedResources.add(resourceId(resource));return key;
 }
 prepare(resource){resource=resourceSnapshot(resource);const version=this.#version;return this.#track((async()=>{await this.clearExpired();need(version===this.#version,'DRAFT_CONTEXT_CHANGED');await this.#obtainKey(resource);need(version===this.#version,'DRAFT_CONTEXT_CHANGED');return {ready:true};})(),version);}
 async #write(resource,envelope,version=this.#version){
  need(version===this.#version,'DRAFT_CONTEXT_CHANGED');resourceId(resource);const b=this.#current(),key=await this.#obtainKey(resource),plain=encoder.encode(JSON.stringify(envelope));need(plain.length<=this.perResourceBytes,'DRAFT_RESOURCE_LIMIT');
  const aad={format:2,tabId:this.#tabId,env:b.env,context:{...b.context},draftGeneration:b.draftGeneration,resource,originalExpiresAtMs:b.originalExpiresAtMs},iv=this.#crypto.getRandomValues(new Uint8Array(12)),aadBytes=encoder.encode(canonical(aad));
  let ciphertext;try{ciphertext=await this.#crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aadBytes,tagLength:128},key,plain);}finally{plain.fill(0);}
  need(version===this.#version&&same(this.#binding?.context,b.context),'DRAFT_CONTEXT_CHANGED');
  const bytes=ciphertext.byteLength+iv.byteLength+aadBytes.byteLength+encoder.encode(canonical(this.#capsule)).length;need(bytes<=this.perResourceBytes,'DRAFT_RESOURCE_LIMIT');
  const record={id:this.#id(resource,b),family:this.#family(b),tabId:this.#tabId,resource,aad,iv,ciphertext,capsule:structuredClone(this.#capsule),bytes};
  await this.#storage('readwrite',async s=>{const rows=await s.all();need(version===this.#version&&same(this.#binding?.context,b.context),'DRAFT_CONTEXT_CHANGED');const total=rows.filter(r=>r.family===record.family&&r.id!==record.id).reduce((n,r)=>n+r.bytes,0)+bytes;need(total<=this.perSessionBytes,'DRAFT_SESSION_LIMIT');await s.put(record);});
  this.#failed=null;return {saved:true,resource};
 }
 save(resource,payload){resource=resourceSnapshot(resource);payload=structuredClone(payload);return this.#enqueue(async version=>{const previous=await this.#read(resource);if(previous?.marker&&previous.payload&&typeof previous.payload==='object'&&Object.hasOwn(previous.payload,'request')){need(payload&&typeof payload==='object'&&!Array.isArray(payload),'INVALID_DRAFT_FORMAT');payload={...payload,request:structuredClone(previous.payload.request)};}return this.#write(resource,{format:2,payload,marker:previous?.marker??null},version);});}
 async #read(resource){
  resourceId(resource);const b=this.#current(),version=this.#version,row=await this.#storage('readonly',s=>s.get(this.#id(resource,b)));need(version===this.#version&&same(this.#binding?.context,b.context),'DRAFT_CONTEXT_CHANGED');if(!row)return null;
  need(resourceId(row.resource)===resourceId(resource)&&row.family===this.#family(b)&&row.aad?.format===2&&row.aad.tabId===this.#tabId&&row.tabId===this.#tabId&&row.aad.env===b.env&&same(row.aad.context,b.context,STABLE)&&row.aad.context.sv<=b.context.sv&&row.aad.context.ue<=b.context.ue&&row.aad.draftGeneration===b.draftGeneration&&row.aad.originalExpiresAtMs===b.originalExpiresAtMs&&resourceId(row.aad.resource)===resourceId(resource),'DRAFT_BINDING_MISMATCH');
  const key=await this.#obtainKey(resource,row.capsule);let plain;
  try{plain=await this.#crypto.subtle.decrypt({name:'AES-GCM',iv:row.iv,additionalData:encoder.encode(canonical(row.aad)),tagLength:128},key,row.ciphertext);}catch{fail('DRAFT_INTEGRITY_FAILURE');}
  need(version===this.#version&&same(this.#binding?.context,b.context),'DRAFT_CONTEXT_CHANGED');
  const bytes=new Uint8Array(plain);let value;try{value=JSON.parse(decoder.decode(bytes));}finally{bytes.fill(0);}
  need(value?.format===2&&Object.hasOwn(value,'payload')&&Object.hasOwn(value,'marker'),'INVALID_DRAFT_FORMAT');
  if(value.marker?.state==='IN_FLIGHT')value.marker={...value.marker,state:'SAVE_OUTCOME_UNKNOWN',manualRecoveryRequired:true};return value;
 }
 async hasResource(resource){resource=resourceSnapshot(resource);const binding=this.#current(),version=this.#version,row=await this.#storage('readonly',store=>store.get(this.#id(resource,binding)));need(version===this.#version&&same(this.#binding?.context,binding.context),'DRAFT_CONTEXT_CHANGED');return Boolean(row&&row.family===this.#family(binding)&&resourceId(row.resource)===resourceId(resource));}
 load(resource){return this.#track(this.#read(resourceSnapshot(resource)));}
 async checkpointMutation({resource,method,payload,context:expected}){
  need(this.checkCurrentContext(expected)&&['POST','PUT','PATCH','DELETE'].includes(method),'INVALID_MUTATION_CONTEXT');
  resource=resourceSnapshot(resource);payload=structuredClone(payload);const b=this.#current(),attempt=Object.freeze({id:this.#crypto.randomUUID(),resource,method,context:Object.freeze({...b.context}),family:this.#family(b),version:this.#version});
  await this.#enqueue(async version=>{const previous=await this.#read(resource);need(!previous?.marker,'SAVE_OUTCOME_UNKNOWN');return this.#write(resource,{format:2,payload,marker:{attemptId:attempt.id,state:'IN_FLIGHT',method,context:{...b.context},attemptedAtMs:this.#clock(),manualRecoveryRequired:true}},version);});return attempt;
 }
 async finishMutation(attempt,receiptCurrentContext){
  need(attempt&&attempt.version===this.#version&&this.checkCurrentContext(attempt.context)&&same(receiptCurrentContext,attempt.context),'STALE_MUTATION_RESPONSE');
  return this.#enqueue(async version=>{need(attempt.version===this.#version&&this.checkCurrentContext(attempt.context),'STALE_MUTATION_RESPONSE');const value=await this.#read(attempt.resource);need(value?.marker?.attemptId===attempt.id,'STALE_MUTATION_ATTEMPT');return this.#write(attempt.resource,{format:2,payload:value.payload,marker:null},version);});
 }
 async resolveRecoveryMarker(resource,{confirmed=false,context:expected,attemptId}={}){need(confirmed===true&&this.checkCurrentContext(expected),'MANUAL_RECOVERY_REQUIRED');resource=resourceSnapshot(resource);return this.#enqueue(async version=>{need(this.checkCurrentContext(expected),'DRAFT_CONTEXT_CHANGED');const value=await this.#read(resource);need(value?.marker?.attemptId===attemptId,'STALE_MUTATION_ATTEMPT');await this.#write(resource,{...value,marker:null},version);return {cleared:true,acknowledgedServerSave:false};});}
 async markUnknown(attempt){
  need(attempt&&this.#binding&&attempt.family===this.#family(),'STALE_MUTATION_ATTEMPT');
  if(!this.#key)return {state:'SAVE_OUTCOME_UNKNOWN',manualRecoveryRequired:true,persistedMarker:'IN_FLIGHT'};
  await this.#enqueue(async version=>{const value=await this.#read(attempt.resource);need(value?.marker?.attemptId===attempt.id,'STALE_MUTATION_ATTEMPT');return this.#write(attempt.resource,{...value,marker:{...value.marker,state:'SAVE_OUTCOME_UNKNOWN',manualRecoveryRequired:true}},version);});return {state:'SAVE_OUTCOME_UNKNOWN',manualRecoveryRequired:true};
 }
 async recoveryMarker(resource){return (await this.#read(resourceSnapshot(resource)))?.marker??null;}
 async reconcileUnknown(resource,readViews){
  resource=resourceSnapshot(resource);const value=await this.#read(resource);need(value?.marker&&typeof readViews==='function','MANUAL_RECOVERY_REQUIRED');
  const expected={...this.#current().context},version=this.#version;
  const views=await readViews({resource,context:expected,cache:'no-store'});need(views!==null&&views!==undefined&&views.available!==false&&version===this.#version&&this.checkCurrentContext(expected),'RECOVERY_READ_UNAVAILABLE');
  return {draft:value.payload,marker:value.marker,views,manualRecoveryRequired:true,automaticReplayAllowed:false};
 }
 discardResource(resource,{expectedContext}={}){
  resource=resourceSnapshot(resource);need(this.checkCurrentContext(expectedContext),'INVALID_DISCARD_CONTEXT');const b=this.#current(),id=this.#id(resource,b);
  return this.#enqueue(version=>this.#storage('readwrite',async store=>{need(version===this.#version&&same(this.#binding?.context,expectedContext),'DRAFT_CONTEXT_CHANGED');const row=await store.get(id);need(version===this.#version&&same(this.#binding?.context,expectedContext),'DRAFT_CONTEXT_CHANGED');if(row)await store.delete(id);return {discarded:Boolean(row),resource,acknowledgedServerSave:false};}));
 }
 async flush(){if(this.#failed)throw this.#failed;const version=this.#version;await Promise.all([...this.#pending].filter(([,v])=>v===version).map(([p])=>p));if(this.#failed)throw this.#failed;}
 async clearExpired(){const now=this.#clock();return this.#storage('readwrite',async s=>{for(const row of await s.all())if(Number.isSafeInteger(row.aad?.originalExpiresAtMs)&&row.aad.originalExpiresAtMs<=now)await s.delete(row.id);});}
 lock(){this.#version++;this.#key=null;this.#verifiedResources.clear();}
 discardSession(){
  const family=this.#binding?this.#family(this.#binding):null;this.#version++;this.#key=null;this.#capsule=null;this.#binding=null;this.#verifiedResources.clear();
  return this.#storage('readwrite',async s=>{for(const row of await s.all())if(family&&row.family===family)await s.delete(row.id);});
 }
}
