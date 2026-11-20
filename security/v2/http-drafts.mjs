import {canonical,requireThat,safeInt,uuid,bytes,b64u,unb64u} from './codec.mjs';
import {expectedContext,requireExpected,selector} from './http-context.mjs';
const GENERATION=1,STABLE=['app','sub','sid','psid','bsid','bv','ce','ae','le'],keys=new WeakMap();
export const draftCapsuleSchemaSQL=[
 'CREATE TABLE IF NOT EXISTS jwt_v2_draft_capsules(sid TEXT NOT NULL,draft_generation INTEGER NOT NULL,kid TEXT NOT NULL,iv TEXT NOT NULL,capsule TEXT NOT NULL,binding_json TEXT NOT NULL,created_at INTEGER NOT NULL,s_exp INTEGER NOT NULL,PRIMARY KEY(sid,draft_generation));',
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_draft_capsule_immutable BEFORE UPDATE ON jwt_v2_draft_capsules BEGIN SELECT RAISE(ABORT,'jwt_v2_immutable_draft_capsule'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_draft_capsule_preserve BEFORE DELETE ON jwt_v2_draft_capsules BEGIN SELECT RAISE(ABORT,'jwt_v2_durable_draft_capsule'); END;"
].join('\n');
// Import-only recipe. Capsule retirement is a separately reviewed retention operation.
function resourceValue(value){
 requireThat(typeof value==='string'||value&&typeof value==='object'&&!Array.isArray(value)&&[Object.prototype,null].includes(Object.getPrototypeOf(value))&&Object.keys(value).length>0&&Object.keys(value).length<=16&&Object.values(value).every(v=>v===null||typeof v==='string'||typeof v==='boolean'||Number.isSafeInteger(v)),'DRAFT_RESOURCE_REQUIRED',400);
 const text=typeof value==='string'?value:canonical(value);requireThat(bytes(text).length>0&&bytes(text).length<=1024&&!/[\u0000-\u001f\u007f]/.test(text),'DRAFT_RESOURCE_REQUIRED',400);return structuredClone(value);
}
async function wrappingKey(settings,kid){
 const registry=settings.draft;requireThat(registry?.keys instanceof Map&&typeof kid==='string'&&registry.keys.has(kid),'DRAFT_WRAPPING_KEY_UNAVAILABLE',503);
 let imported=keys.get(registry);if(!imported){imported=new Map();keys.set(registry,imported);}
 if(!imported.has(kid)){const raw=registry.keys.get(kid);requireThat(raw instanceof Uint8Array&&raw.length===32,'DRAFT_WRAPPING_KEY_UNAVAILABLE',503);imported.set(kid,crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']));}
 return imported.get(kid);
}
const packet=row=>({schema:2,kid:row.kid,iv:row.iv,ciphertext:row.capsule,binding:JSON.parse(row.binding_json)});
function checkedRow(runtime,row,cap){
 requireThat(row&&row.sid===cap.binding.sid&&row.draft_generation===GENERATION&&row.s_exp===cap.binding.s_exp,'DRAFT_CAPSULE_BINDING_CONFLICT',409);
 const aad=JSON.parse(row.binding_json);
 requireThat(aad.schema===2&&aad.purpose==='uaa-draft-key-v2'&&aad.env===runtime.config.env&&aad.app===runtime.app&&aad.draftGeneration===GENERATION&&aad.originalExpiresAtMs===cap.binding.s_exp*1000&&STABLE.every(k=>aad.recordedContext?.[k]===cap.context[k])&&safeInt(aad.recordedContext.sv,1)&&aad.recordedContext.sv<=cap.context.sv&&safeInt(aad.recordedContext.ue)&&aad.recordedContext.ue<=cap.context.ue,'DRAFT_CAPSULE_BINDING_CONFLICT',409);
 resourceValue(aad.firstResource);unb64u(row.iv,12);unb64u(row.capsule,48);return aad;
}
function guarded(runtime,cap,body,nativePlan,statements,capsuleRow=null){
 const store=runtime.store,write=runtime.writeGuard(cap),now=runtime.clock();
 const native=store.guard(nativePlan.sql,nativePlan.args),intent=store.guard("SELECT 1 FROM jwt_v2_intents i JOIN jwt_v2_http_intents h USING(intent_id) JOIN jwt_v2_families f ON f.sid=i.sid WHERE i.intent_id=? AND i.sid=? AND i.kind='draft-key' AND i.state='ISSUED' AND i.binding_json=f.binding_json AND i.generation=f.fingerprint_generation AND i.expires_at>? AND h.purpose='draft-key' AND h.csrf_expires>? AND h.context_json=?",[body.operationId,cap.binding.sid,now,now,canonical(cap.context)]);
 const capsule=capsuleRow?store.guard('SELECT 1 FROM jwt_v2_draft_capsules WHERE sid=? AND draft_generation=? AND kid=? AND iv=? AND capsule=? AND binding_json=? AND s_exp=?',[capsuleRow.sid,GENERATION,capsuleRow.kid,capsuleRow.iv,capsuleRow.capsule,capsuleRow.binding_json,cap.binding.s_exp]):null;
 return [...write.before,native[0],intent[0],...(capsule?[capsule[0]]:[]),...statements,...(capsule?[capsule[1]]:[]),intent[1],native[1],...write.after];
}
async function cacheCapsule(runtime,row){
 const bucket=runtime.settings.bucket,key=runtime.settings.prefix+'draft/'+row.sid+'/'+GENERATION,raw=canonical(packet(row));let cached;
 try{cached=await bucket.get(key);}catch{requireThat(false,'DRAFT_CAPSULE_CACHE_UNAVAILABLE',503);}
 if(!cached){
  try{await bucket.put(key,raw,{onlyIf:new Headers({'If-None-Match':'*'}),httpMetadata:{contentType:'application/json',cacheControl:'private, no-store'}});cached=await bucket.get(key);}catch{requireThat(false,'DRAFT_CAPSULE_CACHE_UNAVAILABLE',503);}
 }
 requireThat(cached&&(!Number.isSafeInteger(cached.size)||cached.size<=8192),'DRAFT_CAPSULE_CACHE_UNAVAILABLE',503);
 let saved;try{saved=new TextDecoder('utf-8',{fatal:true}).decode(await cached.arrayBuffer());}catch{requireThat(false,'DRAFT_CAPSULE_CACHE_UNAVAILABLE',503);}
 requireThat(saved===raw,'DRAFT_CAPSULE_CACHE_CONFLICT',503);
}
export async function releaseDraftKey(runtime,request,body){
 requireThat(request.method==='POST'&&new URL(request.url).pathname==='/auth/v2/draft-key','DRAFT_KEY_POST_REQUIRED',405);
 requireThat(body&&uuid(body.operationId)&&body.draftGeneration===GENERATION&&safeInt(body.originalExpiresAtMs),'DRAFT_KEY_BINDING_REQUIRED',400);
 const resource=resourceValue(body.resource),expected=expectedContext(request,body);
 requireThat(expected&&expected.app===runtime.app,'EXPECTED_CONTEXT_REQUIRED',409);
 const cap=await runtime.authorise(request,{action:'read',authPurpose:'draft-key',operationId:body.operationId});requireExpected(cap.context,expected);
 requireThat(body.originalExpiresAtMs===cap.binding.s_exp*1000,'DRAFT_KEY_BINDING_CONFLICT',409);
 const nativePlan=await runtime.native.draftGuard({runtime,request,cap,binding:cap.binding,rights:cap.rights,resource});
 requireThat(nativePlan&&typeof nativePlan.sql==='string'&&/^SELECT\s/i.test(nativePlan.sql.trim())&&Array.isArray(nativePlan.args),'NATIVE_DRAFT_GUARD_REQUIRED',503);
 const store=runtime.store;let row=await store.first('SELECT * FROM jwt_v2_draft_capsules WHERE sid=? AND draft_generation=?',cap.binding.sid,GENERATION);
 if(!row){
  requireThat(body.capsule===undefined||body.capsule===null,'DRAFT_CAPSULE_MISSING',409);
  const kid=runtime.settings.draft.currentKid,key=await wrappingKey(runtime.settings,kid),iv=crypto.getRandomValues(new Uint8Array(12)),raw=crypto.getRandomValues(new Uint8Array(32));
  const binding={schema:2,purpose:'uaa-draft-key-v2',env:runtime.config.env,app:runtime.app,recordedContext:cap.context,draftGeneration:GENERATION,firstResource:resource,originalExpiresAtMs:cap.binding.s_exp*1000},aad=canonical(binding);let encrypted;
  try{encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:bytes(aad),tagLength:128},key,raw);}finally{raw.fill(0);}
  await store.batch(guarded(runtime,cap,body,nativePlan,[store.stmt('INSERT INTO jwt_v2_draft_capsules(sid,draft_generation,kid,iv,capsule,binding_json,created_at,s_exp) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(sid,draft_generation) DO NOTHING',cap.binding.sid,GENERATION,kid,b64u(iv),b64u(encrypted),aad,runtime.clock(),cap.binding.s_exp)]));
  row=await store.first('SELECT * FROM jwt_v2_draft_capsules WHERE sid=? AND draft_generation=?',cap.binding.sid,GENERATION);
 }
 checkedRow(runtime,row,cap);const capsule=packet(row);if(body.capsule!==undefined&&body.capsule!==null)requireThat(canonical(body.capsule)===canonical(capsule),'DRAFT_CAPSULE_CHANGED',409);
 let raw;try{raw=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64u(row.iv,12),additionalData:bytes(row.binding_json),tagLength:128},await wrappingKey(runtime.settings,row.kid),unb64u(row.capsule,48)));}catch{requireThat(false,'DRAFT_CAPSULE_UNWRAP_FAILED',503);}
 try{
  requireThat(raw.length===32,'DRAFT_CAPSULE_UNWRAP_FAILED',503);
  await cacheCapsule(runtime,row);
  // Recheck after asynchronous unwrap/cache work. This batch is the release
  // linearisation point; native resource denial/lock/reset races cannot pass.
  await store.batch(guarded(runtime,cap,body,nativePlan,[],row));runtime.assertCapability(cap);
  return runtime.json({success:true,state:'UNLOCKED',context:cap.context,operationId:body.operationId,draftGeneration:GENERATION,originalExpiresAtMs:cap.binding.s_exp*1000,capsule,key:b64u(raw)},200,cap);
 }finally{raw.fill(0);}
}
export const draftKeyBoundary=Object.freeze({authority:'Current access and own refresh, exact operation CSRF and context, C05 controls plus same-primary family/floor/native resource guards. No renewal or activity credit.',persistence:'Only AES-GCM wrapped random key is durable and cached privately. First-editor setup writes; no draft text, raw key or journal replica reaches the server.',recovery:'A missing non-authority R2 capsule copy can be restored from the same immutable durable SID/generation capsule after current authority checks. Missing/fenced security controls cannot be rebuilt by this handler.'});
