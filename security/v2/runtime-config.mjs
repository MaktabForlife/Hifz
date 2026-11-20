import registry from './native-authority.json' with {type:'json'};
import {ORIGINS,profileConfig} from './tokens.mjs';
import {strictJSON,requireThat,ascii,safeInt,unb64u,bytes,canonical} from './codec.mjs';
import {dependencyScope} from './issuance-floors.mjs';

const parse=(value,code,maxBytes=65536)=>{try{requireThat(typeof value==='string',code,503);return strictJSON(value,{maxBytes});}catch{requireThat(false,code,503);}};
async function ecKey(jwk,privateKey){
 requireThat(jwk?.kty==='EC'&&jwk.crv==='P-256'&&typeof jwk.x==='string'&&typeof jwk.y==='string'&&Boolean(jwk.d)===privateKey,'INVALID_RUNTIME_SIGNING_KEY',503);
 try{return await crypto.subtle.importKey('jwk',jwk,{name:'ECDSA',namedCurve:'P-256'},false,privateKey?['sign']:['verify']);}catch{requireThat(false,'INVALID_RUNTIME_SIGNING_KEY',503);}
}
async function matchingPair(signing,verification){
 const packet=bytes('uaa-runtime-key-pair-check-v2'),signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},signing,packet);
 requireThat(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},verification,signature,packet),'SIGNING_KEY_PAIR_CONFLICT',503);
}
const keyID=value=>ascii(value,64)&&/^[A-Za-z0-9._-]+$/.test(value);
const publicMaterial=jwk=>canonical({kty:jwk.kty,crv:jwk.crv,x:jwk.x,y:jwk.y});
const sourceDependencyRecipients=Object.freeze({'academy:native:hifz_profile_sync':'hifz','academy:studio-source-authority':'studio'});
// Only projections with an actual native intake can establish a child issuance
// receipt. Raw Academy counters must never become unfulfillable foreign floors.
function sourceDependencyRegistry(rows){
 requireThat(Array.isArray(rows)&&rows.length<=2,'DEPENDENCY_REGISTRY_INVALID',503);
 const seen=new Set();
 for(const r of rows){
  const recipient=r&&sourceDependencyRecipients[r.id];
  requireThat(recipient&&r.ownerApp==='academy'&&ascii(r.ownerEpoch)&&r.scope==='ACCOUNT'&&Array.isArray(r.recipients)&&r.recipients.length===1&&r.recipients[0]===recipient&&Array.isArray(r.actions)&&r.actions.length<=128&&r.actions.every(a=>ascii(a,128))&&new Set(r.actions).size===r.actions.length&&!seen.has(r.id),'DEPENDENCY_REGISTRY_INVALID',503);
  seen.add(r.id);
 }
}

export function selectedV2(request,env,app){
 return env.UAA_V2_ENABLED==='1'&&new URL(request.url).origin===ORIGINS[app];
}
export async function loadRuntimeConfiguration(env,app){
 requireThat(env.UAA_V2_ENABLED==='1'&&registry.app===app,'V2_RUNTIME_NOT_SELECTED',503);
 const raw=parse(env.UAA_V2_CONFIG,'V2_CONFIGURATION_REQUIRED');
 requireThat(raw.schema===2&&raw.app===app&&raw.env==='production'&&raw.publicOrigin===ORIGINS[app]&&raw.academyOrigin===ORIGINS.academy&&raw.activationEnabled===true&&raw.AIEnabled===false&&raw.snapshotSchema===3,'V2_CONFIGURATION_MISMATCH',503);
 requireThat(ascii(raw.generation,64)&&/^[A-Za-z0-9_-]+$/.test(raw.generation)&&ascii(raw.nativeOwnerEpoch)&&safeInt(raw.policyMinutes,15)&&raw.policyMinutes<=200,'V2_CONFIGURATION_MISMATCH',503);
 requireThat(Array.isArray(raw.nativeTables)&&raw.nativeTables.length>0&&raw.nativeTables.length<=256&&new Set(raw.nativeTables).size===raw.nativeTables.length&&raw.nativeTables.every(t=>Object.hasOwn(registry.rules,t)),'INSTALLED_NATIVE_MANIFEST_REQUIRED',503);
 requireThat(Object.entries(registry.rules).every(([t,r])=>!r.required||raw.nativeTables.includes(t)),'REQUIRED_NATIVE_OWNER_MISSING',503);
 const api=parse(env.UAA_V2_API_KEYS_JSON,'API_KEY_REGISTRY_REQUIRED');
 requireThat(keyID(api.currentKid)&&Array.isArray(api.keys)&&api.keys.length>0&&api.keys.length<=20,'API_KEY_REGISTRY_REQUIRED',503);
 const apiKeys=new Map();
 for(const entry of api.keys){requireThat(keyID(entry.kid)&&!apiKeys.has(entry.kid),'API_KEY_REGISTRY_CONFLICT',503);apiKeys.set(entry.kid,await ecKey(entry.jwk,false));}
 requireThat(apiKeys.has(api.currentKid),'CURRENT_API_KEY_REQUIRED',503);
 const apiPrivate=parse(env.UAA_V2_API_PRIVATE_JWK,'API_SIGNER_REQUIRED'),apiSigningKey=await ecKey(apiPrivate,true);
 await matchingPair(apiSigningKey,apiKeys.get(api.currentKid));
 const handoff=parse(env.UAA_V2_HANDOFF_KEYS_JSON,'HANDOFF_KEY_REGISTRY_REQUIRED');
 requireThat(Array.isArray(handoff.keys)&&handoff.keys.length>0&&handoff.keys.length<=20,'HANDOFF_KEY_REGISTRY_REQUIRED',503);
 const handoffKeys=new Map();
 for(const entry of handoff.keys){requireThat(keyID(entry.kid)&&!handoffKeys.has(entry.kid),'HANDOFF_KEY_REGISTRY_CONFLICT',503);handoffKeys.set(entry.kid,await ecKey(entry.jwk,false));}
 for(const a of api.keys)for(const h of handoff.keys)requireThat(publicMaterial(a.jwk)!==publicMaterial(h.jwk),'KEY_PURPOSE_SEPARATION_REQUIRED',503);
 let handoffSigningKey=null;
 if(app==='academy'){requireThat(keyID(handoff.currentKid)&&handoffKeys.has(handoff.currentKid),'HANDOFF_SIGNER_REQUIRED',503);handoffSigningKey=await ecKey(parse(env.UAA_V2_HANDOFF_PRIVATE_JWK,'HANDOFF_SIGNER_REQUIRED'),true);await matchingPair(handoffSigningKey,handoffKeys.get(handoff.currentKid));}
 else requireThat(!env.UAA_V2_HANDOFF_PRIVATE_JWK,'HANDOFF_PRIVATE_KEY_WRONG_OWNER',503);
 const csrfKeys=parse(env.UAA_V2_CSRF_KEYS_JSON,'CSRF_KEYS_REQUIRED');
 const draftKeys=parse(env.UAA_V2_DRAFT_KEYS_JSON,'DRAFT_KEYS_REQUIRED');
 const symmetric=input=>{
  requireThat(keyID(input.currentKid)&&Array.isArray(input.keys)&&input.keys.length>0&&input.keys.length<=20,'SYMMETRIC_KEY_REGISTRY_INVALID',503);
  const keys=new Map();
  for(const entry of input.keys){requireThat(keyID(entry.kid)&&!keys.has(entry.kid),'SYMMETRIC_KEY_REGISTRY_CONFLICT',503);keys.set(entry.kid,unb64u(entry.key,32));}
  requireThat(keys.has(input.currentKid),'CURRENT_SYMMETRIC_KEY_REQUIRED',503);return {currentKid:input.currentKid,keys};
 };
 const csrf=symmetric(csrfKeys),draft=symmetric(draftKeys);
 for(const c of csrfKeys.keys)for(const d of draftKeys.keys)requireThat(c.key!==d.key,'KEY_PURPOSE_SEPARATION_REQUIRED',503);
 const service=parse(env.UAA_V2_SERVICE_KEYS_JSON,'SERVICE_KEYS_REQUIRED');
 requireThat(Array.isArray(service.keys)&&service.keys.length<=20,'SERVICE_KEY_REGISTRY_INVALID',503);
 const serviceKeys=new Map(),servicePaths=new Set(['transactions','redeem','events','reconcile','incidents','logout'].map(p=>'/internal/auth/v2/'+p));
 const materials=new Map();
 const registerMaterial=(value,purpose)=>{unb64u(value,32);const prior=materials.get(value);requireThat(!prior||prior===purpose,'KEY_PURPOSE_SEPARATION_REQUIRED',503);materials.set(value,purpose);};
 for(const k of csrfKeys.keys)registerMaterial(k.key,'csrf');for(const k of draftKeys.keys)registerMaterial(k.key,'draft');
 for(const entry of service.keys){
  requireThat(keyID(entry.kid)&&!serviceKeys.has(entry.kid)&&['academy','studio','hifz'].includes(entry.sourceApp)&&['academy','studio','hifz'].includes(entry.targetApp)&&entry.sourceApp!==entry.targetApp&&[entry.sourceApp,entry.targetApp].includes(app)&&[entry.sourceApp,entry.targetApp].includes('academy')&&Array.isArray(entry.paths)&&entry.paths.length>0&&new Set(entry.paths).size===entry.paths.length&&entry.paths.every(v=>servicePaths.has(v)&&(v.endsWith('/events')?entry.sourceApp==='academy':v.endsWith('/reconcile')||entry.targetApp==='academy')),'SERVICE_KEY_REGISTRY_INVALID',503);
  requireThat(![...csrfKeys.keys,...draftKeys.keys].some(k=>k.key===entry.key),'KEY_PURPOSE_SEPARATION_REQUIRED',503);
  registerMaterial(entry.key,'service:'+entry.sourceApp+':'+entry.targetApp);serviceKeys.set(entry.kid,{...entry,key:unb64u(entry.key,32),env:raw.env});
 }
 if(env.UAA_V2_LIBRARY_METADATA_KEY){requireThat(app==='academy','LIBRARY_METADATA_KEY_WRONG_OWNER',503);registerMaterial(env.UAA_V2_LIBRARY_METADATA_KEY,'academy-library-metadata');}
 if(env.UAA_V2_COORDINATOR_KEY){requireThat(app==='academy','COORDINATOR_KEY_WRONG_OWNER',503);registerMaterial(env.UAA_V2_COORDINATOR_KEY,'academy-coordinator');}
 for(const [name,purpose] of [['UAA_V2_CURSOR_KEYS_JSON','cursor'],['UAA_V2_NATIVE_RPC_KEYS_JSON','native-rpc'],['UAA_V2_PROFILE_KEYS_JSON','profile'],['UAA_V2_STUDIO_AUTHORITY_KEYS_JSON','studio-authority'],['UAA_V2_PORTAL_RPC_KEYS_JSON','portal-rpc']]){
  if(!env[name])continue;const ring=parse(env[name],'PURPOSE_KEY_REGISTRY_REQUIRED');requireThat(Array.isArray(ring.keys)&&ring.keys.length<=20,'PURPOSE_KEY_REGISTRY_INVALID',503);
  const ids=new Set();for(const entry of ring.keys){requireThat(keyID(entry.kid)&&!ids.has(entry.kid),'PURPOSE_KEY_REGISTRY_CONFLICT',503);ids.add(entry.kid);registerMaterial(entry.key,purpose);}
 }
 const config=profileConfig({app,env:raw.env});
 const nativeTables=[...raw.nativeTables].sort();
 const dependenciesFor=sub=>nativeTables.map(table=>({id:app+':native:'+table,scope:registry.rules[table].accountColumn?dependencyScope(sub):'GLOBAL',ownerEpoch:raw.nativeOwnerEpoch}));
 sourceDependencyRegistry(raw.foreignDependencies||[]);
 sourceDependencyRegistry(raw.serviceDependencies||[]);
 const dependencies=new Map((raw.foreignDependencies||[]).map(r=>[r.id,{ownerApp:r.ownerApp,epoch:r.ownerEpoch,recipients:r.recipients,actions:r.actions,scope:r.scope}]));
 requireThat(dependencies.size===(raw.foreignDependencies||[]).length,'DEPENDENCY_REGISTRY_CONFLICT',503);
 const db=app==='academy'?env.ACADEMY_DB:env.DB,bucket=env.AUTH_CACHE;
 requireThat(db?.withSession&&bucket?.get&&bucket?.put,'V2_OWNING_BINDINGS_REQUIRED',503);
 return {raw,config,db,bucket,registry,nativeTables,dependenciesFor,dependencies,apiKeys,apiSigningKey,apiKid:api.currentKid,handoffKeys,handoffSigningKey,handoffKid:handoff.currentKid,csrf,draft,serviceKeys,prefix:'auth-private/v2/'+raw.env+'/'+app+'/'+raw.generation+'/',callbacks:Object.fromEntries(Object.entries(ORIGINS).map(([name,origin])=>[name,{origin,callbacks:name==='academy'?[]:[origin+'/auth/v2/admission/callback',origin+'/auth/v2/unlock/callback'],returns:(raw.returns?.[name]||[origin+'/'])}]))};
}
export const runtimeConfigurationBoundary=Object.freeze({source:'Configuration is server-installed and bound to exact owner/origin/native manifest; request headers never select keys, namespaces or dependencies.',activation:'The committed source manifests stay disabled. Tests may explicitly select a disposable local runtime; no import installs schema or activates hosted state.'});
