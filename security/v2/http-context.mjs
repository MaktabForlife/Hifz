import {canonical,requireThat,reject,bytes,b64u,unb64u,strictJSON,safeInt,uuid,hmac,equal,digest,opaque} from './codec.mjs';
import {ownOrigin,readCookies} from './tokens.mjs';
import {verifyBootstrap} from './browser-security.mjs';

export const CONTEXT_FIELDS=Object.freeze('app sub sid psid bsid bv ce ae le sv ue'.split(' '));
export const selector=(binding,app=binding.app)=>Object.fromEntries(CONTEXT_FIELDS.map(k=>[k,k==='app'?app:binding[k]]));
export function exactContext(value){
 requireThat(value&&typeof value==='object'&&Object.keys(value).length===CONTEXT_FIELDS.length&&CONTEXT_FIELDS.every(k=>Object.hasOwn(value,k)),'EXPECTED_CONTEXT_REQUIRED',409);
 requireThat(['academy','studio','hifz'].includes(value.app)&&typeof value.sub==='string'&&value.sub.length>0&&['sid','psid','bsid'].every(k=>uuid(value[k]))&&['bv','ce','ae','sv'].every(k=>safeInt(value[k],1))&&['le','ue'].every(k=>safeInt(value[k])),'INVALID_EXPECTED_CONTEXT',409);return value;
}
export function expectedContext(request,body){
 const encoded=request.headers.get('X-UAA-Expected-Context');
 let header=null;if(encoded){requireThat(encoded.length<=2048,'EXPECTED_CONTEXT_TOO_LARGE',400);header=exactContext(strictJSON(unb64u(encoded)));}
 const value=body?.expectedContext===undefined?header:body.expectedContext;
 if(value===null)return null;
 if(value)exactContext(value);
 if(header&&body?.expectedContext)requireThat(canonical(header)===canonical(body.expectedContext),'EXPECTED_CONTEXT_CONFLICT',409);
 return value||null;
}
export function requireExpected(actual,expected){requireThat(expected&&canonical(exactContext(expected))===canonical(actual),'OPERATION_SUPERSEDED',409);}
export const httpSchemaSQL=[
 "CREATE TABLE IF NOT EXISTS jwt_v2_http_intents(intent_id TEXT PRIMARY KEY REFERENCES jwt_v2_intents(intent_id),purpose TEXT NOT NULL,context_json TEXT NOT NULL,csrf_expires INTEGER NOT NULL,csrf_kid TEXT NOT NULL);",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_http_intent_immutable BEFORE UPDATE ON jwt_v2_http_intents BEGIN SELECT RAISE(ABORT,'jwt_v2_http_intent_immutable'); END;",
 "CREATE TABLE IF NOT EXISTS jwt_v2_http_transactions(tx TEXT PRIMARY KEY,kind TEXT NOT NULL,sub TEXT,expected_json TEXT,operation_id TEXT NOT NULL UNIQUE,csrf_kid TEXT NOT NULL,csrf_expires INTEGER NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,status TEXT NOT NULL,payload_json TEXT NOT NULL,result_json TEXT);",
 "CREATE TABLE IF NOT EXISTS jwt_v2_draft_capsules(sid TEXT NOT NULL,draft_generation INTEGER NOT NULL,kid TEXT NOT NULL,iv TEXT NOT NULL,capsule TEXT NOT NULL,binding_json TEXT NOT NULL,created_at INTEGER NOT NULL,s_exp INTEGER NOT NULL,PRIMARY KEY(sid,draft_generation));"
].join('\n');
const PURPOSES=new Set(['refresh','logout','switch','draft-key','status','browser-clear','business']);
function csrfPacket(config,purpose,context,operationId,expiresAt){return 'uaa-http-csrf-v2\0'+canonical({schema:2,env:config.env,app:config.app,purpose,context,operationId,expiresAt});}
export class HTTPIntents {
 constructor({store,config,csrf,clock}){Object.assign(this,{store,config,csrf,clock});}
 async proof(meta){const key=this.csrf.keys.get(meta.csrf_kid);requireThat(key,'CSRF_KEY_UNAVAILABLE',503);return b64u(await hmac(key,csrfPacket(this.config,meta.purpose,JSON.parse(meta.context_json),meta.intent_id,meta.csrf_expires)));}
 async issue(family,purpose){
  requireThat(PURPOSES.has(purpose),'INVALID_AUTH_PURPOSE',400);const now=this.clock();
  requireThat(family&&now<family.s_exp&&!['REVOKED','EXPIRED'].includes(family.state),'SESSION_ENDED',401);
  const context=selector(JSON.parse(family.binding_json),this.config.app),kind=purpose;
  let old=await this.store.first("SELECT i.*,h.purpose,h.context_json,h.csrf_expires,h.csrf_kid FROM jwt_v2_intents i JOIN jwt_v2_http_intents h USING(intent_id) WHERE i.sid=? AND i.kind=? AND i.generation=? AND i.state='ISSUED'",family.sid,kind,family.fingerprint_generation);
  if(old&&now<old.csrf_expires&&old.binding_json===family.binding_json)return this.dto(old);
  const id=crypto.randomUUID(),expires=purpose==='business'?Math.min(family.deadline,family.idle_until,family.s_exp):Math.min(now+300,family.s_exp),meta={intent_id:id,purpose,context_json:canonical(context),csrf_expires:expires,csrf_kid:this.csrf.currentKid};
  requireThat(expires>now,'ACCESS_REFRESH_REQUIRED',401);
  const proof=await this.proof(meta),csrfHash=await digest(proof);
  const [guard,clear]=this.store.guard("SELECT 1 FROM jwt_v2_families WHERE sid=? AND binding_json=? AND fingerprint_generation=? AND state NOT IN('REVOKED','EXPIRED') AND s_exp>?",[family.sid,family.binding_json,family.fingerprint_generation,now]);
  try{await this.store.batch([guard,
   this.store.stmt("UPDATE jwt_v2_intents SET state='CANCELLED',superseding_operation=? WHERE sid=? AND kind=? AND generation=? AND state='ISSUED'",id,family.sid,kind,family.fingerprint_generation),
   this.store.stmt("INSERT INTO jwt_v2_intents(intent_id,sid,kind,binding_json,csrf_hash,generation,state,expires_at) VALUES(?,?,?,?,?,?,'ISSUED',?)",id,family.sid,kind,family.binding_json,csrfHash,family.fingerprint_generation,expires),
   this.store.stmt('INSERT INTO jwt_v2_http_intents VALUES(?,?,?,?,?)',id,purpose,meta.context_json,expires,meta.csrf_kid),clear
  ]);}catch(error){
   old=await this.store.first("SELECT i.*,h.purpose,h.context_json,h.csrf_expires,h.csrf_kid FROM jwt_v2_intents i JOIN jwt_v2_http_intents h USING(intent_id) WHERE i.sid=? AND i.kind=? AND i.generation=? AND i.state='ISSUED'",family.sid,kind,family.fingerprint_generation);
   if(old&&old.binding_json===family.binding_json&&now<old.csrf_expires)return this.dto(old);throw error;
  }
  return this.dto({...meta,kind,generation:family.fingerprint_generation});
 }
 async dto(row){
  let proof=await this.proof(row);
  if(row.purpose==='business')proof=b64u(bytes(canonical({schema:2,kid:row.csrf_kid,expiresAt:row.csrf_expires,operationId:row.intent_id,proof})));
  return {intent:{id:row.intent_id,kind:row.kind||row.purpose,generation:row.generation,expiresAtMs:row.csrf_expires*1000},csrf:proof,csrfExpiresAtMs:row.csrf_expires*1000};
 }
 async verify(request,{operationId,purpose,context,allowHistorical=false}){
  verifyBootstrap(request,this.config);requireThat(uuid(operationId)&&PURPOSES.has(purpose),'UNISSUED_OPERATION',403);
  const row=await this.store.first('SELECT i.*,h.purpose,h.context_json,h.csrf_expires,h.csrf_kid FROM jwt_v2_intents i JOIN jwt_v2_http_intents h USING(intent_id) WHERE i.intent_id=?',operationId);
  requireThat(row&&row.purpose===purpose&&row.context_json===canonical(exactContext(context)),'UNISSUED_OPERATION',403);
  requireThat(allowHistorical||this.clock()<row.csrf_expires,'CSRF_EXPIRED',403);
  const supplied=request.headers.get('X-UAA-CSRF');unb64u(supplied,32);requireThat(equal(supplied,await this.proof(row)),'CSRF_INVALID',403);
  return {row,csrfHash:await digest(supplied)};
 }
 async verifyBusiness(request,context){
  const proof=request.headers.get('X-UAA-CSRF'),operationId=request.headers.get('X-UAA-Business-Intent');
  if(!proof||!operationId)return false;
  requireThat(new URL(request.url).origin===this.config.origin,'WRONG_PUBLIC_ORIGIN',403);
  const origin=request.headers.get('Origin'),site=request.headers.get('Sec-Fetch-Site');
  requireThat((!origin||origin===this.config.origin)&&(!site||site==='same-origin')&&request.headers.get('X-UAA-Request')==='2','CROSS_ORIGIN',403);
  requireThat(proof.length<=1024&&uuid(operationId),'BUSINESS_CSRF_INVALID',403);
  const meta=strictJSON(unb64u(proof),{maxBytes:1024});
  requireThat(meta&&Object.keys(meta).sort().join(',')==='expiresAt,kid,operationId,proof,schema'&&meta.schema===2&&meta.operationId===operationId&&safeInt(meta.expiresAt)&&this.clock()<meta.expiresAt,'BUSINESS_CSRF_EXPIRED',403);
  const key=this.csrf.keys.get(meta.kid);requireThat(key,'CSRF_KEY_UNAVAILABLE',503);unb64u(meta.proof,32);
  const expected=b64u(await hmac(key,csrfPacket(this.config,'business',context,operationId,meta.expiresAt)));
  requireThat(equal(meta.proof,expected),'CSRF_INVALID',403);return true;
 }
}
export function decorateResponse(response,context,nowMs){
 const result=new Response(response.body,response);result.headers.set('X-UAA-Contract','2');result.headers.set('X-UAA-Server-Now-Ms',String(nowMs));
 if(context)result.headers.set('X-UAA-Context',b64u(bytes(canonical(context))));
 if(context){result.headers.set('Cache-Control','private, no-store');result.headers.set('Pragma','no-cache');}
 result.headers.set('X-Content-Type-Options','nosniff');return result;
}
export const requestCookies=(request,config)=>readCookies(request.headers.get('Cookie'),config.app);
