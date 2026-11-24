import {canonical,requireThat,uuid,hmac,b64u,unb64u,equal,digest,strictJSON} from './codec.mjs';
import {verifyBootstrap} from './browser-security.mjs';
import {expectedContext,requireExpected} from './http-context.mjs';
const kinds=new Set(['pin','pin/setup','admission/start','admission/finalize','unlock/start','unlock/finalize','admission/proceed','browser-clear','shared-entry']);
export class HTTPTransactions {
 constructor(runtime){this.runtime=runtime;this.store=runtime.store;this.clock=runtime.clock;}
 async create({kind,sub=null,expected=null,payload={},tx:suppliedTx,operationId=crypto.randomUUID(),expiresAt=this.clock()+300}){
  const tx=suppliedTx===undefined?crypto.randomUUID():suppliedTx;
  requireThat(kinds.has(kind)&&uuid(tx)&&uuid(operationId)&&expiresAt>this.clock()&&expiresAt<=this.clock()+300,'INVALID_BROWSER_TRANSACTION',400);
  const updateGeneration=this.runtime.settings.raw.offlineUpdate?.generation;
  if(updateGeneration!==undefined)payload={...payload,updateGeneration};
  const old=suppliedTx===undefined?null:await this.get(tx);
  if(old){requireThat(old.kind===kind&&old.sub===sub&&old.expected_json===(expected===null?null:canonical(expected))&&old.operation_id===operationId&&old.payload_json===canonical(payload),'TRANSACTION_CONFLICT',409);return old;}
  const row=await this.store.stmt("INSERT INTO jwt_v2_http_transactions VALUES(?,?,?,?,?,?,?,?,?,'PENDING',?,NULL) RETURNING *",tx,kind,sub,expected===null?null:canonical(expected),operationId,this.runtime.settings.csrf.currentKid,expiresAt,this.clock(),expiresAt,canonical(payload)).first();
  requireThat(row?.tx===tx&&row.operation_id===operationId,'BROWSER_TRANSACTION_UNAVAILABLE',503);
  return row;
 }
 get(tx){requireThat(uuid(tx),'INVALID_BROWSER_TRANSACTION',400);return this.store.first('SELECT * FROM jwt_v2_http_transactions WHERE tx=?',tx);}
 async proof(row){
  const key=this.runtime.settings.csrf.keys.get(row.csrf_kid);requireThat(key,'CSRF_KEY_UNAVAILABLE',503);
  return b64u(await hmac(key,'uaa-browser-transaction-v2\0'+canonical({env:this.runtime.config.env,app:this.runtime.app,tx:row.tx,kind:row.kind,sub:row.sub,expected:row.expected_json&&JSON.parse(row.expected_json),operationId:row.operation_id,expiresAt:row.csrf_expires})));
 }
 async dto(row,kind=row.kind){return {tx:row.tx,csrf:await this.proof(row),csrfExpiresAtMs:row.csrf_expires*1000,intent:{id:row.operation_id,kind,generation:0,expiresAtMs:row.expires_at*1000}};}
 async verify(request,body,kind,{allowCommitted=false}={}){
  verifyBootstrap(request,this.runtime.config);
  requireThat(uuid(body.operationId)&&(!body.tx||uuid(body.tx)),'TRANSACTION_PROOF_REQUIRED',403);
  const row=body.tx?await this.get(body.tx):await this.store.first('SELECT * FROM jwt_v2_http_transactions WHERE operation_id=?',body.operationId);requireThat(row&&row.kind===kind&&row.operation_id===body.operationId&&this.clock()<row.expires_at&&this.clock()<row.csrf_expires&&(row.status==='PENDING'||allowCommitted&&row.status==='COMMITTED'),'BROWSER_TRANSACTION_EXPIRED',409);
  const generation=this.runtime.settings.raw.offlineUpdate?.generation;
  requireThat(generation===undefined||strictJSON(row.payload_json).updateGeneration===generation,'BROWSER_TRANSACTION_EXPIRED',409);
  const expected=row.expected_json&&JSON.parse(row.expected_json),supplied=expectedContext(request,body);
  if(expected)requireExpected(expected,supplied);else requireThat(supplied===null,'OPERATION_SUPERSEDED',409);
  const proof=request.headers.get('X-UAA-CSRF');unb64u(proof,32);requireThat(equal(proof,await this.proof(row)),'CSRF_INVALID',403);
  return {row,csrfHash:await digest(proof)};
 }
 guard(row){return this.store.guard("SELECT 1 FROM jwt_v2_http_transactions WHERE tx=? AND operation_id=? AND status='PENDING' AND expires_at>?",[row.tx,row.operation_id,this.clock()]);}
}
