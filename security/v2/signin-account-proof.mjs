import {ascii,canonical,digest,exact,requireThat,safeInt,uuid} from './codec.mjs';
import {admissionFloorCondition,admissionFloorGuard} from './publication.mjs';
import {readyAccountSQL} from './shared-account-baselines.mjs';

const fields = ['schema','kind','env','recipient','generation','ownerEpoch','operationId','sub',
 'ce','ae','psid','bsid','bv','le','eligibilityRevision','coverage','ordinal','issuedAt','expiresAt'];

const proofSQL = `SELECT 1 FROM jwt_v2_signin_account_proofs p
 JOIN jwt_v2_accounts a ON a.sub=p.sub AND a.ce=p.ce AND a.ae=p.ae AND a.active=1
 JOIN jwt_v2_event_streams e ON e.source_app='academy' AND e.target_app=p.recipient
  AND e.stream='account-security' AND e.owner_epoch=p.owner_epoch
 WHERE p.recipient=? AND p.owner_epoch=? AND p.sub=? AND p.ce=? AND p.ae=?
 AND p.env=? AND p.generation=? AND p.expires_at>unixepoch()
 AND e.contiguous_through=e.highest_seen AND e.contiguous_through>=p.coverage`;

export function accountGate(runtime,mode,binding) {
 const args=[runtime.app,mode.ownerEpoch,binding.sub,binding.ce,binding.ae];
 if(runtime.settings.raw.signInBaselineRefresh!==true)return {sql:readyAccountSQL,args};
 return {
  sql:`SELECT 1 WHERE EXISTS(${readyAccountSQL}) OR EXISTS(${proofSQL})`,
  args:[...args,...args,runtime.config.env,runtime.settings.raw.signInBaselineGeneration]
 };
}

export async function receiveAccountProof(runtime,peer,value,raw) {
 const mode=runtime.settings.raw.sharedChildEntry;
 requireThat(runtime.settings.raw.signInBaselineRefresh===true&&mode&&runtime.settings.sharedAcademy
  &&peer.sourceApp==='academy'&&peer.targetApp===runtime.app,'SIGNIN_BASELINE_DISABLED',404);
 const p=exact(value,fields),now=runtime.clock();
 requireThat(p.schema===1&&p.kind==='signin-account-baseline'&&canonical(p)===new TextDecoder().decode(raw)
  &&p.env===runtime.config.env&&p.recipient===runtime.app&&ascii(p.generation,64)&&p.generation===runtime.settings.raw.signInBaselineGeneration
  &&p.ownerEpoch===mode.ownerEpoch&&uuid(p.operationId)&&uuid(p.psid)&&uuid(p.bsid)&&ascii(p.sub,180)
  &&['ce','ae','bv','ordinal','issuedAt','expiresAt'].every(k=>safeInt(p[k],1))
  &&['le','coverage','eligibilityRevision'].every(k=>safeInt(p[k]))
  &&p.issuedAt<=now+30&&p.expiresAt>now&&p.expiresAt<=p.issuedAt+604800,'INVALID_SIGNIN_BASELINE',400);
 const store=runtime.store,proofDigest=await digest(p);
 const key=[p.env,p.recipient,p.generation,p.ownerEpoch,p.sub];
 const keyWhere='env=? AND recipient=? AND generation=? AND owner_epoch=? AND sub=?';
 const streamSQL="SELECT contiguous_through,highest_seen FROM jwt_v2_event_streams WHERE source_app='academy' AND target_app=? AND stream='account-security' AND owner_epoch=?";
 const cursor=await store.first(streamSQL,p.recipient,p.ownerEpoch);
 requireThat(cursor,'BASELINE_STREAM_NOT_INSTALLED',503);
 const response=(status,verifiedCoverage,highestSeen)=>({schema:1,kind:'signin-account-baseline-receipt',status,proofDigest,
  env:p.env,recipient:p.recipient,generation:p.generation,ownerEpoch:p.ownerEpoch,operationId:p.operationId,
  psid:p.psid,sub:p.sub,ce:p.ce,ae:p.ae,eligibilityRevision:p.eligibilityRevision,coverage:p.coverage,verifiedCoverage,highestSeen});
 if(cursor.contiguous_through<p.coverage||cursor.contiguous_through!==cursor.highest_seen)
  return response('PENDING',cursor.contiguous_through,cursor.highest_seen);
 const control=await runtime.appControl();
 requireThat(control.sharedAcademyRegistryRevision===runtime.settings.sharedAcademy.revision,'CHILD_AUTHORITY_PENDING',503);
 const mapping=await runtime.native.mappingGuard(p);
 const floor=admissionFloorGuard(store,p);
 const guards=[
  floor,
  store.guard(mapping.sql,mapping.args),
  store.guard(`SELECT 1 FROM (${streamSQL}) WHERE contiguous_through>=? AND contiguous_through=highest_seen`,[p.recipient,p.ownerEpoch,p.coverage]),
  store.guard('SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_signin_proof_receipts WHERE operation_id=? AND proof_digest<>?)',[p.operationId,proofDigest]),
  store.guard(`SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_signin_account_proofs WHERE ${keyWhere}
   AND proof_digest<>? AND (coverage>? OR coverage=? AND ordinal>=? OR ce>? OR ce=? AND ae>?
    OR ce=? AND ae=? AND json_extract(proof,'$.eligibilityRevision')>?))`,
   [...key,proofDigest,p.coverage,p.coverage,p.ordinal,p.ce,p.ce,p.ae,p.ce,p.ae,p.eligibilityRevision]),
  store.guard('SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_accounts WHERE sub=? AND (active=0 OR ce>? OR ce=? AND ae>?))',[p.sub,p.ce,p.ce,p.ae])
 ];
 await store.batch([
  ...guards.map(pair=>pair[0]),
  store.stmt(`INSERT INTO jwt_v2_accounts(sub,ce,ae,le,active,revision) VALUES(?,?,?,0,1,1)
   ON CONFLICT(sub) DO UPDATE SET ce=excluded.ce,ae=excluded.ae,revision=revision+1
   WHERE ce<excluded.ce OR ce=excluded.ce AND ae<excluded.ae`,p.sub,p.ce,p.ae),
  store.stmt(`INSERT INTO jwt_v2_signin_account_proofs VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
   ON CONFLICT(env,recipient,generation,owner_epoch,sub) DO UPDATE SET
   ce=excluded.ce,ae=excluded.ae,coverage=excluded.coverage,ordinal=excluded.ordinal,expires_at=excluded.expires_at,
   proof_digest=excluded.proof_digest,proof=excluded.proof WHERE proof_digest<>excluded.proof_digest`,
   ...key,p.ce,p.ae,p.coverage,p.ordinal,p.expiresAt,proofDigest,canonical(p)),
  store.stmt('INSERT INTO jwt_v2_signin_proof_receipts VALUES(?,?) ON CONFLICT(operation_id) DO NOTHING',p.operationId,proofDigest),
  ...guards.map(pair=>pair[1])
 ]);
 const gate=accountGate(runtime,mode,p),denial=admissionFloorCondition(p);
 const current=await store.first(`SELECT * FROM (${streamSQL})
  WHERE contiguous_through=highest_seen AND contiguous_through>=?
   AND EXISTS(SELECT 1 FROM jwt_v2_signin_account_proofs WHERE ${keyWhere} AND proof_digest=? AND expires_at>unixepoch())
   AND EXISTS(${gate.sql}) AND EXISTS(${denial.sql}) AND EXISTS(${mapping.sql})`,
  p.recipient,p.ownerEpoch,p.coverage,...key,proofDigest,...gate.args,...denial.args,...mapping.args);
 const after=await runtime.appControl();
 requireThat(current&&after.sharedAcademyRegistryRevision===runtime.settings.sharedAcademy.revision,
  'CHILD_AUTHORITY_PENDING',503);
 return response('APPLIED',current.contiguous_through,current.highest_seen);
}
