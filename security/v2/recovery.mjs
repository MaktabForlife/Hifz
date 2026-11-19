import {requireThat,canonical,uuid,digest} from './codec.mjs';
export const recoverySchemaSQL="CREATE TABLE IF NOT EXISTS jwt_v2_recovery_runs(operation_id TEXT PRIMARY KEY,old_generation TEXT NOT NULL,new_generation TEXT NOT NULL UNIQUE,state TEXT NOT NULL,manifest_json TEXT);CREATE TABLE IF NOT EXISTS jwt_v2_recovery_manifests(generation TEXT PRIMARY KEY,operation_id TEXT NOT NULL UNIQUE,manifest_json TEXT NOT NULL,state TEXT NOT NULL);";
export function assertServingGeneration({configuredGeneration,manifest,ingressHeld=false}){
 requireThat(!ingressHeld&&manifest?.state==='SERVING'&&manifest.generation===configuredGeneration,'SECURITY_RECOVERY_INGRESS_HELD',503);
}
export async function recoverNamespace({store,operationId,oldGeneration,approved=false,operations}){
 requireThat(approved,'DEPLOYMENT_APPROVAL_REQUIRED',403);
 requireThat(uuid(operationId)&&typeof oldGeneration==='string'&&oldGeneration.length>0,'INVALID_RECOVERY_OPERATION',400);
 for(const name of ['holdIngress','fencePublishers','capturePrimaryEvidence','publishFreshGeneration','verifyBarriers','pinServingConfiguration','drainOldGeneration','verifyIngressConfiguration','releaseIngress'])requireThat(typeof operations[name]==='function','RECOVERY_ADAPTER_REQUIRED',503);
 let run=await store.first('SELECT * FROM jwt_v2_recovery_runs WHERE operation_id=?',operationId);
 if(!run){
  const generation=crypto.randomUUID();
  await store.stmt("INSERT INTO jwt_v2_recovery_runs VALUES(?,?,?,'FENCING',NULL)",operationId,oldGeneration,generation).run();
  run=await store.first('SELECT * FROM jwt_v2_recovery_runs WHERE operation_id=?',operationId);
 }
 requireThat(run.old_generation===oldGeneration&&run.new_generation!==oldGeneration,'RECOVERY_OPERATION_CONFLICT',409);
 if(run.state==='SERVING')return JSON.parse(run.manifest_json);
 await operations.holdIngress({operationId,oldGeneration});
 await operations.fencePublishers({operationId,oldGeneration});
 await store.batch([store.stmt("UPDATE jwt_v2_objects SET state='FENCED' WHERE generation=? AND state<>'RETIRED'",oldGeneration),store.stmt("UPDATE jwt_v2_recovery_runs SET state='HELD' WHERE operation_id=?",operationId)]);
 const evidence=await operations.capturePrimaryEvidence({operationId,oldGeneration});
 requireThat(evidence&&Array.isArray(evidence.leases)&&evidence.floorsComplete===true,'RECOVERY_EVIDENCE_INCOMPLETE',503);
 const published=await operations.publishFreshGeneration({operationId,generation:run.new_generation,evidence});
 requireThat(published?.generation===run.new_generation&&Array.isArray(published.leases),'RECOVERY_PUBLICATION_INVALID',503);
 for(const lease of published.leases){
  const original=evidence.leases.find(x=>x.sid===lease.sid);
  requireThat(original&&['vat','validationDeadline','s_iat','s_exp','idleUntil'].every(k=>lease[k]===original[k]),'RECOVERY_MUST_NOT_EXTEND_AUTHORITY',503);
 }
 requireThat(await operations.verifyBarriers({operationId,generation:run.new_generation,published})===true,'RECOVERY_BARRIERS_PENDING',503);
 const manifest={schema:2,generation:run.new_generation,operationId,oldGeneration,evidenceDigest:await digest(evidence),publicationDigest:await digest(published),state:'SERVING'};
 await store.batch([store.stmt("INSERT INTO jwt_v2_recovery_manifests VALUES(?,?,?,'SELECTED') ON CONFLICT(generation) DO UPDATE SET manifest_json=excluded.manifest_json",run.new_generation,operationId,canonical(manifest)),store.stmt("UPDATE jwt_v2_recovery_runs SET state='SELECTED',manifest_json=? WHERE operation_id=?",canonical(manifest),operationId)]);
 await operations.pinServingConfiguration({manifest});
 await operations.drainOldGeneration({oldGeneration,manifest});
 requireThat(await operations.verifyIngressConfiguration({oldGeneration,manifest})===true,'RECOVERY_OLD_GENERATION_NOT_DRAINED',503);
 await operations.releaseIngress({manifest});
 await store.stmt("UPDATE jwt_v2_recovery_runs SET state='SERVING' WHERE operation_id=?",operationId).run();return manifest;
}
