import {requireThat,safeInt,uuid} from './codec.mjs';

export const logoutDispatchEnabled=env=>env.UAA_V111_LOGOUT_DISPATCH==='1';

export function logoutDispatchScope(runtime){
 const {offlineUpdate}=runtime.settings.raw;
 requireThat(offlineUpdate&&safeInt(offlineUpdate.generation,1),'LOGOUT_DISPATCH_UNAVAILABLE',503);
 return JSON.stringify([runtime.settings.prefix,offlineUpdate.generation,offlineUpdate.releaseId]);
}

export async function armLogoutDispatch(runtime,operationId){
 if(!logoutDispatchEnabled(runtime.env))return undefined;
 logoutDispatchScope(runtime);
 requireThat(uuid(operationId)&&runtime.env.UAA_LOGOUT_DISPATCH,'LOGOUT_DISPATCH_UNAVAILABLE',503);
 const {generation,releaseId}=runtime.settings.raw.offlineUpdate;
 const expiresAt=await runtime.env.UAA_LOGOUT_DISPATCH.getByName(operationId).arm(operationId);
 requireThat(safeInt(expiresAt,1),'LOGOUT_DISPATCH_UNAVAILABLE',503);
 return {expiresAt,generation,releaseId,namespace:runtime.settings.prefix};
}

// A primary read after expiry cannot miss a later cutoff. The cutoff's
// transaction uses the same D1 clock and rejects the expired permit.
export function childLogoutProgress(runtime,operationId,expiresAt){
 return runtime.store.first(
  "SELECT unixepoch('now')>=? AS expired,q.operation_id,q.state AS report_state,"+
  "q.next_attempt_at AS next_delivery,w.state AS local_state "+
  "FROM (SELECT 1) anchor LEFT JOIN jwt_v2_service_outbox q ON q.operation_id=? AND q.kind='logout' "+
  "LEFT JOIN jwt_v2_worksets w ON w.work_id='local-report-'||q.operation_id",
  expiresAt,operationId);
}
