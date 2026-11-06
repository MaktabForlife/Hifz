// Hifz identity-only, native-account-bound prepared refresh. No Academy hop,
// journal read/cache or copied profile/epoch/source ownership is changed.
import {AuthContractError,createConfiguredAccessEngine,IDLE_SECONDS} from './claims.mjs';
import {createPrototypeStore} from './store.mjs';
const fail=code=>{throw new AuthContractError(code);};
const tuple=['family_id','account_id','parent_session_id','browser_id','browser_generation','credential_epoch','unlock_generation','original_signed_in_at_s','original_expires_at_s','refresh_generation'];
const contextSQL='SELECT f.*,v.permission_version current_permission_version,n.id native_account_id,coalesce(n.credential_epoch,0) native_epoch FROM jwt_v110_families f JOIN jwt_v110_accounts v USING(account_id) JOIN students n ON n.id=f.account_id JOIN jwt_v110_browser_heads b USING(browser_id) WHERE f.family_id=? AND f.refresh_fp=? AND f.refresh_generation=? AND f.revoked=0 AND v.active=1 AND n.active=1 AND v.credential_epoch=f.credential_epoch AND coalesce(n.credential_epoch,0)=f.credential_epoch AND b.generation=f.browser_generation AND f.original_expires_at_s>? AND ?-f.last_fg_refresh_s<5400 AND NOT EXISTS(SELECT 1 FROM jwt_v110_parent_tombstones t WHERE t.parent_session_id=f.parent_session_id)';
const claims=row=>({sub:row.account_id,sid:row.family_id,psid:row.parent_session_id,bsid:row.browser_id,bv:row.browser_generation,ce:row.credential_epoch,pv:row.current_permission_version,ue:row.unlock_generation,s_iat:row.original_signed_in_at_s,s_exp:row.original_expires_at_s});
function internal(body,cookies,claims){
 const value={...body};Object.defineProperty(value,'setCookies',{value:Object.freeze(cookies),enumerable:false});
 if(claims)Object.defineProperty(value,'claims',{value:claims,enumerable:false});return Object.freeze(value);
}
export async function createAccountBoundHifzRefresh({binding,clock=()=>Math.floor(Date.now()/1000),authorizeRotation,...config}){
 if(config.app!=='hifz'||!binding?.withSession||typeof clock!=='function'||authorizeRotation!==undefined&&typeof authorizeRotation!=='function')fail('INVALID_CONFIG');
 const engine=await createConfiguredAccessEngine(config);
 return Object.freeze({async refreshAndIssue(raw,options={}){
  if(!options||Object.keys(options).some(key=>key!=='foreground')||options.foreground!==undefined&&typeof options.foreground!=='boolean')fail('INVALID_REFRESH_MODE');
  const rotation={statements:0,rowsRead:0,rowsWritten:0},identityRead={...rotation},metrics={rotation,identityRead};let selected;
  for(let attempt=0;attempt<2;attempt++){
   const now=clock();if(!Number.isSafeInteger(now)||now<0)fail('INVALID_TIME');
   const store=createPrototypeStore(binding,{app:'hifz',commitClock:clock,prepareRotation:async({family,oldFingerprint,now:preparedAt})=>{
    if(selected&&tuple.some(key=>selected[key]!==family[key]))fail('SESSION_ENDED');selected??={...family};
    const result=await binding.withSession('first-primary').prepare(contextSQL).bind(family.family_id,oldFingerprint,family.refresh_generation,preparedAt,preparedAt).all(),row=result.results[0];
    identityRead.statements++;identityRead.rowsRead+=result.meta?.rows_read||0;identityRead.rowsWritten+=result.meta?.rows_written||0;
    if(!row||row.native_account_id!==row.account_id||tuple.some(key=>row[key]!==family[key]))fail('SESSION_ENDED');
    if(!Number.isSafeInteger(row.last_fg_refresh_s)||row.last_fg_refresh_s<row.original_signed_in_at_s||row.last_fg_refresh_s>preparedAt)fail('INVALID_TIME');
    if(preparedAt-row.last_fg_refresh_s>=IDLE_SECONDS)fail('PIN_REQUIRED');
    if(authorizeRotation)await authorizeRotation({family:row,now:preparedAt});
    const issued=await engine.issue(claims(row),preparedAt);
    return {permissionVersion:row.current_permission_version,nativeEpoch:row.native_epoch,expiresAt:issued.claims.exp,ready(next,committedAt){
     return internal({kind:'rotated',metrics,nativeAccountBound:true,identityOnly:true},[engine.accessCookie(issued.token,issued.claims.exp,committedAt),engine.refreshCookie(next,row.original_expires_at_s,committedAt)],issued.claims);
    }};
   }});
   const committed=await store.refresh(raw,{now,foreground:options.foreground===true});
   for(const key of Object.keys(rotation))rotation[key]+=store.metrics[key];
   if(committed.kind==='rotated')return committed.preparedResponse;
   if(committed.kind!=='retry_preparation')return internal({kind:committed.kind,metrics,nativeAccountBound:true,identityOnly:true},[]);
  }
  return internal({kind:'retry_required',metrics,nativeAccountBound:true,identityOnly:true},[]);
 }});
}
