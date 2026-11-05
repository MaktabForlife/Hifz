// Independent COMPACT Studio issuance proof; no live route imports this.
// Uses only reads of native business tables. JWT metadata here is synthetic;
// production binding/mutation integration remains gated by the live DB hold.
import {AuthContractError,createConfiguredAccessEngine} from './claims.mjs';
import {createPrototypeStore} from './store.mjs';
const fail=code=>{throw new AuthContractError(code);};
const contextSQL='SELECT f.*,v.permission_version current_permission_version,a.account_id native_account_id,a.global_admin,a.epoch native_epoch FROM jwt_v110_families f JOIN jwt_v110_accounts v USING(account_id) JOIN accounts a USING(account_id) JOIN jwt_v110_browser_heads b USING(browser_id) WHERE f.family_id=? AND f.refresh_fp=? AND f.refresh_generation=? AND f.revoked=0 AND v.active=1 AND a.active=1 AND a.admitted=1 AND v.credential_epoch=f.credential_epoch AND a.epoch=f.credential_epoch AND b.generation=f.browser_generation AND f.original_expires_at_s>? AND ?-f.last_fg_refresh_s<5400 AND NOT EXISTS(SELECT 1 FROM jwt_v110_parent_tombstones t WHERE t.parent_session_id=f.parent_session_id)';
const compactMode=Object.freeze({v:1,app:'studio',mode:'identity'});
const isCompact=r=>Boolean(r&&Object.getPrototypeOf(r)===Object.prototype&&Object.keys(r).length===3&&r.v===1&&r.app==='studio'&&r.mode==='identity');
export async function createStudioCompactEngine(config){
 if(config?.app!=='studio')fail('INVALID_CONFIG');
 const base=await createConfiguredAccessEngine({...config,validateRights:isCompact});
 return Object.freeze({
  async issue(input,now){
   if(!input||typeof input!=='object'||Object.hasOwn(input,'r'))fail('INVALID_COMPACT_INPUT');
   return base.issue({...input,r:compactMode},now);
  },
  verify:(token,now)=>base.verify(token,now),
  accessCookie:(token,expiry,now)=>base.accessCookie(token,expiry,now),
  refreshCookie:(token,expiry,now)=>base.refreshCookie(token,expiry,now)
 });
}
const familyTuple=['family_id','account_id','parent_session_id','browser_id','browser_generation','credential_epoch','unlock_generation','original_signed_in_at_s','original_expires_at_s','refresh_generation'];
function parameters(family,fp,now){return [family.family_id,fp,family.refresh_generation,now,now];}
function internalResult(publicFields,cookies=[],claims){
 const result={...publicFields};
 // Defence in depth: HTTP adapters must still allowlist their JSON body.
 // Accidental JSON.stringify(result) must not disclose Set-Cookie or claims.
 Object.defineProperty(result,'setCookies',{value:Object.freeze(cookies),enumerable:false});
 if(claims)Object.defineProperty(result,'claims',{value:claims,enumerable:false});
 return Object.freeze(result);
}
function currentClaims(row){
 return {sub:row.account_id,sid:row.family_id,psid:row.parent_session_id,bsid:row.browser_id,bv:row.browser_generation,ce:row.credential_epoch,pv:row.current_permission_version,ue:row.unlock_generation,s_iat:row.original_signed_in_at_s,s_exp:row.original_expires_at_s};
}
async function identitySnapshot(db,family,fp,now){
 const result=await db.prepare(contextSQL).bind(...parameters(family,fp,now)).all(),row=result.results[0];
 if(!row||row.native_account_id!==row.account_id||familyTuple.some(key=>row[key]!==family[key]))fail('SESSION_ENDED');
 return {row,metrics:{statements:1,rowsRead:result.meta?.rows_read||0,rowsWritten:result.meta?.rows_written||0}};
}
export async function createAccountBoundCompactStudioRefresh({binding,clock=()=>Math.floor(Date.now()/1000),...config}){
 if(config.app!=='studio'||!binding?.withSession||typeof clock!=='function')fail('INVALID_CONFIG');
 const engine=await createStudioCompactEngine(config);
 return Object.freeze({
  async refreshAndIssue(raw,options={}){
   if(!options||Object.keys(options).some(k=>k!=='foreground')||(options.foreground!==undefined&&typeof options.foreground!=='boolean'))fail('INVALID_REFRESH_MODE');
   const rotation={statements:0,rowsRead:0,rowsWritten:0},identityRead={...rotation};
   const metrics={rotation,identityRead};let selectedFamily;

   for(let attempt=0;attempt<2;attempt++){
    const now=clock();if(!Number.isSafeInteger(now)||now<0)fail('INVALID_TIME');
    const store=createPrototypeStore(binding,{app:'studio',commitClock:clock,
     async prepareRotation({family,oldFingerprint,now:preparedAt}){
      if(selectedFamily&&familyTuple.some(key=>family[key]!==selectedFamily[key]))fail('SESSION_ENDED');
      selectedFamily??={...family};
      const current=await identitySnapshot(binding.withSession('first-primary'),family,oldFingerprint,preparedAt);
      for(const key of Object.keys(identityRead))identityRead[key]+=current.metrics[key];
      // Every fallible identity read, compact claim validation/signing and initial
      // capacity check completes while the browser's old refresh is current.
      const issued=await engine.issue(currentClaims(current.row),preparedAt);
      return {permissionVersion:current.row.current_permission_version,nativeEpoch:current.row.native_epoch,nativeGlobalAdmin:current.row.global_admin,expiresAt:issued.claims.exp,
       ready(next,committedAt){
        return internalResult({kind:'rotated',metrics,nativeAccountBound:true,compact:true},[engine.accessCookie(issued.token,issued.claims.exp,committedAt),engine.refreshCookie(next,current.row.original_expires_at_s,committedAt)],issued.claims);
       }
      };
     }
    });
    const committed=await store.refresh(raw,{now,foreground:options.foreground===true});
    for(const key of Object.keys(rotation))rotation[key]+=store.metrics[key];
    if(committed.kind==='rotated'){
     // No native read/sign/cookie construction remains after the primary CAS.
     return committed.preparedResponse;
    }
    if(committed.kind!=='retry_preparation')return internalResult({kind:committed.kind,metrics,nativeAccountBound:true,compact:true});
   }
   // Bounded PV churn has committed no successor and emits no cookies. The
   // original raw secret remains current unless a concurrent request won.
   return internalResult({kind:'retry_required',metrics,nativeAccountBound:true,compact:true});
  }
 });
}

// Experimental protected-read identity gate. Material authorization remains in
// the requested native resource handler; this never exports a grant directory.
export async function authenticateCompactStudio({engine,binding,token,now}){
 if(!engine?.verify||!binding?.withSession)fail('INVALID_CONFIG');
 const claims=await engine.verify(token,now);
 const sql='SELECT a.account_id,a.display_name,a.active,a.admitted,a.epoch,a.verified_at,a.global_admin,f.last_fg_refresh_s,v.permission_version current_permission_version FROM jwt_v110_families f JOIN jwt_v110_accounts v USING(account_id) JOIN accounts a USING(account_id) JOIN jwt_v110_browser_heads b USING(browser_id) WHERE f.family_id=? AND f.account_id=? AND f.parent_session_id=? AND f.browser_id=? AND f.browser_generation=? AND f.credential_epoch=? AND f.unlock_generation=? AND f.original_signed_in_at_s=? AND f.original_expires_at_s=? AND f.revoked=0 AND v.active=1 AND a.active=1 AND a.admitted=1 AND v.credential_epoch=f.credential_epoch AND a.epoch=f.credential_epoch AND b.generation=f.browser_generation AND f.original_expires_at_s>? AND NOT EXISTS(SELECT 1 FROM jwt_v110_parent_tombstones t WHERE t.parent_session_id=f.parent_session_id)';
 const result=await binding.withSession('first-primary').prepare(sql).bind(claims.sid,claims.sub,claims.psid,claims.bsid,claims.bv,claims.ce,claims.ue,claims.s_iat,claims.s_exp,now).all(),row=result.results[0];
 if(!row)fail('SESSION_ENDED');
 if(now-row.last_fg_refresh_s>=5400)fail('PIN_REQUIRED');
 if(row.current_permission_version!==claims.pv)fail('TOKEN_UPDATE_REQUIRED');
 const actor=Object.fromEntries(['account_id','display_name','active','admitted','epoch','verified_at','global_admin'].map(key=>[key,row[key]]));
 return Object.freeze({actor:Object.freeze(actor),claims,metrics:{statements:1,rowsRead:result.meta?.rows_read||0,rowsWritten:result.meta?.rows_written||0}});
}
