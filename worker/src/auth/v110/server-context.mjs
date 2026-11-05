// Opt-in, READ-ONLY V110 display-context producer. No family creation, refresh,
// native credential change, material grant or background/foreground update.
// This is not a replacement for each resource handler's current native guards.
import {AuthContractError,createConfiguredAccessEngine,cookieNames,parseUniqueCookie} from './claims.mjs';
import {createNativeCookieEngine} from './native-rights.mjs';
import {createStudioCompactEngine} from './compact-studio.mjs';
const issuers=Object.freeze({academy:'https://ummabbadacademy.app',studio:'https://worshipuponbaseera.ummabbadacademy.app',hifz:'https://mahadarwa-hifz.ummabbadacademy.app'});
const fail=code=>{throw new AuthContractError(code);};
const headers={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'};
const reply=(value,status=200,extra={})=>Response.json(value,{status,headers:{...headers,...extra}});
const familyWhere='f.family_id=? AND f.account_id=? AND f.parent_session_id=? AND f.browser_id=? AND f.browser_generation=? AND f.credential_epoch=? AND f.unlock_generation=? AND f.original_signed_in_at_s=? AND f.original_expires_at_s=? AND f.revoked=0 AND v.active=1 AND v.credential_epoch=f.credential_epoch AND b.generation=f.browser_generation AND f.original_expires_at_s>? AND NOT EXISTS(SELECT 1 FROM jwt_v110_parent_tombstones t WHERE t.parent_session_id=f.parent_session_id)';
const joins=Object.freeze({
 academy:{sql:"JOIN accounts n USING(account_id) JOIN account_credentials c USING(account_id)",where:"n.active=1 AND c.pin_setup=1 AND length(trim(c.pin_hash))>0 AND c.credential_epoch=f.credential_epoch AND EXISTS(SELECT 1 FROM account_sessions s WHERE s.session_id=f.family_id AND s.account_id=f.account_id AND s.credential_epoch=f.credential_epoch AND s.revoked_at IS NULL AND s.expires_at>?)"},
 studio:{sql:"JOIN accounts n USING(account_id)",where:"n.active=1 AND n.admitted=1 AND n.epoch=f.credential_epoch"},
 hifz:{sql:"JOIN students n ON n.id=f.account_id",where:"n.active=1 AND coalesce(n.credential_epoch,0)=f.credential_epoch"}
});
function configuredOrigin(value){
 let url;try{url=new URL(value);}catch{fail('CONTEXT_UNAVAILABLE');}
 if(url.origin!==value||url.username||url.password||url.protocol!=='https:'&&!(url.protocol==='http:'&&['127.0.0.1','localhost'].includes(url.hostname)))fail('CONTEXT_UNAVAILABLE');
 return value;
}
export async function readDisplayContext(request,env,{app,clock=()=>Math.floor(Date.now()/1000)}){
 if(!Object.hasOwn(issuers,app))return reply({code:'CONTEXT_UNAVAILABLE'},503);
 if(env.JWT_V110_BROWSER!=='1')return reply({code:'V110_NOT_ENABLED'},404);
 if(request.method!=='GET')return reply({code:'METHOD_NOT_ALLOWED'},405,{Allow:'GET'});
 try{
  // Explicit reviewed deployment config. Never adopt request Host/Origin.
  const expected=configuredOrigin(env.JWT_V110_REQUEST_ORIGIN||issuers[app]);
  if(new URL(request.url).origin!==expected||request.headers.get('Origin')&&request.headers.get('Origin')!==expected)return reply({code:'ORIGIN_NOT_ALLOWED'},403);
  const now=clock();if(!Number.isSafeInteger(now)||now<0)fail('CONTEXT_UNAVAILABLE');
  let publicKeys;try{publicKeys=JSON.parse(env.JWT_V110_PUBLIC_KEYS_JSON);}catch{fail('CONTEXT_UNAVAILABLE');}
  const config={app,issuer:issuers[app],publicKeys,...(app==='academy'?{academyCookieDomain:'ummabbadacademy.app'}:{})};
  const engine=app==='academy'?await createNativeCookieEngine(config):app==='studio'?await createStudioCompactEngine(config):await createConfiguredAccessEngine(config);
  const token=parseUniqueCookie(request.headers.get('Cookie')||'',cookieNames[app].access);
  const verified=await engine.verify(token,now),claims=app==='academy'?verified.claims:verified;
  const binding=app==='academy'?env.ACADEMY_DB:env.DB;
  if(!binding?.withSession)fail('CONTEXT_UNAVAILABLE');
  const native=joins[app],sql='SELECT f.last_fg_refresh_s,v.permission_version current_permission_version FROM jwt_v110_families f JOIN jwt_v110_accounts v USING(account_id) JOIN jwt_v110_browser_heads b USING(browser_id) '+native.sql+' WHERE '+familyWhere+' AND '+native.where;
  const args=[claims.sid,claims.sub,claims.psid,claims.bsid,claims.bv,claims.ce,claims.ue,claims.s_iat,claims.s_exp,now,...(app==='academy'?[new Date(now*1000).toISOString()]:[])];
  const result=await binding.withSession('first-primary').prepare(sql).bind(...args).all(),row=result.results[0];
  if(!row)fail('V110_SESSION_REQUIRED');
  if(!Number.isSafeInteger(row.last_fg_refresh_s)||row.last_fg_refresh_s<claims.s_iat||row.last_fg_refresh_s>now)fail('CONTEXT_UNAVAILABLE');
  if(now-row.last_fg_refresh_s>=5400)fail('PIN_REQUIRED');
  if(row.current_permission_version!==claims.pv)fail('TOKEN_UPDATE_REQUIRED');
  // Academy/Hifz native IDs may differ. Shared browser correlation uses only
  // parent/browser bindings; no alias is reinterpreted as a journal owner.
  const session={app,accountId:claims.sub,sessionId:claims.sid,parentId:claims.psid,browserId:claims.bsid,browserGeneration:claims.bv,credentialEpoch:claims.ce,securityVersion:claims.pv,unlockGeneration:claims.ue,originalSignedAtMs:claims.s_iat*1000,originalExpiresAtMs:claims.s_exp*1000,lastForegroundRefreshMs:row.last_fg_refresh_s*1000,serverNowMs:now*1000};
  return reply({session,initialViews:[]});
 }catch(error){
  const code=error instanceof AuthContractError?error.code:'CONTEXT_UNAVAILABLE';
  if(['PIN_REQUIRED','TOKEN_UPDATE_REQUIRED'].includes(code))return reply({code},401);
  if(['CONTEXT_UNAVAILABLE','INVALID_CONFIG','INVALID_KEY_REGISTRY','INVALID_COOKIE_CONFIG'].includes(code))return reply({code:'CONTEXT_UNAVAILABLE'},503);
  return reply({code:'V110_SESSION_REQUIRED'},401);
 }
}
