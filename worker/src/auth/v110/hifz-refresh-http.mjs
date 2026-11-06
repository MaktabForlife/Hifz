// Native Hifz refresh transport, opt-in only. No Master request, grant
// export, family admission, PIN/unlock or native resource cutover is performed.
import {base64url,importJWK} from 'jose';
import {AuthContractError,cookieNames,parseUniqueCookie,IDLE_SECONDS} from './claims.mjs';
import {createAccountBoundHifzRefresh} from './hifz-refresh.mjs';
import {fingerprint} from './store.mjs';
const issuer='https://mahadarwa-hifz.ummabbadacademy.app';
const csrfPath='/auth/v110/csrf',refreshPath='/auth/v110/refresh';
const deny=code=>{throw new AuthContractError(code);};
const integer=n=>Number.isSafeInteger(n)&&n>=0;
const csrfBytes=value=>{
 if(typeof value!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(value))deny('CSRF_REQUIRED');
 const bytes=base64url.decode(value);if(bytes.byteLength!==32||base64url.encode(bytes)!==value)deny('CSRF_REQUIRED');return bytes;
};
function origin(value){let url;try{url=new URL(value);}catch{deny('REFRESH_UNAVAILABLE');}
 if(url.origin!==value||url.username||url.password||url.protocol!=='https:'&&!(url.protocol==='http:'&&['127.0.0.1','localhost'].includes(url.hostname)))deny('REFRESH_UNAVAILABLE');return value;
}
const reply=(body,status=200,more={})=>Response.json(body,{status,headers:{'Cache-Control':'private, no-store','Pragma':'no-cache','X-Content-Type-Options':'nosniff',...more}});
async function body(request){
 if(!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('Content-Type')||''))deny('INVALID_REFRESH_BODY');
 const reader=request.body?.getReader(),decoder=new TextDecoder('utf-8',{fatal:true});let size=0,text='';
 try{if(reader)for(;;){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>1024){await reader.cancel();deny('INVALID_REFRESH_BODY');}text+=decoder.decode(part.value,{stream:true});}text+=decoder.decode();
  const value=JSON.parse(text||'{}');if(!value||Object.getPrototypeOf(value)!==Object.prototype||Object.keys(value).some(key=>key!=='foreground')||value.foreground!==undefined&&typeof value.foreground!=='boolean')deny('INVALID_REFRESH_BODY');return value;
 }catch(error){if(error instanceof AuthContractError)throw error;deny('INVALID_REFRESH_BODY');}
 finally{reader?.releaseLock();}
}
function currentClock(family,now){
 if(!integer(family.last_fg_refresh_s)||!integer(family.original_signed_in_at_s)||family.last_fg_refresh_s<family.original_signed_in_at_s||family.last_fg_refresh_s>now)deny('REFRESH_UNAVAILABLE');
 if(now-family.last_fg_refresh_s>=IDLE_SECONDS)deny('PIN_REQUIRED');
}
const csrfData=family=>new TextEncoder().encode(JSON.stringify(['uaa-csrf-v1','hifz',issuer,family.family_id,family.account_id,family.parent_session_id,family.browser_id,family.browser_generation,family.credential_epoch,family.unlock_generation,family.original_signed_in_at_s,family.original_expires_at_s]));
const lookupSQL='SELECT f.* FROM jwt_v110_families f JOIN jwt_v110_accounts v USING(account_id) JOIN jwt_v110_browser_heads b USING(browser_id) JOIN students n ON n.id=f.account_id WHERE f.refresh_fp=? AND f.revoked=0 AND v.active=1 AND n.active=1 AND v.credential_epoch=f.credential_epoch AND coalesce(n.credential_epoch,0)=f.credential_epoch AND b.generation=f.browser_generation AND f.original_expires_at_s>? AND NOT EXISTS(SELECT 1 FROM jwt_v110_parent_tombstones t WHERE t.parent_session_id=f.parent_session_id)';
export async function handleHifzRefresh(request,env,{clock=()=>Math.floor(Date.now()/1000)}={}){
 const path=new URL(request.url).pathname;
 if(![csrfPath,refreshPath].includes(path))return reply({code:'NOT_FOUND'},404);
 if(env.JWT_V110_REFRESH!=='1')return reply({code:'V110_NOT_ENABLED'},404);
 const method=path===csrfPath?'GET':'POST';if(request.method!==method)return reply({code:'METHOD_NOT_ALLOWED'},405,{Allow:method});
 try{
  const expected=origin(env.JWT_V110_REQUEST_ORIGIN||issuer),url=new URL(request.url);
  if(url.origin!==expected||url.search||request.headers.get('Sec-Fetch-Site')!=='same-origin'||request.headers.get('Origin')&&request.headers.get('Origin')!==expected||method==='POST'&&request.headers.get('Origin')!==expected)return reply({code:'ORIGIN_NOT_ALLOWED'},403);
  if(!env.DB?.withSession||!env.JWT_V110_RATE_LIMITER?.limit)deny('REFRESH_UNAVAILABLE');
  const now=clock();if(!integer(now))deny('REFRESH_UNAVAILABLE');
  let publicKeys,privateJWK;try{
   if(typeof env.JWT_V110_PRIVATE_KEY_JSON!=='string'||env.JWT_V110_PRIVATE_KEY_JSON.length>8192)deny('REFRESH_UNAVAILABLE');
   publicKeys=JSON.parse(env.JWT_V110_PUBLIC_KEYS_JSON);privateJWK=JSON.parse(env.JWT_V110_PRIVATE_KEY_JSON);
  }catch{deny('REFRESH_UNAVAILABLE');}
  const publicJWK=Array.isArray(publicKeys)&&publicKeys.find(key=>key.kid===env.JWT_V110_SIGNING_KID);
  if(!privateJWK||privateJWK.kty!=='EC'||privateJWK.crv!=='P-256'||!privateJWK.d||privateJWK.kid!==env.JWT_V110_SIGNING_KID||!publicJWK||publicJWK.x!==privateJWK.x||publicJWK.y!==privateJWK.y)deny('REFRESH_UNAVAILABLE');
  let secret;try{secret=csrfBytes(env.JWT_V110_CSRF_SECRET);}catch{deny('REFRESH_UNAVAILABLE');}
  const csrfKey=await crypto.subtle.importKey('raw',secret,{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
  const ip=request.headers.get('CF-Connecting-IP')||'unavailable';
  const rateKey=base64url.encode(new Uint8Array(await crypto.subtle.sign('HMAC',csrfKey,new TextEncoder().encode('uaa-refresh-rate-v1\0'+ip))));
  if((await env.JWT_V110_RATE_LIMITER.limit({key:'v110-hifz-'+rateKey})).success!==true)return reply({code:'RATE_LIMITED'},429,{'Retry-After':'60'});
  const raw=parseUniqueCookie(request.headers.get('Cookie')||'',cookieNames.hifz.refresh);
  const config={app:'hifz',issuer,publicKeys,signingKey:await importJWK(privateJWK,'ES256'),signingKid:env.JWT_V110_SIGNING_KID};
  let proof;
  const refresh=await createAccountBoundHifzRefresh({binding:env.DB,clock,...config,authorizeRotation:async({family,now})=>{
   currentClock(family,now);
   if(!await crypto.subtle.verify('HMAC',csrfKey,proof,csrfData(family)))deny('CSRF_REQUIRED');
  }});
  if(path===csrfPath){
   // Current refresh ownership, not an expired access cookie, permits reloading
   // this same-family CSRF proof after a new tab or lost response.
   const fp=await fingerprint('hifz',raw),result=await env.DB.withSession('first-primary').prepare(lookupSQL).bind(fp,now).all(),family=result.results[0];
   if(!family)deny('SESSION_ENDED');currentClock(family,now);
   const csrf=base64url.encode(new Uint8Array(await crypto.subtle.sign('HMAC',csrfKey,csrfData(family))));
   return reply({csrf});
  }
  const input=await body(request);proof=csrfBytes(request.headers.get('X-UAA-CSRF'));
  const result=await refresh.refreshAndIssue(raw,{foreground:input.foreground===true});
  if(result.kind!=='rotated')return reply({code:result.kind==='in_progress'?'REFRESH_IN_PROGRESS':result.kind==='readmit_required'?'READMISSION_REQUIRED':'RETRY_REFRESH'},409,{'Retry-After':'1'});
  // Public JSON is allowlisted. Internal prepared cookies/claims never leak
  // through serialization, logs, metrics or the response body.
  const response=reply({refreshed:true});
  for(const value of result.setCookies)response.headers.append('Set-Cookie',value);
  return response;
 }catch(error){
  const code=error instanceof AuthContractError?error.code:'REFRESH_UNAVAILABLE';
  if(code==='CSRF_REQUIRED')return reply({code},403);
  if(code==='INVALID_REFRESH_BODY')return reply({code},400);
  if(code==='PIN_REQUIRED')return reply({code},401);
  if(['REFRESH_UNAVAILABLE','INVALID_CONFIG','INVALID_KEY_REGISTRY','INVALID_SIGNER','SIGNER_UNAVAILABLE','INVALID_PREPARATION','PREPARATION_EXPIRED','INVALID_TIME','INVALID_COOKIE_CONFIG'].includes(code))return reply({code:'REFRESH_UNAVAILABLE'},503);
  return reply({code:'V110_SESSION_REQUIRED'},401);
 }
}
