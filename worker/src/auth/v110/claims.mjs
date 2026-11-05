// V110 independent contract prototype. No application route imports this module.
import {SignJWT,jwtVerify,importJWK} from 'jose';
export class AuthContractError extends Error {
 constructor(code){super(code);this.name='AuthContractError';this.code=code;}
}
const fail=code=>{throw new AuthContractError(code);};
const apps=new Set(['academy','studio','hifz']);
const id=v=>typeof v==='string'&&/^[-A-Za-z0-9_:]{1,180}$/.test(v);
const uint=v=>Number.isSafeInteger(v)&&v>=0;
const utf8=v=>new TextEncoder().encode(v).byteLength;
const fields=['ver','iss','aud','sub','sid','psid','bsid','bv','ce','pv','ue','iat','exp','s_iat','s_exp','jti'];
const allowed=new Set([...fields,'r']);
export const ACCESS_SECONDS=900,IDLE_SECONDS=5400,SESSION_SECONDS=604800;
export const cookieNames=Object.freeze({
 academy:{access:'__Secure-uaa_a',refresh:'__Host-uaa_r'},
 studio:{access:'__Host-uas_a',refresh:'__Host-uas_r'},
 hifz:{access:'__Host-uah_a',refresh:'__Host-uah_r'}
});
export function validateClaims(p,{app,issuer,audience,now,validateRights}){
 if(!p||typeof p!=='object'||Array.isArray(p)||Object.keys(p).some(k=>!allowed.has(k)))fail('INVALID_CLAIMS');
 if(fields.some(k=>!Object.hasOwn(p,k))||p.ver!==1||p.iss!==issuer||p.aud!==audience)fail('INVALID_CLAIMS');
 if(['sub','sid','psid','bsid','jti'].some(k=>!id(p[k])))fail('INVALID_BINDING');
 if(['bv','ce','pv','ue','iat','exp','s_iat','s_exp'].some(k=>!uint(p[k]))||!uint(now))fail('INVALID_TIME');
 if(p.s_iat>p.iat||p.s_exp<=p.s_iat||p.s_exp-p.s_iat>SESSION_SECONDS||p.iat>now||p.exp<=now||p.s_exp<=now||p.exp<=p.iat||p.exp>p.s_exp||p.exp-p.iat>ACCESS_SECONDS)fail('EXPIRED_OR_EXCESSIVE_LIFETIME');
 if(app==='academy'&&p.sid!==p.psid)fail('INVALID_PARENT');
 if(app==='hifz'){if(Object.hasOwn(p,'r'))fail('UNEXPECTED_RIGHTS');}
 else if(typeof validateRights!=='function'||validateRights(p.r)!==true)fail('INVALID_RIGHTS');
 return p;
}
export async function createAccessEngine({app,issuer,publicKeys,signingKey,signingKid,validateRights,maxTokenBytes=3600}){
 if(!apps.has(app)||typeof issuer!=='string'||new URL(issuer).origin!==issuer||!issuer.startsWith('https://'))fail('INVALID_CONFIG');
 const audience='urn:ummabbadacademy:'+app+':api',registry=new Map();
 if(!Array.isArray(publicKeys)||publicKeys.length<1||publicKeys.length>4)fail('INVALID_CONFIG');
 for(const jwk of publicKeys){
  if(!jwk||jwk.kty!=='EC'||jwk.crv!=='P-256'||Object.hasOwn(jwk,'d')||!/^[A-Za-z0-9._-]{1,64}$/.test(jwk.kid||'')||registry.has(jwk.kid))fail('INVALID_KEY_REGISTRY');
  registry.set(jwk.kid,await importJWK(jwk,'ES256'));
 }
 if(signingKey&&(!registry.has(signingKid)||signingKey.type!=='private'))fail('INVALID_SIGNER');
 const options=now=>({app,issuer,audience,now,validateRights});
 return Object.freeze({
  async issue(input,now){
   const p={...input,ver:1,iss:issuer,aud:audience,iat:now,exp:Math.min(now+ACCESS_SECONDS,input.s_exp),jti:crypto.randomUUID()};
   validateClaims(p,options(now));
   if(!signingKey)fail('SIGNER_UNAVAILABLE');
   const token=await new SignJWT(p).setProtectedHeader({alg:'ES256',typ:'uaa-access+jwt',kid:signingKid}).sign(signingKey);
   if(utf8(token)>maxTokenBytes)fail('CLAIMS_TOO_LARGE');
   return {token,claims:p};
  },
  async verify(token,now){
   if(typeof token!=='string'||utf8(token)>maxTokenBytes||!uint(now))fail('INVALID_TOKEN');
   try{
    const {payload,protectedHeader}=await jwtVerify(token,header=>{
     if(header.alg!=='ES256'||header.typ!=='uaa-access+jwt'||typeof header.kid!=='string'||!registry.has(header.kid)||Object.hasOwn(header,'jku')||Object.hasOwn(header,'x5u')||Object.hasOwn(header,'jwk'))fail('UNTRUSTED_KEY');
     return registry.get(header.kid);
    },{algorithms:['ES256'],issuer,audience,typ:'uaa-access+jwt',requiredClaims:fields,currentDate:new Date(now*1000),clockTolerance:0});
    if(Object.keys(protectedHeader).some(k=>!['alg','typ','kid'].includes(k)))fail('INVALID_HEADER');
    return validateClaims(payload,options(now));
   }catch{fail('INVALID_TOKEN');}
  }
 });
}
// Values come only from reviewed deployment configuration, never Host/Origin.
export function validateAcademyCookieConfig(config){
 const domain=config?.academyCookieDomain,issuer=config?.academyIssuer;
 if(typeof domain!=='string'||domain.length>253||domain!==domain.toLowerCase()||!domain.includes('.')||/^[0-9.]+$/.test(domain)||domain.split('.').some(label=>!/^([a-z0-9]|[a-z0-9][a-z0-9-]{0,61}[a-z0-9])$/.test(label)))fail('INVALID_COOKIE_CONFIG');
 let url;try{url=new URL(issuer);}catch{fail('INVALID_COOKIE_CONFIG');}
 if(typeof issuer!=='string'||url.protocol!=='https:'||url.origin!==issuer||url.hostname!==domain||url.port)fail('INVALID_COOKIE_CONFIG');
 return {domain,issuer};
}
export function accessCookie(app,token,expiresAt,now,config){
 if(!apps.has(app)||typeof token!=='string'||!/^[A-Za-z0-9_.-]+$/.test(token)||!uint(expiresAt)||!uint(now)||expiresAt<=now)fail('INVALID_COOKIE');
 const name=cookieNames[app].access,domain=app==='academy'?'; Domain='+validateAcademyCookieConfig(config).domain:'';
 const value=name+'='+token+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='+Math.min(ACCESS_SECONDS,expiresAt-now)+domain;
 if(utf8(value)>3800)fail('COOKIE_TOO_LARGE');return value;
}
export function refreshCookie(app,token,expiresAt,now){
 if(!apps.has(app)||!/^[A-Za-z0-9_-]{43}$/.test(token)||!uint(expiresAt)||!uint(now)||expiresAt<=now||expiresAt-now>SESSION_SECONDS)fail('INVALID_COOKIE');
 return cookieNames[app].refresh+'='+token+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='+(expiresAt-now);
}
export function parseUniqueCookie(header,name){
 if(typeof header!=='string'||utf8(header)>8192)fail('INVALID_COOKIE_HEADER');
 const parts=header.split(';');if(parts.length>64)fail('INVALID_COOKIE_HEADER');
 const found=parts.map(x=>x.trim()).filter(x=>x.slice(0,x.indexOf('='))===name);
 if(found.length!==1)fail('AMBIGUOUS_OR_MISSING_COOKIE');
 return found[0].slice(found[0].indexOf('=')+1);
}
export function cookieSizeReport(setCookies,otherRequestCookies=[]){
 const setCookieBytes=setCookies.map(utf8);
 const cookieHeader=[...setCookies.map(x=>x.split(';',1)[0]),...otherRequestCookies].join('; ');
 return {setCookieBytes,cookieHeaderBytes:utf8(cookieHeader),fits:setCookieBytes.every(n=>n<=3800)&&utf8(cookieHeader)<=8192};
}

// Production-facing composition: one reviewed config chooses issuer, verifier,
// signer and cookie scope. Low-level engines remain useful for size profiling.
export async function createConfiguredAccessEngine(config){
 const app=config?.app;
 let scope;
 if(app==='academy'){
  scope={academyIssuer:config.issuer,academyCookieDomain:config.academyCookieDomain};
  validateAcademyCookieConfig(scope);
  if(config.academyIssuer!==undefined&&config.academyIssuer!==config.issuer)fail('INVALID_COOKIE_CONFIG');
 }else if(Object.hasOwn(config||{},'academyCookieDomain'))fail('HOST_ONLY_COOKIE_CONFIG_REQUIRED');
 const engine=await createAccessEngine(config);
 return Object.freeze({
  async issue(input,now){
   const issued=await engine.issue(input,now);
   return {...issued,setCookie:accessCookie(app,issued.token,issued.claims.exp,now,scope)};
  },
  verify:(token,now)=>engine.verify(token,now),
  accessCookie:(token,expiresAt,now)=>accessCookie(app,token,expiresAt,now,scope),
  refreshCookie:(token,expiresAt,now)=>refreshCookie(app,token,expiresAt,now)
 });
}
