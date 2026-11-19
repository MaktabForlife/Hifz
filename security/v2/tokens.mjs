import {bytes,b64u,unb64u,strictJSON,canonical,exact,requireThat,uuid,safeInt,ascii,reject} from './codec.mjs';
export const APPS=['academy','studio','hifz'];
export const ORIGINS=Object.freeze({academy:'https://ummabbadacademy.app',studio:'https://worshipuponbaseera.ummabbadacademy.app',hifz:'https://mahadarwa-hifz.ummabbadacademy.app'});
const API='ver env iss aud sub sid psid bsid bv ce ae le sv ue pv vat iat exp s_iat s_exp jti'.split(' ');
const COMMON='ver env iss aud sub psid bsid bv ce ae s_iat s_exp tx jti iat exp'.split(' ');
const FIELDS={api:API,admission:[...COMMON,'afg'],unlock:[...COMMON,'sid','le','sv','ue']};
const signatureReceipts=new WeakMap();
const TYPES={api:'uaa-access+jwt',admission:'uaa-admission+jwt',unlock:'uaa-unlock+jwt'};
export const BINDING='ver env iss aud sub sid psid bsid bv ce ae le sv ue pv vat s_iat s_exp'.split(' ');
export function profileConfig({app,env='production',origin=ORIGINS[app],academyOrigin=ORIGINS.academy}){
 requireThat(APPS.includes(app)&&['feature','production'].includes(env),'INVALID_CONFIG',503);
 for(const value of [origin,academyOrigin]){let u;try{u=new URL(value);}catch{reject('INVALID_ORIGIN',503);}requireThat(u.protocol==='https:'&&u.origin===value,'INVALID_ORIGIN',503);}
 return Object.freeze({app,env,origin,academyOrigin});
}
function validate(c,p,cfg,{now,idleUntil,timedUntil=Number.MAX_SAFE_INTEGER,initial=false,allowExpired=false}={}){
 exact(c,FIELDS[p]);requireThat(c.ver===2&&c.env===cfg.env&&c.iss===(p==='api'?cfg.origin:cfg.academyOrigin),'WRONG_ISSUER');
 requireThat(c.aud==='urn:uaa:'+cfg.env+':'+cfg.app+':'+(p==='api'?'api':p)+':v2','WRONG_AUDIENCE');
 requireThat(typeof c.sub==='string'&&c.sub.length>0&&bytes(c.sub).length<=180&&!/[\u0000-\u0020\u007f]/.test(c.sub),'INVALID_SUBJECT');
 for(const field of ['psid','bsid','jti',...(p==='api'||p==='unlock'?['sid']:[]),...(p!=='api'?['tx']:[])])requireThat(uuid(c[field]),'INVALID_UUID');
 for(const k of ['bv','ce','ae',...(p==='api'||p==='unlock'?['sv']:[])])requireThat(safeInt(c[k],1),'INVALID_COUNTER');
 for(const k of p==='api'||p==='unlock'?['le','ue']:[])requireThat(safeInt(c[k]),'INVALID_COUNTER');
 for(const k of ['iat','exp','s_iat','s_exp',...(p==='api'?['vat']:[]),...(p==='admission'?['afg']:[])])requireThat(safeInt(c[k]),'INVALID_TIME');
 requireThat(safeInt(now)&&c.iat<=now+30&&c.s_exp-c.s_iat===604800&&c.s_iat<=c.iat&&c.iat<c.exp&&c.exp<=c.s_exp,'INVALID_TIME');
 if(!allowExpired)requireThat(now<c.exp,'TOKEN_EXPIRED');
 if(p==='api'){
  requireThat(typeof c.pv==='string'&&c.pv.length===43,'INVALID_VECTOR_DIGEST');unb64u(c.pv,32);
  requireThat(initial==='PRECHECK'?c.vat<=c.iat:initial?c.vat<=c.s_iat&&c.s_iat<=c.iat:c.s_iat<=c.vat&&c.vat<=c.iat,'INVALID_VALIDATION_TIME');
  requireThat(safeInt(idleUntil)&&safeInt(timedUntil)&&c.exp<=Math.min(c.iat+900,c.vat+900,idleUntil,timedUntil),'INVALID_LEASE');
  requireThat(now<Math.min(c.vat+900,idleUntil,timedUntil,c.s_exp)||allowExpired,'LEASE_EXPIRED');
  if(cfg.app==='academy')requireThat(c.sid===c.psid,'INVALID_PARENT');
 }else{
  requireThat(cfg.app!=='academy'&&c.exp===Math.min(c.iat+60,c.s_exp),'INVALID_PROOF');
  if(p==='admission')requireThat(c.s_iat<=c.afg&&c.afg<=c.iat,'INVALID_FOREGROUND');
 }
 return c;
}
export async function issueToken(claims,{profile='api',config,key,kid,...limits}){
 requireThat(FIELDS[profile]&&ascii(kid,64)&&/^[A-Za-z0-9._-]+$/.test(kid),'INVALID_KEY_ID',503);
 validate(claims,profile,config,limits);
 const header=b64u(bytes(canonical({alg:'ES256',typ:TYPES[profile],kid}))),body=b64u(bytes(canonical(claims))),input=header+'.'+body;
 const signature=new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,bytes(input)));
 requireThat(signature.length===64,'INVALID_SIGNER',503);
 const token=input+'.'+b64u(signature);requireThat(bytes(token).length<=2048,'TOKEN_TOO_LARGE',503);return token;
}
export async function verifyToken(token,{profile='api',config,keys,withdrawn=new Set(),projection,preverified,...limits}){
 requireThat(FIELDS[profile]&&typeof token==='string'&&bytes(token).length<=2048,'TOKEN_TOO_LARGE');
 const parts=token.split('.');requireThat(parts.length===3,'INVALID_JWS');
 const header=exact(strictJSON(unb64u(parts[0]),{maxBytes:2048}),['alg','typ','kid']);
 requireThat(header.alg==='ES256'&&header.typ===TYPES[profile]&&typeof header.kid==='string'&&/^[A-Za-z0-9._-]{1,64}$/.test(header.kid),'WRONG_TOKEN_PROFILE');
 const key=keys.get(header.kid);requireThat(key&&!withdrawn.has(header.kid),'UNTRUSTED_KEY');
 const receipt=preverified&&signatureReceipts.get(preverified);
 let parsed;
 if(receipt&&receipt.token===token&&receipt.config===config&&receipt.keys===keys&&receipt.key===key&&receipt.profile===profile)parsed=receipt.claims;
 else{
  const ok=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,unb64u(parts[2],64),bytes(parts[0]+'.'+parts[1]));requireThat(ok,'INVALID_SIGNATURE');
  parsed=strictJSON(unb64u(parts[1]),{maxBytes:2048});
 }
 const claims=validate(parsed,profile,config,limits);
 if(projection)for(const field of BINDING)requireThat(claims[field]===projection[field],'SECURITY_BINDING_CHANGED');
 return claims;
}
export function ownOrigin(request,config){
 requireThat(new URL(request.url).origin===config.origin,'WRONG_PUBLIC_ORIGIN',403);
 requireThat(request.headers.get('Origin')===config.origin,'CROSS_ORIGIN',403);
}
const COOKIES={academy:['__Host-uaa_a','__Host-uaa_r'],studio:['__Host-studio_a','__Host-studio_r'],hifz:['__Host-hifz_a','__Host-hifz_r']};
export function readCookies(header,app){
 const source=header??'';requireThat(typeof source==='string','INVALID_COOKIE_HEADER',400);
 requireThat(bytes(source).length<=8192,'COOKIE_HEADER_TOO_LARGE',431);
 requireThat(COOKIES[app],'INVALID_CONFIG',503);const values=Object.create(null);
 for(const part of source.split(';')){
  const i=part.indexOf('=');if(i<0)continue;const name=part.slice(0,i).trim();
  if(!COOKIES[app].includes(name))continue;
  requireThat(!Object.hasOwn(values,name),'DUPLICATE_COOKIE');values[name]=part.slice(i+1);
 }
 if(Object.hasOwn(values,COOKIES[app][1]))unb64u(values[COOKIES[app][1]],32);
 return {access:values[COOKIES[app][0]],refresh:values[COOKIES[app][1]]};
}
export function cookiePair({app,access,refresh,now,accessExpires,originalExpires}){
 requireThat(COOKIES[app]&&safeInt(now)&&safeInt(accessExpires)&&safeInt(originalExpires),'INVALID_COOKIE',503);
 requireThat(accessExpires>now&&accessExpires<=now+900&&originalExpires>now&&originalExpires<=now+604800,'INVALID_COOKIE_DEADLINE',503);
 requireThat(typeof access==='string'&&!/[;\r\n]/.test(access),'INVALID_COOKIE',503);unb64u(refresh,32);
 return [access,refresh].map((value,i)=>COOKIES[app][i]+'='+value+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='+((i?originalExpires:accessExpires)-now)+'; Expires='+new Date((i?originalExpires:accessExpires)*1000).toUTCString());
}

export async function preverifyAPI(token,{config,keys,now}){
 const claims=Object.freeze(await verifyToken(token,{config,keys,now,idleUntil:Number.MAX_SAFE_INTEGER,timedUntil:Number.MAX_SAFE_INTEGER,initial:'PRECHECK'}));
 const header=strictJSON(unb64u(token.split('.')[0]));
 const selector=Object.freeze({sid:claims.sid,sub:claims.sub,kid:header.kid});
 signatureReceipts.set(selector,{token,config,keys,key:keys.get(header.kid),profile:'api',claims});
 return selector; // authenticated selector only, no authority before current durable controls.
}
