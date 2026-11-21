import {childAuthorityRequest,withoutCookies,withoutSetCookie} from '../../security/v2/http-cookie-boundary.mjs';
import {handleNativeProfile,PROFILE_PATH} from '../../security/v2/profile-service.mjs';
import {HIFZ_PUBLIC_ASSETS} from './v111-public-assets.js';
import {guardedHifzDB} from './v111-guarded-db.js';

export const HIFZ_V2_ORIGIN='https://mahadarwa-hifz.ummabbadacademy.app';
const publicPaths=new Set(HIFZ_PUBLIC_ASSETS);
const nativePaths=new Set(['/sabaq','/sabaq-dhor','/dhor','/reflections','/maktab/settings','/maktab/position','/maktab/attendance','/maktab/summary','/maktab/dhor-default-entry','/maktab/attendance-week','/maktab/attendance-register','/maktab/terms','/maktab/calendar','/maktab/calendar/holiday-proposal','/maktab/calendar/islamic-proposal','/maktab/calendar/confirm','/maktab/sabaq','/maktab/sabaq-dhor','/maktab/dhor','/plans','/attendance','/attendance/page','/attendance/haidh-settings','/attendance/mark-range','/attendance/predict','/position','/profile','/dhor-schedule/default-entry','/dhor-schedule/upcoming','/tajweed-tags','/tajweed-tags/update','/maktab-groups','/maktab-groups/update','/admin/users','/admin/reset-pin','/admin/change-role','/admin/register-student','/admin/create-teaching-profile','/admin/update-user']);
const childAuth=new Set(['bootstrap','refresh','status','logout','switch','admission/start','admission/callback','admission/finalize','unlock/start','unlock/callback','unlock/finalize','draft-key','browser-clear'].map(p=>'/auth/v2/'+p));
const sharedEntryMethods=new Map([
 ['/auth/v2/shared-entry',['GET','POST']],
 ['/auth/v2/shared-entry/start',['POST']],
 ['/auth/v2/shared-entry/status',['POST']],
 ['/auth/v2/shared-entry/continue',['POST']],
 ['/auth/v2/shared-entry/callback',['GET','POST']],
 ['/auth/v2/shared-entry/return.mjs',['GET']],
 ['/auth/v2/shared-entry-client.mjs',['GET']]
]);
const internalAuth=new Set(['transactions','redeem','events','reconcile','incidents','logout'].map(p=>'/internal/auth/v2/'+p));
const identityWrites=new Set(['/admin/reset-pin','/admin/change-role','/admin/register-student','/admin/create-teaching-profile','/admin/update-user']);
const fail=(code,status)=>new Response(JSON.stringify({error:code,code}),{status,headers:{'Content-Type':'application/json','Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'}});
const noCors=response=>{const h=new Headers(response.headers);for(const k of [...h.keys()])if(k.toLowerCase().startsWith('access-control-'))h.delete(k);h.set('Cache-Control','private, no-store');h.set('Referrer-Policy','no-referrer');h.set('X-Content-Type-Options','nosniff');return new Response(response.body,{status:response.status,statusText:response.statusText,headers:h});};
const validId=v=>typeof v==='string'&&v.length>0&&new TextEncoder().encode(v).length<=180&&!/[\u0000-\u0020\u007f]/.test(v);
export function hifzActor(cap,runtime) {
 runtime.assertCapability(cap);
 if(!validId(cap.binding?.sub)||!validId(cap.rights?.nativeStudentId)||!['student','teacher','admin'].includes(cap.rights?.role)||!Number.isSafeInteger(cap.deadline))throw Object.assign(new Error('Native identity unavailable'),{code:'HIFZ_NATIVE_IDENTITY_REQUIRED',status:503});
 return Object.freeze({id:cap.rights.nativeStudentId,role:cap.rights.role,exp:cap.deadline*1000});
}
export function createHifzV2Handler({runtimeFactory,dispatchNative}) {
 if(typeof runtimeFactory!=='function'||typeof dispatchNative!=='function')throw new TypeError('Trusted Hifz runtime and native dispatcher required');
 return async function fetchHifzV2(request,env,ctx) {
  const url=new URL(request.url),path=url.pathname;
  if(url.origin!==HIFZ_V2_ORIGIN)return fail('UNTRUSTED_APP_ORIGIN',421);
  if(path.includes('%')||path.includes('\\'))return fail('INVALID_ROUTE',400);
  try {
   if((internalAuth.has(path)||path===PROFILE_PATH)&&(request.headers.has('Cookie')||request.headers.has('Origin'))){
    return path===PROFILE_PATH?fail('PROFILE_REQUEST_FORBIDDEN',403):fail('SERVICE_TRANSPORT_ONLY',401);
   }
   request=childAuthorityRequest(request);
   if(path===PROFILE_PATH)return noCors(await handleNativeProfile(await runtimeFactory(env),request));
   if(sharedEntryMethods.has(path)){
    if(!sharedEntryMethods.get(path).includes(request.method))return fail('METHOD_NOT_ALLOWED',405);
    const response=await (await runtimeFactory(env)).handle(request,ctx);
    // Only the fixed callback handler supplies CORS, after verifying Academy's exact Origin.
    return path==='/auth/v2/shared-entry/callback'&&request.method==='POST'?response:noCors(response);
   }
   if(childAuth.has(path)||internalAuth.has(path)||path==='/auth/v2/relay.mjs'){
    if(request.method!==(path==='/auth/v2/relay.mjs'?'GET':'POST'))return fail('METHOD_NOT_ALLOWED',405);
    const runtime=await runtimeFactory(env),response=await runtime.handle(request,ctx);
    return response instanceof Response?noCors(response):fail('AUTH_ROUTE_UNAVAILABLE',503);
   }
   if(path==='/api/header-date'||path==='/api/health')return request.method==='GET'?noCors(withoutSetCookie(await dispatchNative(withoutCookies(request),env,ctx))):fail('METHOD_NOT_ALLOWED',405);
   if(path==='/api'||path.startsWith('/api/')) {
    const nativePath=path.slice(4);
    if(!nativePaths.has(nativePath)&&!/^\/maktab\/(?:terms|calendar)\/\d+$/.test(nativePath))return fail('NOT_FOUND',404);
    if(request.headers.has('Authorization'))return fail('NATIVE_BEARER_DISABLED',401);
    if(identityWrites.has(nativePath)||(nativePath==='/admin/users'&&request.method==='DELETE'))return fail('ACADEMY_MANAGED',403);
    const runtime=await runtimeFactory(env),action=nativePath.startsWith('/admin/')?'sensitive':['GET','HEAD'].includes(request.method)?'read':'write';
    const cap=await runtime.authorise(request,{action}),actor=hifzActor(cap,runtime);
    const nativeEnv={...env,DB:guardedHifzDB(env.DB,()=>runtime.writeGuard(cap,{sensitive:action==='sensitive'}))};
    const target=new URL(request.url);target.pathname=nativePath;
    const response=withoutSetCookie(await dispatchNative(new Request(target,withoutCookies(request)),nativeEnv,ctx,actor));
    return noCors(await runtime.decorate(response,cap));
   }
   // Explicit shell routes only. Protected/unknown paths never reach a SPA fallback.
   let shell=path==='/'||path==='/index.html'||path==='/academy'||(/^\/[A-Za-z0-9]{4,64}$/.test(path)&&!nativePaths.has(path)&&!/^\/(?:api|auth|internal|worker|security|config|tests|public|assets|admin)$/i.test(path));
   let publicPath=path;
   if(path.startsWith('/_assets/')){
    const configured=env.UAA_V2_PUBLIC_ASSET_PREFIX;
    const prefixes=typeof configured==='string'?configured.split(',',3):[];
    if(prefixes.length>2||prefixes.some(prefix=>!/^\/_assets\/[0-9a-f]{64}\/$/.test(prefix)))return fail('NOT_FOUND',404);
    const prefix=prefixes.find(candidate=>path.startsWith(candidate));
    if(!prefix)return fail('NOT_FOUND',404);
    publicPath='/'+path.slice(prefix.length);if(publicPath==='/index.html')shell=true;
    if(!publicPaths.has(publicPath))return fail('NOT_FOUND',404);
   }
   if(!shell&&!publicPaths.has(publicPath))return fail('NOT_FOUND',404);
   if(publicPath==='/js/sw.js')return fail('SERVICE_WORKER_DISABLED',404);
   if(!['GET','HEAD'].includes(request.method))return fail('METHOD_NOT_ALLOWED',405);
   if(!env.ASSETS?.fetch)return fail('STATIC_ASSETS_UNAVAILABLE',503);
   const assetUrl=new URL(request.url);if(shell&&!path.startsWith('/_assets/'))assetUrl.pathname='/index.html';
   const response=withoutSetCookie(await env.ASSETS.fetch(new Request(assetUrl,{method:request.method})));
   if(!response.ok)return fail('ASSET_UNAVAILABLE',response.status===404?404:503);
   if(!shell){
    const type=response.headers.get('Content-Type')||'';
    if(/\.(?:m?js)$/.test(path)&&!/(?:javascript|ecmascript)/i.test(type))return fail('ASSET_TYPE_MISMATCH',503);
    if(path.endsWith('.css')&&!/^text\/css\b/i.test(type))return fail('ASSET_TYPE_MISMATCH',503);
    if(path.endsWith('.json')&&!/^application\/json\b/i.test(type))return fail('ASSET_TYPE_MISMATCH',503);
    return noCors(response);
   }
   const h=new Headers(response.headers);h.delete('Content-Length');h.delete('Content-Encoding');
   h.set('Content-Type','text/html; charset=utf-8');h.set('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://ummabbadacademy.app");
   let html=null;
   if(request.method==='GET'){
    const runtime=await runtimeFactory(env);
    const sharedEntry=runtime.settings.raw.sharedChildEntry?'<meta name="hifz-shared-entry" content="enabled">':'';
    html=(await response.text()).replace('<head>','<head>\n<meta name="hifz-auth-mode" content="v2">'+sharedEntry);
   }
   return noCors(new Response(html,{status:200,headers:h}));
  } catch(error) {return fail(typeof error?.code==='string'?error.code:'HIFZ_V2_UNAVAILABLE',Number.isInteger(error?.status)&&error.status>=400&&error.status<=599?error.status:503);}
 };
}
