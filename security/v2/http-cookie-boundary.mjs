import {ACADEMY_SHARED_COOKIE} from './tokens.mjs';

export function withoutCookies(request,name=null){
 const original=request.headers.get('Cookie');
 if(original===null)return request;
 const remaining=name===null?'':original.split(';')
  .filter(pair=>pair.split('=',1)[0].trim()!==name)
  .map(pair=>pair.trim()).filter(Boolean).join('; ');
 if(remaining===original)return request;
 const headers=new Headers(request.headers);
 if(remaining)headers.set('Cookie',remaining);
 else headers.delete('Cookie');
 return new Request(request,{headers});
}

export function withoutSetCookie(response){
 if(!response.headers.has('Set-Cookie'))return response;
 const headers=new Headers(response.headers);
 headers.delete('Set-Cookie');
 return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
}


const sharedEntryPaths=new Set(['/auth/v2/shared-entry','/auth/v2/shared-entry/start','/auth/v2/shared-entry/continue']);

const sharedEntryAssets=new Set([
 '/auth/v2/shared-entry','/auth/v2/shared-entry-client.mjs','/auth/v2/shared-entry/return.mjs',
 '/auth/v2/browser-session.mjs','/auth/v2/browser-drafts.mjs'
]);

export function childAuthorityRequest(request){
 const url=new URL(request.url);
 const read=request.method==='GET'||request.method==='HEAD';
 if(url.pathname==='/auth/v2/shared-entry/callback'||read&&sharedEntryAssets.has(url.pathname)){
  return withoutCookies(request);
 }
 if(request.method==='POST'&&!url.search&&sharedEntryPaths.has(url.pathname))return request;
 return withoutCookies(request,ACADEMY_SHARED_COOKIE);
}
