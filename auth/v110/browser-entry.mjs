import {installAppPrivacy} from './browser-app-privacy.mjs';
import {browserOrigins,createBrowserControl,installBrowserRelay} from './browser-control-relay.mjs';
// Only a reviewed, explicit feature config can install this native transport
// boundary. URL queries and request headers never select trusted origins.
export function installNativePrivacy({win,doc,config,nativeFetch}){
 if(config?.enabled!==true)return null;
 const origins=browserOrigins(config.origins),app=config.app;
 if(!['academy','studio','hifz'].includes(app)||win.location.origin!==origins[app]||typeof nativeFetch!=='function')throw Error('INVALID_NATIVE_PRIVACY_CONFIG');
 const apiOrigins=new Set(config.apiOrigins||[origins[app]]);
 if([...apiOrigins].some(origin=>{try{return new URL(origin).origin!==origin;}catch{return true;}}))throw Error('INVALID_NATIVE_API_ORIGIN');
 const contextURL=origins[app]+'/auth/v110/context';
 const publicPaths={
  academy:new Set(['/api/account/check','/api/account/login','/api/account/setup-pin','/api/account/logout','/api/academy/hub/login','/api/academy/setup/head']),
  studio:new Set(['/auth/login','/auth/exchange','/auth/logout','/api/config']),
  hifz:new Set(['/auth/academy','/auth/lookup','/auth/policy'])
 }[app];
 const privateURL=url=>apiOrigins.has(url.origin)&&url.href!==contextURL&&!publicPaths.has(url.pathname)&&
  (app==='hifz'?!url.pathname.startsWith('/auth/'):url.pathname.startsWith('/api/')||url.pathname.startsWith('/auth/'));
 const runtime=installAppPrivacy({win,doc,app,origins,verifySession:async({signal})=>{
  const response=await nativeFetch(contextURL,{credentials:'same-origin',cache:'no-store',signal});
  if(!response.ok)throw Error('CURRENT_V110_CONTEXT_REQUIRED');
  return response.json();
 },channelFactory:name=>new BroadcastChannel(name),onClear:reason=>{
  const gate=doc.querySelector('[data-uaa-public-gate]');gate?.setAttribute('data-reason',reason);
  const message=gate?.querySelector('[data-uaa-gate-message]');if(message)message.textContent=['logout','switch','known-cancellation','lock'].includes(reason)?'Your private display is locked. Return to Academy, or check your sign-in again.':'Checking the current sign-in before showing private information.';
 }});
 function wrappedResponse(response,stamp,done){
  return new Proxy(response,{get(target,key){
   if(['json','text','blob','arrayBuffer','formData'].includes(key))return async(...args)=>{try{const value=await target[key](...args);await runtime.current(stamp);return value;}finally{done();}};
   if(key==='clone')return ()=>wrappedResponse(target.clone(),stamp,()=>{});
   const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;
  }});
 }
 async function fetchGuard(input,options={}){
  const url=new URL(typeof input==='string'||input instanceof URL?String(input):input.url,win.location.href);
  if(app!=='academy'&&apiOrigins.has(url.origin)&&['/auth/login','/auth/register'].includes(url.pathname))throw Error('ACADEMY_SIGNIN_REQUIRED');
  if(url.href===contextURL)throw Error('CONTEXT_ROUTE_IS_PRIVATE_TO_ADAPTER');
  if(!privateURL(url))return nativeFetch(input,options);
  if(!await runtime.ready())throw new DOMException('Current Academy sign-in is required.','AbortError');
  const stamp=await runtime.capture(),controller=new AbortController(),upstream=options.signal||input?.signal;
  const abort=()=>controller.abort();if(upstream?.aborted)controller.abort();else upstream?.addEventListener?.('abort',abort,{once:true});
  const untrack=runtime.trackController(controller),done=()=>{untrack();upstream?.removeEventListener?.('abort',abort);};
  try{
   const response=await nativeFetch(input,{...options,signal:controller.signal,cache:'no-store',credentials:'same-origin'});
   if(response.status===401){runtime.clear('known-cancellation');throw new DOMException('This app session needs verification.','AbortError');}
   await runtime.current(stamp);return wrappedResponse(response,stamp,done);
  }catch(error){done();throw error;}
 }
 return Object.freeze({runtime,fetch:fetchGuard,origins,app});
}
// The relay document is a public static protocol endpoint, not an auth service.
// Exact app origins must come from the same reviewed build configuration.
export function startRelayDocument({win,origins}){
 const storage=win.localStorage,locks=win.navigator.locks;
 if(!locks?.request)throw Error('BROWSER_CONTROL_UNAVAILABLE');
 const control=createBrowserControl({storage,exclusive:fn=>locks.request('uaa-v110-ui-control',fn)});
 return installBrowserRelay({win,origins,control,channelFactory:name=>new BroadcastChannel(name)});
}
