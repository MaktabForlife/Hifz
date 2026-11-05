import {createDisplayMemory,validDisplaySession} from './browser-display-state.mjs';
import {browserBinding,browserOrigins} from './browser-control-relay.mjs';
import {createBrowserControlClient} from './browser-control-client.mjs';
const API_ACTIONS=new Set(['logout','switch','known-cancellation']);
const deny=()=>{throw new DOMException('Verify your Academy session before opening private information.','AbortError');};
// Installed only by an explicit feature configuration. This gate never maps
// legacy verifiedAt/profile/token timestamps into V110 foreground/session clocks.
export function installAppPrivacy({win,doc,app,origins,verifySession,onClear=()=>{},onReady=()=>{},channelFactory,clock,setTimer,cancelTimer}){
 origins=browserOrigins(origins);
 if(win.location.origin!==origins[app]||typeof verifySession!=='function')throw Error('INVALID_APP_PRIVACY_CONFIG');
 let generation=0,context=null,verifiedBinding=null,brokerRevision=null,readiness=null,closed=false,signInIntent=null,everRevealed=false,needsNativeReset=false;
 const controllers=new Set(),urls=new Set();let cache,broker;
 const mask=()=>{
  doc.documentElement.classList.add('uaa-v110-masked');
  doc.documentElement.dataset.uaaV110State='masked';
  for(const el of doc.querySelectorAll('audio,video')){
   try{el.pause();}catch{}el.removeAttribute('src');for(const child of el.querySelectorAll('source'))child.removeAttribute('src');try{el.load();}catch{}
  }
  for(const el of doc.querySelectorAll('iframe:not([data-uaa-control]),object,embed')){el.removeAttribute('src');el.removeAttribute('data');el.remove();}
  for(const url of urls)URL.revokeObjectURL(url);urls.clear();
 };
 const clear=reason=>{
  generation++;context=null;verifiedBinding=null;brokerRevision=null;if(everRevealed)needsNativeReset=true;mask();
  for(const controller of controllers)controller.abort();controllers.clear();
  onClear(reason);
  win.dispatchEvent(new CustomEvent('uaa-v110-private-cleared',{detail:{app,reason}}));
 };
 const invalidate=()=>{cache?.clear('known-cancellation');if(needsNativeReset)queueMicrotask(()=>win.location.reload());};
 broker=createBrowserControlClient({win,doc,app,origins,onInvalidate:invalidate});
 cache=createDisplayMemory({app,clock,setTimer,cancelTimer,channelFactory,onClear:clear,onState:state=>{
  // A ready context permits native data loading. Native account/render hooks
  // must still call reveal() after their checked bootstrap, never before.
  if(state.phase==='ready')win.dispatchEvent(new CustomEvent('uaa-v110-context-ready',{detail:{app}}));
 },verifySession:async args=>{
  const mine=generation,result=await verifySession(args);
  if(mine!==generation)deny();
  if(!result||!validDisplaySession(result.session,app))throw Error('CURRENT_CONTEXT_UNAVAILABLE');
  const current=result.session,binding=await browserBinding(current),head=await broker.read();
  if(!head?.active||head.binding!==binding)throw Error('BROWSER_CONTEXT_CHANGED');
  if(mine!==generation)deny();
  const checked=await broker.assert({revision:head.revision,binding});
  if(mine!==generation)deny();
  context=structuredClone(current);verifiedBinding=binding;brokerRevision=checked.revision;
  return {session:current,initialViews:result.initialViews||[]};
 }});
 // Once a private native document has been shown, resumption starts a fresh
 // document. Old native globals/DOM/media references can never be unmasked.
 // Public versioned assets remain reusable; only current app data is reloaded.
 const resume=()=>{
  if(doc.visibilityState==='hidden')return;
  if(needsNativeReset){mask();win.location.reload();return;}
  void ready();
 };
 const hide=()=>cache.clear('hidden');
 const visibility=()=>doc.visibilityState==='hidden'?hide():resume();
 win.addEventListener('pagehide',hide);win.addEventListener('pageshow',resume);doc.addEventListener('visibilitychange',visibility);
 mask();
 function ready(){
  if(closed||doc.visibilityState==='hidden')return Promise.resolve(false);
  if(needsNativeReset){mask();return Promise.resolve(false);}
  if(cache.state().phase==='ready')return Promise.resolve(true);
  if(!readiness){const task=cache.recheck('resume').finally(()=>{if(readiness===task)readiness=null;});readiness=task;}
  return readiness;
 }
 async function capture(){
  if(closed||cache.state().phase!=='ready'||!context)deny();
  const mine=generation,binding=verifiedBinding,revision=brokerRevision;
  try{await broker.assert({revision,binding});}catch{cache.clear('known-cancellation');deny();}
  if(mine!==generation||cache.state().phase!=='ready')deny();
  return Object.freeze({generation:mine,binding,revision,accountId:context.accountId});
 }
 async function current(stamp){
  if(!stamp||stamp.generation!==generation||stamp.binding!==verifiedBinding||stamp.revision!==brokerRevision||cache.state().phase!=='ready')deny();
  try{await broker.assert({revision:stamp.revision,binding:stamp.binding});}catch{cache.clear('known-cancellation');deny();}
  if(stamp.generation!==generation||cache.state().phase!=='ready')deny();
 }
 return Object.freeze({
  ready,capture,current,
  get session(){return context?structuredClone(context):null;},
  async reveal(accountId){
   if(needsNativeReset){mask();win.location.reload();deny();}
   const stamp=await capture();if(accountId!==stamp.accountId){cache.clear('context-mismatch');deny();}
   await current(stamp);
   everRevealed=true;
   doc.documentElement.classList.remove('uaa-v110-masked');doc.documentElement.dataset.uaaV110State='ready';
   onReady();return stamp;
  },
  async guard(promise,stamp){const value=await promise;await current(stamp);return value;},
  trackURL(url){if(typeof url!=='string'||!url.startsWith('blob:'))throw Error('INVALID_PRIVATE_URL');urls.add(url);return url;},
  trackController(controller){if(!controller?.abort)throw Error('INVALID_PRIVATE_REQUEST');controllers.add(controller);return ()=>controllers.delete(controller);},
  clear(reason='manual'){cache.clear(reason);},
  async clearAll(reason){
   if(!API_ACTIONS.has(reason))throw Error('INVALID_GLOBAL_CLEAR');
   signInIntent=null;cache.clear(reason,{broadcast:true});
   // Local privacy has completed even if the broker is unavailable.
   const state=await broker.clear(reason);return {revision:state.revision};
  },
  async beginMasterSignIn(){
   if(app!=='academy')throw Error('MASTER_ONLY');
   cache.clear('switch',{broadcast:true});
   const state=await broker.clear('switch');signInIntent={revision:state.revision,generation};return {...signInIntent};
  },
  async completeMasterSignIn(intent,verifiedReply){
   if(app!=='academy'||!signInIntent||intent?.revision!==signInIntent.revision||intent.generation!==signInIntent.generation||generation!==intent.generation||!validDisplaySession(verifiedReply?.session,'academy'))deny();
   // This entrypoint is for the actual successful Academy credential/handover
   // flow, not an ordinary refresh or a child-provided session DTO.
   const session=verifiedReply.session,binding=await browserBinding(session);
   await broker.establish({expectedRevision:intent.revision,binding,expiresAtMs:session.originalExpiresAtMs});
   signInIntent=null;return ready();
  },
  close(){if(closed)return;cache.close();closed=true;win.removeEventListener('pagehide',hide);win.removeEventListener('pageshow',resume);doc.removeEventListener('visibilitychange',visibility);broker.close();}
 });
}
