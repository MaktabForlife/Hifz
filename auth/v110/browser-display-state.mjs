// Isolated browser display-memory prototype. Not imported by any live app.
// This is UI state, NEVER server authorization. It stores no credentials,
// touches no persistent storage and provides no cross-origin coordinator.
const APPS=new Set(['academy','studio','hifz']);
const ID=/^[-A-Za-z0-9_:]{1,180}$/;
const IDLE=5400000,ABSOLUTE=604800000;
const FIELDS=['app','accountId','sessionId','parentId','browserId','browserGeneration','credentialEpoch','securityVersion','unlockGeneration','originalSignedAtMs','originalExpiresAtMs','lastForegroundRefreshMs','serverNowMs'];
const BINDING=FIELDS.filter(x=>!['serverNowMs','lastForegroundRefreshMs'].includes(x));
const reasons=new Set(['logout','switch','lock','known-cancellation','view-changed','manual','hidden','resume','verification-failed','context-mismatch','load-failed','closed']);
const safeInt=v=>Number.isSafeInteger(v)&&v>=0;
const plain=v=>Boolean(v&&Object.getPrototypeOf(v)===Object.prototype);
const exact=(v,keys)=>plain(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const copy=v=>structuredClone(v);
export function validDisplaySession(s,app){
 if(!exact(s,FIELDS)||s.app!==app||!APPS.has(app))return false;
 if(['accountId','sessionId','parentId','browserId'].some(k=>typeof s[k]!=='string'||!ID.test(s[k])))return false;
 if(FIELDS.filter(k=>k.endsWith('Ms')||k.endsWith('Generation')||k.endsWith('Epoch')||k==='securityVersion').some(k=>!safeInt(s[k])))return false;
 if(s.originalExpiresAtMs<=s.originalSignedAtMs||s.originalExpiresAtMs-s.originalSignedAtMs>ABSOLUTE||s.serverNowMs<s.originalSignedAtMs||s.lastForegroundRefreshMs<s.originalSignedAtMs||s.lastForegroundRefreshMs>s.serverNowMs)return false;
 if(app==='academy'&&s.sessionId!==s.parentId)return false;
 return true;
}
const identity=s=>JSON.stringify(BINDING.map(k=>s[k]));
function validView(view){
 return exact(view,['version','items'])&&typeof view.version==='string'&&view.version.length>0&&view.version.length<=256&&Array.isArray(view.items)&&view.items.every(item=>exact(item,['id','label','href'])&&typeof item.id==='string'&&ID.test(item.id)&&typeof item.label==='string'&&item.label.length<=160&&typeof item.href==='string'&&item.href.length<=512&&item.href.startsWith('/')&&!item.href.startsWith('//')&&!/[\u0000-\u0020\\]/.test(item.href));
}
export function createDisplayMemory({app,verifySession,onState=()=>{},onClear=()=>{},clock=()=>performance.now(),setTimer=(fn,ms)=>setTimeout(fn,ms),cancelTimer=id=>clearTimeout(id),channelFactory,maxEntries=8,maxViewBytes=256000}){
 if(!APPS.has(app)||typeof verifySession!=='function'||typeof clock!=='function'||!Number.isSafeInteger(maxEntries)||maxEntries<1||!Number.isSafeInteger(maxViewBytes)||maxViewBytes<1)throw Error('INVALID_DISPLAY_CONFIG');
 let epoch=0,phase='masked',reason='resume',session=null,deadline=0,timer=null,closed=false;
 const views=new Map(),pending=new Set(),unbind=new Set(),serials=new Map();let visible=()=>true;
 const channel=channelFactory?.('uaa-display-memory-v1-'+app);
 const report=()=>Object.freeze({app,phase,reason,epoch,entryCount:views.size,hasSession:Boolean(session),remainingMs:phase==='ready'?Math.max(0,deadline-clock()):0});
 function clear(why='manual',{broadcast=false}={}){
  if(closed)return;
  reason=reasons.has(why)?why:'manual';phase='masked';epoch++;session=null;deadline=0;views.clear();serials.clear();
  if(timer!==null){cancelTimer(timer);timer=null;}
  for(const controller of pending)controller.abort();pending.clear();
  // Internal state and pending loads are invalidated BEFORE rendering hooks.
  onClear(reason);onState(report());
  // Peer delivery is best effort and must never prevent local masking.
  // A transport failure is not evidence that another tab cleared.
  if(broadcast){try{channel?.postMessage({type:'CLEAR_DISPLAY',app,reason});}catch{}}
 }
 function check(){
  if(!closed&&phase==='ready'&&clock()>=deadline)clear('lock',{broadcast:true});
  return !closed&&phase==='ready';
 }
 function armExpiry(){
  const mine=epoch;
  timer=setTimer(()=>{
   // A cancelled/dequeued older callback must not alter a newer timer.
   if(closed||mine!==epoch||phase!=='ready')return;
   timer=null;
   // Timer scheduling can be early. Keep the original deadline and re-arm
   // until it has actually been reached, without waiting for a cache API call.
   if(check())armExpiry();
  },Math.max(1,Math.ceil(deadline-clock())));
  timer?.unref?.();
 }
 function save(key,view){
  if(typeof key!=='string'||!ID.test(key)||!validView(view))throw Error('INVALID_DISPLAY_VIEW');
  // An optional memory budget is not a material-access/account limit.
  // Large valid views may be rendered once, but are deliberately not cached.
  const value=copy(view);
  // A replacement must retire the old view even when the new one is not cached.
  views.delete(key);
  if(new TextEncoder().encode(JSON.stringify(value)).byteLength<=maxViewBytes){
   views.set(key,value);
   while(views.size>maxEntries)views.delete(views.keys().next().value);
  }
  return copy(value);
 }
 function envelope(value){
  return exact(value,['context','view'])&&validDisplaySession(value.context,app)&&session&&identity(value.context)===identity(session)&&validView(value.view);
 }
 async function recheck(why='resume'){
  if(closed)return false;
  if(!visible()){clear('hidden');return false;}
  clear(why);const mine=epoch,started=clock(),controller=new AbortController();pending.add(controller);
  try{
   // MUST be a fresh authoritative response, not cached browser metadata.
   // It may piggyback session+views on one existing app response.
   const reply=await verifySession({signal:controller.signal,reason:why});
   if(closed||mine!==epoch)return false;
   if(!visible()){clear('hidden');return false;}
   pending.delete(controller);
   if(!reply||!validDisplaySession(reply.session,app)||!Array.isArray(reply.initialViews||[])){clear('verification-failed');return false;}
   const current=reply.session,remaining=Math.min(current.originalExpiresAtMs,current.lastForegroundRefreshMs+IDLE)-current.serverNowMs;
   // Anchor at REQUEST START, not response arrival, so delay cannot prolong
   // the local privacy deadline. Server authorization stays authoritative.
   const until=started+remaining;
   if(remaining<=0||clock()>=until){clear('lock');return false;}
   session=copy(current);deadline=until;phase='ready';reason=why;
   for(const entry of reply.initialViews||[]){
    if(!exact(entry,['key','context','view'])||!envelope({context:entry.context,view:entry.view}))throw Error('INVALID_INITIAL_DISPLAY');
    save(entry.key,entry.view);
   }
   armExpiry();
   onState(report());return true;
  }catch{
   pending.delete(controller);if(!closed&&mine===epoch)clear('verification-failed');return false;
  }
 }
 async function load(key,loader,{force=false}={}){
  if(typeof key!=='string'||!ID.test(key))throw Error('INVALID_DISPLAY_KEY');
  if(!check())return null;
  if(!force&&views.has(key))return copy(views.get(key));
  if(typeof loader!=='function')throw Error('INVALID_DISPLAY_LOADER');
  const mine=epoch,contextKey=identity(session),sequence=(serials.get(key)||0)+1,controller=new AbortController();serials.set(key,sequence);pending.add(controller);
  try{
   const reply=await loader({signal:controller.signal});
   pending.delete(controller);
   if(!check()||epoch!==mine||serials.get(key)!==sequence||!session||identity(session)!==contextKey)return null;
   if(!envelope(reply)){clear('context-mismatch',{broadcast:true});return null;}
   return save(key,reply.view);
  }catch{
   pending.delete(controller);if(!closed&&mine===epoch&&serials.get(key)===sequence)clear('load-failed');return null;
  }
 }
 const listener=event=>{const m=event?.data;if(m?.type==='CLEAR_DISPLAY'&&m.app===app)clear(m.reason,{broadcast:false});};
 if(channel){if(channel.addEventListener)channel.addEventListener('message',listener);else channel.onmessage=listener;}
 function bindLifecycle(win,doc){
  if(unbind.size)throw Error('DISPLAY_LIFECYCLE_ALREADY_BOUND');
  let available=true;visible=()=>available&&doc.visibilityState!=='hidden';
  const hidden=()=>{if(doc.visibilityState==='hidden')clear('hidden');else void recheck('resume');};
  const hide=()=>{available=false;clear('hidden');},show=()=>{available=true;void recheck('resume');};
  win.addEventListener('pagehide',hide);win.addEventListener('pageshow',show);doc.addEventListener('visibilitychange',hidden);
  const remove=()=>{win.removeEventListener('pagehide',hide);win.removeEventListener('pageshow',show);doc.removeEventListener('visibilitychange',hidden);unbind.delete(remove);visible=()=>true;};
  unbind.add(remove);if(!visible())clear('hidden');return remove;
 }
 return Object.freeze({
  recheck,load,clear,bindLifecycle,
  peek(key){return check()&&views.has(key)?copy(views.get(key)):null;},
  state(){check();return report();},
  close(){if(closed)return;try{clear('closed');}finally{closed=true;for(const remove of [...unbind])remove();if(channel?.removeEventListener)channel.removeEventListener('message',listener);channel?.close?.();}}
 });
}
