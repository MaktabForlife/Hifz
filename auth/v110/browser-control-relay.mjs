// V110 browser control is a UI clearing fence, NEVER server authorization.
// Storage contains opaque control metadata only. No tokens, identity labels,
// material permissions or private content may be sent to this broker.
const APPS=['academy','studio','hifz'];
const HASH=/^[a-f0-9]{64}$/;
const NONCE=/^[A-Za-z0-9_-]{32,96}$/;
const REV=/^[a-f0-9-]{36}$/;
const reasons=new Set(['logout','switch','known-cancellation']);
const plain=v=>v&&Object.getPrototypeOf(v)===Object.prototype;
const exact=(v,keys)=>plain(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
export function browserOrigins(config){
 if(!exact(config,APPS))throw Error('INVALID_BROWSER_ORIGINS');
 const origins={};
 for(const app of APPS){
  const value=config[app];let u;try{u=new URL(value);}catch{throw Error('INVALID_BROWSER_ORIGINS');}
  if(u.origin!==value||u.username||u.password||u.protocol!=='https:'&&!(u.protocol==='http:'&&['localhost','127.0.0.1'].includes(u.hostname)))throw Error('INVALID_BROWSER_ORIGINS');
  origins[app]=value;
 }
 if(new Set(Object.values(origins)).size!==3)throw Error('DISTINCT_APP_ORIGINS_REQUIRED');
 return Object.freeze(origins);
}
export async function browserBinding(session){
 if(!session||typeof session.parentId!=='string'||typeof session.browserId!=='string'||!Number.isSafeInteger(session.browserGeneration)||session.browserGeneration<0)throw Error('INVALID_BROWSER_BINDING');
 const bytes=new TextEncoder().encode(JSON.stringify(['uaa-ui-fence-v1',session.parentId,session.browserId,session.browserGeneration]));
 return [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(x=>x.toString(16).padStart(2,'0')).join('');
}
export function validBrowserState(v){
 return exact(v,['v','revision','active','binding','expiresAtMs'])&&v.v===1&&REV.test(v.revision)&&typeof v.active==='boolean'&&
  (v.active?HASH.test(v.binding)&&Number.isSafeInteger(v.expiresAtMs)&&v.expiresAtMs>0:v.binding===null&&v.expiresAtMs===0);
}
export function createBrowserControl({storage,exclusive,clock=()=>Date.now(),revision=()=>crypto.randomUUID(),onChange=()=>{}}){
 if(!storage?.getItem||!storage?.setItem||typeof exclusive!=='function')throw Error('BROWSER_CONTROL_UNAVAILABLE');
 const key='uaa-v110-ui-control-v1';
 const read=()=>{
  const raw=storage.getItem(key);if(raw===null)return null;
  if(typeof raw!=='string'||raw.length>1024)throw Error('BROWSER_CONTROL_UNAVAILABLE');
  let value;try{value=JSON.parse(raw);}catch{throw Error('BROWSER_CONTROL_UNAVAILABLE');}
  if(!validBrowserState(value))throw Error('BROWSER_CONTROL_UNAVAILABLE');
  return value;
 };
 const write=value=>{if(!validBrowserState(value))throw Error('BROWSER_CONTROL_UNAVAILABLE');storage.setItem(key,JSON.stringify(value));onChange(structuredClone(value));return structuredClone(value);};
 return Object.freeze({
  async snapshot(){return exclusive(()=>{const value=read();return value&&value.active&&clock()>=value.expiresAtMs?write({v:1,revision:revision(),active:false,binding:null,expiresAtMs:0}):structuredClone(value);});},
  async clear(reason){
   if(!reasons.has(reason))throw Error('INVALID_GLOBAL_CLEAR');
   return exclusive(()=>write({v:1,revision:revision(),active:false,binding:null,expiresAtMs:0}));
  },
  async establish({expectedRevision,binding,expiresAtMs}){
   if(!REV.test(expectedRevision)||!HASH.test(binding)||!Number.isSafeInteger(expiresAtMs))throw Error('INVALID_BROWSER_CONTROL');
   return exclusive(()=>{
    const value=read();
    if(!value||value.revision!==expectedRevision||value.active||expiresAtMs<=clock()||expiresAtMs-clock()>604800000)throw Error('STALE_BROWSER_CONTROL');
    return write({v:1,revision:revision(),active:true,binding,expiresAtMs});
   });
  },
  async assert({revision:expected,binding}){
   if(!REV.test(expected)||!HASH.test(binding))throw Error('INVALID_BROWSER_CONTROL');
   return exclusive(()=>{const value=read();if(!value||!value.active||value.revision!==expected||value.binding!==binding||clock()>=value.expiresAtMs)throw Error('BROWSER_CONTEXT_CHANGED');return structuredClone(value);});
  }
 });
}
// A document connection is source/origin/nonce bound. Only Academy can establish.
// This module does not inspect an auth cookie or authenticate a Master session;
// the Academy consumer MUST supply fresh verified context through its own gate.
export function installBrowserRelay({win,origins,control,channelFactory}){
 origins=browserOrigins(origins);
 if(win.location.origin!==origins.academy||win.parent===win)throw Error('INVALID_RELAY_HOST');
 const peers=new Map();let closed=false;
 const channel=channelFactory?.('uaa-v110-ui-control');
 const safePost=(source,origin,value)=>{try{source.postMessage(value,origin);}catch{}};
 const notify=async()=>{
  if(closed)return;let state=null;try{state=await control.snapshot();}catch{}
  for(const [source,peer]of peers)safePost(source,peer.origin,{v:1,type:'UAA_CONTROL_CHANGED',nonce:peer.nonce,state});
 };
 const signal=()=>{void notify();try{channel?.postMessage({v:1,type:'CONTROL_CHANGED'});}catch{}};
 const listener=async event=>{
  const m=event.data;
  if(closed||!plain(m)||m.v!==1||!APPS.includes(m.app)||origins[m.app]!==event.origin||!NONCE.test(m.nonce||'')||!NONCE.test(m.requestId||''))return;
  if(!event.source||event.source!==win.parent)return;
  const reply=(ok,state=null,code)=>safePost(event.source,event.origin,{v:1,type:'UAA_CONTROL_REPLY',nonce:m.nonce,requestId:m.requestId,ok,state,...(code?{code}:{})});
  if(m.type==='UAA_CONTROL_CONNECT'){
   if(!exact(m,['v','type','app','nonce','requestId']))return;
   peers.set(event.source,{origin:event.origin,nonce:m.nonce,app:m.app});
   try{reply(true,await control.snapshot());}catch{reply(false,null,'BROWSER_CONTROL_UNAVAILABLE');}return;
  }
  const peer=peers.get(event.source);if(!peer||peer.nonce!==m.nonce||peer.app!==m.app)return;
  try{
   let state,changed=false;
   if(m.type==='UAA_CONTROL_READ'&&exact(m,['v','type','app','nonce','requestId']))state=await control.snapshot();
   else if(m.type==='UAA_CONTROL_CLEAR'&&exact(m,['v','type','app','nonce','requestId','reason'])){state=await control.clear(m.reason);changed=true;}
   else if(m.type==='UAA_CONTROL_ESTABLISH'&&peer.app==='academy'&&exact(m,['v','type','app','nonce','requestId','expectedRevision','binding','expiresAtMs'])){state=await control.establish(m);changed=true;}
   else if(m.type==='UAA_CONTROL_ASSERT'&&exact(m,['v','type','app','nonce','requestId','revision','binding']))state=await control.assert(m);
   else return;
   reply(true,state);if(changed)signal();
  }catch{reply(false,null,'BROWSER_CONTEXT_UNVERIFIABLE');void notify();}
 };
 win.addEventListener('message',listener);win.addEventListener('storage',notify);win.addEventListener('pageshow',notify);
 channel?.addEventListener?.('message',notify);
 return Object.freeze({notify,close(){closed=true;peers.clear();win.removeEventListener('message',listener);win.removeEventListener('storage',notify);win.removeEventListener('pageshow',notify);channel?.removeEventListener?.('message',notify);channel?.close?.();}});
}
