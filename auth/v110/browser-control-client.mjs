import {browserOrigins,validBrowserState} from './browser-control-relay.mjs';
const random=()=>btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
const APPS=['academy','studio','hifz'];
// All broker messages are UI hints/control fences. No message authorizes an API.
// The frame is deliberately on Academy's configured origin, never a URL derived
// from request headers or an untrusted return/next query string.
export function createBrowserControlClient({win,doc,app,origins,onInvalidate=()=>{},timeoutMs=4000,framePath='/auth/v110/browser-control.html'}){
 origins=browserOrigins(origins);
 if(!APPS.includes(app)||win.location.origin!==origins[app]||framePath!=='/auth/v110/browser-control.html'||!Number.isSafeInteger(timeoutMs)||timeoutMs<100||timeoutMs>10000)throw Error('INVALID_BROWSER_CLIENT');
 const nonce=random(),pending=new Map();let closed=false,connected=false,epoch=0,ready=null,knownRevision=null,loaded=false,mounted=false,loading=null;
 const frame=doc.createElement('iframe');frame.hidden=true;frame.setAttribute('data-uaa-control','');frame.title='Academy browser privacy coordination';frame.setAttribute('aria-hidden','true');frame.setAttribute('sandbox','allow-scripts allow-same-origin');frame.src=origins.academy+framePath;
 function rejectAll(){for(const p of pending.values()){clearTimeout(p.timer);p.reject(Error('BROWSER_CONTEXT_CHANGED'));}pending.clear();}
 function invalidate(){if(closed)return;epoch++;rejectAll();onInvalidate();}
 const listener=event=>{
  const m=event.data;
  if(closed||event.origin!==origins.academy||event.source!==frame.contentWindow||!m||m.v!==1||m.nonce!==nonce)return;
  if(m.type==='UAA_CONTROL_CHANGED'){
   // Never accept a broadcast as permission to reveal or adopt a new identity.
   if(m.state&&validBrowserState(m.state)&&m.state.revision===knownRevision)return;
   invalidate();return;
  }
  if(m.type!=='UAA_CONTROL_REPLY'||typeof m.requestId!=='string')return;
  const p=pending.get(m.requestId);if(!p)return;pending.delete(m.requestId);clearTimeout(p.timer);
  if(p.epoch!==epoch||m.ok!==true||m.state!==null&&!validBrowserState(m.state)){p.reject(Error('BROWSER_CONTEXT_UNVERIFIABLE'));return;}
  knownRevision=m.state?.revision||null;p.resolve(m.state);
 };
 win.addEventListener('message',listener);
 function send(type,values={}){
  if(closed)return Promise.reject(Error('BROWSER_CONTROL_UNAVAILABLE'));
  const requestId=random(),mine=epoch;
  return new Promise((resolve,reject)=>{
   const timer=setTimeout(()=>{pending.delete(requestId);invalidate();reject(Error('BROWSER_CONTROL_UNAVAILABLE'));},timeoutMs);
   pending.set(requestId,{epoch:mine,resolve,reject,timer});
   try{frame.contentWindow.postMessage({v:1,type,app,nonce,requestId,...values},origins.academy);}catch{pending.delete(requestId);clearTimeout(timer);invalidate();reject(Error('BROWSER_CONTROL_UNAVAILABLE'));}
  });
 }
 async function loadFrame(){
  if(loaded)return;
  if(!loading)loading=new Promise((resolve,reject)=>{
   const timer=setTimeout(()=>{invalidate();reject(Error('BROWSER_CONTROL_UNAVAILABLE'));},timeoutMs);
   frame.addEventListener('load',()=>{clearTimeout(timer);loaded=true;resolve();},{once:true});
   frame.addEventListener('error',()=>{clearTimeout(timer);invalidate();reject(Error('BROWSER_CONTROL_UNAVAILABLE'));},{once:true});
   if(!mounted){mounted=true;(doc.body||doc.documentElement).append(frame);}
  });
  return loading;
 }
 async function connect(){
  if(closed)throw Error('BROWSER_CONTROL_UNAVAILABLE');
  if(connected)return;
  if(!ready){
   const task=loadFrame().then(()=>send('UAA_CONTROL_CONNECT')).then(()=>{connected=true;}).catch(error=>{if(ready===task)ready=null;throw error;});
   ready=task;
  }
  return ready;
 }
 const request=async(type,values)=>{await connect();return send(type,values);};
 return Object.freeze({
  connect,
  read:()=>request('UAA_CONTROL_READ'),
  assert:values=>request('UAA_CONTROL_ASSERT',values),
  // An explicit sign-out/switch clears locally BEFORE attempting this request.
  clear:reason=>request('UAA_CONTROL_CLEAR',{reason}),
  establish:values=>{if(app!=='academy')return Promise.reject(Error('MASTER_ONLY'));return request('UAA_CONTROL_ESTABLISH',values);},
  state:()=>({connected,epoch,closed}),
  close(){if(closed)return;invalidate();closed=true;win.removeEventListener('message',listener);frame.remove();}
 });
}
