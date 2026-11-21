/* Explicit V2 adapter. Existing native scripts and disabled SW remain in source. */
(function(){
 'use strict';
 if(document.querySelector('meta[name="hifz-auth-mode"]')?.content!=='v2')return;
 const origin='https://mahadarwa-hifz.ummabbadacademy.app';
 let academyEntry=location.origin===origin&&location.pathname==='/'&&location.search==='?academy-entry=1'&&!location.hash;
 if(academyEntry)history.replaceState(history.state,'','/');
 const state={active:true,session:null,drafts:null,client:null,lastState:null};
 globalThis.HifzV111=state;
 const prepared=new Set(),restorable=new Map();let checkpoint=Promise.resolve();
 const mask=()=>{prepared.clear();restorable.clear();document.documentElement.setAttribute('data-hifz-private-mask','');};
 mask();
 const style=document.createElement('style');style.textContent='html[data-hifz-private-mask] #appShell,html[data-hifz-private-mask] #hifzV2Recovery,html[data-hifz-private-mask] #hifzV2Draft{visibility:hidden!important}#hifzV2Access,#hifzV2Recovery{max-width:48rem;margin:2rem auto;padding:1rem}#hifzV2Recovery pre{white-space:pre-wrap;overflow-wrap:anywhere}';document.head.appendChild(style);
 function panel(){
  let host=document.getElementById('hifzV2Access');if(host)return host;
  host=document.createElement('section');host.id='hifzV2Access';
  const title=document.createElement('h2');title.textContent='Hifz sign-in';host.appendChild(title);
  const status=document.createElement('p');status.id='hifzV2Status';status.setAttribute('role','status');host.appendChild(status);
  for(const [label,run] of [['Continue through Academy',()=>state.journey()],['Refresh Hifz',()=>state.start()],['Sign out',()=>state.logout()]]){
   const button=document.createElement('button');button.type='button';button.textContent=label;button.addEventListener('click',()=>run().catch(e=>{status.textContent=e.message||'The request is unavailable.';}));host.appendChild(button);
  }
  const link=document.createElement('a');link.href='https://ummabbadacademy.app/';link.textContent='Open Academy';host.appendChild(link);document.body.appendChild(host);return host;
 }
 state.showAccess=(message='Continue through Academy to sign in or unlock Hifz.')=>{mask();if(typeof hideAllLoginScreens==='function')hideAllLoginScreens();panel().hidden=false;document.getElementById('hifzV2Status').textContent=message;};
 function discardNative(){
  mask();state.client?.clear();
  if(typeof clearHifzPrivateMemory==='function')clearHifzPrivateMemory();
  const shell=document.getElementById('appShell');if(shell)shell.replaceChildren();
  document.getElementById('hifzV2Recovery')?.remove();document.getElementById('hifzV2Draft')?.remove();
 }
 state.clear=()=>{discardNative();return state.session?.clearAvailable();};
 state.logout=async()=>{
  const pending=state.session?.logout();discardNative();state.showAccess('This browser is cleared. Sign-out on other apps and devices may still be pending.');
  try{await pending;}catch{state.showAccess('This browser is cleared. Global sign-out is unconfirmed.');}
 };
 state.switchAccount=async()=>{
  const pending=state.session?.switchAccount();discardNative();state.showAccess('This browser is cleared. Choose the replacement account through Academy.');
  const result=await pending;if(result?.navigateUrl)location.assign(result.navigateUrl);
 };
 let journeyFlight=null;
 state.journey=()=>journeyFlight??=(async()=>{
  await state.ready;
  const result=state.session.getContext()?await state.session.beginUnlock({returnTo:'/'}):await state.session.beginAdmission({returnTo:'/'});
  if(!result?.navigateUrl)throw new Error('Academy sign-in is temporarily unavailable.');
  const target=new URL(result.navigateUrl);if(target.origin!=='https://ummabbadacademy.app')throw new Error('Academy sign-in address is unavailable.');location.assign(target.href);
 })().finally(()=>{journeyFlight=null;});
 state.recover=async resource=>{
  await state.ready;
  let host=document.getElementById('hifzV2Recovery');if(!host){host=document.createElement('section');host.id='hifzV2Recovery';document.body.appendChild(host);}host.replaceChildren();
  const warning=document.createElement('p');warning.textContent='SAVE OUTCOME UNKNOWN. Do not retry the original save. Review the retained draft and fresh records. Matching text or an absent row does not prove whether a partial save happened.';host.appendChild(warning);
  const refresh=document.createElement('button');refresh.textContent='Read current records';refresh.type='button';host.appendChild(refresh);
  refresh.addEventListener('click',async()=>{
   refresh.disabled=true;
   try{
    const recovery=await state.client.recover(resource),pre=document.createElement('pre');pre.textContent=JSON.stringify({retainedDraft:recovery.draft,currentRecords:recovery.views},null,2);host.appendChild(pre);
    for(const [path,rows] of Object.entries(recovery.views.journals))for(const row of rows){
     if(!row.id||row.source==='maktab'||(typeof currentUser!=='undefined'&&row.student_id!==currentUser.id))continue;
     const edit=document.createElement('button');edit.type='button';edit.textContent='Edit existing '+path.slice(1)+' entry '+row.id;
     edit.addEventListener('click',async()=>{
      try{
       state.client.allowExistingCorrection(resource,recovery,path,row);
       if(typeof clearLogContext==='function')clearLogContext();
       if(path==='/reflections'){await showScreen('reflections');loadTadabburEntryForEdit(row);}
       else await openEntryForEdit({'/sabaq':'sabaq','/sabaq-dhor':'sabaqDhor','/dhor':'dhor'}[path],row,false);
       host.hidden=true;
      }catch(e){warning.textContent=e.message||'Manual correction is unavailable.';}
     });host.appendChild(edit);
    }
    const note=document.createElement('p');note.textContent='The original outcome remains unknown. Only deliberate edits of actual existing entries are offered. If completion is still unclear, keep the draft and ask for support.';host.appendChild(note);
   }catch(e){warning.textContent='Current records are unavailable. The unknown outcome and retained draft remain. Do not retry the original save.';}
   finally{refresh.disabled=false;}
  });
 };
 state.ready=(async()=>{
  if(location.origin!==origin)throw new Error('Hifz is not available at this address.');
  const [{createBrowserSession},{createBrowserDrafts},{createHifzClient}]=await Promise.all([import('/js/v111/browser-session.mjs'),import('/js/v111/browser-drafts.mjs'),import('/js/v111-client.mjs')]);
  state.drafts=createBrowserDrafts({crypto:globalThis.crypto,indexedDB:globalThis.indexedDB,releaseCapsule:args=>state.session.draftKey(args),onUnavailable:()=>{mask();state.showAccess('Protected draft storage is unavailable. Private editors remain locked.');}});
  state.session=createBrowserSession({app:'hifz',origin,fetch:globalThis.fetch.bind(globalThis),crypto:globalThis.crypto,sessionStorage:globalThis.sessionStorage,localStorage:globalThis.localStorage,indexedDB:globalThis.indexedDB,locks:globalThis.navigator?.locks,BroadcastChannel:globalThis.BroadcastChannel,onMask:masked=>{if(masked){mask();state.showAccess('Hifz is masked until its current session is checked.');}else document.documentElement.removeAttribute('data-hifz-private-mask');},drafts:state.drafts,onState:dto=>{state.lastState=dto;},checkpoint:async()=>{await checkpoint;await state.drafts.flush();}});
  state.client=createHifzClient({session:state.session,drafts:state.drafts,onUnknown:({resource})=>{void state.recover(resource);},onRecoveryUnavailable:()=>state.showAccess('Current records are unavailable. The unknown save and retained draft remain. Do not retry the original save.')});
  try{return await state.session.bootstrap();}catch(e){state.showAccess('Continue through Academy. Hifz could not confirm a current unlocked session.');return null;}

})();
 state.start=async()=>{
  const current=await state.ready;
  try{
   if(academyEntry){
    academyEntry=false;
    if(['SIGNED_OUT','LOCKED','ADMITTED_LOCKED'].includes(current?.state)){
     state.showAccess('Continuing through Academy…');
     await state.journey();
     return;
    }
   }
   await state.session.ensureFresh();
   const ticket=state.client.beginView(),loaded=await bootApp();
   if(loaded!==true||!state.session.getContext())return;
   state.client.assertView(ticket);state.session.reveal(ticket.context);panel().hidden=true;
  }catch(e){state.showAccess(e.message||'Continue through Academy to unlock Hifz.');}
 };
 // Draft snapshots are encrypted by the shared SDK; no key/body enters storage here.
 function editorFor(target){
  const card=target?.closest?.('#card-sabaq,#card-sabaqDhor,#card-dhor,#tadabburCard');if(!card)return null;
  const kind={'card-sabaq':'sabaq','card-sabaqDhor':'sabaq-dhor','card-dhor':'dhor',tadabburCard:'reflections'}[card.id];
  const targetId=typeof logCtxIsMaktab==='function'&&logCtxIsMaktab()?'id.'+encodeURIComponent(logCtxStudentId()):'own';
  const editingId=kind==='sabaq'?(typeof sabaqEditingId==='undefined'?null:sabaqEditingId):kind==='sabaq-dhor'?(typeof sabaqDhorEditingId==='undefined'?null:sabaqDhorEditingId):kind==='dhor'?(typeof dhorEditingId==='undefined'?null:dhorEditingId):(typeof tadabburEditingId==='undefined'?null:tadabburEditingId);
  return {card,kind,editingId,resource:'hifz:/editor/'+kind+':'+targetId};
 }
 async function prepareEditor(resource){
  if(prepared.has(resource))return;
  await state.session.ensureFresh();const expected=state.session.getContext();
  const saved=await state.drafts.load(resource);if(!saved)await state.drafts.save(resource,{format:2,fields:{},editingId:null});else if(saved.payload?.fields&&Object.keys(saved.payload.fields).length)restorable.set(resource,saved.payload);
  if(!state.session.checkCurrentContext(expected))throw new Error('The editor context changed.');prepared.add(resource);
 }
 function offerRetained(editor){
  const draft=restorable.get(editor.resource),expected=state.session.getContext();if(!draft)return;
  let host=document.getElementById('hifzV2Draft');if(!host){host=document.createElement('section');host.id='hifzV2Draft';document.body.appendChild(host);}host.replaceChildren();
  const note=document.createElement('p');note.textContent='A protected draft is available for this editor. Review current records before saving. Restoring fields does not replay any save.';host.appendChild(note);
  const pre=document.createElement('pre');pre.textContent=JSON.stringify(draft.fields,null,2);host.appendChild(pre);
  const restore=document.createElement('button');restore.type='button';restore.textContent='Restore fields to matching editor';host.appendChild(restore);
  restore.addEventListener('click',()=>{
   const live=editorFor(editor.card.querySelector('input,textarea,select'));
   if(!state.session.checkCurrentContext(expected)||live?.resource!==editor.resource||live.editingId!==(draft.editingId??null)){note.textContent='Open the matching current entry before restoring these draft fields.';return;}
   for(const input of editor.card.querySelectorAll('input[id],textarea[id],select[id]'))if(Object.hasOwn(draft.fields,input.id)&&input.type!=='password'&&input.type!=='hidden'){if(input.type==='checkbox')input.checked=Boolean(draft.fields[input.id]);else input.value=String(draft.fields[input.id]??'');}
   restorable.delete(editor.resource);host.hidden=true;
  });
 }
 document.addEventListener('focusin',event=>{
  const editor=editorFor(event.target);if(!editor||!state.session?.getContext()||prepared.has(editor.resource))return;
  const input=event.target,oldReadOnly=input.readOnly;if('readOnly' in input)input.readOnly=true;
  void prepareEditor(editor.resource).then(()=>{if('readOnly' in input)input.readOnly=oldReadOnly;if(restorable.has(editor.resource))offerRetained(editor);}).catch(()=>{mask();state.showAccess('Protected editor storage is unavailable. Keep this page open.');});
 });
 function requirePreparedInput(event){
  if(!event.target?.matches?.('input,textarea,select,[contenteditable="true"]')||event.type==='keydown'&&event.key==='Tab')return;
  const editor=editorFor(event.target);if(!editor||prepared.has(editor.resource))return;
  event.preventDefault();void prepareEditor(editor.resource).then(()=>{event.target.focus();if(typeof showBanner==='function')showBanner('Protected editor ready. Continue entering your draft.');}).catch(()=>{mask();state.showAccess('Protected editor storage is unavailable. Keep this page open.');});
 }
 document.addEventListener('pointerdown',requirePreparedInput,true);document.addEventListener('keydown',requirePreparedInput,true);
 document.addEventListener('beforeinput',event=>{const editor=editorFor(event.target);if(editor&&!prepared.has(editor.resource))event.preventDefault();},true);
 document.addEventListener('input',event=>{
  const editor=editorFor(event.target);if(!editor||!state.session?.getContext())return;
  const fields={};for(const input of editor.card.querySelectorAll('input[id],textarea[id],select[id]')){
   if(input.type==='password')continue;fields[input.id]=input.type==='checkbox'?input.checked:input.value;
  }
  checkpoint=checkpoint.then(()=>prepareEditor(editor.resource)).then(()=>state.drafts.save(editor.resource,{format:2,fields,editingId:editor.editingId})).catch(()=>{mask();state.showAccess('The draft could not be protected. Keep this page open; private editors are locked.');});
 });
 globalThis.addEventListener('pagehide',()=>{mask();state.session?.scheduleRenewal({activeWork:false});state.session?.pagehide();});
 globalThis.addEventListener('pageshow',event=>{if(event.persisted&&state.session){mask();void state.session.pageshow().then(()=>state.start()).catch(()=>state.showAccess());}});
 document.addEventListener('visibilitychange',()=>{if(document.hidden){mask();state.session?.scheduleRenewal({activeWork:false});state.session?.pagehide();}else if(state.session){void state.session.pageshow().then(()=>state.start()).catch(()=>state.showAccess());}});
 for(const type of ['pointerdown','keydown','touchstart','scroll'])document.addEventListener(type,event=>{if(event.isTrusted&&state.session?.getContext()&&!document.hidden){state.session.recordActivity({kind:type==='keydown'?'keyboard':type==='pointerdown'?'pointer':type==='touchstart'?'touch':'scroll',manual:true});state.session.scheduleRenewal({activeWork:true,jitterMs:crypto.getRandomValues(new Uint32Array(1))[0]%5001});}},{passive:true});
})();
