export const sharedEntryClientSource=String.raw`
const storageKey='uaa-child-entry-return-v2';
const academy='https://ummabbadacademy.app';
const encoder=new TextEncoder();
const encode=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
const proof=()=>encode(crypto.getRandomValues(new Uint8Array(32)));
const sha256=value=>crypto.subtle.digest('SHA-256',encoder.encode(value));

async function post(path,body,csrf){
 const headers={'Content-Type':'application/json','X-UAA-Request':'2'};
 if(csrf)headers['X-UAA-CSRF']=csrf;
 if(body.expectedContext)headers['X-UAA-Expected-Context']=encode(encoder.encode(JSON.stringify(body.expectedContext)));
 const response=await fetch(path,{method:'POST',credentials:'same-origin',mode:'same-origin',redirect:'error',
  cache:'no-store',referrerPolicy:'same-origin',headers,body:JSON.stringify(body)});
 const dto=await response.json();
 if(dto.contractVersion===2&&(response.ok&&dto.success===true||response.status===423&&dto.state==='ADMITTED_LOCKED'&&dto.returnTo))return dto;
 throw Object.assign(Error(dto.code||'CHILD_AUTHORITY_PENDING'),{status:response.status});
}

function navigateLocal(destination){
 const target=new URL(destination,location.origin);
 if(target.origin!==location.origin||!destination.startsWith('/'))throw Error('UNREGISTERED_RETURN');
 location.replace(target.href);
}

async function finish(body,csrf,confirm=false){
 let unavailable;
 try{
  const result=await post('/auth/v2/shared-entry',{...body,...(confirm?{confirmAcademyAccount:true}:{})},csrf);
  if(result.outcome!=='SUPERSEDED')return result;
  unavailable=Error('CHILD_AUTHORITY_PENDING');
 }catch(error){
  if(error.status&&error.status<500)throw error;
  unavailable=error;
 }
 const result=await post('/auth/v2/shared-entry/status',body,csrf);
 if(result.outcome==='INSTALLED_CURRENT')return result;
 if(result.outcome==='UNCONFIRMED'&&!body.expectedContext)throw Error('CHILD_ENTRY_INSTALLATION_UNCONFIRMED');
 throw unavailable;
}

async function requestReturn(body,csrf,area,mode){
 const state=proof();
 const stateHash=Array.from(new Uint8Array(await sha256(state)),byte=>byte.toString(16).padStart(2,'0')).join('');
 const registered=await post('/auth/v2/shared-entry/continue',{...body,stateHash,...(mode==='continue'?{}:{mode})},csrf);
 if(registered.tx!==body.tx||registered.operationId!==body.operationId)throw Error('STATE_CONFLICT');
 sessionStorage.setItem(storageKey,JSON.stringify({body,csrf,area,state,mode}));
 const target=new URL('/auth/v2/shared-return',academy);
 target.searchParams.set('tx',body.tx);
 target.hash=state;
 location.assign(target.href);
}

export function chooseAcademyAccount(status){
 return new Promise(resolve=>{
  status.textContent='Choose an account to open this programme.';
  const choices=document.createElement('div');
  const buttons=[
   ['continue','Continue with your Academy account'],
   ['select','Use another account'],
   ['cancel','Cancel']
  ];
  for(const [choice,label] of buttons){
   const button=document.createElement('button');
   button.type='button';
   button.textContent=label;
   button.addEventListener('click',()=>{choices.remove();resolve(choice);},{once:true});
   choices.append(button);
  }
  status.after(choices);
  choices.querySelector('button').focus();
 });
}

async function openEntry(body,csrf,area,status,returning=false){
 try{
  const result=await finish(body,csrf);
  if(!['UNLOCKED','ADMITTED_LOCKED'].includes(result.state)||!result.returnTo)throw Error('CHILD_AUTHORITY_PENDING');
  navigateLocal(result.returnTo);
 }catch(error){
  if(error.message==='ACCOUNT_SELECTION_REQUIRED'){
   const choice=await chooseAcademyAccount(status);
   if(choice==='continue'){
    const result=await finish(body,csrf,true);
    if(!['UNLOCKED','ADMITTED_LOCKED'].includes(result.state)||!result.returnTo)throw Error('CHILD_AUTHORITY_PENDING');
    navigateLocal(result.returnTo);
   }else if(choice==='select'){
    if(returning){navigateLocal('/auth/v2/shared-entry?area='+encodeURIComponent(area));return;}
    await requestReturn(body,csrf,area,'select');
   }else status.textContent='The programme is closed. You can return to Academy.';
   return;
  }
  if(!returning&&['ACADEMY_SIGN_IN_REQUIRED','SHARED_ENTRY_RECOVERY_REQUIRED'].includes(error.message)){
   await requestReturn(body,csrf,area,error.message==='SHARED_ENTRY_RECOVERY_REQUIRED'?'renew':'continue');
   return;
  }
  throw error;
 }
}

function showError(status,error){
 const messages={
  ACCESS_DENIED:'Your account does not have access to this programme.',
  PIN_REQUIRED:'This programme is locked. Use the app’s Academy PIN unlock.',
  ACCOUNT_SELECTION_REQUIRED:'The Academy account changed. Open the programme again to make a new choice.',
  SHARED_CHILD_REFRESH_MISSING:'This browser still has a session. Open the programme again after that session expires.',
  ACADEMY_SIGN_IN_REQUIRED:'Academy could not confirm your sign-in. Try again from the dashboard.'
 };
 status.textContent=messages[error.message]||'The programme could not be opened. Try again from Academy.';
 const link=document.getElementById('academy-link');
 if(link)link.hidden=false;
}

export async function resumeChildEntry(status){
 try{
  const params=new URLSearchParams(location.hash.slice(1));
  if([...params].length!==3||!['tx','state','expired'].every(key=>params.getAll(key).length===1))throw Error('STATE_CONFLICT');
  const saved=JSON.parse(sessionStorage.getItem(storageKey)||'null');
  if(!saved)return false;
  if(saved.body.tx!==params.get('tx')||saved.state!==params.get('state'))throw Error('STATE_CONFLICT');
  sessionStorage.removeItem(storageKey);
  if(params.get('expired')==='1'||saved.mode==='select'){
   navigateLocal('/auth/v2/shared-entry?area='+encodeURIComponent(saved.area));
   return true;
  }
  try{await openEntry({...saved.body,returnState:saved.state},saved.csrf,saved.area,status,true);}
  catch(error){
   if(error.message!=='CHILD_ENTRY_INSTALLATION_UNCONFIRMED')throw error;
   navigateLocal('/auth/v2/shared-entry?area='+encodeURIComponent(saved.area));
  }
 }catch(error){showError(status,error);}
 return true;
}

const entry=document.querySelector('main[data-shared-entry-area]');
if(entry){
 const area=entry.dataset.sharedEntryArea,status=document.getElementById('entry-status');
 try{
  async function open(initial){
   const expectedContext=initial.context??null,verifier=proof(),challenge=encode(await sha256(verifier));
   const start=await post('/auth/v2/shared-entry/start',{destination:area,challenge,expectedContext});
   const body={tx:start.tx,operationId:start.operationId,expectedContext,verifier};
   await openEntry(body,start.csrf,area,status);
  }
  const initial=await post('/auth/v2/bootstrap',{purpose:'refresh',expectedContext:null});
  try{await open(initial);}
  catch(error){
   const canRefresh=['ACCESS_REFRESH_REQUIRED','LEASE_EXPIRED','INVALID_VALIDATION_TIME','PERMISSIONS_REFRESH_REQUIRED'].includes(error.message);
   if(error.message==='CHILD_ENTRY_INSTALLATION_UNCONFIRMED'){
    await open(await post('/auth/v2/bootstrap',{purpose:'refresh',expectedContext:null}));
   }else{
    if(!canRefresh||!initial.context||!initial.intent?.id)throw error;
    const current=await post('/auth/v2/refresh',{
     operationId:initial.intent.id,expectedContext:initial.context,qualifyingActivity:false
    },initial.csrf);
    await open(current);
   }
  }
 }catch(error){showError(status,error);}
}
`;
