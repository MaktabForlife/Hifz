// Hifz adapter over the common browser SDK. No cookies/tokens/keys are stored here.
const encoder=new TextEncoder();
const error=(code,message=code)=>Object.assign(new Error(message),{code});
const checkResponse=async response=>{
 if(!(response instanceof Response))throw error('NATIVE_RESPONSE_UNAVAILABLE');
 let value;try{value=await response.json();}catch{throw error('NATIVE_RESPONSE_UNAVAILABLE');}
 if(!response.ok)throw Object.assign(error(value?.code||'NATIVE_REQUEST_FAILED',value?.error||'The request is unavailable.'),{status:response.status});
 if(value===null||value===undefined)throw error('NATIVE_RESPONSE_UNAVAILABLE');return value;
};
export function createHifzClient({session,drafts,onUnknown=()=>{},onRecoveryUnavailable=()=>{}}){
 if(!session?.protectedFetch||!session?.getContext||!drafts?.checkpointMutation||!drafts?.reconcileUnknown)throw new TypeError('Common browser session and encrypted drafts required');
 const fields=['app','sub','sid','psid','bsid','bv','ce','ae','le','sv','ue'],stable=fields.filter(k=>!['sv','ue'].includes(k)),same=(a,b,keys=fields)=>keys.every(k=>a?.[k]===b?.[k]);
 const corrections=new Map();let readFault=0;
 const route=input=>{const u=new URL(input,'https://mahadarwa-hifz.ummabbadacademy.app');if(!input.startsWith('/')||input.startsWith('//')||u.origin!=='https://mahadarwa-hifz.ummabbadacademy.app'||u.pathname.startsWith('/api/'))throw error('INVALID_NATIVE_PATH');return u;};
 const viewVersion=()=>session.getState?.().viewVersion??null;
 const current=(expected,view=null)=>{const state=session.getState?.();if(!session.checkCurrentContext(expected)||view!==null&&view!==viewVersion()||state&&(state.state!=='UNLOCKED'||state.suspended||state.validationRequired))throw error('STALE_NATIVE_CONTEXT');};
 const shape=(path,options={})=>{
  const u=route(path),method=String(options.method||'GET').toUpperCase();let payload=null;
  if(options.body!==undefined){try{payload=JSON.parse(options.body);}catch{throw error('INVALID_NATIVE_PAYLOAD');}}
  const selected=payload?.student_id||u.searchParams.get('student_id'),explicitTarget=Boolean(selected),target=selected||'own';
  if(typeof target!=='string'||encoder.encode(target).length>180)throw error('INVALID_NATIVE_TARGET');
  const base='hifz:'+u.pathname+':'+(explicitTarget?'id.'+encodeURIComponent(target):'own'),entry=payload?.id??u.searchParams.get('id');
  const resource=entry!==null&&entry!==undefined?base+':entry:'+String(entry):base;
  if(encoder.encode(resource).length>512)throw error('INVALID_NATIVE_RESOURCE');
  return {u,method,payload,target,explicitTarget,base,entry,resource};
 };
 async function request(path,options={}){
  const s=shape(path,options),mutation=!['GET','HEAD'].includes(s.method);
  const headers=new Headers(options.headers);headers.delete('Authorization');if(options.body!==undefined)headers.set('Content-Type','application/json');options={...options,headers};
  await session.ensureFresh();const context=session.getContext(),view=viewVersion();if(!context)throw error('NATIVE_SESSION_REQUIRED');
  if(!mutation){try{const response=await session.protectedFetch('/api'+s.u.pathname+s.u.search,{...options,cache:'no-store'}),actual=session.responseProvenance?.(response),renewed=actual?.renewedFrom&&actual.renewedFrom.viewVersion===view&&same(actual.renewedFrom.context,context)&&same(actual.context,context,stable)&&actual.context.sv>context.sv&&actual.context.ue===context.ue,proof=renewed?{context:actual.context,view:actual.viewVersion}:{context,view};current(proof.context,proof.view);const value=await checkResponse(response);current(proof.context,proof.view);return value;}catch(cause){readFault++;throw cause;}}
  if(!['POST','PUT','PATCH','DELETE'].includes(s.method))throw error('INVALID_NATIVE_METHOD');
  const old=await drafts.recoveryMarker(s.base);
  if(old){
   const approved=corrections.get(s.resource);
   if(s.method!=='PATCH'||s.entry===null||s.entry===undefined||!approved){onUnknown({resource:s.base});throw error('SAVE_OUTCOME_UNKNOWN','This save has an unknown outcome. Review the current records before making a manual correction.');}
   current(approved.context,approved.viewVersion);corrections.delete(s.resource);
  }
  let attempt;
  try{attempt=await drafts.checkpointMutation({resource:s.resource,method:s.method,payload:{path:s.u.pathname+s.u.search,method:s.method,payload:s.payload},context});}
  catch(e){if(e.code==='SAVE_OUTCOME_UNKNOWN')onUnknown({resource:s.resource});throw e;}
  try{
   const value=await checkResponse(await session.protectedFetch('/api'+s.u.pathname+s.u.search,options));
   current(context,view);await drafts.finishMutation(attempt,session.getContext());return value;
  }catch(cause){
   try{await drafts.markUnknown(attempt);}catch{/* Durable in-flight marker remains unknown after a lock. */}
   onUnknown({resource:s.resource});const e=error('SAVE_OUTCOME_UNKNOWN','The save outcome is unknown. Do not retry it. Review fresh journal, plan, comment and attendance records.');e.resource=s.resource;throw e;
  }
 }
 async function recover(resource){
  await session.ensureFresh();const context=session.getContext(),view=viewVersion();if(!context)throw error('NATIVE_SESSION_REQUIRED');
  try{return await drafts.reconcileUnknown(resource,async()=>{
   current(context,view);const saved=await drafts.load(resource);const original=saved?.payload;
   if(!original||typeof original.path!=='string')throw error('RECOVERY_READ_UNAVAILABLE');
   const s=shape(original.path,{method:original.method,body:JSON.stringify(original.payload)}),query=new URLSearchParams();
   if(s.explicitTarget)query.set('student_id',s.target);
   const suffix=query.size?'?'+query:'';
   const paths=['/sabaq','/sabaq-dhor','/dhor','/reflections'];
   const values=await Promise.all([...paths,'/plans','/attendance'].map(path=>request(path+suffix,{cache:'no-store'})));
   if(values.some(v=>!Array.isArray(v)))throw error('RECOVERY_READ_UNAVAILABLE');
   current(context);
   return {available:true,context:{...context},viewVersion:view,target:s.target,explicitTarget:s.explicitTarget,journals:Object.fromEntries(paths.map((path,i)=>[path,values[i]])),plans:values[4],attendance:values[5],comments:Object.fromEntries(paths.map((path,i)=>[path,values[i].map(row=>({id:row.id,student_comment:row.student_comment,student_comment_private:row.student_comment_private,teacher_feedback:row.teacher_feedback,teacher_feedback_visibility:row.teacher_feedback_visibility}))])),automaticReplayAllowed:false};
  });}catch(e){onRecoveryUnavailable({resource,code:e.code||'RECOVERY_READ_UNAVAILABLE'});throw e;}
 }
 function allowExistingCorrection(resource,recovery,path,row){
  const s=shape(path),expected=recovery?.views?.context;current(expected);
  const rows=recovery?.views?.journals?.[s.u.pathname];
  if(!recovery?.manualRecoveryRequired||!Array.isArray(rows)||!row?.id||row.source==='maktab'||!rows.some(r=>r.id===row.id&&r.student_id===row.student_id))throw error('MANUAL_CORRECTION_REQUIRED');
  // Separate selected-row PATCH only; original POST and its marker stay unknown.
  const base='hifz:'+s.u.pathname+':'+(recovery.views.explicitTarget?'id.'+encodeURIComponent(recovery.views.target):'own');
  corrections.set(base+':entry:'+String(row.id),{context:{...expected},viewVersion:recovery.views.viewVersion??null,unknownResource:resource});
 }
 return Object.freeze({request,recover,allowExistingCorrection,beginView(){const context=session.getContext(),view=viewVersion();current(context,view);return {context:{...context},viewVersion:view,readFault};},assertView(ticket){current(ticket?.context,ticket?.viewVersion??null);if(!ticket||ticket.readFault!==readFault)throw error('NATIVE_VIEW_READ_FAILED');return true;},clear(){corrections.clear();},shape});
}
