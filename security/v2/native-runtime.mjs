import {HifzNativeAdapter} from './native-adapter.mjs';
import {createHifzProfileIntake} from './native-profile-intake.mjs';
import {PROFILE_ID,authenticatedProfileProjection} from './profile-service.mjs';
import {requireThat,safeInt} from './codec.mjs';

// Only the owning app's reviewed mapping resolves canonical accounts to journals.
// No browser registration, PIN verification, account provisioning or journal rekey.
export async function createNativeRuntime({env,store,clock,dependenciesFor,ensureDependencies}) {
 requireThat(env?.DB?.withSession&&store&&typeof clock==='function'&&typeof dependenciesFor==='function'&&typeof ensureDependencies==='function','HIFZ_NATIVE_RUNTIME_REQUIRED',503);
 const adapter=sub=>new HifzNativeAdapter({env,clock,dependencies:dependenciesFor(sub)});
 const mapped=async binding=>{
  requireThat(binding&&safeInt(binding.ce,1),'HIFZ_CREDENTIAL_EPOCH_REQUIRED',401);
  const a=adapter(binding.sub),identity=await a.identity(binding.sub);
  requireThat(identity.sourceCredentialEpoch===binding.ce,'CREDENTIAL_CHANGED',401);
  return {a,identity};
 };
 return Object.freeze({
  async applyProfileProjection(packet){return createHifzProfileIntake({store,dependenciesFor,dependencyRegistry:store.dependencyRegistry,profileDependencyId:PROFILE_ID,verifySourceProjection:authenticatedProfileProjection,ensureDependencies}).apply(packet);},
  async applySecurityFactPlan({target,scopeSub}){
   if(target.type!=='credentialEpoch')return [];
   requireThat(target.sub===scopeSub&&safeInt(target.newCe,1),'HIFZ_CREDENTIAL_FACT_CONFLICT',409);
   return [store.stmt('UPDATE students SET credential_epoch=credential_epoch+1 WHERE id IN(SELECT student_id FROM academy_profile_links WHERE academy_user_id=? COLLATE BINARY AND source_credential_epoch<?)',scopeSub,target.newCe),store.stmt('UPDATE academy_profile_links SET source_credential_epoch=? WHERE academy_user_id=? COLLATE BINARY AND source_credential_epoch<?',target.newCe,scopeSub,target.newCe)];
  },
  async identity(sub) {
   const identity=await adapter(sub).identity(sub);
   return {sub:identity.sub,ce:identity.sourceCredentialEpoch,nativeStudentId:identity.nativeStudentId,role:identity.role,sourceRevision:identity.sourceRevision,pinResetVersion:identity.pinResetVersion};
  },
  async mappingGuard(binding,rights) {
   const {a,identity}=await mapped(binding);
   if(rights)requireThat(identity.nativeStudentId===rights.nativeStudentId&&identity.role===rights.role,'HIFZ_NATIVE_AUTHORITY_CHANGED',409);
   return a.identityGuard(identity);
  },
  async draftGuard({binding,rights,resource}) {
   const {a,identity}=await mapped(binding);
   requireThat(rights?.nativeStudentId===identity.nativeStudentId&&rights?.role===identity.role,'HIFZ_NATIVE_AUTHORITY_CHANGED',409);
   requireThat(typeof resource==='string'&&new TextEncoder().encode(resource).length<=512,'HIFZ_DRAFT_RESOURCE_DENIED',403);
   const match=resource.match(/^hifz:(\/[a-z0-9/-]+):([^:]+)(?::entry:([1-9][0-9]*))?$/);
   requireThat(match,'HIFZ_DRAFT_RESOURCE_DENIED',403);
   const path=match[1];let target;
   try{target=match[2]==='own'?identity.nativeStudentId:match[2].startsWith('id.')?decodeURIComponent(match[2].slice(3)):null;}catch{requireThat(false,'HIFZ_DRAFT_RESOURCE_DENIED',403);}
   requireThat(typeof target==='string'&&(match[2]==='own'||'id.'+encodeURIComponent(target)===match[2]),'HIFZ_DRAFT_RESOURCE_DENIED',403);
   const own=new Set(['/sabaq','/sabaq-dhor','/dhor','/reflections','/attendance','/attendance/mark-range','/attendance/predict','/position','/profile']);
   const teacher=new Set(['/maktab/sabaq','/maktab/sabaq-dhor','/maktab/dhor','/maktab/position','/maktab/terms','/maktab/calendar','/maktab/calendar/confirm','/attendance/haidh-settings']);
   const admin=new Set(['/maktab/settings','/tajweed-tags','/tajweed-tags/update','/maktab-groups','/maktab-groups/update']);
   const role=identity.role,isTeacher=role==='teacher'||role==='admin';
   const editor=/^\/editor\/(?:sabaq|sabaq-dhor|dhor|reflections)$/.test(path);
   requireThat((editor&&(target===identity.nativeStudentId||isTeacher))||(own.has(path)&&(target===identity.nativeStudentId||isTeacher))||(teacher.has(path)&&isTeacher)||(admin.has(path)&&role==='admin')||(/^\/maktab\/(?:terms|calendar)\/[1-9][0-9]*$/.test(path)&&isTeacher),'HIFZ_DRAFT_RESOURCE_DENIED',403);
   requireThat(!editor||!match[3],'HIFZ_DRAFT_RESOURCE_DENIED',403);
   const mapping=a.identityGuard(identity),parts=['EXISTS('+mapping.sql+')','EXISTS(SELECT 1 FROM students target WHERE target.id=? AND target.active=1)'],args=[...mapping.args,target];
   if(match[3]){
    const tables={'/sabaq':'sabaq_log','/sabaq-dhor':'sabaq_dhor_log','/dhor':'dhor_log','/reflections':'reflections','/maktab/sabaq':'maktab_sabaq_log','/maktab/sabaq-dhor':'maktab_sabaq_dhor_log','/maktab/dhor':'maktab_dhor_log'};
    requireThat(tables[path],'HIFZ_DRAFT_RESOURCE_DENIED',403);
    parts.push('EXISTS(SELECT 1 FROM '+tables[path]+' entry WHERE entry.id=? AND entry.student_id=?)');args.push(match[3],target);
   }
   return {sql:'SELECT 1 WHERE '+parts.join(' AND '),args};
  },
  async capture({binding}) {
   requireThat(binding&&safeInt(binding.ce,1),'HIFZ_CREDENTIAL_EPOCH_REQUIRED',401);
   return adapter(binding.sub).capture({sub:binding.sub,sourceCredentialEpoch:binding.ce});
  }
 });
}
