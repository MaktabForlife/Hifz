import {academyOwnsProfiles} from '../../worker/src/profile-ownership.js';
import {canonical,requireThat,reject,safeInt,ascii,bytes,b64u,sha256,vectorDigest} from './codec.mjs';

const pick=(row,keys)=>Object.fromEntries(keys.filter(k=>Object.hasOwn(row,k)).map(k=>[k,row[k]]));
const validId=value=>requireThat(typeof value==='string'&&bytes(value).length>0&&bytes(value).length<=180&&!/[\u0000-\u0020\u007f]/.test(value),'INVALID_NATIVE_ID',400);
function references(input){
 requireThat(Array.isArray(input)&&input.length>0&&input.length<=256,'NATIVE_DEPENDENCIES_REQUIRED',503);
 const out=input.map(r=>{requireThat(r&&ascii(r.id)&&ascii(r.ownerEpoch)&&typeof r.scope==='string'&&bytes(r.scope).length>0&&bytes(r.scope).length<=512,'INVALID_NATIVE_DEPENDENCY',503);return {id:r.id,scope:r.scope,ownerEpoch:r.ownerEpoch};});
 out.sort((a,b)=>a.id===b.id?(a.scope<b.scope?-1:a.scope>b.scope?1:0):a.id<b.id?-1:1);
 requireThat(out.every((r,i)=>i===0||r.id!==out[i-1].id||r.scope!==out[i-1].scope),'DUPLICATE_NATIVE_DEPENDENCY',503);return out;
}
async function localVector(db,refs){
 const rows=(await db.prepare("SELECT json_extract(j.value,'$.id') id,json_extract(j.value,'$.scope') scope,d.owner_epoch,d.revision FROM json_each(?) j LEFT JOIN jwt_v2_dependencies d ON d.id=json_extract(j.value,'$.id') AND d.scope=json_extract(j.value,'$.scope') ORDER BY id,scope").bind(JSON.stringify(refs)).all()).results;
 requireThat(rows.length===refs.length&&rows.every(r=>ascii(r.owner_epoch)&&safeInt(r.revision,1)),'NATIVE_DEPENDENCY_UNAVAILABLE',503);
 requireThat(rows.every(r=>refs.some(ref=>ref.id===r.id&&ref.scope===r.scope&&ref.ownerEpoch===r.owner_epoch)),'NATIVE_OWNER_EPOCH_RECONCILIATION_REQUIRED',503);
 const ownerVector=[];for(const r of rows)ownerVector.push([r.id+':'+b64u(await sha256(bytes(r.scope))).slice(0,22),r.owner_epoch,r.revision]);
 return {rows,ownerVector,vectorGuards:rows.map(r=>[r.id,r.scope,r.owner_epoch,r.revision]),pv:await vectorDigest(ownerVector)};
}
const bounded=rights=>{requireThat(bytes(canonical(rights)).length<=2*1024*1024,'NATIVE_RIGHTS_TOO_LARGE',503);return rights;};
const rowsBound=rows=>{requireThat(rows.length<=6000,'NATIVE_SCOPE_TOO_LARGE',503);return rows;};

export class HifzNativeAdapter {
 constructor({env,dependencies,clock=()=>Math.floor(Date.now()/1000)}){
  requireThat(env?.DB?.withSession&&typeof clock==='function','NATIVE_HIFZ_BINDING_REQUIRED',503);
  this.env=env;this.db=env.DB.withSession('first-primary');this.dependencies=references(dependencies);this.clock=clock;
 }
 async identity(sub){
  validId(sub);requireThat(await academyOwnsProfiles({...this.env,DB:this.db}),'HIFZ_PROFILE_AUTHORITY_REQUIRED',503);
  const row=await this.db.prepare('SELECT l.academy_user_id,l.student_id,l.source_revision,l.source_credential_epoch,l.pin_reset_version,s.id,s.role,s.active,(SELECT count(*) FROM academy_profile_links duplicate WHERE duplicate.student_id=s.id) links FROM academy_profile_links l JOIN students s ON s.id=l.student_id WHERE l.academy_user_id=?').bind(sub).first();
  requireThat(row,'HIFZ_PROFILE_REQUIRED',401);
  requireThat(row.links===1&&row.id===row.student_id,'HIFZ_IDENTITY_MAPPING_CONFLICT',409);
  requireThat(row.active===1,'HIFZ_PROFILE_INACTIVE',401);
  requireThat(['student','teacher','admin'].includes(row.role)&&safeInt(row.source_revision,1)&&safeInt(row.source_credential_epoch,1)&&safeInt(row.pin_reset_version),'HIFZ_IDENTITY_METADATA_REQUIRED',503);
  return Object.freeze({sub:row.academy_user_id,nativeStudentId:row.student_id,role:row.role,sourceRevision:row.source_revision,sourceCredentialEpoch:row.source_credential_epoch,pinResetVersion:row.pin_reset_version});
 }
 identityGuard(identity){
  return {sql:'SELECT 1 FROM academy_profile_links l JOIN students s ON s.id=l.student_id WHERE l.academy_user_id=? AND l.student_id=? AND l.source_revision=? AND l.source_credential_epoch=? AND l.pin_reset_version=? AND s.active=1 AND s.role=? AND (SELECT count(*) FROM academy_profile_links duplicate WHERE duplicate.student_id=s.id)=1',
   args:[identity.sub,identity.nativeStudentId,identity.sourceRevision,identity.sourceCredentialEpoch,identity.pinResetVersion,identity.role]};
 }
 async capture({sub,sourceCredentialEpoch}){
  validId(sub);requireThat(safeInt(sourceCredentialEpoch,1),'SOURCE_CREDENTIAL_EPOCH_REQUIRED',503);
  const vat=this.clock();requireThat(safeInt(vat),'NATIVE_CLOCK_REQUIRED',503);
  for(let attempt=0;attempt<2;attempt++){
   const before=await localVector(this.db,this.dependencies),identity=await this.identity(sub);
   requireThat(identity.sourceCredentialEpoch===sourceCredentialEpoch,'CREDENTIAL_CHANGED',401);
   const after=await localVector(this.db,this.dependencies),current=await this.identity(identity.sub);
   if(canonical(before.rows)!==canonical(after.rows)||canonical(identity)!==canonical(current))continue;
   const checkedAt=this.clock();requireThat(safeInt(checkedAt)&&checkedAt>=vat&&checkedAt<vat+900,'NATIVE_VALIDATION_EXPIRED',503);
   return {app:'hifz',sub:identity.sub,nativeStudentId:identity.nativeStudentId,sourceCredentialEpoch,rights:bounded({nativeStudentId:identity.nativeStudentId,role:identity.role}),sourceProvenance:{revision:identity.sourceRevision,credentialEpoch:identity.sourceCredentialEpoch,pinResetVersion:identity.pinResetVersion,freshContact:false},ownerVector:after.ownerVector,vectorGuards:after.vectorGuards,pv:after.pv,vat,primaryCheckedAt:checkedAt,timedUntil:Number.MAX_SAFE_INTEGER};
  }
  reject('NATIVE_AUTHORITY_CHANGED_DURING_CAPTURE',503);
 }
}
export const hifzNativeAdapterBoundary=Object.freeze({
 identity:'Academy canonical ID is resolved through reviewed academy_profile_links to the permanent native students.id. Missing, duplicate or incomplete mappings deny; this adapter never claims or rekeys a journal.',
 data:'Journal/attendance/progress remain live native business data and are never included in authentication cache payloads.',
 credentials:'No child PIN verifier, native bearer sign-in, local epoch as Academy epoch, or real account operation is introduced.'
});
