import {canonical,requireThat,ascii,safeInt,bytes,b64u,sha256,vectorDigest,digest} from './codec.mjs';
export async function vectorFromGuards(guards){
 requireThat(Array.isArray(guards)&&guards.length>0&&guards.length<=256,'AUTHORITATIVE_VECTOR_REQUIRED',503);
 const vector=[];
 for(const row of guards){
  requireThat(Array.isArray(row)&&row.length===4&&ascii(row[0])&&typeof row[1]==='string'&&bytes(row[1]).length>0&&bytes(row[1]).length<=512&&ascii(row[2])&&safeInt(row[3],1),'INVALID_VECTOR_GUARD',503);
  vector.push([row[0]+':'+b64u(await sha256(bytes(row[1]))).slice(0,22),row[2],row[3]]);
 }
 vector.sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
 requireThat(vector.every((v,i)=>i===0||v[0]!==vector[i-1][0]),'DUPLICATE_VECTOR_GUARD',503);return vector;
}
export async function assertCaptureReceipt({capture,binding,projection,guards,manifest,app,env,now}){
 requireThat(capture&&capture.app===app&&capture.sub===binding.sub&&capture.pv===binding.pv&&capture.vat===binding.vat&&safeInt(capture.primaryCheckedAt)&&capture.primaryCheckedAt>=capture.vat&&capture.primaryCheckedAt<=now,'FRESH_NATIVE_CAPTURE_REQUIRED',503);
 requireThat(Array.isArray(manifest)&&manifest.length>0,'DEPENDENCY_MANIFEST_REQUIRED',503);
 const configured=manifest.map(r=>[r.id,r.scope,r.ownerEpoch]).sort((a,b)=>canonical(a)<canonical(b)?-1:1);
 const supplied=guards.map(r=>[r[0],r[1],r[2]]).sort((a,b)=>canonical(a)<canonical(b)?-1:1);
 requireThat(canonical(configured)===canonical(supplied),'NATIVE_DEPENDENCY_COVERAGE_MISMATCH',503);
 requireThat(safeInt(capture.timedUntil)&&safeInt(projection.timedUntil)&&projection.timedUntil<=capture.timedUntil&&projection.timedUntil>now,'CAPTURE_TIMED_BOUND_REQUIRED',409);
 const expected=await vectorFromGuards(guards),pv=await vectorDigest(expected);
 requireThat(canonical(capture.vectorGuards)===canonical(guards)&&canonical(capture.ownerVector)===canonical(expected)&&canonical(projection.ownerVector)===canonical(expected)&&pv===binding.pv,'CAPTURE_VECTOR_BINDING_MISMATCH',409);
 requireThat(canonical(projection.binding)===canonical(binding)&&projection.rightsHash===await digest(capture.rights),'CAPTURE_RIGHTS_BINDING_MISMATCH',409);
 requireThat(binding.env===env,'WRONG_CAPTURE_ENVIRONMENT',409);
 return capture;
}
export function manifestForSubject(registry,sub,ownerEpoch){
 requireThat(registry?.schema===2&&typeof sub==='string'&&ascii(ownerEpoch),'INVALID_DEPENDENCY_MANIFEST',503);
 return Object.entries(registry.rules).map(([table,rule])=>({id:registry.app+':native:'+table,scope:rule.accountColumn?'ACCOUNT:'+sub.replace(/[a-z]/g,c=>c.toUpperCase()):'GLOBAL',ownerEpoch}));
}
