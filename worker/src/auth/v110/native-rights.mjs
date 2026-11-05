// Independent V110 native-rights representation prototype. No live route imports it.
// Every authority field is explicit. Current publication/lifecycle/time/ownership
// and fresh Admin checks remain in their owning application, not in this codec.
import {base64url} from 'jose';
import {AuthContractError,createAccessEngine,createConfiguredAccessEngine} from './claims.mjs';
const fail=code=>{throw new AuthContractError(code);};
const plain=o=>Boolean(o&&Object.getPrototypeOf(o)===Object.prototype);
const exact=(o,keys)=>plain(o)&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
const uint=n=>Number.isSafeInteger(n)&&n>=0;
const bit=n=>n===0||n===1;
const stable=s=>typeof s==='string'&&/^[-A-Za-z0-9_:]{1,180}$/.test(s);
const short=s=>typeof s==='string'&&s.length<=180&&!/[\u0000-\u001f]/.test(s);
const month=s=>typeof s==='string'&&/^\d{4}-(0[1-9]|1[0-2])$/.test(s);
const role=s=>['PROGRAM_ADMIN','ADMIN','SENIOR','TEACHER','STUDENT'].includes(s);
const academyKeys=['v','app','globalAdmin','roles','subscriptions','substituteGrants','monthlyMedia','monthlyMediaEnabled','surahGrants','surahGrantsEnabled','myLinksAvailable','websiteAdmitted'];
const studioKeys=['v','app','globalAdmin','participation','staff','paidMonths','websiteMonths','surahGrants','retainedPlaylists'];
export const MAX_NATIVE_BYTES=2*1024*1024,MAX_PACKED_BYTES=65536;
function rows(value,check,key=x=>JSON.stringify(x)){
 if(!Array.isArray(value)||value.length>50000)return false;
 const seen=new Set();
 for(const row of value){if(!check(row))return false;const k=key(row);if(seen.has(k))return false;seen.add(k);}
 return true;
}
const tuple=(row,n)=>Array.isArray(row)&&row.length===n;
const ids=x=>rows(x,stable);
export function validateNativeRights(app,r){
 if(app==='academy'){
  return exact(r,academyKeys)&&r.v===1&&r.app===app&&typeof r.globalAdmin==='boolean'
   &&rows(r.roles,x=>tuple(x,2)&&stable(x[0])&&role(x[1]))
   &&ids(r.subscriptions)
   &&rows(r.substituteGrants,x=>tuple(x,2)&&stable(x[0])&&stable(x[1]),x=>x[0])
   &&rows(r.monthlyMedia,x=>tuple(x,4)&&stable(x[0])&&month(x[1])&&uint(x[2])&&ids(x[3]),x=>JSON.stringify(x.slice(0,2)))
   &&rows(r.surahGrants,x=>tuple(x,3)&&stable(x[0])&&stable(x[1])&&uint(x[2]),x=>JSON.stringify(x.slice(0,2)))
   &&['monthlyMediaEnabled','surahGrantsEnabled','myLinksAvailable','websiteAdmitted'].every(k=>typeof r[k]==='boolean');
 }
 if(app==='studio'){
  return exact(r,studioKeys)&&r.v===1&&r.app===app&&typeof r.globalAdmin==='boolean'
   &&rows(r.participation,x=>tuple(x,5)&&stable(x[0])&&bit(x[1])&&bit(x[2])&&bit(x[3])&&short(x[4]),x=>x[0])
   &&rows(r.staff,x=>tuple(x,3)&&stable(x[0])&&['ADMIN','TEACHER'].includes(x[1])&&bit(x[2]),x=>x[0])
   &&rows(r.paidMonths,x=>tuple(x,3)&&stable(x[0])&&month(x[1])&&short(x[2]))
   &&rows(r.websiteMonths,x=>tuple(x,2)&&stable(x[0])&&month(x[1]))
   &&ids(r.surahGrants)
   &&rows(r.retainedPlaylists,x=>tuple(x,4)&&stable(x[0])&&stable(x[1])&&month(x[2])&&['PAID','WEBSITE'].includes(x[3]),x=>JSON.stringify([x[0],x[2],x[3]]));
 }
 return false;
}
function sorted(value){return value.slice().sort((a,b)=>JSON.stringify(a)<JSON.stringify(b)?-1:JSON.stringify(a)>JSON.stringify(b)?1:0);}
function requiredArray(v){if(!Array.isArray(v))fail('INCOMPLETE_NATIVE_RIGHTS');return v;}
function nativeBit(v){if(typeof v==='boolean')return v;if(!bit(v))fail('INVALID_NATIVE_FLAG');return Boolean(v);}
function nativeRow(row,keys){if(!exact(row,keys))fail('INVALID_NATIVE_ROW');return row;}
export function projectStudioRights(input){
 const names=['global_admin','participation','staff','paid_months','website_months','surah_grants','mou_playlist_retained'];
 if(!exact(input,names))fail('INCOMPLETE_NATIVE_RIGHTS');
 const r={v:1,app:'studio',globalAdmin:nativeBit(input.global_admin),
  participation:requiredArray(input.participation).map(x=>{nativeRow(x,['offering_id','enrolled','live','purchased','cohort']);return [x.offering_id,x.enrolled,x.live,x.purchased,x.cohort];}),
  staff:requiredArray(input.staff).map(x=>{nativeRow(x,['offering_id','role','can_create_account']);return [x.offering_id,x.role,x.can_create_account];}),
  paidMonths:requiredArray(input.paid_months).map(x=>{nativeRow(x,['offering_id','month','cohort']);return [x.offering_id,x.month,x.cohort];}),
  websiteMonths:requiredArray(input.website_months).map(x=>{nativeRow(x,['offering_id','month']);return [x.offering_id,x.month];}),
  surahGrants:requiredArray(input.surah_grants).map(x=>{nativeRow(x,['website_id']);return x.website_id;}),
  retainedPlaylists:requiredArray(input.mou_playlist_retained).map(x=>{nativeRow(x,['playlist_id','offering_id','source_month','kind']);return [x.playlist_id,x.offering_id,x.source_month,x.kind];})
 };
 for(const key of studioKeys)if(Array.isArray(r[key]))r[key]=sorted(r[key]);
 if(!validateNativeRights('studio',r))fail('INVALID_NATIVE_RIGHTS');return r;
}
export function projectAcademyRights(state,{websiteAdmitted}={}){
 if(!plain(state)||!plain(state.account)||typeof websiteAdmitted!=='boolean')fail('INCOMPLETE_NATIVE_RIGHTS');
 let grants;try{grants=JSON.parse(state.account.substitute_grants??'[]');}catch{fail('INVALID_NATIVE_RIGHTS');}
 const r={v:1,app:'academy',globalAdmin:nativeBit(state.account.global_admin),
  roles:requiredArray(state.roles).map(x=>{nativeRow(x,['activity_key','role']);return [x.activity_key,x.role];}),
  subscriptions:requiredArray(state.subscriptions).map(x=>{nativeRow(x,['activity_key']);return x.activity_key;}),
  substituteGrants:requiredArray(grants).map(x=>{nativeRow(x,['id','activityKey']);return [x.id,x.activityKey];}),
  monthlyMedia:requiredArray(state.monthlyMedia).map(x=>{nativeRow(x,['activity_key','lesson_month','revision','class_ids_json']);let classes;try{classes=JSON.parse(x.class_ids_json);}catch{fail('INVALID_NATIVE_RIGHTS');}return [x.activity_key,x.lesson_month,x.revision,classes];}),
  monthlyMediaEnabled:state.monthlyMediaEnabled,
  surahGrants:requiredArray(state.surahGrants).map(x=>{nativeRow(x,['activity_key','surah_id','revision']);return [x.activity_key,x.surah_id,x.revision];}),
  surahGrantsEnabled:state.surahGrantsEnabled,myLinksAvailable:state.myLinksAvailable,websiteAdmitted
 };
 for(const key of academyKeys)if(Array.isArray(r[key]))r[key]=sorted(r[key]);
 if(!validateNativeRights('academy',r))fail('INVALID_NATIVE_RIGHTS');return r;
}
async function boundedBytes(stream,limit){
 const reader=stream.getReader(),chunks=[];let length=0;
 try{for(;;){const {value,done}=await reader.read();if(done)break;length+=value.byteLength;if(length>limit){await reader.cancel();fail('NATIVE_RIGHTS_TOO_LARGE');}chunks.push(value);}}
 finally{reader.releaseLock();}
 const out=new Uint8Array(length);let offset=0;for(const chunk of chunks){out.set(chunk,offset);offset+=chunk.byteLength;}return out;
}
export function validatePackedRights(app,r){
 if(!['academy','studio'].includes(app)||!exact(r,['v','app','codec','body'])||r.v!==2||r.app!==app||r.codec!=='native-zjson-1'||typeof r.body!=='string'||r.body.length<1||r.body.length>Math.ceil(MAX_PACKED_BYTES*4/3)||!/^[A-Za-z0-9_-]+$/.test(r.body))return false;
 try{const bytes=base64url.decode(r.body);return bytes.byteLength<=MAX_PACKED_BYTES&&base64url.encode(bytes)===r.body;}catch{return false;}
}
export async function packNativeRights(app,r){
 if(!validateNativeRights(app,r))fail('INVALID_NATIVE_RIGHTS');
 const input=new TextEncoder().encode(JSON.stringify(r));if(input.byteLength>MAX_NATIVE_BYTES)fail('NATIVE_RIGHTS_TOO_LARGE');
 const compressed=await boundedBytes(new Blob([input]).stream().pipeThrough(new CompressionStream('deflate')),MAX_PACKED_BYTES);
 return {v:2,app,codec:'native-zjson-1',body:base64url.encode(compressed)};
}
export async function unpackNativeRights(app,wire){
 if(!validatePackedRights(app,wire))fail('INVALID_PACKED_RIGHTS');
 try{
  const bytes=await boundedBytes(new Blob([base64url.decode(wire.body)]).stream().pipeThrough(new DecompressionStream('deflate')),MAX_NATIVE_BYTES);
  const r=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  if(!validateNativeRights(app,r))fail('INVALID_NATIVE_RIGHTS');return r;
 }catch(error){if(error instanceof AuthContractError)throw error;fail('INVALID_PACKED_RIGHTS');}
}
export async function createNativeAccessEngine(config){
 const app=config.app;if(!['academy','studio'].includes(app))fail('INVALID_CONFIG');
 const base=await createAccessEngine({...config,validateRights:r=>validatePackedRights(app,r)});
 return Object.freeze({
  async issue(input,rights,now){
   const packed=await packNativeRights(app,rights);
   return base.issue({...input,r:packed},now);
  },
  async verify(token,now){
   // Signature, exact app/purpose/key, size and lifetime are checked FIRST.
   const claims=await base.verify(token,now);
   return {claims,rights:await unpackNativeRights(app,claims.r)};
  }
 });
}

export async function createNativeCookieEngine(config){
 const app=config.app;if(!['academy','studio'].includes(app))fail('INVALID_CONFIG');
 const base=await createConfiguredAccessEngine({...config,validateRights:r=>validatePackedRights(app,r)});
 return Object.freeze({
  async issue(input,rights,now){return base.issue({...input,r:await packNativeRights(app,rights)},now);},
  async verify(token,now){const claims=await base.verify(token,now);return {claims,rights:await unpackNativeRights(app,claims.r)};},
  accessCookie:(token,expiresAt,now)=>base.accessCookie(token,expiresAt,now),
  refreshCookie:(token,expiresAt,now)=>base.refreshCookie(token,expiresAt,now)
 });
}
