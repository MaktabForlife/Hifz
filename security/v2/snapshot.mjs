import {bytes,strictJSON,canonical,exact,requireThat,reject,safeInt,ascii,uuid,domainDigest,digest,hmac,b64u,unb64u,equal,hex} from './codec.mjs';
import {BUCKETS,validateEvent} from './events.mjs';
const META='schema env requestId ownerApp recipientApp stream ownerEpoch coveredThrough predecessorEpoch predecessorCoveredThrough snapshotId createdAt expiresAt totalRecords bucketCounts pageCount'.split(' ');
const BASE=META.filter(k=>!['totalRecords','bucketCounts','pageCount'].includes(k));
const PAGE=[...META,...'mode snapshotDigest pageIndex recordOffset entries previousPageDigest pageDigest nextPageToken'.split(' ')];
const REQUEST='schema env sourceApp targetApp requestId ownerApp recipientApp stream ownerEpoch contiguousThrough missingRanges knownFloorsDigest pageToken'.split(' ');
const TYPES={accountCutoffs:'accountCutoff',credentialFloors:'credentialEpoch',parentCutoffs:'parent',browserCutoffs:'browser',keyWithdrawals:'key',policies:'policy',dependencyFloors:'dependency'};
const FIELDS={accountCutoff:'type sub maxCe maxAe reason incidentId',credentialEpoch:'type sub newCe reason',parent:'type sub psid bsid bv ce ae',browser:'type bsid maxBv',key:'type purpose kid registryRevision',policy:'type policyId ownerEpoch revision inactivityMinutes',dependency:'type id ownerEpoch revision effect deniedActions'};
const HEX=/^[0-9a-f]{64}$/;
const q=()=>crypto.randomUUID();
export function snapshotContract(config){const version=config?.snapshotSchema??2;requireThat(version===2||version===3,'UNSUPPORTED_SNAPSHOT_SCHEMA',409);return version;}
export const snapshotDomain=(metadata,kind)=>'uaa-'+kind+'-v'+(metadata.schema??2);
export function snapshotEffect(record){if(record.type==='dependency'&&Object.hasOwn(record,'sub')){const {sub,...target}=record;return {target,scopeSub:sub};}return {target:record,scopeSub:record.sub??null};}
const pick=(x,keys)=>Object.fromEntries(keys.map(k=>[k,x[k]]));
const subject=s=>typeof s==='string'&&bytes(s).length>0&&bytes(s).length<=180&&!/[\u0000-\u0020\u007f]/.test(s);
export const snapshotSchemaSQL=[
 "CREATE TABLE IF NOT EXISTS jwt_v2_receive_requests(request_id TEXT PRIMARY KEY,request_binding TEXT NOT NULL,request_json TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN('PENDING','COMPLETE','CANCELLED')));",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_receive_request_immutable BEFORE UPDATE ON jwt_v2_receive_requests WHEN OLD.request_id<>NEW.request_id OR OLD.request_binding<>NEW.request_binding OR OLD.request_json<>NEW.request_json OR (OLD.status IN('COMPLETE','CANCELLED') AND NEW.status<>OLD.status) BEGIN SELECT RAISE(ABORT,'reconcile_request_immutable'); END;",
 'CREATE TABLE IF NOT EXISTS jwt_v2_reconcile_guards(id TEXT PRIMARY KEY,accepted INTEGER NOT NULL CHECK(accepted=1));',
 "CREATE TABLE IF NOT EXISTS jwt_v2_reconcile_captures(snapshot_id TEXT PRIMARY KEY,request_id TEXT NOT NULL UNIQUE,request_binding TEXT NOT NULL,base_json TEXT NOT NULL,cursor_key_id TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN('CAPTURING','CAPTURED','BUILDING','READY')),metadata_json TEXT,snapshot_digest TEXT);",
 'CREATE TABLE IF NOT EXISTS jwt_v2_reconcile_records(ordinal INTEGER PRIMARY KEY AUTOINCREMENT,snapshot_id TEXT NOT NULL,bucket TEXT NOT NULL,raw_json TEXT NOT NULL,canonical_json TEXT,semantic_key TEXT,UNIQUE(snapshot_id,bucket,canonical_json),UNIQUE(snapshot_id,bucket,semantic_key));',
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_capture_record_insert BEFORE INSERT ON jwt_v2_reconcile_records WHEN NOT EXISTS(SELECT 1 FROM jwt_v2_reconcile_captures WHERE snapshot_id=NEW.snapshot_id AND status='CAPTURING') BEGIN SELECT RAISE(ABORT,'snapshot_capture_immutable'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_capture_record_update BEFORE UPDATE ON jwt_v2_reconcile_records WHEN OLD.snapshot_id<>NEW.snapshot_id OR OLD.bucket<>NEW.bucket OR OLD.raw_json<>NEW.raw_json OR (OLD.canonical_json IS NOT NULL AND (OLD.canonical_json IS NOT NEW.canonical_json OR OLD.semantic_key IS NOT NEW.semantic_key)) BEGIN SELECT RAISE(ABORT,'snapshot_record_immutable'); END;",
 'CREATE TABLE IF NOT EXISTS jwt_v2_reconcile_parts(snapshot_id TEXT NOT NULL,page_index INTEGER NOT NULL,record_offset INTEGER NOT NULL,entries_json TEXT NOT NULL,PRIMARY KEY(snapshot_id,page_index));',
 'CREATE TABLE IF NOT EXISTS jwt_v2_reconcile_pages(snapshot_id TEXT NOT NULL,page_index INTEGER NOT NULL,request_token TEXT,page_json TEXT NOT NULL,PRIMARY KEY(snapshot_id,page_index),UNIQUE(snapshot_id,request_token));',
 "CREATE TABLE IF NOT EXISTS jwt_v2_receive_snapshots(snapshot_id TEXT PRIMARY KEY,request_id TEXT NOT NULL UNIQUE,metadata_json TEXT NOT NULL,snapshot_digest TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN('STAGED','VERIFIED','APPLIED')));",
 'CREATE TABLE IF NOT EXISTS jwt_v2_receive_pages(snapshot_id TEXT NOT NULL,page_index INTEGER NOT NULL,page_json TEXT NOT NULL,PRIMARY KEY(snapshot_id,page_index));',
 'CREATE TABLE IF NOT EXISTS jwt_v2_receive_records(snapshot_id TEXT NOT NULL,record_offset INTEGER NOT NULL,bucket TEXT NOT NULL,record_json TEXT NOT NULL,record_digest TEXT NOT NULL,semantic_key TEXT NOT NULL,PRIMARY KEY(snapshot_id,record_offset),UNIQUE(snapshot_id,bucket,record_json),UNIQUE(snapshot_id,bucket,semantic_key));',
 'CREATE TABLE IF NOT EXISTS jwt_v2_snapshot_effects(snapshot_id TEXT NOT NULL,record_offset INTEGER NOT NULL,record_digest TEXT NOT NULL,work_id TEXT NOT NULL,PRIMARY KEY(snapshot_id,record_offset));',
 'CREATE TABLE IF NOT EXISTS jwt_v2_replay_captures(request_id TEXT PRIMARY KEY,request_binding TEXT NOT NULL,reply_json TEXT NOT NULL);',

 "CREATE TRIGGER IF NOT EXISTS jwt_v2_capture_header_immutable BEFORE UPDATE ON jwt_v2_reconcile_captures WHEN OLD.snapshot_id<>NEW.snapshot_id OR OLD.request_id<>NEW.request_id OR OLD.request_binding<>NEW.request_binding OR OLD.base_json<>NEW.base_json OR OLD.cursor_key_id<>NEW.cursor_key_id OR (OLD.metadata_json IS NOT NULL AND OLD.metadata_json IS NOT NEW.metadata_json) OR (OLD.snapshot_digest IS NOT NULL AND OLD.snapshot_digest IS NOT NEW.snapshot_digest) OR (OLD.status='READY' AND NEW.status<>'READY') BEGIN SELECT RAISE(ABORT,'snapshot_header_immutable'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_receive_header_immutable BEFORE UPDATE ON jwt_v2_receive_snapshots WHEN OLD.snapshot_id<>NEW.snapshot_id OR OLD.request_id<>NEW.request_id OR OLD.metadata_json<>NEW.metadata_json OR OLD.snapshot_digest<>NEW.snapshot_digest OR (OLD.status='APPLIED' AND NEW.status<>'APPLIED') OR (OLD.status='VERIFIED' AND NEW.status='STAGED') BEGIN SELECT RAISE(ABORT,'snapshot_header_immutable'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_source_page_immutable BEFORE UPDATE ON jwt_v2_reconcile_pages BEGIN SELECT RAISE(ABORT,'snapshot_page_immutable'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_receive_page_immutable BEFORE UPDATE ON jwt_v2_receive_pages BEGIN SELECT RAISE(ABORT,'snapshot_page_immutable'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_source_part_immutable BEFORE UPDATE ON jwt_v2_reconcile_parts BEGIN SELECT RAISE(ABORT,'snapshot_part_immutable'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_receive_record_immutable BEFORE UPDATE ON jwt_v2_receive_records BEGIN SELECT RAISE(ABORT,'snapshot_record_immutable'); END;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_snapshot_effect_immutable BEFORE UPDATE ON jwt_v2_snapshot_effects BEGIN SELECT RAISE(ABORT,'snapshot_effect_immutable'); END;"
].join('\n');

export function validateReconcileRequest(value,config){
 exact(value,REQUEST);
 requireThat(value.schema===2&&value.env===config.env&&value.ownerApp==='academy'&&['studio','hifz'].includes(value.recipientApp)&&value.recipientApp===config.recipientApp&&value.sourceApp===value.recipientApp&&value.targetApp==='academy'&&uuid(value.requestId)&&ascii(value.stream),'INVALID_RECONCILE_REQUEST',400);
 requireThat(value.ownerEpoch===null||ascii(value.ownerEpoch),'INVALID_OWNER_EPOCH',400);
 requireThat(safeInt(value.contiguousThrough)&&Array.isArray(value.missingRanges)&&value.missingRanges.length<=20,'INVALID_MISSING_RANGES',400);
 let last=0;
 for(const range of value.missingRanges){requireThat(Array.isArray(range)&&range.length===2&&safeInt(range[0],1)&&safeInt(range[1],1)&&range[0]<=range[1]&&range[0]>last,'INVALID_MISSING_RANGES',400);last=range[1];}
 requireThat(value.knownFloorsDigest===null||HEX.test(value.knownFloorsDigest),'INVALID_FLOORS_DIGEST',400);
 if(value.ownerEpoch===null)requireThat(value.contiguousThrough===0&&value.knownFloorsDigest===null,'INVALID_GENESIS_REQUEST',400);
 if(value.pageToken!==null)unb64u(value.pageToken,32);
 return value;
}
export const requestBinding=request=>canonical({...request,pageToken:null});
function validateBase(meta,config,now){
 exact(meta,BASE);
 requireThat(meta.schema===snapshotContract(config)&&meta.env===config.env&&meta.ownerApp==='academy'&&meta.recipientApp===config.recipientApp&&['studio','hifz'].includes(meta.recipientApp)&&uuid(meta.requestId)&&uuid(meta.snapshotId)&&ascii(meta.stream)&&ascii(meta.ownerEpoch),'INVALID_SNAPSHOT_BINDING',409);
 requireThat(safeInt(meta.coveredThrough)&&safeInt(meta.createdAt)&&safeInt(meta.expiresAt)&&meta.expiresAt-meta.createdAt===600&&safeInt(now)&&now<meta.expiresAt&&meta.createdAt<=now+30,'SNAPSHOT_EXPIRED_OR_INVALID',409);
 requireThat(meta.predecessorEpoch===null?meta.predecessorCoveredThrough===null:ascii(meta.predecessorEpoch)&&safeInt(meta.predecessorCoveredThrough),'INVALID_PREDECESSOR',409);
}
export function validateEpoch(meta,trust){
 requireThat(trust&&trust.stream===meta.stream,'UNREGISTERED_STREAM',409);
 if(trust.currentEpoch===meta.ownerEpoch){requireThat(meta.predecessorEpoch===null&&meta.predecessorCoveredThrough===null,'UNEXPECTED_PREDECESSOR',409);return;}
 if(trust.currentEpoch===null){
  requireThat(trust.genesisEpoch===meta.ownerEpoch&&meta.predecessorEpoch===null&&meta.predecessorCoveredThrough===null,'UNRECOGNISED_GENESIS',409);return;
 }
 const bridge=trust.bridges?.get(meta.ownerEpoch);
 requireThat(bridge&&bridge.predecessorEpoch===trust.currentEpoch&&bridge.predecessorEpoch===meta.predecessorEpoch&&bridge.coveredThrough===meta.predecessorCoveredThrough&&bridge.denialsIncluded===true,'EPOCH_BRIDGE_REQUIRED',409);
}
function validateMetadata(meta,config,now){
 exact(meta,META);validateBase(pick(meta,BASE),config,now);
 exact(meta.bucketCounts,BUCKETS);
 requireThat(safeInt(meta.totalRecords)&&safeInt(meta.pageCount,1)&&BUCKETS.every(b=>safeInt(meta.bucketCounts[b]))&&BUCKETS.reduce((n,b)=>n+meta.bucketCounts[b],0)===meta.totalRecords,'SNAPSHOT_COUNT_CONFLICT',409);
 requireThat(meta.bucketCounts.localCutoffs===0&&meta.pageCount<=Math.max(1,meta.totalRecords),'INVALID_REMOTE_SNAPSHOT',409);
}
export function validateRecord(bucket,record,{ownerEpoch,recipientApp,dependencies=new Map(),recognisedEpochs=new Set([ownerEpoch]),snapshotSchema=2}){
 requireThat(BUCKETS.includes(bucket)&&bucket!=='localCutoffs'&&record?.type===TYPES[bucket],'INVALID_SNAPSHOT_BUCKET',409);
 exact(record,(FIELDS[record.type]+(record.type==='dependency'&&snapshotSchema===3?' sub':'')).split(' '));
 canonical(record);
 for(const field of ['maxCe','maxAe','newCe','bv','ce','ae','maxBv','registryRevision','revision'])if(Object.hasOwn(record,field))requireThat(safeInt(record[field],1),'INVALID_SNAPSHOT_COUNTER',409);
 for(const field of ['psid','bsid'])if(Object.hasOwn(record,field))requireThat(uuid(record[field]),'INVALID_SNAPSHOT_UUID',409);
 if(Object.hasOwn(record,'sub'))requireThat(record.type==='dependency'&&snapshotSchema===3&&record.sub===null||subject(record.sub),'INVALID_SNAPSHOT_SUBJECT',409);
 switch(record.type){
  case 'accountCutoff':requireThat(['VOLUNTARY_LOGOUT','VERIFIED_REFRESH_REUSE','SUSPICIOUS_ACTIVITY','CONFIRMED_KEY_COMPROMISE','ACCOUNT_DISABLED'].includes(record.reason)&&(record.incidentId===null||uuid(record.incidentId)),'INVALID_SNAPSHOT_CUTOFF',409);break;
  case 'credentialEpoch':requireThat(['ADMIN_PIN_RESET','PASSWORD_RESET'].includes(record.reason),'INVALID_SNAPSHOT_CREDENTIAL_REASON',409);break;
  case 'key':requireThat(record.purpose==='academy-handoff'&&/^[A-Za-z0-9._-]{1,64}$/.test(record.kid),'INVALID_SNAPSHOT_KEY',409);break;
  case 'policy':requireThat(record.policyId==='session-inactivity'&&recognisedEpochs.has(record.ownerEpoch)&&safeInt(record.inactivityMinutes,15)&&record.inactivityMinutes<=200,'INVALID_SNAPSHOT_POLICY',409);break;
  case 'dependency':{
   const rule=dependencies.get(record.id);
   requireThat(rule&&rule.ownerApp==='academy'&&rule.recipients.includes(recipientApp)&&(record.ownerEpoch===rule.epoch||rule.epochs?.has(record.ownerEpoch))&&safeInt(record.revision,1),'SNAPSHOT_DEPENDENCY_OWNER_CONFLICT',409);
    if(snapshotSchema===3)requireThat(['ACCOUNT','GLOBAL'].includes(rule.scope)&&(rule.scope==='GLOBAL'?record.sub===null:subject(record.sub)),'SNAPSHOT_DEPENDENCY_SCOPE_CONFLICT',409);
    else requireThat(rule.scope==='GLOBAL','AMBIGUOUS_LEGACY_DEPENDENCY_SCOPE',409);
   requireThat(['INVALIDATE','DENY'].includes(record.effect)&&Array.isArray(record.deniedActions)&&new Set(record.deniedActions).size===record.deniedActions.length,'INVALID_SNAPSHOT_ACTIONS',409);
   requireThat(record.deniedActions.every((v,i)=>ascii(v)&&rule.actions.includes(v)&&(i===0||record.deniedActions[i-1]<v)),'INVALID_SNAPSHOT_ACTIONS',409);
   requireThat(record.effect==='INVALIDATE'?record.deniedActions.length===0:record.deniedActions.length>0,'INVALID_SNAPSHOT_EFFECT',409);break;
  }
 }
 return record;
}
function semanticKey(record){
 switch(record.type){
  case 'accountCutoff':return canonical([record.sub,record.maxCe,record.maxAe]);
  case 'credentialEpoch':return canonical([record.sub,record.newCe]);
  case 'parent':return canonical([record.sub,record.psid,record.bsid,record.bv,record.ce,record.ae]);
  case 'browser':return canonical([record.bsid,record.maxBv]);
  case 'key':return canonical([record.purpose,record.kid,record.registryRevision]);
  case 'policy':return canonical([record.policyId,record.ownerEpoch,record.revision]);
  case 'dependency':return canonical([record.id,Object.hasOwn(record,'sub')?record.sub:null,record.ownerEpoch,record.revision]);
 }
}
export function compareUtf8(a,b){
 const x=bytes(a),y=bytes(b);for(let i=0;i<Math.min(x.length,y.length);i++)if(x[i]!==y[i])return x[i]<y[i]?-1:1;return Math.sign(x.length-y.length);
}
const bucketIndex=b=>BUCKETS.indexOf(b);
const ordered=(previous,current)=>!previous||bucketIndex(previous.bucket)<bucketIndex(current.bucket)||previous.bucket===current.bucket&&compareUtf8(previous.json,current.json)<0;
function defaultDigestStream(){requireThat(typeof crypto.DigestStream==='function','STREAMING_DIGEST_UNAVAILABLE',503);return new crypto.DigestStream('SHA-256');}
export async function streamingSnapshotDigest(metadata,recordsForBucket,{digestStreamFactory=defaultDigestStream}={}){
 const stream=digestStreamFactory(),writer=stream.getWriter();
 const write=s=>writer.write(bytes(s));
  await write(snapshotDomain(metadata,'security-snapshot')+'\0{"metadata":'+canonical(metadata)+',"state":{');
 const keys=[...BUCKETS,'schema'].sort();
 for(let k=0;k<keys.length;k++){
  const name=keys[k];if(k)await write(',');await write(canonical(name)+':');
   if(name==='schema'){await write(String(metadata.schema??2));continue;}
  await write('[');let first=true;
  for await(const recordJSON of recordsForBucket(name)){if(!first)await write(',');await write(recordJSON);first=false;}
  await write(']');
 }
 await write('}}');await writer.close();return hex(await stream.digest);
}
function cursorData(meta,snapshotDigest,nextPageIndex){
 return {env:meta.env,ownerApp:meta.ownerApp,recipientApp:meta.recipientApp,requestId:meta.requestId,stream:meta.stream,ownerEpoch:meta.ownerEpoch,snapshotId:meta.snapshotId,snapshotDigest,nextPageIndex,expiresAt:meta.expiresAt};
}
export const snapshotCursor=async(meta,snapshotDigest,nextPageIndex,key)=>b64u(await hmac(key,canonical(cursorData(meta,snapshotDigest,nextPageIndex))));


export class SnapshotStore {
 constructor(primary){this.primary=primary;}
 stmt(sql,...args){return this.primary.stmt(sql,...args);}
 first(sql,...args){return this.primary.first(sql,...args);}
 all(sql,...args){return this.primary.all(sql,...args);}
 batch(items){return this.primary.batch(items);}
 guard(sql,args=[]){const id=q();return [this.stmt('INSERT INTO jwt_v2_reconcile_guards VALUES(?,EXISTS('+sql+'))',id,...args),this.stmt('DELETE FROM jwt_v2_reconcile_guards WHERE id=?',id)];}
 async capturePrimary({request,base,cursorKeyId,selectors,guard,config,now}){
  validateReconcileRequest(request,config);validateBase(base,config,now);
  requireThat(base.requestId===request.requestId&&base.env===request.env&&base.stream===request.stream&&base.ownerApp===request.ownerApp&&base.recipientApp===request.recipientApp&&request.pageToken===null&&ascii(cursorKeyId,64),'CAPTURE_BINDING_CONFLICT',409);
  const prior=await this.first('SELECT * FROM jwt_v2_reconcile_captures WHERE request_id=?',request.requestId);
  if(prior){requireThat(prior.request_binding===requestBinding(request),'RECONCILE_REQUEST_CONFLICT',409);const old=strictJSON(prior.base_json);requireThat(now<old.expiresAt,'SNAPSHOT_EXPIRED_OR_INVALID',409);return prior.snapshot_id;}
  // guard/selectors are trusted native-adapter SQL, never request-provided SQL.
  // The guard must fence the exact owning stream epoch/watermark and split phase.
  requireThat(guard&&typeof guard.sql==='string'&&Array.isArray(guard.args)&&Array.isArray(selectors),'OWNING_CAPTURE_GUARD_REQUIRED',503);
  const [g,clear]=this.guard(guard.sql,guard.args);
  const parts=selectors.map(s=>{requireThat(BUCKETS.includes(s.bucket)&&s.bucket!=='localCutoffs'&&typeof s.sql==='string'&&Array.isArray(s.args),'INVALID_CAPTURE_SELECTOR',503);return this.stmt('INSERT INTO jwt_v2_reconcile_records(snapshot_id,bucket,raw_json) SELECT ?,?,record_json FROM ('+s.sql+')',base.snapshotId,s.bucket,...s.args);});
  try{await this.batch([g,this.stmt("INSERT INTO jwt_v2_reconcile_captures(snapshot_id,request_id,request_binding,base_json,cursor_key_id,status) VALUES(?,?,?,?,?,'CAPTURING')",base.snapshotId,request.requestId,requestBinding(request),canonical(base),cursorKeyId),...parts,this.stmt("UPDATE jwt_v2_reconcile_captures SET status='CAPTURED' WHERE snapshot_id=?",base.snapshotId),clear]);}
  catch(error){const raced=await this.first('SELECT * FROM jwt_v2_reconcile_captures WHERE request_id=?',request.requestId);if(!raced)throw error;requireThat(raced.request_binding===requestBinding(request),'RECONCILE_REQUEST_CONFLICT',409);requireThat(now<strictJSON(raced.base_json).expiresAt,'SNAPSHOT_EXPIRED_OR_INVALID',409);return raced.snapshot_id;}
  return base.snapshotId;
 }
 async *recordRows(snapshotId,bucket,{receiver=false}={}){
  if(receiver){
   let offset=-1;
   for(;;){const rows=await this.all('SELECT record_offset,record_json FROM jwt_v2_receive_records WHERE snapshot_id=? AND bucket=? AND record_offset>? ORDER BY record_offset LIMIT 20',snapshotId,bucket,offset);if(!rows.length)return;for(const r of rows){offset=r.record_offset;yield r.record_json;}}
  }else{
   let previous=null;
   for(;;){const rows=await this.all('SELECT canonical_json FROM jwt_v2_reconcile_records WHERE snapshot_id=? AND bucket=? AND canonical_json IS NOT NULL AND (? IS NULL OR CAST(canonical_json AS BLOB)>CAST(? AS BLOB)) ORDER BY CAST(canonical_json AS BLOB) LIMIT 20',snapshotId,bucket,previous,previous);if(!rows.length)return;for(const r of rows){previous=r.canonical_json;yield r.canonical_json;}}
  }
 }
 async *orderedRecords(snapshotId){
  for(const bucket of BUCKETS)for await(const json of this.recordRows(snapshotId,bucket))yield {bucket,record:strictJSON(json),json};
 }
}

export async function buildSnapshot({store,snapshotId,cursorKey,cursorKeyId,config,recordConfig={},now,digestStreamFactory,clock=()=>Math.floor(Date.now()/1000)}){
 const capture=await store.first('SELECT * FROM jwt_v2_reconcile_captures WHERE snapshot_id=?',snapshotId);requireThat(capture,'SNAPSHOT_CAPTURE_MISSING',409);
 const base=strictJSON(capture.base_json);validateBase(base,config,now);requireThat(capture.cursor_key_id===cursorKeyId,'CURSOR_KEY_CONFLICT',409);
 if(capture.status==='READY'){const metadata=strictJSON(capture.metadata_json);validateMetadata(metadata,config,Math.max(now,clock()));return {metadata,snapshotDigest:capture.snapshot_digest};}
 requireThat(['CAPTURED','BUILDING'].includes(capture.status),'SNAPSHOT_CAPTURE_INCOMPLETE',409);
 let ordinal=0;
 for(;;){
  const rows=await store.all('SELECT ordinal,bucket,CASE WHEN length(CAST(raw_json AS BLOB))<=61440 THEN raw_json ELSE NULL END raw_json FROM jwt_v2_reconcile_records WHERE snapshot_id=? AND ordinal>? ORDER BY ordinal LIMIT 20',snapshotId,ordinal);
  if(!rows.length)break;
  for(const row of rows){
   ordinal=row.ordinal;requireThat(row.raw_json!==null,'SNAPSHOT_RECORD_TOO_LARGE',503);
   const record=validateRecord(row.bucket,strictJSON(row.raw_json),{...recordConfig,snapshotSchema:base.schema,ownerEpoch:base.ownerEpoch,recipientApp:base.recipientApp}),json=canonical(record);
   requireThat(bytes(canonical({bucket:row.bucket,record})).length<=61438,'SNAPSHOT_RECORD_TOO_LARGE',503);
   const old=await store.first('SELECT canonical_json,semantic_key FROM jwt_v2_reconcile_records WHERE ordinal=?',ordinal);
   if(old.canonical_json!==null){requireThat(old.canonical_json===json&&old.semantic_key===semanticKey(record),'SNAPSHOT_RECORD_CONFLICT',409);continue;}
   try{await store.stmt('UPDATE jwt_v2_reconcile_records SET canonical_json=?,semantic_key=? WHERE ordinal=?',json,semanticKey(record),ordinal).run();}
   catch(error){reject('DUPLICATE_OR_CONFLICTING_SNAPSHOT_FACT',409);}
  }
 }
 const counts=Object.fromEntries(BUCKETS.map(b=>[b,0]));let entries=[],offset=0,pageIndex=0;
 async function flush(){
  const part={entries,offset,index:pageIndex},json=canonical(entries);
  const prior=await store.first('SELECT * FROM jwt_v2_reconcile_parts WHERE snapshot_id=? AND page_index=?',snapshotId,pageIndex);
  requireThat(!prior||prior.entries_json===json&&prior.record_offset===offset,'SNAPSHOT_PART_CONFLICT',409);
  if(!prior)await store.stmt('INSERT INTO jwt_v2_reconcile_parts VALUES(?,?,?,?) ON CONFLICT(snapshot_id,page_index) DO NOTHING',snapshotId,pageIndex,offset,json).run();
  const stored=await store.first('SELECT * FROM jwt_v2_reconcile_parts WHERE snapshot_id=? AND page_index=?',snapshotId,pageIndex);requireThat(stored.entries_json===json&&stored.record_offset===offset,'SNAPSHOT_PART_CONFLICT',409);
  offset+=entries.length;pageIndex++;entries=[];return part;
 }
 for await(const entry of store.orderedRecords(snapshotId)){
  const wire={bucket:entry.bucket,record:entry.record};
  if(entries.length&&(entries.length===20||bytes(canonical([...entries,wire])).length>61440))await flush();
  entries.push(wire);counts[entry.bucket]++;requireThat(safeInt(counts[entry.bucket]),'SNAPSHOT_COUNT_OVERFLOW',503);
 }
 if(entries.length||pageIndex===0)await flush();
 const metadata={...base,totalRecords:offset,bucketCounts:counts,pageCount:pageIndex};validateMetadata(metadata,config,now);
 const snapshotDigest=await streamingSnapshotDigest(metadata,b=>store.recordRows(snapshotId,b),{digestStreamFactory});
 await store.stmt("UPDATE jwt_v2_reconcile_captures SET status='BUILDING',metadata_json=?,snapshot_digest=? WHERE snapshot_id=? AND status IN('CAPTURED','BUILDING')",canonical(metadata),snapshotDigest,snapshotId).run();
 let previousPageDigest=await domainDigest(snapshotDomain(metadata,'snapshot-start'),{metadata,snapshotDigest}),requestToken=null;
 for(let i=0;i<pageIndex;i++){
  const part=await store.first('SELECT * FROM jwt_v2_reconcile_parts WHERE snapshot_id=? AND page_index=?',snapshotId,i);requireThat(part,'SNAPSHOT_PART_MISSING',409);
  const nextPageToken=i===pageIndex-1?null:await snapshotCursor(metadata,snapshotDigest,i+1,cursorKey);
  const page={...metadata,mode:'SNAPSHOT',snapshotDigest,pageIndex:i,recordOffset:part.record_offset,entries:strictJSON(part.entries_json),previousPageDigest,nextPageToken};
  page.pageDigest=await domainDigest(snapshotDomain(metadata,'snapshot-page'),page);const json=canonical(page);
  requireThat(bytes(json).length<=65536,'SNAPSHOT_PAGE_TOO_LARGE',503);
  const prior=await store.first('SELECT page_json FROM jwt_v2_reconcile_pages WHERE snapshot_id=? AND page_index=?',snapshotId,i);requireThat(!prior||prior.page_json===json,'SNAPSHOT_PAGE_CONFLICT',409);
  if(!prior)await store.stmt('INSERT INTO jwt_v2_reconcile_pages VALUES(?,?,?,?) ON CONFLICT(snapshot_id,page_index) DO NOTHING',snapshotId,i,requestToken,json).run();
  const stored=await store.first('SELECT * FROM jwt_v2_reconcile_pages WHERE snapshot_id=? AND page_index=?',snapshotId,i);requireThat(stored.page_json===json&&stored.request_token===requestToken,'SNAPSHOT_PAGE_CONFLICT',409);
  previousPageDigest=page.pageDigest;requestToken=nextPageToken;
 }
 validateMetadata(metadata,config,Math.max(now,clock()));
 const [g,clear]=store.guard('SELECT 1 FROM jwt_v2_reconcile_captures WHERE snapshot_id=? AND status=? AND metadata_json=? AND snapshot_digest=?',[snapshotId,'BUILDING',canonical(metadata),snapshotDigest]);
 await store.batch([g,store.stmt("UPDATE jwt_v2_reconcile_captures SET status='READY' WHERE snapshot_id=?",snapshotId),clear]);
 return {metadata,snapshotDigest};
}

export async function serveSnapshotPage({store,request,config,cursorKey,cursorKeyId,now}){
 validateReconcileRequest(request,config);
 const capture=await store.first('SELECT * FROM jwt_v2_reconcile_captures WHERE request_id=?',request.requestId);requireThat(capture?.status==='READY','SNAPSHOT_CAPTURE_UNAVAILABLE',409);
 requireThat(capture.request_binding===requestBinding(request)&&capture.cursor_key_id===cursorKeyId,'RECONCILE_REQUEST_CONFLICT',409);
 const metadata=strictJSON(capture.metadata_json);validateMetadata(metadata,config,now);
 const row=await store.first('SELECT * FROM jwt_v2_reconcile_pages WHERE snapshot_id=? AND request_token IS ?',capture.snapshot_id,request.pageToken);requireThat(row,'INVALID_SNAPSHOT_CURSOR',409);
 const page=strictJSON(row.page_json);
 if(page.pageIndex>0)requireThat(equal(request.pageToken,await snapshotCursor(metadata,capture.snapshot_digest,page.pageIndex,cursorKey)),'INVALID_SNAPSHOT_CURSOR',409);
 return row.page_json;
}


function validatePage(raw,{config,recordConfig,trust,now}){
 const size=typeof raw==='string'?bytes(raw).length:raw.byteLength;requireThat(size<=65536,'BODY_TOO_LARGE',413);
 const page=strictJSON(raw);exact(page,PAGE);const meta=pick(page,META);validateMetadata(meta,config,now);validateEpoch(meta,trust);
 requireThat(page.mode==='SNAPSHOT'&&HEX.test(page.snapshotDigest)&&HEX.test(page.previousPageDigest)&&HEX.test(page.pageDigest)&&safeInt(page.pageIndex)&&page.pageIndex<meta.pageCount&&safeInt(page.recordOffset)&&Array.isArray(page.entries)&&page.entries.length<=20&&bytes(canonical(page.entries)).length<=61440,'INVALID_SNAPSHOT_PAGE',409);
 requireThat(page.pageIndex===meta.pageCount-1?page.nextPageToken===null:page.entries.length>0&&typeof page.nextPageToken==='string','INVALID_SNAPSHOT_CONTINUATION',409);
 if(page.nextPageToken!==null)unb64u(page.nextPageToken,32);
 requireThat(meta.totalRecords===0?meta.pageCount===1&&page.pageIndex===0&&page.recordOffset===0&&page.entries.length===0:page.entries.length>0,'INVALID_EMPTY_SNAPSHOT',409);
 let previous=null;
 for(const entry of page.entries){
  exact(entry,['bucket','record']);validateRecord(entry.bucket,entry.record,{...recordConfig,snapshotSchema:meta.schema,ownerEpoch:meta.ownerEpoch,recipientApp:meta.recipientApp});
  const current={bucket:entry.bucket,json:canonical(entry.record)};requireThat(ordered(previous,current),'SNAPSHOT_RECORD_ORDER',409);previous=current;
 }
 const text=typeof raw==='string'?raw:new TextDecoder('utf-8',{fatal:true}).decode(raw);requireThat(canonical(page)===text,'NONCANONICAL_SNAPSHOT_WIRE',409);
 return {page,meta,text};
}

export class SnapshotReceiver {
 constructor({store,config,trust,recordConfig={},digestStreamFactory,clock=()=>Math.floor(Date.now()/1000),pendingRequest=null}){
  Object.assign(this,{store,config,trust,recordConfig,digestStreamFactory,clock});
  this.ready=pendingRequest?this.registerRequest(pendingRequest):Promise.resolve();
 }
 async registerRequest(request){
  validateReconcileRequest(request,this.config);
  requireThat(request.pageToken===null&&request.stream===this.trust.stream,'INVALID_RECONCILE_REGISTRATION',409);
  const binding=requestBinding(request),prior=await this.store.first('SELECT * FROM jwt_v2_receive_requests WHERE request_id=?',request.requestId);
  if(prior){requireThat(prior.request_binding===binding,'RECONCILE_REQUEST_CONFLICT',409);requireThat(prior.status!=='CANCELLED','RECONCILE_REQUEST_CANCELLED',409);return {requestId:request.requestId,status:prior.status};}
  try{await this.store.stmt("INSERT INTO jwt_v2_receive_requests VALUES(?,?,?,'PENDING')",request.requestId,binding,canonical(request)).run();}
  catch(error){const raced=await this.store.first('SELECT * FROM jwt_v2_receive_requests WHERE request_id=?',request.requestId);if(!raced)throw error;requireThat(raced.request_binding===binding,'RECONCILE_REQUEST_CONFLICT',409);requireThat(raced.status!=='CANCELLED','RECONCILE_REQUEST_CANCELLED',409);return {requestId:request.requestId,status:raced.status};}
  return {requestId:request.requestId,status:'PENDING'};
 }
 async cancelRequest(requestId){
  await this.ready;
  await this.store.stmt("UPDATE jwt_v2_receive_requests SET status='CANCELLED' WHERE request_id=? AND status='PENDING'",requestId).run();
 }
 async pendingFor(meta){
  await this.ready;
  const row=await this.store.first('SELECT * FROM jwt_v2_receive_requests WHERE request_id=?',meta.requestId);
  requireThat(row&&['PENDING','COMPLETE'].includes(row.status),'UNREQUESTED_RECONCILIATION_REPLY',409);
  const request=validateReconcileRequest(strictJSON(row.request_json),this.config);
  requireThat(row.request_binding===requestBinding(request)&&request.requestId===meta.requestId&&request.env===meta.env&&request.ownerApp===meta.ownerApp&&request.recipientApp===meta.recipientApp&&request.stream===meta.stream,'RECONCILE_RESPONSE_BINDING_CONFLICT',409);
  const same=request.ownerEpoch===meta.ownerEpoch;
  const genesis=request.ownerEpoch===null&&this.trust.currentEpoch===null&&this.trust.genesisEpoch===meta.ownerEpoch;
  const bridge=request.ownerEpoch!==null&&meta.predecessorEpoch===request.ownerEpoch&&this.trust.bridges?.get(meta.ownerEpoch)?.predecessorEpoch===request.ownerEpoch;
  requireThat(same||genesis||bridge,'RECONCILE_RESPONSE_EPOCH_CONFLICT',409);
  requireThat(genesis||(same?meta.coveredThrough>=request.contiguousThrough:meta.predecessorCoveredThrough>=request.contiguousThrough),'RECONCILE_WATERMARK_REGRESSION',409);
  return row;
 }
 async stage(raw,{now}){
  // Low-level adapter: transport authentication must precede this call. It never grants API authority.
  await this.ready;
  const {page,meta,text}=validatePage(raw,{config:this.config,recordConfig:this.recordConfig,trust:this.trust,now});
  await this.pendingFor(meta);
  const unsigned=Object.fromEntries(Object.entries(page).filter(([k])=>k!=='pageDigest'));
  requireThat(equal(page.pageDigest,await domainDigest(snapshotDomain(meta,'snapshot-page'),unsigned)),'SNAPSHOT_PAGE_DIGEST',409);
  if(page.pageIndex===0)requireThat(equal(page.previousPageDigest,await domainDigest(snapshotDomain(meta,'snapshot-start'),{metadata:meta,snapshotDigest:page.snapshotDigest})),'SNAPSHOT_CHAIN_SEED',409);
  let capture=await this.store.first('SELECT * FROM jwt_v2_receive_snapshots WHERE snapshot_id=? OR request_id=?',meta.snapshotId,meta.requestId);
  requireThat(!capture||capture.snapshot_id===meta.snapshotId&&capture.metadata_json===canonical(meta)&&capture.snapshot_digest===page.snapshotDigest,'SNAPSHOT_METADATA_CONFLICT',409);
  if(!capture)await this.store.stmt("INSERT INTO jwt_v2_receive_snapshots VALUES(?,?,?,?,'STAGED') ON CONFLICT DO NOTHING",meta.snapshotId,meta.requestId,canonical(meta),page.snapshotDigest).run();
  capture=await this.store.first('SELECT * FROM jwt_v2_receive_snapshots WHERE snapshot_id=? OR request_id=?',meta.snapshotId,meta.requestId);
  requireThat(capture?.snapshot_id===meta.snapshotId&&capture.metadata_json===canonical(meta)&&capture.snapshot_digest===page.snapshotDigest,'SNAPSHOT_METADATA_CONFLICT',409);
  const old=await this.store.first('SELECT page_json FROM jwt_v2_receive_pages WHERE snapshot_id=? AND page_index=?',meta.snapshotId,page.pageIndex);
  requireThat(!old||old.page_json===text,'CONFLICTING_DUPLICATE_PAGE',409);
  if(!old)await this.store.stmt('INSERT INTO jwt_v2_receive_pages VALUES(?,?,?) ON CONFLICT(snapshot_id,page_index) DO NOTHING',meta.snapshotId,page.pageIndex,text).run();
  const stored=await this.store.first('SELECT page_json FROM jwt_v2_receive_pages WHERE snapshot_id=? AND page_index=?',meta.snapshotId,page.pageIndex);requireThat(stored.page_json===text,'CONFLICTING_DUPLICATE_PAGE',409);
  return this.verify(meta.snapshotId,{now});
 }
 async verify(snapshotId,{now}){
  const capture=await this.store.first('SELECT * FROM jwt_v2_receive_snapshots WHERE snapshot_id=?',snapshotId);requireThat(capture,'SNAPSHOT_CAPTURE_MISSING',409);
  const meta=strictJSON(capture.metadata_json);validateMetadata(meta,this.config,now);validateEpoch(meta,this.trust);await this.pendingFor(meta);
  const count=await this.store.first('SELECT count(*) n FROM jwt_v2_receive_pages WHERE snapshot_id=?',snapshotId);
  if(count.n<meta.pageCount)return {status:'STAGED',complete:false,snapshotId};
  requireThat(count.n===meta.pageCount,'EXTRA_SNAPSHOT_PAGE',409);
  let previousDigest=await domainDigest(snapshotDomain(meta,'snapshot-start'),{metadata:meta,snapshotDigest:capture.snapshot_digest}),offset=0,previousRecord=null,previousEntries=null;
  const counts=Object.fromEntries(BUCKETS.map(b=>[b,0]));
  for(let index=0;index<meta.pageCount;index++){
   const row=await this.store.first('SELECT page_json FROM jwt_v2_receive_pages WHERE snapshot_id=? AND page_index=?',snapshotId,index);requireThat(row,'SNAPSHOT_PAGE_GAP',409);
   const {page}=validatePage(row.page_json,{config:this.config,recordConfig:this.recordConfig,trust:this.trust,now});
   requireThat(page.pageIndex===index&&page.recordOffset===offset&&page.previousPageDigest===previousDigest&&canonical(pick(page,META))===capture.metadata_json&&page.snapshotDigest===capture.snapshot_digest,'SNAPSHOT_CHAIN_OR_OFFSET',409);
   const unsigned=Object.fromEntries(Object.entries(page).filter(([k])=>k!=='pageDigest'));requireThat(page.pageDigest===await domainDigest(snapshotDomain(meta,'snapshot-page'),unsigned),'SNAPSHOT_PAGE_DIGEST',409);
   if(previousEntries&&previousEntries.length<20)requireThat(bytes(canonical([...previousEntries,page.entries[0]])).length>61440,'NON_GREEDY_SNAPSHOT_PARTITION',409);
   for(const entry of page.entries){
    const current={bucket:entry.bucket,json:canonical(entry.record)};
    requireThat(ordered(previousRecord,current),'SNAPSHOT_RECORD_ORDER',409);previousRecord=current;counts[entry.bucket]++;
    const old=await this.store.first('SELECT * FROM jwt_v2_receive_records WHERE snapshot_id=? AND record_offset=?',snapshotId,offset);
    requireThat(!old||old.bucket===entry.bucket&&old.record_json===current.json,'SNAPSHOT_RECORD_CONFLICT',409);
    if(!old){
     try{await this.store.stmt('INSERT INTO jwt_v2_receive_records VALUES(?,?,?,?,?,?) ON CONFLICT(snapshot_id,record_offset) DO NOTHING',snapshotId,offset,entry.bucket,current.json,await digest(entry.record),semanticKey(entry.record)).run();
      const stored=await this.store.first('SELECT * FROM jwt_v2_receive_records WHERE snapshot_id=? AND record_offset=?',snapshotId,offset);requireThat(stored.bucket===entry.bucket&&stored.record_json===current.json&&stored.semantic_key===semanticKey(entry.record),'SNAPSHOT_RECORD_CONFLICT',409);}
     catch{reject('DUPLICATE_OR_CONFLICTING_SNAPSHOT_FACT',409);}
    }
    offset++;
   }
   previousDigest=page.pageDigest;previousEntries=page.entries;
  }
  requireThat(offset===meta.totalRecords&&canonical(counts)===canonical(meta.bucketCounts),'SNAPSHOT_COUNT_CONFLICT',409);
  const actual=await streamingSnapshotDigest(meta,b=>this.store.recordRows(snapshotId,b,{receiver:true}),{digestStreamFactory:this.digestStreamFactory});
  requireThat(equal(actual,capture.snapshot_digest),'SNAPSHOT_FINAL_DIGEST',409);
  validateMetadata(meta,this.config,Math.max(now,this.clock()));
  await this.store.stmt("UPDATE jwt_v2_receive_snapshots SET status=CASE WHEN status='APPLIED' THEN status ELSE 'VERIFIED' END WHERE snapshot_id=?",snapshotId).run();
  return {status:capture.status==='APPLIED'?'APPLIED':'VERIFIED',complete:true,snapshotId,publicationPending:capture.status!=='APPLIED'};
 }
 async applyRecords(snapshotId,{now,planEffect}){
  const verified=await this.verify(snapshotId,{now});requireThat(verified.complete,'SNAPSHOT_INCOMPLETE',409);
  const capture=await this.store.first('SELECT metadata_json FROM jwt_v2_receive_snapshots WHERE snapshot_id=?',snapshotId),metadata=strictJSON(capture.metadata_json);
  let offset=-1;
  for(;;){
   const rows=await this.store.all('SELECT * FROM jwt_v2_receive_records WHERE snapshot_id=? AND record_offset>? ORDER BY record_offset LIMIT 20',snapshotId,offset);if(!rows.length)break;
   for(const row of rows){
    offset=row.record_offset;const old=await this.store.first('SELECT e.*,w.target_json,w.scope_sub FROM jwt_v2_snapshot_effects e JOIN jwt_v2_worksets w ON w.work_id=e.work_id WHERE e.snapshot_id=? AND e.record_offset=?',snapshotId,offset);if(old){const scoped=snapshotEffect(strictJSON(row.record_json));requireThat(old.record_digest===row.record_digest&&old.target_json===canonical(scoped.target)&&(old.scope_sub??null)===scoped.scopeSub,'SNAPSHOT_APPLICATION_CONFLICT',409);continue;}
    validateMetadata(metadata,this.config,Math.max(now,this.clock()));
    const effect=await planEffect({bucket:row.bucket,record:strictJSON(row.record_json),recordDigest:row.record_digest,snapshotId,offset});
    requireThat(ascii(effect.workId,256)&&Array.isArray(effect.statements),'SNAPSHOT_EFFECT_PLAN_REQUIRED',503);
    validateMetadata(metadata,this.config,Math.max(now,this.clock()));
    const [g,clear]=this.store.guard("SELECT 1 FROM jwt_v2_receive_snapshots WHERE snapshot_id=? AND status IN('VERIFIED','APPLIED')",[snapshotId]);
    const expected=snapshotEffect(strictJSON(row.record_json));
     const [coverage,coverageClear]=this.store.guard('SELECT 1 FROM jwt_v2_worksets WHERE work_id=? AND target_json=? AND scope_sub IS ?',[effect.workId,canonical(expected.target),expected.scopeSub]);
    try{await this.store.batch([g,...effect.statements,coverage,this.store.stmt('INSERT INTO jwt_v2_snapshot_effects VALUES(?,?,?,?)',snapshotId,offset,row.record_digest,effect.workId),coverageClear,clear]);}
    catch(error){const raced=await this.store.first('SELECT e.*,w.target_json,w.scope_sub FROM jwt_v2_snapshot_effects e JOIN jwt_v2_worksets w ON w.work_id=e.work_id WHERE e.snapshot_id=? AND e.record_offset=?',snapshotId,offset);if(!raced)throw error;requireThat(raced.record_digest===row.record_digest&&raced.work_id===effect.workId&&raced.target_json===canonical(expected.target)&&(raced.scope_sub??null)===expected.scopeSub,'SNAPSHOT_APPLICATION_CONFLICT',409);}
   }
  }
  return this.finishApplied(snapshotId,{now});
 }
 async finishApplied(snapshotId,{now}){
  const verified=await this.verify(snapshotId,{now});requireThat(verified.complete,'SNAPSHOT_INCOMPLETE',409);
  const capture=await this.store.first('SELECT * FROM jwt_v2_receive_snapshots WHERE snapshot_id=?',snapshotId);requireThat(capture&&['VERIFIED','APPLIED'].includes(capture.status),'SNAPSHOT_NOT_VERIFIED',409);
  const meta=strictJSON(capture.metadata_json);validateMetadata(meta,this.config,Math.max(now,this.clock()));validateEpoch(meta,this.trust);
  let applied=0,offset=-1;
  for(;;){const rows=await this.store.all('SELECT r.record_offset,r.record_json,r.record_digest,e.record_digest effect_digest,w.target_json,w.scope_sub,w.state FROM jwt_v2_receive_records r LEFT JOIN jwt_v2_snapshot_effects e ON e.snapshot_id=r.snapshot_id AND e.record_offset=r.record_offset LEFT JOIN jwt_v2_worksets w ON w.work_id=e.work_id WHERE r.snapshot_id=? AND r.record_offset>? ORDER BY r.record_offset LIMIT 20',snapshotId,offset);if(!rows.length)break;for(const row of rows){offset=row.record_offset;const expected=snapshotEffect(strictJSON(row.record_json));if(row.record_digest===row.effect_digest&&row.state==='APPLIED'&&row.target_json===canonical(expected.target)&&(row.scope_sub??null)===expected.scopeSub)applied++;}}
  if(applied!==meta.totalRecords)return {status:'VERIFIED',publicationPending:true,snapshotId};
  const [g,clear]=this.store.guard("SELECT 1 FROM jwt_v2_receive_snapshots WHERE snapshot_id=? AND status IN('VERIFIED','APPLIED')",[snapshotId]);
  const [pending,pendingClear]=this.store.guard("SELECT 1 FROM jwt_v2_receive_requests WHERE request_id=? AND status IN('PENDING','COMPLETE')",[meta.requestId]);
  await this.store.batch([g,pending,this.store.stmt("UPDATE jwt_v2_receive_snapshots SET status='APPLIED' WHERE snapshot_id=?",snapshotId),this.store.stmt("UPDATE jwt_v2_receive_requests SET status='COMPLETE' WHERE request_id=? AND status='PENDING'",meta.requestId),
   this.store.stmt('INSERT INTO jwt_v2_event_streams(source_app,target_app,stream,owner_epoch,contiguous_through,highest_seen) VALUES(?,?,?,?,?,?) ON CONFLICT(source_app,target_app,stream,owner_epoch) DO UPDATE SET contiguous_through=max(contiguous_through,excluded.contiguous_through),highest_seen=max(highest_seen,excluded.highest_seen)',meta.ownerApp,meta.recipientApp,meta.stream,meta.ownerEpoch,meta.coveredThrough,meta.coveredThrough),pendingClear,clear]);
  return {status:'APPLIED',publicationPending:false,snapshotId,coveredThrough:meta.coveredThrough};
 }
}

const REPLAY='schema env requestId ownerApp recipientApp stream ownerEpoch mode coveredThrough events digest nextPageToken'.split(' ');
export async function encodeEventReplay({request,events,coveredThrough,ownerEpoch,config,streams,dependencies}){
 validateReconcileRequest(request,config);requireThat(request.pageToken===null&&Array.isArray(events)&&events.length<=20&&safeInt(coveredThrough),'INVALID_EVENT_REPLAY',409);
 requireThat(ascii(ownerEpoch)&&streams.get(request.stream)?.has(ownerEpoch)&&(request.ownerEpoch===ownerEpoch||request.ownerEpoch===null&&config.genesisEpoch===ownerEpoch),'RECONCILIATION_REQUIRED',409);
 let previous=0;
 for(const event of events){
  await validateEvent(event,{env:config.env,targetApp:config.recipientApp,streams,dependencies});
  requireThat(event.ownerEpoch===ownerEpoch&&event.stream===request.stream&&event.sequence>previous&&event.sequence<=coveredThrough&&request.missingRanges.some(([first,last])=>event.sequence>=first&&event.sequence<=last),'EVENT_REPLAY_RANGE_CONFLICT',409);previous=event.sequence;
 }
 const reply={schema:2,env:request.env,requestId:request.requestId,ownerApp:request.ownerApp,recipientApp:request.recipientApp,stream:request.stream,ownerEpoch,mode:'EVENTS',coveredThrough,events,nextPageToken:null};
 reply.digest=await domainDigest('uaa-event-replay-v2',reply);const raw=canonical(reply);requireThat(bytes(raw).length<=65536,'SNAPSHOT_REQUIRED',409);return raw;
}
export async function verifyEventReplay({raw,request,config,streams,dependencies}){
 validateReconcileRequest(request,config);const reply=exact(strictJSON(raw),REPLAY);
 requireThat(reply.schema===2&&reply.env===request.env&&reply.requestId===request.requestId&&reply.ownerApp===request.ownerApp&&reply.recipientApp===request.recipientApp&&reply.stream===request.stream&&reply.mode==='EVENTS'&&reply.nextPageToken===null&&HEX.test(reply.digest),'INVALID_EVENT_REPLAY',409);
 const encoded=await encodeEventReplay({request,events:reply.events,coveredThrough:reply.coveredThrough,ownerEpoch:reply.ownerEpoch,config,streams,dependencies});
 requireThat(encoded===(typeof raw==='string'?raw:new TextDecoder('utf-8',{fatal:true}).decode(raw)),'EVENT_REPLAY_DIGEST_OR_WIRE',409);
 return {events:reply.events,sourceWatermark:reply.coveredThrough,automaticCoverage:false};
}
export async function persistEventReplay({store,request,raw,guard,config,streams,dependencies}){
 const old=await store.first('SELECT * FROM jwt_v2_replay_captures WHERE request_id=?',request.requestId);
 if(old){requireThat(old.request_binding===requestBinding(request),'RECONCILE_REQUEST_CONFLICT',409);await verifyEventReplay({raw:old.reply_json,request,config,streams,dependencies});return old.reply_json;}
 requireThat(guard&&typeof guard.sql==='string'&&Array.isArray(guard.args),'OWNING_CAPTURE_GUARD_REQUIRED',503);
 await verifyEventReplay({raw,request,config,streams,dependencies});
 const [g,clear]=store.guard(guard.sql,guard.args);
 await store.batch([g,store.stmt('INSERT INTO jwt_v2_replay_captures VALUES(?,?,?)',request.requestId,requestBinding(request),raw),clear]);
 return raw;
}
