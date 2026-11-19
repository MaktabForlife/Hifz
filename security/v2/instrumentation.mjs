/**
 * Per-request instrumentation. Scope/source labels are closed, caller-declared
 * enums, never inferred from SQL text, parameters, keys, accounts or rights.
 * D1 reported rows, SQLite changes and host timings are different measurements.
 * CPU is unavailable unless an explicitly labelled trusted sampler is injected.
 */
const APPS=new Set(['academy','studio','hifz']);
const SCOPES=new Set(['authentication','business']);
const SPAN_SCOPES=new Set(['authentication','business','mixed']);
const SOURCES=new Set(['cloudflare-d1','synthetic','unknown']);
const CPU_SOURCES=new Set(['unavailable','host-process','synthetic','platform-reported']);
const OPERATIONS=new Set(['protected-request','business-request','native-authority-change','sql-first','sql-all','sql-run','sql-batch','sql-exec','r2-control-read','r2-payload-read','r2-other-read','r2-control-write','r2-payload-write','r2-other-write','r2-business-read','r2-business-write']);
const stmtInfo=new WeakMap(),dbInfo=new WeakMap(),bucketInfo=new WeakMap();
const valid=(ok,code='METRIC_LABEL_REJECTED')=>{if(!ok){const e=Error(code);e.code=code;throw e;}};
const count=n=>Number.isSafeInteger(n)&&n>=0;
const clockValue=clock=>{try{const n=clock?.();return typeof n==='number'&&Number.isFinite(n)&&n>=0?n:null;}catch{return null;}};
const emptyMeta=()=>({observations:0,rowsRead:0,rowsReadSamples:0,rowsReadUnavailable:0,rowsWritten:0,rowsWrittenSamples:0,rowsWrittenUnavailable:0,statementChanges:0,statementChangesSamples:0,statementChangesUnavailable:0});
const emptyScope=()=>({statements:0,requestsContainingScope:0,failedRequestsContainingScope:0,metadata:{'cloudflare-d1':emptyMeta(),synthetic:emptyMeta(),unknown:emptyMeta()}});
const emptyR2=()=>({readRequests:0,writeRequests:0,readMisses:0,successfulWrites:0,conditionalWriteRequests:0,preconditionMisses:0,errors:0,controlReads:0,payloadReads:0,otherReads:0,controlWriteRequests:0,payloadWriteRequests:0,otherWriteRequests:0,unconditionalControlWrites:0});
function labels(scope,operation){valid(SPAN_SCOPES.has(scope)&&OPERATIONS.has(operation));}
function addMetadata(bucket,result,unavailable=false){
 bucket.observations++;
 const m=!unavailable&&result&&typeof result==='object'&&result.meta&&typeof result.meta==='object'?result.meta:null;
 for(const [field,sum,samples,missing] of [['rows_read','rowsRead','rowsReadSamples','rowsReadUnavailable'],['rows_written','rowsWritten','rowsWrittenSamples','rowsWrittenUnavailable'],['changes','statementChanges','statementChangesSamples','statementChangesUnavailable']]){
  if(m&&count(m[field])){bucket[sum]+=m[field];bucket[samples]++;}else bucket[missing]++;
 }
}
export class RequestMetrics {
 #app;#clock;#cpuClock;#cpuSource;#emit;#maxSamples;#data;
 constructor({app,clock=()=>performance.now(),cpuClock=null,cpuSource='unavailable',emit=null,maxSamples=64}={}){
  valid(APPS.has(app)&&typeof clock==='function'&&CPU_SOURCES.has(cpuSource)&&count(maxSamples)&&maxSamples<=256);
  valid(cpuClock===null?cpuSource==='unavailable':typeof cpuClock==='function'&&cpuSource!=='unavailable','CPU_SOURCE_REQUIRED');
  valid(emit===null||typeof emit==='function');
  this.#app=app;this.#clock=clock;this.#cpuClock=cpuClock;this.#cpuSource=cpuSource;this.#emit=emit;this.#maxSamples=maxSamples;
  this.#data={app,classification:'Caller-declared purpose; SQL text and parameters are never inspected or logged.',
   sql:{requests:0,statements:0,failedRequests:0,statementCountUnavailable:0,authentication:emptyScope(),business:emptyScope()},
   r2:{authentication:emptyR2(),business:emptyR2()},timings:{},emitFailures:0};
 }
 #event(event){
  // Only module-created numeric/enum events reach the sink; payloads never do.
  if(this.#emit)try{this.#emit(Object.freeze({...event,app:this.#app}));}catch{this.#data.emitFailures++;}
 }
 async measure({scope,operation},fn){
  labels(scope,operation);valid(typeof fn==='function','MEASUREMENT_CALLBACK_REQUIRED');
  const wallStart=clockValue(this.#clock),cpuStart=clockValue(this.#cpuClock);let outcome='ok';
  try{return await fn();}catch(error){outcome='error';throw error;}
  finally{
   const end=clockValue(this.#clock),cpuEnd=clockValue(this.#cpuClock),wallMs=wallStart!==null&&end!==null&&end>=wallStart?end-wallStart:null;
   const cpuMicros=cpuStart!==null&&cpuEnd!==null&&cpuEnd>=cpuStart?cpuEnd-cpuStart:null;
   const key=scope+':'+operation,record=this.#data.timings[key]||(this.#data.timings[key]={scope,operation,count:0,errors:0,wallMs:0,wallUnavailable:0,cpuMicros:0,cpuUnavailable:0,cpuSource:this.#cpuSource,samples:[],droppedSamples:0});
   record.count++;if(outcome==='error')record.errors++;if(wallMs===null)record.wallUnavailable++;else record.wallMs+=wallMs;
   if(cpuMicros===null)record.cpuUnavailable++;else record.cpuMicros+=cpuMicros;
   const sample={outcome,wallMs,cpuMicros};if(record.samples.length<this.#maxSamples)record.samples.push(sample);else record.droppedSamples++;
   this.#event({kind:'timing',scope,operation,outcome,wallMs,cpuMicros,cpuSource:this.#cpuSource});
  }
 }
 sqlRequest({entries,result=null,error=false,first=false,unknownStatements=false}){
  valid(Array.isArray(entries)&&entries.length>0);
  for(const e of entries)valid(SCOPES.has(e.scope)&&SOURCES.has(e.metadataSource));
  const sql=this.#data.sql;sql.requests++;if(error)sql.failedRequests++;
  if(unknownStatements)sql.statementCountUnavailable++;else sql.statements+=entries.length;
  const represented=new Set(entries.map(e=>e.scope));
  for(const scope of represented){sql[scope].requestsContainingScope++;if(error)sql[scope].failedRequestsContainingScope++;}
  const results=Array.isArray(result)?result:[result];
  for(let i=0;i<entries.length;i++){
   const entry=entries[i],scope=sql[entry.scope];if(!unknownStatements)scope.statements++;
   // D1 first() returns a row, not D1Result metadata. Never trust a row.meta.
   addMetadata(scope.metadata[entry.metadataSource],results[i],Boolean(error||first||unknownStatements));
  }
  this.#event({kind:'sql',scopes:[...represented].sort(),requestCount:1,statementCount:unknownStatements?null:entries.length,outcome:error?'error':'ok'});
 }
 r2Request({scope,type,method,result,error=false,conditional=false}){
  valid(SCOPES.has(scope)&&['control','payload','other','business'].includes(type)&&['get','put'].includes(method));
  const r=this.#data.r2[scope];if(method==='get'){r.readRequests++;if(type==='control')r.controlReads++;else if(type==='payload')r.payloadReads++;else r.otherReads++;if(!error&&result===null)r.readMisses++;}
  else{r.writeRequests++;if(type==='control')r.controlWriteRequests++;else if(type==='payload')r.payloadWriteRequests++;else r.otherWriteRequests++;if(conditional)r.conditionalWriteRequests++;if(type==='control'&&!conditional)r.unconditionalControlWrites++;if(!error){if(result===null)r.preconditionMisses++;else r.successfulWrites++;}}
  if(error)r.errors++;
  this.#event({kind:'r2',scope,type,method,outcome:error?'error':method==='put'&&result===null?'precondition-miss':result===null?'miss':'ok',conditional:Boolean(conditional)});
 }
 snapshot(){
  return structuredClone({...this.#data,interpretation:{
   rowMetadata:'Only rows_read/rows_written actually returned by the declared adapter are counted. Unavailable metadata is not zero.',
   changes:'Statement changes are driver-reported logical changes, not total trigger writes or billed Cloudflare rows.',
   requestCounts:'sql.requests is physical requests. Per-scope requestsContainingScope may overlap for a mixed batch; do not sum them.',
   timing:'Wall latency is not Worker CPU. Optional CPU samples retain their declared provenance; overlapping spans must not be summed as request CPU.',
   privacy:'No SQL strings/params, R2 keys/bodies, IDs, PINs, tokens or rights are stored in metric labels/events.',
   lifetime:'Use a fresh collector per request or measured operation; concurrent background work needs its own collector.'
  }});
 }
}
export function instrumentD1(db,metrics,{scope,metadataSource='unknown'}={}){
 valid(metrics instanceof RequestMetrics&&SCOPES.has(scope)&&SOURCES.has(metadataSource));db=dbInfo.get(db)?.native||db;const descriptor={scope,metadataSource};
 function statement(native){
  if(stmtInfo.has(native))return native;
  const proxy=new Proxy(native,{get(target,key){
   if(key==='bind')return (...args)=>statement(target.bind(...args));
   if(['first','all','run'].includes(key))return (...args)=>metrics.measure({scope,operation:'sql-'+key},async()=>{
    try{const result=await target[key](...args);metrics.sqlRequest({entries:[descriptor],result,first:key==='first'});return result;}
    catch(error){metrics.sqlRequest({entries:[descriptor],error:true,first:key==='first'});throw error;}
   });
   const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;
  }});
  stmtInfo.set(proxy,{native,descriptor});return proxy;
 }
 let proxy;
 proxy=new Proxy(db,{get(target,key){
  if(key==='prepare')return sql=>statement(target.prepare(sql));
  if(key==='withSession')return (...args)=>{const next=target.withSession(...args);return next===target?proxy:instrumentD1(next,metrics,{scope,metadataSource});};
  if(key==='batch')return list=>{
   valid(Array.isArray(list)&&list.length>0,'INVALID_METRIC_BATCH');
   const entries=list.map(s=>stmtInfo.get(s)?.descriptor||descriptor),actual=list.map(s=>stmtInfo.get(s)?.native||s),spanScope=new Set(entries.map(e=>e.scope)).size>1?'mixed':entries[0].scope;
   return metrics.measure({scope:spanScope,operation:'sql-batch'},async()=>{
    try{const result=await target.batch(actual);metrics.sqlRequest({entries,result});return result;}
    catch(error){metrics.sqlRequest({entries,error:true});throw error;}
   });
  };
  if(key==='exec')return sql=>metrics.measure({scope,operation:'sql-exec'},async()=>{
   try{const result=await target.exec(sql);metrics.sqlRequest({entries:[descriptor],result,unknownStatements:true});return result;}
   catch(error){metrics.sqlRequest({entries:[descriptor],error:true,unknownStatements:true});throw error;}
  });
  const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;
 }});
 dbInfo.set(proxy,{native:db});return proxy;
}
export function instrumentR2(bucket,metrics,{scope,authPrefix=null}={}){
 valid(metrics instanceof RequestMetrics&&SCOPES.has(scope));bucket=bucketInfo.get(bucket)?.native||bucket;if(scope==='authentication')valid(typeof authPrefix==='string'&&/^auth-private\/v2\/(?:production|feature)\/(?:academy|studio|hifz)\/[A-Za-z0-9_-]{1,128}\/$/.test(authPrefix),'AUTH_METRIC_PREFIX_REQUIRED');
 const typeFor=key=>{
  if(scope==='business')return 'business';
  if(typeof key!=='string'||!key.startsWith(authPrefix))return 'other';
  const suffix=key.slice(authPrefix.length);if(suffix.startsWith('rights/'))return 'payload';
  if(suffix==='control/app'||suffix.startsWith('control/resource/')||suffix.startsWith('security/session/'))return 'control';return 'other';
 };
 const proxy=new Proxy(bucket,{get(target,key){
  if(key==='get'||key==='put')return (...args)=>{
   const type=typeFor(args[0]),operation='r2-'+type+'-'+(key==='get'?'read':'write'),conditional=key==='put'&&Boolean(args[2]?.onlyIf);
   return metrics.measure({scope,operation},async()=>{
    try{const result=await target[key](...args);metrics.r2Request({scope,type,method:key,result,conditional});return result;}
    catch(error){metrics.r2Request({scope,type,method:key,error:true,conditional});throw error;}
   });
  };
  const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;
 }});
 bucketInfo.set(proxy,{native:bucket});return proxy;
}
export function cacheMetricDelta(before,after){
 const result={};for(const key of ['controlReads','payloadReads','conditionalWrites']){
  valid(count(before?.[key])&&count(after?.[key])&&after[key]>=before[key],'INVALID_METRIC_WINDOW');result[key]=after[key]-before[key];
 }return result;
}
export function measurementWindow(before,after,{authorisationOutcome='not-recorded',immutableMemoHit=false,independentResourceControls=0}={}){
 valid(['allowed','denied','not-recorded'].includes(authorisationOutcome)&&typeof immutableMemoHit==='boolean'&&count(independentResourceControls),'INVALID_METRIC_WINDOW');
 const difference=(a,b)=>{valid(count(a)&&count(b)&&b>=a,'INVALID_METRIC_WINDOW');return b-a;};
 const auth=after?.sql?.authentication,beforeAuth=before?.sql?.authentication,r2=after?.r2?.authentication,beforeR2=before?.r2?.authentication;
 const result={
  authSqlRequests:difference(beforeAuth?.requestsContainingScope,auth?.requestsContainingScope),
  authSqlStatements:difference(beforeAuth?.statements,auth?.statements),
  businessSqlStatements:difference(before?.sql?.business?.statements,after?.sql?.business?.statements),
  authR2ReadRequests:difference(beforeR2?.readRequests,r2?.readRequests),authR2WriteRequests:difference(beforeR2?.writeRequests,r2?.writeRequests),
  businessR2ReadRequests:difference(before?.r2?.business?.readRequests,after?.r2?.business?.readRequests),
  controlReads:difference(beforeR2?.controlReads,r2?.controlReads),payloadReads:difference(beforeR2?.payloadReads,r2?.payloadReads),
  controlWriteRequests:difference(beforeR2?.controlWriteRequests,r2?.controlWriteRequests)
 };
 result.matchesTwoControlNoSqlShape=result.authSqlRequests===0&&result.authSqlStatements===0&&result.controlReads===2&&result.payloadReads===0&&result.authR2ReadRequests===2&&result.authR2WriteRequests===0;
 result.authorisationOutcome=authorisationOutcome;result.immutableMemoHit=immutableMemoHit;result.independentResourceControls=independentResourceControls;
 result.matchesEligibleTwoControlMemoHit=result.matchesTwoControlNoSqlShape&&authorisationOutcome==='allowed'&&immutableMemoHit&&independentResourceControls===0;
 result.qualification='An isolated window with caller-supplied outcome/memo evidence, not independent authorisation proof. Extra resource policies, payload misses, business SQL and provider capacity/cost need separate evidence.';return result;
}
