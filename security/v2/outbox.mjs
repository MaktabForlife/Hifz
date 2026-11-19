import {strictJSON,canonical,digest,requireThat,safeInt,uuid,ascii} from './codec.mjs';
export async function materialiseNativeEvent(store,{changeId,targetApp}){
 requireThat(store.app==='academy'&&['studio','hifz'].includes(targetApp)&&safeInt(changeId,1),'INVALID_OUTBOX_OWNER',403);
 const pending=await store.first('SELECT * FROM jwt_v2_native_outbox WHERE change_id=? AND target_app=?',changeId,targetApp);
 requireThat(pending,'OUTBOX_ITEM_UNKNOWN',503);if(pending.event_json)return strictJSON(pending.event_json);
 const change=await store.first('SELECT * FROM jwt_v2_authority_changes WHERE change_id=?',changeId);
 requireThat(change&&uuid(change.operation_id)&&change.target_json,'NATIVE_CAPTURE_INCOMPLETE',503);
 const stream=await store.first('SELECT * FROM jwt_v2_sender_streams WHERE target_app=? AND stream=?',targetApp,'account-security');
 requireThat(stream&&safeInt(stream.next_sequence+1,1),'OUTBOX_STREAM_UNAVAILABLE',503);
 const target=strictJSON(change.target_json);
 const event={schema:2,env:store.env,sourceApp:'academy',targetApp,eventId:crypto.randomUUID(),operationId:change.operation_id,stream:stream.stream,ownerEpoch:stream.owner_epoch,sequence:stream.next_sequence,sub:change.sub,kind:change.event_kind,target,committedAt:change.created_at,commitRef:'native-change:'+changeId};
 event.digest=await digest(event);
 const [guard,clear]=store.guard('SELECT 1 FROM jwt_v2_native_outbox n JOIN jwt_v2_sender_streams s ON s.target_app=n.target_app WHERE n.change_id=? AND n.target_app=? AND n.event_json IS NULL AND s.stream=? AND s.owner_epoch=? AND s.next_sequence=?',[changeId,targetApp,stream.stream,stream.owner_epoch,stream.next_sequence]);
 try{
  await store.batch([guard,
   store.stmt('UPDATE jwt_v2_sender_streams SET next_sequence=next_sequence+1 WHERE target_app=? AND stream=?',targetApp,stream.stream),
   store.stmt('UPDATE jwt_v2_native_outbox SET event_json=?,digest=? WHERE change_id=? AND target_app=?',canonical(event),event.digest,changeId,targetApp),
   store.stmt('INSERT INTO jwt_v2_outbox(event_id,event_json,digest,target_app) VALUES(?,?,?,?)',event.eventId,canonical(event),event.digest,targetApp),clear]);
  return event;
 }catch(error){
  const won=await store.first('SELECT event_json FROM jwt_v2_native_outbox WHERE change_id=? AND target_app=?',changeId,targetApp);
  if(won?.event_json)return strictJSON(won.event_json);throw error;
 }
}

// Additive metadata only. The scheduled delivery pump is not wired or enabled here.
export const outboxSchemaSQL=[
 'CREATE TABLE IF NOT EXISTS jwt_v2_delivery_streams(target_app TEXT NOT NULL,stream TEXT NOT NULL,last_selected_tick INTEGER NOT NULL DEFAULT 0 CHECK(last_selected_tick>=0 AND last_selected_tick<=9007199254740991),PRIMARY KEY(target_app,stream));',
 'CREATE INDEX IF NOT EXISTS jwt_v2_delivery_fair ON jwt_v2_delivery_streams(last_selected_tick,target_app,stream);',
 "CREATE INDEX IF NOT EXISTS jwt_v2_outbox_due_stream ON jwt_v2_outbox(state,target_app,json_extract(event_json,'$.stream'),next_attempt_at);",
 "INSERT INTO jwt_v2_delivery_streams(target_app,stream) SELECT DISTINCT target_app,json_extract(event_json,'$.stream') FROM jwt_v2_outbox WHERE json_valid(event_json) AND json_type(event_json,'$.stream')='text' ON CONFLICT(target_app,stream) DO NOTHING;",
 "CREATE TRIGGER IF NOT EXISTS jwt_v2_outbox_register_stream AFTER INSERT ON jwt_v2_outbox WHEN json_valid(NEW.event_json) AND json_type(NEW.event_json,'$.stream')='text' BEGIN INSERT INTO jwt_v2_delivery_streams(target_app,stream) VALUES(NEW.target_app,json_extract(NEW.event_json,'$.stream')) ON CONFLICT(target_app,stream) DO NOTHING; END;"
].join('\n');

export function retryDelaySeconds(attempt,{jitter=({maxJitter})=>maxJitter?crypto.getRandomValues(new Uint32Array(1))[0]%(maxJitter+1):0}={}){
 requireThat(safeInt(attempt,1),'OUTBOX_ATTEMPT_EXHAUSTED',503);
 const base=attempt>=5?900:60*2**(attempt-1);
 // Positive bounded jitter never retries before the 60/120/240/480-second base.
 // At the 900-second cap it is zero; prior jitter retains phase dispersion.
 const maxJitter=Math.min(30,Math.floor(base/10),900-base),extra=jitter({attempt,base,maxJitter});
 requireThat(safeInt(extra)&&extra<=maxJitter,'INVALID_OUTBOX_JITTER',503);
 return base+extra;
}
function freezeEvent(value){
 if(value&&typeof value==='object'){for(const child of Object.values(value))freezeEvent(child);Object.freeze(value);}
 return value;
}
export async function deliverOutbox(store,{sendAuthenticated,now,limit=20,jitter}){
 requireThat(store.app==='academy'&&typeof sendAuthenticated==='function'&&safeInt(now)&&safeInt(limit,1)&&limit<=50,'INVALID_OUTBOX_PUMP',503);
 let applied=0,attempted=0,selected=0;
 // One selected row per pass; the durable logical tick makes fairness work even
 // when limit=1, calls share a timestamp, or fresh rows arrive in a busy stream.
 while(selected<50&&attempted<limit){
  const stream=await store.first("SELECT s.target_app,s.stream FROM jwt_v2_delivery_streams s WHERE EXISTS(SELECT 1 FROM jwt_v2_outbox o WHERE o.state='PENDING' AND o.target_app=s.target_app AND json_extract(o.event_json,'$.stream')=s.stream AND o.next_attempt_at<=?) ORDER BY s.last_selected_tick,s.target_app,s.stream LIMIT 1",now);
  if(!stream)break;
  selected++;
  const item=await store.first("SELECT * FROM jwt_v2_outbox WHERE state='PENDING' AND target_app=? AND json_extract(event_json,'$.stream')=? AND next_attempt_at<=? ORDER BY next_attempt_at,rowid LIMIT 1",stream.target_app,stream.stream,now);
  if(!item)continue;
  const event=freezeEvent(strictJSON(item.event_json));
  requireThat(event.eventId===item.event_id&&event.digest===item.digest&&event.env===store.env&&event.sourceApp==='academy'&&event.targetApp===stream.target_app&&event.stream===stream.stream,'OUTBOX_BINDING_CONFLICT',503);
  const attempt=item.attempts+1;
  requireThat(safeInt(item.attempts)&&safeInt(attempt,1),'OUTBOX_ATTEMPT_EXHAUSTED',503);
  const delay=retryDelaySeconds(attempt,{jitter}),nextAttempt=now+delay;
  requireThat(safeInt(nextAttempt),'OUTBOX_TIME_EXHAUSTED',503);
  const [guard,clear]=store.guard("SELECT 1 FROM jwt_v2_outbox WHERE event_id=? AND digest=? AND event_json=? AND state='PENDING' AND attempts=? AND next_attempt_at<=?",[item.event_id,item.digest,item.event_json,item.attempts,now]);
  try{
   await store.batch([guard,
    store.stmt('UPDATE jwt_v2_outbox SET attempts=?,next_attempt_at=? WHERE event_id=? AND digest=?',attempt,nextAttempt,item.event_id,item.digest),
    store.stmt('UPDATE jwt_v2_delivery_streams SET last_selected_tick=(SELECT max(last_selected_tick)+1 FROM jwt_v2_delivery_streams) WHERE target_app=? AND stream=?',stream.target_app,stream.stream),clear]);
  }catch(error){
   const current=await store.first('SELECT state,attempts,next_attempt_at FROM jwt_v2_outbox WHERE event_id=?',item.event_id);
   if(current&&(current.state!=='PENDING'||current.attempts!==item.attempts||current.next_attempt_at>now))continue;
   throw error;
  }
  attempted++;
  try{
   // The transport creates fresh authenticated headers for every invocation.
   // Only immutable event bytes, not a persisted nonce/time/signature, are reused.
   const reply=await sendAuthenticated(event,Object.freeze({eventJSON:item.event_json,attempt,now,targetApp:stream.target_app,stream:stream.stream}));
   const matches=reply?.schema===2&&Array.isArray(reply.results)?reply.results.filter(r=>r.eventId===item.event_id&&r.digest===item.digest):[];
   const result=matches.length===1?matches[0]:null;
   if(result?.status==='APPLIED'&&ascii(result.appliedRef,128)){
    const changed=await store.stmt("UPDATE jwt_v2_outbox SET state='APPLIED' WHERE event_id=? AND digest=? AND state='PENDING'",item.event_id,item.digest).run();
    applied+=Number(changed.meta?.changes||0);
   }
  }catch{
   // No message/body/credential is logged; eligibility was committed before send.
   // A timeout or failed transport is not an application acknowledgement.
  }
 }
 return {attempted,applied};
}
