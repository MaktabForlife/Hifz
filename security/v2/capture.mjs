import {requireThat,ascii} from './codec.mjs';
const q=n=>{requireThat(/^[a-z_][a-z0-9_]*$/i.test(n),'INVALID_SCHEMA_IDENTIFIER',503);return '"'+n+'"';};
const lit=s=>"'"+s.replaceAll("'","''")+"'";
const opUUID="lower(hex(randomblob(4)))||'-'||lower(hex(randomblob(2)))||'-4'||substr(lower(hex(randomblob(2))),2,3)||'-8'||substr(lower(hex(randomblob(2))),2,3)||'-'||lower(hex(randomblob(6)))";
export function captureDDL({registry,available,ownerEpoch}){
 requireThat(registry.schema===2&&ascii(ownerEpoch),'INVALID_CAPTURE_CONFIG',503);
 const statements=[],included=[],missing=[];
 for(const [table,rule] of Object.entries(registry.rules)){
  const actual=available[table];
  if(!actual){requireThat(!rule.required,'REQUIRED_AUTHORITY_TABLE_MISSING',503);missing.push(table);continue;}
  requireThat(rule.columns.every(c=>actual.includes(c)),'AUTHORITY_COLUMN_MISMATCH',503);
  if(registry.app==='academy'&&table==='account_credentials'){
   statements.push("CREATE TRIGGER jwt_v2_credential_counter BEFORE UPDATE ON account_credentials WHEN NEW.credential_epoch<OLD.credential_epoch OR (NEW.pin_hash IS NOT OLD.pin_hash AND NEW.credential_epoch<=OLD.credential_epoch) BEGIN SELECT RAISE(ABORT,'jwt_v2_credential_epoch_required'); END;");
  }
  const id=registry.app+':native:'+table,account=rule.accountColumn;
  const subject=row=>rule.identityMapping==='academy-profile-link'?'(SELECT academy_user_id FROM academy_profile_links WHERE student_id='+row+'.id)':account?row+'.'+q(account):'NULL';
  const scope=row=>account?"'ACCOUNT:'||upper(CAST("+subject(row)+" AS TEXT))":"'GLOBAL'";
  for(const verb of ['INSERT','UPDATE','DELETE']){
   const rows=verb==='UPDATE'?['OLD','NEW']:[verb==='DELETE'?'OLD':'NEW'];
   const conditions=[];
   if(verb==='UPDATE')conditions.push('('+rule.columns.map(c=>'OLD.'+q(c)+' IS NOT NEW.'+q(c)).join(' OR ')+')');
   if(rule.identityMapping==='academy-profile-link')conditions.push('('+rows.map(row=>subject(row)+' IS NOT NULL').join(' OR ')+')');
   if(rule.settingFilter){
    const setting=row=>'('+rule.settingFilter.map(k=>row+'.setting_key '+(k.includes('%')?'LIKE ':'=')+lit(k)).join(' OR ')+')';
    conditions.push('('+rows.map(setting).join(' OR ')+')');
   }
   const when=conditions.length?' WHEN '+conditions.join(' AND '):'';let body='';
   for(let i=0;i<rows.length;i++){
    const row=rows[i],different=i===1?scope('OLD')+' IS NOT '+scope('NEW'):'1',condition=' WHERE '+different;
    body+='INSERT INTO jwt_v2_dependencies(id,scope,owner_epoch,revision) SELECT '+lit(id)+','+scope(row)+','+lit(ownerEpoch)+',1'+condition+' ON CONFLICT(id,scope) DO UPDATE SET revision=revision+1; ';
    body+='INSERT INTO jwt_v2_authority_changes(dependency,scope,owner_epoch,revision,source_table,verb,created_at,operation_id,sub) SELECT '+lit(id)+','+scope(row)+','+lit(ownerEpoch)+',revision,'+lit(table)+','+lit(verb)+',unixepoch(),'+opUUID+','+subject(row)+' FROM jwt_v2_dependencies WHERE id='+lit(id)+' AND scope='+scope(row)+' AND '+different+'; ';
    const change="change_id=(SELECT max(change_id) FROM jwt_v2_authority_changes WHERE dependency="+lit(id)+' AND scope='+scope(row)+') AND '+different;
    const current='SELECT * FROM jwt_v2_authority_changes WHERE '+change;
    const canonicalSub=subject(row);
    const credential=registry.app==='academy'&&table==='account_credentials'&&verb==='UPDATE'?'NEW.credential_epoch>OLD.credential_epoch':'0';
    const localDisabled=registry.app==='hifz'&&table==='students'?(verb==='DELETE'?'1':verb==='UPDATE'?'OLD.active<>0 AND NEW.active=0':'0'):'0';
    const disabled=registry.app==='academy'&&table==='accounts'?(verb==='DELETE'?'1':verb==='UPDATE'?'OLD.active<>0 AND NEW.active=0':'0'):'0';
    const hasAccount=account?'EXISTS(SELECT 1 FROM jwt_v2_accounts WHERE sub='+canonicalSub+' COLLATE NOCASE)':'0';
    const accountCe='(SELECT ce FROM jwt_v2_accounts WHERE sub='+canonicalSub+' COLLATE NOCASE)',accountAe='(SELECT ae FROM jwt_v2_accounts WHERE sub='+canonicalSub+' COLLATE NOCASE)';
    // SQLite JSON object member order is explicitly JCS key order for these fixed typed records.
    const dependencyTarget="json_object('deniedActions',json('[]'),'effect','INVALIDATE','id',dependency,'ownerEpoch',owner_epoch,'revision',revision,'type','dependency')";
    const credentialTarget=credential!=='0'?"json_object('newCe',NEW.credential_epoch,'reason',CASE WHEN (NEW.pin_hash IS NULL OR length(trim(NEW.pin_hash))=0) AND NEW.pin_setup=0 THEN 'ADMIN_PIN_RESET' ELSE 'PASSWORD_RESET' END,'sub',NEW.account_id,'type','credentialEpoch')":dependencyTarget;
    const localTarget="json_object('ae',"+accountAe+",'app','hifz','ce',"+accountCe+",'maxLe',(SELECT le FROM jwt_v2_accounts WHERE sub="+canonicalSub+" COLLATE NOCASE),'sub',"+canonicalSub+",'type','localEpoch')";
    const accountTarget="json_object('incidentId',operation_id,'maxAe',"+accountAe+",'maxCe',"+accountCe+",'reason','ACCOUNT_DISABLED','sub',"+canonicalSub+",'type','accountCutoff')";
    body+='UPDATE jwt_v2_authority_changes SET event_kind=CASE WHEN '+credential+" THEN 'credential-epoch-advanced' WHEN ("+disabled+') AND '+hasAccount+" THEN 'account-revoked' WHEN ("+localDisabled+") AND "+hasAccount+" THEN 'local-restriction' ELSE 'authority-updated' END,target_json=CASE WHEN "+credential+' THEN '+credentialTarget+' WHEN ('+disabled+') AND '+hasAccount+' THEN '+accountTarget+' WHEN ('+localDisabled+') AND '+hasAccount+' THEN '+localTarget+' ELSE '+dependencyTarget+' END WHERE '+change+'; ';
    // Current Core security effects share the native facts' transaction, including reset-time revocation.
    if(credential!=='0'){
     body+='INSERT INTO jwt_v2_pin_gates(sub,generation) SELECT NEW.account_id,NEW.credential_epoch WHERE '+credential+' AND '+different+' ON CONFLICT(sub) DO UPDATE SET generation=excluded.generation,failures=0,paused_until=0,reservation=NULL,reservation_until=NULL WHERE generation<excluded.generation; ';
     body+="UPDATE jwt_v2_ceremonies SET status='CANCELLED' WHERE sub=NEW.account_id COLLATE NOCASE AND status IN('PENDING','CODE_ISSUED','GRANTED') AND "+credential+' AND '+different+'; ';
     body+="UPDATE jwt_v2_ceremony_attempts SET status='CANCELLED' WHERE sub=NEW.account_id COLLATE NOCASE AND status IN('ISSUED','RESERVED') AND "+credential+' AND '+different+'; ';
     body+='DELETE FROM jwt_v2_ceremony_reservations WHERE sub=NEW.account_id COLLATE NOCASE AND '+credential+' AND '+different+'; ';
     body+="UPDATE jwt_v2_parents SET state='REVOKED' WHERE sub=NEW.account_id COLLATE NOCASE AND ce<NEW.credential_epoch AND "+credential+' AND '+different+'; ';
    }
    if(credential!=='0')body+='UPDATE jwt_v2_accounts SET ce=NEW.credential_epoch,revision=revision+1 WHERE sub=NEW.account_id COLLATE NOCASE AND ce<NEW.credential_epoch AND '+different+'; ';
    if(localDisabled!=='0')body+='UPDATE jwt_v2_accounts SET active=0,le=le+1,revision=revision+1 WHERE sub='+canonicalSub+' COLLATE NOCASE AND ('+localDisabled+') AND '+different+'; ';
    if(registry.app==='hifz'&&table==='students'&&verb!=='DELETE')body+='UPDATE jwt_v2_accounts SET active=NEW.active WHERE sub='+canonicalSub+' COLLATE NOCASE AND active<>NEW.active AND '+different+'; ';
    if(disabled!=='0'){
     body+='INSERT INTO jwt_v2_cutoffs(sub,ce,ae,operation_id,target_json) SELECT json_extract(target_json,\'$.sub\'),json_extract(target_json,\'$.maxCe\'),json_extract(target_json,\'$.maxAe\'),operation_id,target_json FROM jwt_v2_authority_changes WHERE '+change+" AND event_kind='account-revoked'; ";
     body+='UPDATE jwt_v2_accounts SET active=0,ae=ae+1,revision=revision+1 WHERE sub='+canonicalSub+' COLLATE NOCASE AND ('+disabled+') AND '+different+'; ';
    }
    if(registry.app==='academy'&&table==='accounts'&&verb!=='DELETE')body+='UPDATE jwt_v2_accounts SET active=NEW.active WHERE sub=NEW.account_id COLLATE NOCASE AND active<>NEW.active AND '+different+'; ';
    body+='INSERT INTO jwt_v2_restrictions(restriction_id,target_json,scope_sub,digest,created_at) SELECT operation_id,target_json,sub,NULL,created_at FROM jwt_v2_authority_changes WHERE '+change+'; ';
    body+="INSERT INTO jwt_v2_worksets(work_id,target_json,scope_sub,watermark,created_at,state) SELECT operation_id,target_json,sub,(SELECT COALESCE(max(ordinal),0) FROM jwt_v2_families),created_at,'PENDING' FROM jwt_v2_authority_changes WHERE "+change+'; ';
    const scoped=account?'sub='+canonicalSub+' COLLATE NOCASE':'1';
    const revoked="EXISTS(SELECT 1 FROM ("+current+") change WHERE (change.event_kind='credential-epoch-advanced' AND jwt_v2_families.ce<json_extract(change.target_json,'$.newCe')) OR (change.event_kind='local-restriction' AND jwt_v2_families.ce=json_extract(change.target_json,'$.ce') AND jwt_v2_families.ae=json_extract(change.target_json,'$.ae') AND jwt_v2_families.le<=json_extract(change.target_json,'$.maxLe')) OR (change.event_kind='account-revoked' AND (jwt_v2_families.ce<json_extract(change.target_json,'$.maxCe') OR (jwt_v2_families.ce=json_extract(change.target_json,'$.maxCe') AND jwt_v2_families.ae<=json_extract(change.target_json,'$.maxAe')))))";
    body+="UPDATE jwt_v2_families SET state=CASE WHEN "+revoked+" AND state<>'EXPIRED' THEN 'REVOKED' ELSE state END,authority_ready=0,cr=cr+1 WHERE s_exp>unixepoch() AND "+scoped+' AND '+different+'; ';
    body+="UPDATE jwt_v2_intents SET state='CANCELLED',superseding_operation=(SELECT operation_id FROM jwt_v2_authority_changes WHERE "+change+") WHERE state='ISSUED' AND sid IN(SELECT sid FROM jwt_v2_families WHERE "+scoped+') AND '+different+'; ';
    body+='INSERT INTO jwt_v2_publications(work_id,sid,expected_cr) SELECT change.operation_id,f.sid,f.cr FROM ('+current+') change JOIN jwt_v2_families f ON f.ordinal<=(SELECT watermark FROM jwt_v2_worksets WHERE work_id=change.operation_id) WHERE f.s_exp>unixepoch() AND '+(account?'f.sub='+canonicalSub+' COLLATE NOCASE':'1')+'; ';
    if(registry.app==='academy'){
     const recipients=['studio',...(['accounts','account_credentials','global_role_assignments','role_assignments','activities','academy_teacher_designations'].includes(table)?['hifz']:[])];
     for(const recipient of recipients)body+='INSERT INTO jwt_v2_native_outbox(change_id,target_app) SELECT change_id,'+lit(recipient)+' FROM jwt_v2_authority_changes WHERE '+change+'; ';
    }
   }
   statements.push('CREATE TRIGGER jwt_v2_capture_'+table+'_'+verb.toLowerCase()+' AFTER '+verb+(verb==='UPDATE'?' OF '+rule.columns.map(q).join(','):'')+' ON '+q(table)+when+' BEGIN '+body+' END;');
  }
  included.push(table);
 }
 return {sql:statements.join('\n'),included,missing};
}
export async function inspectCaptureSchema(db){
 const rows=(await db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").all()).results,out={};
 for(const row of rows)out[row.name]=(await db.prepare('PRAGMA table_info('+q(row.name)+')').all()).results.map(c=>c.name);
 return out;
}
export async function nativeFence(db,{academy=false}={}){
 if(!academy)return {pending:false};
 const row=await db.prepare('SELECT version,(SELECT count(*) FROM split_write_fence) pending FROM split_read_state WHERE singleton=1').first();
 requireThat(row,'SPLIT_STATE_UNAVAILABLE',503);return {pending:row.pending!==0,version:row.version};
}
export function assertRegistrySurface({registry,rightsInputs}){
 for(const [table,columns] of Object.entries(rightsInputs)){
  const rule=registry.rules[table];requireThat(rule&&columns.every(c=>rule.columns.includes(c)),'UNCLASSIFIED_AUTHORITY_FIELD',503);
 }
}
