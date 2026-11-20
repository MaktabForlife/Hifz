import {requireThat} from './codec.mjs';
// Exact actual-view gaps beyond the preserved 0028/0029 native queue triggers.
export function profileSourcePrerequisites({registry,available}){
 if(registry.app!=='academy'||!registry.rules.hifz_profile_sync||!available.hifz_profile_sync)return '';
 for(const [table,fields] of Object.entries({accounts:['account_id'],account_credentials:['account_id','credential_epoch'],academy_settings:['setting_key','setting_value'],activities:['activity_key','active','lifecycle']}))requireThat(fields.every(c=>available[table]?.includes(c)),'HIFZ_PROFILE_PROJECTION_INPUT_MISSING',503);
 const advance="UPDATE hifz_profile_sync SET revision=revision+1,attempts=0,next_attempt_at=0,last_error_code=NULL,updated_at=CURRENT_TIMESTAMP";
 const statements=[];
 for(const verb of ['INSERT','UPDATE','DELETE']){
  const rows=verb==='UPDATE'?['OLD','NEW']:[verb==='DELETE'?'OLD':'NEW'];
  statements.push('CREATE TRIGGER jwt_v2_hifz_profile_setting_'+verb.toLowerCase()+' AFTER '+verb+" ON academy_settings WHEN "+rows.map(r=>r+".setting_key='HifzProfileActivityKey'").join(' OR ')+' BEGIN '+advance+'; END;');
 }
 for(const verb of ['INSERT','DELETE']){
  const row=verb==='INSERT'?'NEW':'OLD';
  statements.push('CREATE TRIGGER jwt_v2_hifz_profile_activity_'+verb.toLowerCase()+' AFTER '+verb+' ON activities WHEN '+row+".activity_key=(SELECT setting_value FROM academy_settings WHERE setting_key='HifzProfileActivityKey') BEGIN "+advance+'; END;');
  statements.push('CREATE TRIGGER jwt_v2_hifz_profile_credential_'+verb.toLowerCase()+' AFTER '+verb+' ON account_credentials BEGIN '+advance+' WHERE account_id='+row+'.account_id; END;');
 }
 statements.push("CREATE TRIGGER jwt_v2_hifz_profile_activity_key AFTER UPDATE OF activity_key ON activities WHEN OLD.activity_key IS NOT NEW.activity_key COLLATE BINARY AND (OLD.activity_key=(SELECT setting_value FROM academy_settings WHERE setting_key='HifzProfileActivityKey') OR NEW.activity_key=(SELECT setting_value FROM academy_settings WHERE setting_key='HifzProfileActivityKey')) BEGIN "+advance+'; END;');
 return statements.join('\n');
}
