import {canonical,requireThat} from './codec.mjs';

export const sharedEntrySchemaSQL=[
 'CREATE TABLE IF NOT EXISTS jwt_v2_shared_account_baselines(sub TEXT PRIMARY KEY,ce INTEGER NOT NULL,ae INTEGER NOT NULL,owner_epoch TEXT NOT NULL,coverage INTEGER NOT NULL,snapshot_id TEXT NOT NULL REFERENCES jwt_v2_receive_snapshots(snapshot_id));',
 'CREATE TABLE IF NOT EXISTS jwt_v2_shared_snapshot_heads(owner_epoch TEXT PRIMARY KEY,coverage INTEGER NOT NULL,captured_at INTEGER NOT NULL,snapshot_id TEXT NOT NULL REFERENCES jwt_v2_receive_snapshots(snapshot_id));',
 'CREATE TABLE IF NOT EXISTS jwt_v2_shared_entry_families(sid TEXT PRIMARY KEY,tx TEXT UNIQUE NOT NULL);',
 'CREATE TABLE IF NOT EXISTS jwt_v2_shared_entry_retirements(prior_sid TEXT PRIMARY KEY,successor_sid TEXT NOT NULL,covered INTEGER NOT NULL DEFAULT 0 CHECK(covered IN(0,1)));',
 'CREATE INDEX IF NOT EXISTS jwt_v2_shared_entry_retirements_successor ON jwt_v2_shared_entry_retirements(successor_sid,covered);'
].join('\n');

export function sharedBaselineHeadPlan(store,metadata){
 if(metadata.schema!==4||metadata.stream!=='account-security')return [];
 return [store.stmt("INSERT INTO jwt_v2_shared_snapshot_heads VALUES(?,?,?,?) ON CONFLICT(owner_epoch) DO UPDATE SET coverage=excluded.coverage,captured_at=excluded.captured_at,snapshot_id=excluded.snapshot_id WHERE excluded.coverage>jwt_v2_shared_snapshot_heads.coverage OR excluded.coverage=jwt_v2_shared_snapshot_heads.coverage AND excluded.captured_at>jwt_v2_shared_snapshot_heads.captured_at",metadata.ownerEpoch,metadata.coveredThrough,metadata.createdAt,metadata.snapshotId)];
}

export function sharedAccountSelector(recipient){
 requireThat(['studio','hifz'].includes(recipient),'SHARED_BASELINE_DIRECTION_REQUIRED',503);
 const eligible=recipient==='studio'
  ?"NOT EXISTS(SELECT 1 FROM website_platform_admissions p WHERE p.account_id=n.account_id AND p.active=0)"
  :"EXISTS(SELECT 1 FROM hifz_profile_sync q JOIN hifz_profile_sync_projection p USING(account_id) WHERE q.account_id=n.account_id AND p.active=1)";
 return {bucket:'accountBaselines',sql:"SELECT json_object('type','accountBaseline','sub',n.account_id,'ce',c.credential_epoch,'ae',coalesce(a.ae,1)) record_json FROM accounts n JOIN account_credentials c ON c.account_id=n.account_id LEFT JOIN jwt_v2_accounts a ON a.sub=n.account_id WHERE n.active=1 AND c.pin_setup=1 AND (a.sub IS NULL OR a.active=1 AND a.ce=c.credential_epoch) AND "+eligible+" LIMIT 10001",args:[]};
}

export function sharedAccountBaselinePlan(store,{record,metadata,workId,now}){
 requireThat(['studio','hifz'].includes(store.app)&&metadata.schema===4&&metadata.recipientApp===store.app&&metadata.stream==='account-security'&&record.type==='accountBaseline','SHARED_BASELINE_DIRECTION_REQUIRED',503);
 const {sub,ce,ae}=record,epoch=metadata.ownerEpoch,coverage=metadata.coveredThrough;
 const [verified,clear]=store.guard("SELECT 1 FROM jwt_v2_receive_snapshots p JOIN jwt_v2_receive_records r ON r.snapshot_id=p.snapshot_id WHERE p.snapshot_id=? AND p.metadata_json=? AND p.status IN('VERIFIED','APPLIED') AND r.bucket='accountBaselines' AND r.record_json=?",[metadata.snapshotId,canonical(metadata),canonical(record)]);
 const [monotonic,monotonicClear]=store.guard("SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM jwt_v2_shared_account_baselines WHERE sub=? AND owner_epoch=? AND coverage=? AND (ce<>? OR ae<>?))",[sub,epoch,coverage,ce,ae]);
 return {workId,statements:[
  verified,monotonic,
  store.stmt("INSERT INTO jwt_v2_accounts(sub,ce,ae,le,active,revision) VALUES(?,?,?,0,1,1) ON CONFLICT(sub) DO UPDATE SET ce=excluded.ce,ae=excluded.ae,revision=jwt_v2_accounts.revision+1 WHERE jwt_v2_accounts.active=1 AND (excluded.ce>jwt_v2_accounts.ce OR excluded.ce=jwt_v2_accounts.ce AND excluded.ae>jwt_v2_accounts.ae)",sub,ce,ae),
  store.stmt("INSERT INTO jwt_v2_shared_account_baselines VALUES(?,?,?,?,?,?) ON CONFLICT(sub) DO UPDATE SET ce=excluded.ce,ae=excluded.ae,owner_epoch=excluded.owner_epoch,coverage=excluded.coverage,snapshot_id=excluded.snapshot_id WHERE (excluded.ce>jwt_v2_shared_account_baselines.ce OR excluded.ce=jwt_v2_shared_account_baselines.ce AND excluded.ae>=jwt_v2_shared_account_baselines.ae) AND ((excluded.owner_epoch<>jwt_v2_shared_account_baselines.owner_epoch OR excluded.coverage>jwt_v2_shared_account_baselines.coverage OR excluded.coverage=jwt_v2_shared_account_baselines.coverage AND (SELECT json_extract(metadata_json,'$.createdAt') FROM jwt_v2_receive_snapshots WHERE snapshot_id=excluded.snapshot_id)>(SELECT json_extract(metadata_json,'$.createdAt') FROM jwt_v2_receive_snapshots WHERE snapshot_id=jwt_v2_shared_account_baselines.snapshot_id)) AND (excluded.owner_epoch<>jwt_v2_shared_account_baselines.owner_epoch OR excluded.coverage>=jwt_v2_shared_account_baselines.coverage))",sub,ce,ae,epoch,coverage,metadata.snapshotId),
  store.stmt("INSERT INTO jwt_v2_worksets(work_id,target_json,scope_sub,watermark,created_at,state) VALUES(?,?,?,0,?,'APPLIED')",workId,canonical(record),sub,now),
  monotonicClear,clear
 ]};
}

export const readyAccountSQL="SELECT 1 FROM jwt_v2_shared_account_baselines b JOIN jwt_v2_accounts a ON a.sub=b.sub JOIN jwt_v2_receive_snapshots p ON p.snapshot_id=b.snapshot_id JOIN jwt_v2_shared_snapshot_heads h ON h.owner_epoch=b.owner_epoch AND h.snapshot_id=b.snapshot_id AND h.coverage=b.coverage JOIN jwt_v2_event_streams e ON e.source_app='academy' AND e.target_app=? AND e.stream='account-security' AND e.owner_epoch=b.owner_epoch WHERE b.owner_epoch=? AND b.sub=? AND b.ce=? AND b.ae=? AND a.ce=b.ce AND a.ae=b.ae AND a.active=1 AND p.status='APPLIED' AND json_extract(p.metadata_json,'$.ownerApp')='academy' AND json_extract(p.metadata_json,'$.recipientApp')=e.target_app AND json_extract(p.metadata_json,'$.ownerEpoch')=b.owner_epoch AND json_extract(p.metadata_json,'$.stream')=e.stream AND json_extract(p.metadata_json,'$.coveredThrough')=b.coverage AND e.contiguous_through>=b.coverage AND e.contiguous_through=e.highest_seen";
