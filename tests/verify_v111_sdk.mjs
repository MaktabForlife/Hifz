import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {createBrowserSession} from '../security/v2/browser-session.mjs';
import {createBrowserDrafts} from '../security/v2/browser-drafts.mjs';
import {createHifzClient} from '../js/v111-client.mjs';
let passed=0,failed=0;
async function check(name,fn){try{await fn();passed++;}catch(e){failed++;console.error('FAIL:',name,e.code||e.message);}}
const now=1795080000000,uuid=n=>'00000000-0000-4000-8000-'+String(n).padStart(12,'0');
const context={app:'hifz',sub:'canonical-fixture',sid:uuid(1),psid:uuid(2),bsid:uuid(3),bv:1,ce:1,ae:1,le:0,sv:1,ue:0};
const storeRows=new Map(),store={async transaction(mode,fn){return fn({async get(id){return structuredClone(storeRows.get(id));},async all(){return [...storeRows.values()].map(v=>structuredClone(v));},async put(row){storeRows.set(row.id,structuredClone(row));},async delete(id){storeRows.delete(id);}});}};
let session,mode='success',sent=[],effects=0,masked=true;
const key=Buffer.alloc(32,7).toString('base64url');
const dto=purpose=>({contractVersion:2,success:true,state:'UNLOCKED',context,serverNowMs:now,originalExpiresAtMs:now+604800000,idleUntilMs:now+5400000,validationDeadlineMs:now+900000,draftGeneration:1,env:'production',csrf:'synthetic-'+purpose,csrfExpiresAtMs:now+60000,intent:{id:uuid(10),kind:purpose,generation:1,expiresAtMs:now+60000},businessIntent:{id:uuid(11),kind:'business',generation:1,expiresAtMs:now+60000},csrfByPurpose:{business:'synthetic-business'}});
const headers=()=>({'Content-Type':'application/json','X-UAA-Contract':'2','X-UAA-Context':Buffer.from(JSON.stringify(context)).toString('base64url'),'X-UAA-Server-Now-Ms':String(now)});
const transport=async(url,init)=>{
 const path=new URL(url).pathname,body=init.body?JSON.parse(init.body):{};sent.push({path,method:init.method||'GET',headers:new Headers(init.headers),credentials:init.credentials});
 if(path==='/auth/v2/bootstrap')return new Response(JSON.stringify(dto(body.purpose)));
 if(path==='/auth/v2/draft-key')return new Response(JSON.stringify({...dto('draft-key'),key,capsule:{synthetic:'capsule'},draftGeneration:body.draftGeneration,originalExpiresAtMs:body.originalExpiresAtMs}));
 if(path.startsWith('/api/')){
  if(init.method&&init.method!=='GET'){effects++;if(mode==='lost')throw Error('response lost after effects');return new Response(JSON.stringify({id:effects}),{headers:headers()});}
  if(mode==='unavailable')return new Response(JSON.stringify({error:'unavailable'}),{status:503,headers:headers()});
  const rows=path==='/api/sabaq'?[{id:1,student_id:'native-fixture',student_comment:'checked partial effect'}]:[];return new Response(JSON.stringify(rows),{headers:headers()});
 }
 throw Error('Unexpected synthetic endpoint '+path);
};
const drafts=createBrowserDrafts({crypto:webcrypto,store,clock:()=>now,tabId:uuid(50),releaseCapsule:args=>session.draftKey(args)});
session=createBrowserSession({app:'hifz',origin:'https://mahadarwa-hifz.ummabbadacademy.app',fetch:transport,crypto:webcrypto,locks:{async request(name,options,fn){return fn();}},BroadcastChannel:null,clock:()=>now,monotonicClock:()=>0,setTimer:()=>null,clearTimer:()=>{},drafts,onMask:v=>{masked=v;}});
const client=createHifzClient({session,drafts});
await check('real common SDK bootstrap binds encrypted Hifz drafts',async()=>{await session.bootstrap();assert.deepEqual(session.getContext(),context);await drafts.save('hifz:/editor/sabaq:own',{fields:{note:'synthetic-private-note'}});assert.ok(storeRows.size);assert.ok(!JSON.stringify([...storeRows.values()]).includes('synthetic-private-note'));session.reveal(context);assert.equal(masked,false);});
await check('real SDK sends cookie and CSRF transport and native unchanged JSON',async()=>{const rows=await client.request('/sabaq');assert.equal(rows[0].id,1);const last=sent.at(-1);assert.equal(last.credentials,'include');assert.ok(last.headers.has('X-UAA-CSRF'));assert.ok(last.headers.has('X-UAA-Expected-Context'));assert.equal(last.headers.has('Authorization'),false);});
await check('lost response retains encrypted marker with no automatic retry',async()=>{mode='lost';await assert.rejects(()=>client.request('/sabaq',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({date:'2026-11-19',student_comment:'synthetic-private-note'})}),{code:'SAVE_OUTCOME_UNKNOWN'});assert.equal(effects,1);assert.equal((await drafts.recoveryMarker('hifz:/sabaq:own')).state,'SAVE_OUTCOME_UNKNOWN');assert.ok(!JSON.stringify([...storeRows.values()]).includes('synthetic-private-note'));mode='success';await assert.rejects(()=>client.request('/sabaq',{method:'POST',body:'{}'}),{code:'SAVE_OUTCOME_UNKNOWN'});assert.equal(effects,1);});
await check('fresh real SDK reconciliation preserves unknown partial state',async()=>{const result=await client.recover('hifz:/sabaq:own');assert.equal(result.automaticReplayAllowed,false);assert.equal(result.views.journals['/sabaq'][0].student_comment,'checked partial effect');assert.equal((await drafts.recoveryMarker('hifz:/sabaq:own')).state,'SAVE_OUTCOME_UNKNOWN');assert.equal(effects,1);});
await check('failed real SDK reconciliation never becomes empty success',async()=>{mode='unavailable';await assert.rejects(()=>client.recover('hifz:/sabaq:own'));assert.equal((await drafts.recoveryMarker('hifz:/sabaq:own')).state,'SAVE_OUTCOME_UNKNOWN');mode='success';});
await check('real SDK logout clear masks before asynchronous encrypted discard',async()=>{const pending=session.clearAvailable();assert.equal(masked,true);assert.equal(session.getContext(),null);await pending;assert.equal(storeRows.size,0);});
session.dispose();console.log(passed+' passed, '+failed+' failed');if(failed)process.exitCode=1;
