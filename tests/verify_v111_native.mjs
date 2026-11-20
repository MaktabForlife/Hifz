import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createDatabase,d1Database,seedStudent} from './helpers/database.mjs';
import {createHifzV2Handler,HIFZ_V2_ORIGIN,hifzActor} from '../worker/src/hifz-v2.js';
import {guardedHifzDB} from '../worker/src/v111-guarded-db.js';
import {createNativeRuntime} from '../security/v2/native-runtime.mjs';
import nativeWorker,{dispatchNative} from '../worker/src/index.js';
let passed=0,failed=0;
async function check(name,fn){try{await fn();passed++;}catch(e){failed++;console.error('FAIL:',name,e.message);}}
const sqlite=createDatabase();seedStudent(sqlite,'native-fixture',{login_id:'NATIVE1',active:1});seedStudent(sqlite,'other-fixture',{login_id:'OTHER1',active:1});
const DB=d1Database(sqlite),caps=new WeakSet();let nextRole='student',nativeId='native-fixture',guardAllowed=true,authorised=0,guardCalls=0;
const runtime={
 async handle(request){return new Response(JSON.stringify({route:new URL(request.url).pathname}),{headers:{'Content-Type':'application/json'}});},
 async authorise(){authorised++;const cap={binding:{sub:'academy-fixture'},rights:{nativeStudentId:nativeId,role:nextRole},deadline:Math.floor(Date.now()/1000)+900};caps.add(cap);return cap;},
 assertCapability(cap){assert.ok(caps.has(cap));},
 writeGuard(){guardCalls++;return {sql:'SELECT 1 WHERE ?=1',args:[Number(guardAllowed)]};},
 decorate(response){const h=new Headers(response.headers);h.set('X-UAA-Contract','2');return new Response(response.body,{status:response.status,headers:h});}
};
const fetch=createHifzV2Handler({runtimeFactory:async()=>runtime,dispatchNative});
let assetCalls=0;
const env={DB,PROFILE_AUTHORITY:'academy',ASSETS:{async fetch(request){assetCalls++;return new Response(readFileSync(new URL('../index.html',import.meta.url),'utf8'),{headers:{'Content-Type':'text/html'}});}}};
const req=(path,init={})=>new Request(HIFZ_V2_ORIGIN+path,init);
await check('canonical provider alias denied before assets/auth',async()=>{const old=assetCalls;assert.equal((await fetch(new Request('https://ummabbadacademy.hifz-helper.app/'),env)).status,421);assert.equal(assetCalls,old);});
await check('unknown protected and native root paths never get HTML',async()=>{for(const path of ['/api/unknown','/auth/v2/unknown','/internal/anything','/sabaq','/profile','/security/v2/store.mjs','/worker/src/index.js']){const old=assetCalls;assert.equal((await fetch(req(path),env)).status,404,path);assert.equal(assetCalls,old);}});
await check('PIN endpoints and old handoff denied',async()=>{for(const path of ['/auth/login','/auth/register','/auth/lookup','/auth/academy','/internal/academy/handoff','/api/auth/login','/auth/v2/pin'])assert.equal((await fetch(req(path,{method:'POST'}),env)).status,404,path);});
await check('legacy bearer cannot authorise V2 native request',async()=>{const old=authorised;assert.equal((await fetch(req('/api/profile',{headers:{Authorization:'Bearer synthetic'}}),env)).status,401);assert.equal(authorised,old);});
await check('exact C19 routes route to common runtime only',async()=>{assert.equal((await fetch(req('/auth/v2/bootstrap',{method:'POST'}),env)).status,200);assert.equal((await fetch(req('/auth/v2/bootstrap'),env)).status,405);assert.equal((await fetch(req('/internal/auth/v2/events',{method:'POST'}),env)).status,200);});
await check('explicit shell route injects V2 and strict CSP',async()=>{const r=await fetch(req('/NATIVE1'),env);assert.equal(r.status,200);assert.match(await r.text(),/name="hifz-auth-mode" content="v2"/);assert.match(r.headers.get('Content-Security-Policy'),/script-src 'self'/);});
await check('private-source extension and SW not exposed',async()=>{assert.equal((await fetch(req('/config/v111-auth.json'),env)).status,404);assert.equal((await fetch(req('/js/sw.js'),env)).status,404);});
await check('asset fallback HTML cannot masquerade as JS',async()=>assert.equal((await fetch(req('/js/api.js'),env)).status,503));
await check('native mapped profile uses permanent student id and unchanged body',async()=>{const beforeGuard=guardCalls;const r=await fetch(req('/api/profile'),env);assert.equal(guardCalls,beforeGuard);assert.equal(r.status,200);assert.equal((await r.json()).id,'native-fixture');assert.equal(r.headers.get('X-UAA-Contract'),'2');assert.equal(r.headers.get('Access-Control-Allow-Origin'),null);});
await check('unbranded or incomplete capability fails closed',()=>{assert.throws(()=>hifzActor({binding:{sub:'x'},rights:{nativeStudentId:'admin',role:'admin'},deadline:1},runtime));const bad={binding:{sub:'x'},rights:{role:'admin'},deadline:1};caps.add(bad);assert.throws(()=>hifzActor(bad,runtime));});
await check('student cannot read another journal or plans',async()=>{for(const path of ['/api/sabaq?student_id=other-fixture','/api/plans?student_id=other-fixture'])assert.equal((await fetch(req(path),env)).status,403);});
await check('native effect is fenced and keeps native id',async()=>{const r=await fetch(req('/api/reflections',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({date:'2026-11-19',reflection:'synthetic'})}),env);assert.equal(r.status,200);assert.equal(sqlite.prepare('SELECT student_id FROM reflections').get().student_id,'native-fixture');});
await check('revoked guard rejects effect inside owning transaction',async()=>{guardAllowed=false;const before=sqlite.prepare('SELECT count(*) n FROM reflections').get().n;const r=await fetch(req('/api/reflections',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({date:'2026-11-19',reflection:'blocked'})}),env);assert.equal(r.status,500);assert.equal(sqlite.prepare('SELECT count(*) n FROM reflections').get().n,before);guardAllowed=true;});
await check('identity credential mutations stay Academy managed',async()=>assert.equal((await fetch(req('/api/admin/reset-pin',{method:'POST'}),env)).status,403));
await check('native teacher privacy predicates preserved',async()=>{nextRole='teacher';nativeId='other-fixture';const r=await fetch(req('/api/reflections?student_id=native-fixture'),env);assert.equal(r.status,200);assert.ok(Array.isArray(await r.json()));nextRole='student';nativeId='native-fixture';});
await check('guarded batches rollback earlier effects on later failure',async()=>{const guarded=guardedHifzDB(DB,{sql:'SELECT 1',args:[]});const count=sqlite.prepare('SELECT count(*) n FROM reflections').get().n;await assert.rejects(()=>guarded.batch([guarded.prepare("INSERT INTO reflections(student_id,date,entered_by,created_at) VALUES (?,?,?,?)").bind('native-fixture','2026-11-19','native-fixture','synthetic'),guarded.prepare('UPDATE definitely_missing_table SET x=1')]));assert.equal(sqlite.prepare('SELECT count(*) n FROM reflections').get().n,count);});
await check('unclassified SQL and write through first/all denied',async()=>{const guarded=guardedHifzDB(DB,{sql:'SELECT 1',args:[]});assert.throws(()=>guarded.prepare('WITH x AS (SELECT 1) DELETE FROM reflections'));await assert.rejects(()=>guarded.prepare('DELETE FROM reflections').all());});
await check('non V2 native policy route unchanged',async()=>{const r=await nativeWorker.fetch(new Request('https://native.fixture/auth/policy'),{PROFILE_AUTHORITY:'academy',DB});assert.equal(r.status,200);assert.deepEqual(await r.json(),{academy_profiles_only:true});});

await check('native factory resolves real canonical/native mapping and epoch',async()=>{
 DB.withSession=()=>DB;
 sqlite.prepare('INSERT INTO academy_profile_links(academy_user_id,student_id,source_revision,source_credential_epoch,pin_reset_version) VALUES (?,?,?,?,?)').run('academy-fixture','native-fixture',1,1,0);
 const native=await createNativeRuntime({env:{DB,PROFILE_AUTHORITY:'academy'},store:{},clock:()=>Math.floor(Date.now()/1000),dependenciesFor:()=>[{id:'H.identity-local',scope:'academy-fixture',ownerEpoch:'epoch-fixture'}],ensureDependencies:async()=>{}});
 assert.deepEqual(await native.identity('academy-fixture'),{sub:'academy-fixture',ce:1,nativeStudentId:'native-fixture',role:'student',sourceRevision:1,pinResetVersion:0});
 const binding={sub:'academy-fixture',ce:1},rights={nativeStudentId:'native-fixture',role:'student'};
 const guard=await native.mappingGuard(binding,rights);assert.ok(sqlite.prepare(guard.sql).get(...guard.args));
 await assert.rejects(()=>native.identity('missing-fixture'));
 await assert.rejects(()=>native.mappingGuard({sub:'academy-fixture',ce:2},rights));
 await assert.rejects(()=>native.mappingGuard(binding,{...rights,role:'admin'}));
 const draft=await native.draftGuard({binding,rights,resource:'hifz:/sabaq:own'});assert.ok(sqlite.prepare(draft.sql).get(...draft.args));
 await assert.rejects(()=>native.draftGuard({binding,rights,resource:'hifz:/sabaq:id.other-fixture'}));
 await assert.rejects(()=>native.draftGuard({binding,rights,resource:'hifz:/unknown:own'}));
 await assert.rejects(()=>native.draftGuard({binding,rights,resource:'hifz:/editor/sabaq:id.other-fixture'}));
 sqlite.prepare('UPDATE students SET role=? WHERE id=?').run('teacher','native-fixture');
 const teacherRights={...rights,role:'teacher'};
 const teacherDraft=await native.draftGuard({binding,rights:teacherRights,resource:'hifz:/editor/sabaq:id.other-fixture'});assert.ok(sqlite.prepare(teacherDraft.sql).get(...teacherDraft.args));
 await assert.rejects(()=>native.draftGuard({binding,rights:teacherRights,resource:'hifz:/sabaq:id.%6Fther-fixture'}));
 sqlite.prepare('UPDATE students SET role=? WHERE id=?').run('student','native-fixture');
 const id=sqlite.prepare('SELECT id FROM reflections WHERE student_id=?').get('native-fixture').id;
 const rowGuard=await native.draftGuard({binding,rights,resource:'hifz:/reflections:own:entry:'+id});assert.ok(sqlite.prepare(rowGuard.sql).get(...rowGuard.args));
 const absent=await native.draftGuard({binding,rights,resource:'hifz:/reflections:own:entry:999999'});assert.equal(sqlite.prepare(absent.sql).get(...absent.args),undefined);
 sqlite.prepare('UPDATE students SET active=0 WHERE id=?').run('native-fixture');assert.equal(sqlite.prepare(guard.sql).get(...guard.args),undefined);
 sqlite.prepare('UPDATE students SET active=1 WHERE id=?').run('native-fixture');
});
sqlite.close();console.log(passed+' passed, '+failed+' failed');if(failed)process.exitCode=1;
