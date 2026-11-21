import test from 'node:test';import assert from 'node:assert/strict';import {createHifzV2Handler,HIFZ_V2_ORIGIN as origin} from '../worker/src/hifz-v2.js';
const prefix='/_assets/'+'a'.repeat(64)+'/';
function setup(flag=prefix){const calls=[],auth=[];const handle=createHifzV2Handler({runtimeFactory:async()=>{auth.push(true);throw Error('Synthetic protected route requires runtime');},dispatchNative:()=>{throw Error('No native dispatch permitted');}}),env={...(flag===null?{}:{UAA_V2_PUBLIC_ASSET_PREFIX:flag}),ASSETS:{fetch:async request=>{calls.push(new URL(request.url).pathname);const path=new URL(request.url).pathname,type=path.endsWith('.css')?'text/css':path.endsWith('.html')?'text/html':path.endsWith('.json')?'application/json':/\.m?js$/.test(path)?'text/javascript':'image/png';return new Response(path.endsWith('.html')?'<html><head></head><body></body></html>':'synthetic public asset',{headers:{'Content-Type':type}});}}};return{calls,auth,run:(path,method='GET',appOrigin=origin)=>handle(new Request(appOrigin+path,{method}),env,{}),env};}
test('Hifz accepts only the configured candidate prefix plus an existing public leaf and forwards exact original versioned path',async()=>{const f=setup();for(const leaf of ['js/v111-session.js','js/v111-client.mjs','css/base.css','manifest.json','appicons/logo.png']){const response=await f.run(prefix+leaf);assert.equal(response.status,200,leaf);assert.equal(f.calls.at(-1),prefix+leaf);}assert.equal(f.auth.length,0);const index=await f.run(prefix+'index.html');assert.equal(index.status,200);assert.equal(f.calls.at(-1),prefix+'index.html');assert(index.headers.has('Content-Security-Policy'));assert((await index.text()).includes('hifz-auth-mode'));});
test('missing, invalid and mismatched prefix fail closed for hashed assets while ordinary public paths remain unchanged',async()=>{for(const flag of [null,'/_assets/'+'A'.repeat(64)+'/',prefix.slice(0,-1),prefix+'extra/','/_assets/'+'b'.repeat(64)+'/']){const f=setup(flag),denied=await f.run(prefix+'js/v111-session.js');assert.equal(denied.status,404);assert.equal(f.calls.length,0);assert.equal((await f.run('/js/v111-session.js')).status,200);assert.equal(f.calls.length,1);}});
test('versioned APIs, source/database/private paths, unknown leaves, traversal and service workers never reach ASSETS',async()=>{const f=setup();for(const leaf of ['api/profile','api/admin/users','admin/users','internal/auth/v2/events','security/v2/runtime.mjs','worker/src/index.js','database.sqlite','config/secrets.json','js/not-registered.js','js/sw.js','index.html/extra','/js/v111-session.js','%2e%2e%2fsecurity/v2/runtime.mjs']){const response=await f.run(prefix+leaf);assert([400,404].includes(response.status),leaf+':'+response.status);}assert.equal(f.calls.length,0);assert.equal(f.auth.length,0);});
test('candidate static methods/origin and MIME checks retain the existing boundary',async()=>{const f=setup();assert.equal((await f.run(prefix+'js/v111-session.js','POST')).status,405);assert.equal((await f.run(prefix+'js/v111-session.js','GET','https://ummabbadacademy.app')).status,421);assert.equal(f.calls.length,0);f.env.ASSETS.fetch=async()=>new Response('<html>',{headers:{'Content-Type':'text/html'}});const mismatch=await f.run(prefix+'js/v111-session.js');assert.equal(mismatch.status,503);assert.equal((await mismatch.json()).code,'ASSET_TYPE_MISMATCH');});

test('current and previous approved Hifz prefixes serve exact public files and deny third or malformed prefixes',async()=>{
 const previous='/_assets/'+'b'.repeat(64)+'/',unknown='/_assets/'+'c'.repeat(64)+'/';
 const leaf='js/v111/browser-session.mjs';
 const enabled=setup(prefix+','+previous);
 assert.equal((await enabled.run(prefix+leaf)).status,200);
 assert.equal((await enabled.run(previous+leaf)).status,200);
 assert.deepEqual(enabled.calls,[prefix+leaf,previous+leaf]);
 assert.equal((await enabled.run(unknown+leaf)).status,404);
 for(const configured of [prefix+','+previous+','+unknown,prefix+',',prefix+',invalid']){
  const invalid=setup(configured);
  assert.equal((await invalid.run(prefix+leaf)).status,404);
  assert.equal(invalid.calls.length,0);
 }
 assert.equal((await enabled.run(previous+'js/sw.js')).status,404);
 assert.equal(enabled.auth.length,0);
});
