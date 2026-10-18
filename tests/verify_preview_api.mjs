import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../js/api.js',import.meta.url),'utf8');
let passed=0,failed=0;
const check=(name,ok)=>{if(ok)passed++;else{failed++;console.log('FAIL:',name);}};
function base(host,override=null,blocked=false){
 const context=vm.createContext({location:{hostname:host},localStorage:{getItem(){if(blocked)throw Error('private mode');return override;}}});
 vm.runInContext(source,context);return vm.runInContext('API_BASE',context);
}
for(const host of ['dev.maktab-hifz.pages.dev','abc123.maktab-hifz.pages.dev','hifzhelper-dev.pages.dev','localhost','127.0.0.1']){
 check(host+' uses development',base(host).includes('api-dev.'));
 check(host+' stays development with storage disabled',base(host,null,true).includes('api-dev.'));
}
for(const host of ['hifz.maktab4life.org','maktab-hifz.pages.dev'])check(host+' remains production',base(host)==='https://hifzhelper-api.hifzhelper-app.workers.dev');
check('explicit local API override still wins',base('dev.maktab-hifz.pages.dev','http://localhost:8787')==='http://localhost:8787');
console.log(`${passed} passed, ${failed} failed`);process.exitCode=failed?1:0;
