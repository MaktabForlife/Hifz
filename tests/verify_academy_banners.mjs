import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {JSDOM} from 'jsdom';
import {headerDate,jamiatDate} from '../worker/src/header-date.js';
import worker from '../worker/src/index.js';
const read=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
let passed=0;const check=(name,value)=>{assert(value,name);passed++;};
const html=read('index.html'),auth=read('js/auth.js');
for(const [role,screen,forbidden] of [
 ['student','journal',['maktabSummary','maktabAttendance','admin','maktabSettings']],
 ['teacher','maktabSummary',['journal','logDetail','settings','maktabJournal','admin','maktabSettings']],
 ['admin','admin',['journal','logDetail','settings','maktabJournal']]
]){
 const dom=new JSDOM(html,{runScripts:'outside-only',url:'https://hifz.invalid/Example'}),w=dom.window,opened=[];
 w.iconHtml=()=>'<svg aria-hidden="true"></svg>';w.openFloatingTimer=()=>opened.push('timer');w.setupHifzHeaderDate=()=>opened.push('date');w.appVersionFromScriptTag=()=> '5.1';
 w.showScreen=id=>{opened.push(id);w.updateHifzNavigation(id);};
 w.eval(auth+`\ncurrentUser={name:'Test <Account>',role:'${role}'};setupAuthBandAndDropdown();renderAuthBand();`);
 const doc=w.document,menu=doc.getElementById('authDropdownNav');
 check(role+' has two header banners',doc.querySelectorAll('#authBand>.hifz-brand-banner,#authBand>.hifz-account-banner').length===2);
 check(role+' profile uses text, not injected markup',doc.querySelector('.user-name').textContent==='Test <Account>'&&!doc.querySelector('.user-name account'));
 check(role+' has its real Hifz role',doc.getElementById('hifzHeaderRole').textContent===role[0].toUpperCase()+role.slice(1));
 check(role+' has no excluded activity links',!menu.querySelector('[data-nav="sih"],[data-nav="juzTracker"]'));
 check(role+' has no Academy role tabs',!menu.textContent.match(/LEARN|TEACH|ADMIN/));
 for(const id of forbidden)check(role+' does not expose '+id,!menu.querySelector('[data-nav="'+id+'"]'));
 menu.querySelector('[data-nav="'+screen+'"]').click();check(role+' navigates inside Hifz',opened.at(-1)===screen);
 check(role+' highlights the current destination',menu.querySelector('[data-nav="'+screen+'"]').getAttribute('aria-pressed')==='true');
 doc.getElementById('homeDropdownBtn').click();check(role+' Home still opens Hifz Home',opened.at(-1)==='home');
 doc.getElementById('timerDropdownBtn').click();check(role+' Timer still opens',opened.at(-1)==='timer');
 for(const id of ['homeDropdownBtn','refreshBtn','logoutBtn'])check(role+' keeps one '+id+' in top-banner page actions',doc.querySelectorAll('#'+id).length===1&&doc.getElementById(id).parentElement.id==='hifzPageActions'&&!!doc.getElementById(id).closest('.hifz-brand-banner'));
 w.eval("setMaktabZoomLink('https://zoom.invalid/class');updateAuthBandZoom();");check(role+' keeps the configured class Zoom link',doc.getElementById('authBandZoom').href==='https://zoom.invalid/class'&&!doc.getElementById('authBandZoom').classList.contains('hidden'));
 w.setupAuthBandAndDropdown();w.setupAuthBandAndDropdown();
 check(role+' repeated header setup cannot duplicate page controls', ['homeDropdownBtn','refreshBtn','logoutBtn','authBandZoom'].every(id=>doc.querySelectorAll('#'+id).length===1));
 check(role+' second banner contains profile and navigation only', !doc.querySelector('.hifz-account-banner #hifzPageActions,.hifz-account-banner #authBandZoom'));
 const clicks=opened.filter(item=>item==='home').length;doc.getElementById('homeDropdownBtn').click();
 check(role+' rebuilt Home action navigates exactly once',opened.filter(item=>item==='home').length===clicks+1);
 dom.window.close();
}
const dateHtml='<div class="dual-date-widget" data-site-y="2026" data-site-m="10" data-site-d="17"><div class="value islamic hd-out">6 Jumada al-ula 1448</div></div>';
const request=()=>new Request('https://hifz.invalid/api/header-date'),now=new Date('2026-10-17T10:00:00Z'),entries=new Map();let calls=0;
const cache={match:async r=>entries.get(r.url)?.clone(),put:async(r,response)=>entries.set(r.url,response.clone())};
const fetcher=async(url,options)=>{check('date reads the same public source as Academy',url==='https://jamiat.org.za/');check('date sends no credentials',!options.headers.Authorization&&options.redirect==='manual');calls++;return new Response(dateHtml);};
const first=await headerDate(request(),{now,cache,fetcher});check('header date permits the Hifz frontend origin',first.headers.get('Access-Control-Allow-Origin')==='*');check('date matches the current Academy day',(await first.json()).hijri==='6 Jumada al-ula 1448');
await headerDate(request(),{now,cache,fetcher});check('date reuses the edge cache',calls===1);check('stale source date is refused',jamiatDate(dateHtml,'2026-10-18')===null);
const unavailable=await headerDate(request(),{now,cache:null,fetcher:async()=>new Response('x'.repeat(512*1024+1))});check('oversized source produces an explicit unavailable date',(await unavailable.json()).hijri===null);
const previous=globalThis.fetch;globalThis.fetch=async()=>new Response(dateHtml);const env={};Object.defineProperty(env,'DB',{get(){throw Error('Unexpected database access');}});
try{const result=await worker.fetch(request(),env);check('public date route requires no D1 or login',result.status===200);check('public date rejects writes',(await worker.fetch(new Request(request(),{method:'POST'}),env)).status===405);}finally{globalThis.fetch=previous;}
console.log(`${passed} passed, 0 failed`);
