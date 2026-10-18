import {JSDOM} from 'jsdom';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {readSummarySource} from './helpers/journal-source.mjs';
const require=createRequire(import.meta.url);
const {JOURNAL_LOG_SCHEMA,journalContentChanges}=require('../shared/journalSchema.js');
const read=f=>readFileSync(new URL('../'+f,import.meta.url),'utf8');
let passed=0,failed=0;
const check=(name,ok)=>{if(ok)passed++;else{failed++;console.log('FAIL:',name);}};
const dom=new JSDOM('<!doctype html><body></body>',{runScripts:'outside-only',url:'http://localhost/'});
const w=dom.window;
w.eval(read('shared/data.js')+'\n'+read('js/position.js')+'\n'+read('js/tajweed.js')+'\n'+readSummarySource()+'\nwindow.quickState=()=>maktabQuickLogState;');
w.iconHtml=()=>'';
w.journalCellShorthand=(type,rows)=>rows.map(row=>row.id||'Teacher entry').join(',');
w.showBanner=message=>{throw Error(message);};
w.currentUser={id:'P1',name:'Personal Student',role:'admin'};
let token='session-1',profile={mushaf:'13line',baseline_selection:[]};
w.getToken=()=>token;
const copy=value=>JSON.parse(JSON.stringify(value));
const date='2026-10-18';
let writes=[],positionWrites=[],refreshes=0,blockRead=null;
const data={personal:{sabaq:[],sabaqDhor:[],dhor:[]},maktab:{sabaq:[],sabaqDhor:[],dhor:[]}};
const clients=(mode,type)=>({
  async get(since){if(blockRead)await blockRead;return copy(data[mode][type].filter(row=>!since||row.date>=since));},
  async save(body){writes.push({mode,type,method:'POST',body:copy(body)});const row={...body,id:100+writes.length};data[mode][type].push(row);return copy(row);},
  async update(id,body){writes.push({mode,type,method:'PATCH',id,body:copy(body)});const row=data[mode][type].find(row=>row.id===id);if(!row)throw Error('wrong journal');Object.assign(row,body);return copy(row);}
});
for(const type of Object.keys(JOURNAL_LOG_SCHEMA)){
  w[{sabaq:'apiSabaq',sabaqDhor:'apiSabaqDhor',dhor:'apiDhor'}[type]]=clients('personal',type);
  w[{sabaq:'apiGetMaktabSabaq',sabaqDhor:'apiGetMaktabSabaqDhor',dhor:'apiGetMaktabDhor'}[type]]=()=>clients('maktab',type).get();
}
w.apiFetch=async(path,opts)=>{
  const type=Object.keys(JOURNAL_LOG_SCHEMA).find(type=>path==='/maktab/'+JOURNAL_LOG_SCHEMA[type].path);
  if(!type)throw Error('Unexpected endpoint: '+path);
  const body=JSON.parse(opts.body);
  return opts.method==='POST'?clients('maktab',type).save(body):clients('maktab',type).update(body.id,body);
};
w.apiMaktabSummary=async()=>({sabaq:copy(data.maktab.sabaq),sabaq_dhor:copy(data.maktab.sabaqDhor),dhor:copy(data.maktab.dhor)});
w.apiGetProfile=async()=>copy(profile);
w.loadMaktabSettings=async()=>({mushaf:'15line_madani'});
w.apiGetPosition=w.apiGetMaktabPosition=async()=>({position_json:'{}'});
w.apiSavePosition=async body=>positionWrites.push({mode:'personal',body});
w.apiSaveMaktabPosition=async(id,body)=>positionWrites.push({mode:'maktab',id,body});
w.apiSaveProfile=async body=>{Object.assign(profile,body);};
w.renderMaktabSummaryScreen=async()=>{};
const fixture=(type,mode)=>({
  id:7,date,student_id:mode==='personal'?'P1':'S2',tajweed_tag_ids:'1',
  student_comment:'Keep this private note',student_comment_private:1,
  teacher_feedback:'Keep this feedback',teacher_feedback_visibility:'private',
  ...(type==='sabaq'?{sabaq_from:'2:1',sabaq_to:'2:5',line_count:99,page_count:2.75}
    :type==='sabaqDhor'?{zone:'saved zone',mistakes:4,from_surah:2,from_ayah:1,to_surah:2,to_ayah:5}
    :{segment_from:7,segment_to:10,ref:'uthmani',mistakes:3,duration_seconds:123,lap_times:'[20,40,63]'})
});
const open=async(mode,type,edit=true)=>{
  const context=w.createJournalQuickContext(mode,{id:mode==='personal'?'P1':'S2',name:mode==='personal'?'Personal Student':'Maktab Student'},async()=>{refreshes++;});
  await w.openJournalQuickLog(context,date,type,null,copy(data[mode]),{combined:true,entry:edit?data[mode][type][0]:null});
  return context;
};
const confirmation=()=>w.document.getElementById('maktabQuickLogConfirm')||w.document.getElementById('mql_sd_manual_confirm');
const confirm=()=>{confirmation().checked=true;};
const status=()=>w.document.getElementById('maktabQuickLogStatus').textContent;
const error=()=>w.document.getElementById('maktabQuickLogError').textContent;
try{
  check('shared contract excludes identity and permissions',!Object.keys(journalContentChanges('sabaq',{student_id:'wrong',id:99,source:'maktab',date,sabaq_to:'2:2'})).some(k=>['student_id','id','source'].includes(k)));
  for(const mode of ['personal','maktab'])for(const type of Object.keys(JOURNAL_LOG_SCHEMA)){
    const row=fixture(type,mode);data[mode][type]=[row];
    await open(mode,type);
    check(mode+' '+type+' opens Edit with saved tags',w.quickState().editing.id===7&&w.quickState().tajweed[type][0]==='1');
    check(mode+' '+type+' requires a fresh confirmation',!confirmation().checked);
    const before=writes.length;
    await w.maktabSaveQuickLog();
    check(mode+' '+type+' cannot save unconfirmed edits',writes.length===before);
    if(type==='dhor')check(mode+' Dhor preserves crossing Juz and reference',w.document.getElementById('quick_dhor_from_juz').value==='1'&&w.document.getElementById('quick_dhor_to_juz').value==='2'&&w.document.getElementById('quick_dhor_to_portion').value==='2');
    w.quickState().tajweed[type]=['2'];confirm();await w.maktabSaveQuickLog();
    const patch=writes.at(-1);
    check(mode+' '+type+' updates the existing row in the correct journal',patch.mode===mode&&patch.type===type&&patch.method==='PATCH'&&patch.id===7);
    check(mode+' '+type+' sends only changed visible fields',JSON.stringify(Object.keys(patch.body).filter(k=>k!=='id').sort())==='["tajweed_tag_ids"]');
    check(mode+' '+type+' preserves notes, privacy and feedback',row.student_comment==='Keep this private note'&&row.student_comment_private===1&&row.teacher_feedback_visibility==='private');
    check(mode+' '+type+' preserves hidden detail values',type==='sabaq'?row.line_count===99&&row.page_count===2.75:type==='sabaqDhor'?row.zone==='saved zone'&&row.mistakes===4:row.duration_seconds===123&&row.lap_times==='[20,40,63]'&&row.mistakes===3);
    check(mode+' '+type+' refreshes without closing and clears confirmation',!w.quickState().editing&&!!w.document.getElementById('maktabQuickLogSheet')&&!confirmation().checked&&status().includes('updated'));
    await open(mode,type);confirm();const unchanged=writes.length;await w.maktabSaveQuickLog();
    check(mode+' '+type+' unchanged edit does not write',writes.length===unchanged&&status()==='No changes to save.');
  }
  for(const mode of ['personal','maktab'])for(const type of Object.keys(JOURNAL_LOG_SCHEMA)){
    await open(mode,type,false);
    if(type==='sabaq'){w.quickState().drafts.sabaq={from:{surah:2,ayah:6},to:{surah:2,ayah:7}};w.maktabQuickRenderBody();confirm();}
    else if(type==='sabaqDhor')w.document.getElementById('mql_sd_picker_confirm').checked=true;
    else{const input=w.document.getElementById('mql_dhor_juz');input.value='3';input.dispatchEvent(new w.Event('change',{bubbles:true}));confirm();}
    await w.maktabSaveQuickLog();const post=writes.at(-1);
    check(mode+' '+type+' adds through its own endpoint',post.mode===mode&&post.type===type&&post.method==='POST'&&post.body.date===date);
    check(mode+' '+type+' identity cannot leak to personal saves',mode==='maktab'?post.body.student_id==='S2':!('student_id'in post.body));
  }
  const teacherRow={...fixture('sabaq','personal'),id:null,source:'maktab',maktab_log_id:7,teacher_name:'Teacher'};
  data.personal.sabaq=[teacherRow,fixture('sabaq','personal')];
  const own=await open('personal','sabaq',false);
  check('personal merged journal displays teacher attribution and read-only state',w.document.querySelectorAll('.quick-readonly').length===1&&w.document.querySelector('.quick-readonly').textContent.includes('Teacher · Read only'));
  w.journalQuickEditEntry(teacherRow);
  check('teacher-confirmed row cannot enter personal Edit',!w.quickState().editing&&!own.canEdit(teacherRow));
  w.document.querySelector('[data-quick-edit="1"]').click();
  check('multiple rows select the correct personal id',w.quickState().editing.id===7&&w.quickState().editing.source!=='maktab');
  const old=fixture('sabaq','personal');data.personal.sabaq=[old];await open('personal','sabaq');
  w.document.getElementById('mql_to_ayah').value='8';w.document.getElementById('mql_to_ayah').dispatchEvent(new w.Event('change',{bubbles:true}));
  confirm();await w.maktabSaveQuickLog();
  check('changed Sabaq range recalculates counts',old.sabaq_to==='2:8'&&old.line_count!==99&&writes.at(-1).body.page_count!==undefined);
  await open('personal','sabaq');confirm();await w.maktabQuickChangeDate('2026-10-17');
  check('changing date preserves Edit target and clears confirmation',w.quickState().editing.id===7&&!confirmation().checked);
  confirm();await w.maktabSaveQuickLog();
  check('date-only edit updates original id without erasing content',writes.at(-1).id===7&&writes.at(-1).body.date==='2026-10-17'&&Object.keys(writes.at(-1).body).length===1&&old.sabaq_to==='2:8');
  data.personal.sabaq=[fixture('sabaq','personal'),{...teacherRow,date:'2026-10-19'}];await open('personal','sabaq');
  w.quickState().tajweed.sabaq=['3'];confirm();const positionBefore=positionWrites.length;await w.maktabSaveQuickLog();
  check('editing older personal Sabaq never moves progress past a newer Maktab entry',positionWrites.length===positionBefore);
  data.personal.sabaq=[fixture('sabaq','personal')];await open('personal','sabaq');
  w.quickState().drafts.sabaq.to.ayah=9;w.maktabQuickRenderBody();
  w.quickState().tajweed.sabaq=['4'];w.journalQuickAddMode('dhor');w.journalQuickAddMode('sabaq');
  check('switching types in Add discards Edit values',!w.quickState().editing&&w.quickState().tajweed.sabaq.length===0);
  w.quickState().drafts.sabaq.to={surah:2,ayah:9};w.quickState().tajweed.sabaq=['4'];w.journalQuickAddMode('dhor');w.journalQuickAddMode('sabaq');
  check('switching types in Add retains each independent draft',w.quickState().drafts.sabaq.to.ayah===9&&w.quickState().tajweed.sabaq[0]==='4');
  await open('personal','sabaq');w.quickState().tajweed.sabaq=['5'];confirm();
  let release;blockRead=new Promise(resolve=>{release=resolve;});const count=writes.length;
  const pending=w.maktabSaveQuickLog();token='session-2';release();blockRead=null;await pending;
  check('session change during asynchronous read prevents write',writes.length===count&&error().includes('session changed'));
  token='session-1';
  await open('personal','sabaq');w.quickState().tajweed.sabaq=['6'];confirm();
  blockRead=new Promise(resolve=>{release=resolve;});const beforeClose=writes.length;
  const cancelled=w.maktabSaveQuickLog();w.maktabCloseQuickLog();release();blockRead=null;await cancelled;
  check('closing before the request is sent cancels the write',writes.length===beforeClose);
  const details=[];
  w.clearLogContext=()=>details.push('personal');
  w.showScreen=async(screen,type)=>details.push([screen,type]);
  w.applyLogDetailSharedDate=(date)=>details.push(date);
  w.openMaktabDay=async(student,date,type)=>details.push([student.id,date,type]);
  w.EDIT_HANDLERS={sabaq:(entry,latest)=>details.push({id:entry.id,latest})};
  const personalContext=w.createJournalQuickContext('personal',{id:'P1'});
  await personalContext.detail('sabaq',date,data.personal.sabaq[0]);
  check('personal Detail retains journal, selected date and Edit target',details[0]==='personal'&&details[1][0]==='logDetail'&&details[2]===date&&details[3].id===7&&details[3].latest);
  details.length=0;
  const maktabContext=w.createJournalQuickContext('maktab',{id:'S2'});
  await maktabContext.detail('sabaq',date,data.maktab.sabaq[0]);
  check('Maktab Detail retains student, date and Edit target',details[0][0]==='S2'&&details[0][1]===date&&details[0][2]==='sabaq'&&details[1].id===7&&!details[1].latest);
  check('personal context rejects another user',(()=>{try{w.createJournalQuickContext('personal',{id:'S2'}).assertCurrent();return false;}catch{return true;}})());
  w.currentUser.role='student';
  check('student cannot open Maktab editing context',(()=>{try{w.createJournalQuickContext('maktab',{id:'S2'}).assertCurrent();return false;}catch{return true;}})());
  check('successful edits refreshed their calling journals',refreshes>=12);
}catch(e){failed++;console.log('FAIL:',e.stack);}finally{w.close();}
console.log(`${passed} passed, ${failed} failed`);process.exitCode=failed?1:0;
