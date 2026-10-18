/* Hifzhelper build 5.2 | js/journalQuickContext.js */
// Capture the journal, student and login when opening the editor. Async saves
// must never consult a different student's mutable full-card LOG_CTX.
function createJournalQuickContext(mode, student, afterSave){
  if(!['personal','maktab'].includes(mode) || !student || !student.id) throw new Error('Choose a journal.');
  const owner = Object.freeze({...student});
  const actor = typeof currentUser !== 'undefined' ? currentUser && currentUser.id : null;
  const token = typeof getToken === 'function' ? getToken() : null;
  function assertCurrent(){
    if(typeof currentUser !== 'undefined' && (!currentUser || currentUser.id !== actor)) throw new Error('Your account changed. Reopen the journal.');
    if(typeof getToken === 'function' && getToken() !== token) throw new Error('Your session changed. Reopen the journal.');
    if(mode === 'personal' && actor !== owner.id) throw new Error('Choose your own personal journal.');
    if(mode === 'maktab' && typeof currentUser !== 'undefined' && !['teacher','admin'].includes(currentUser.role)) throw new Error('A teacher must confirm Maktab entries.');
  }
  const clients = mode === 'personal' ? {sabaq:apiSabaq,sabaqDhor:apiSabaqDhor,dhor:apiDhor} : Object.fromEntries(Object.entries(JOURNAL_LOG_SCHEMA).map(([type,schema])=>{
    const path='/maktab/'+schema.path;
    return [type,{
      get:()=>type==='sabaq'?apiGetMaktabSabaq(owner.id):type==='sabaqDhor'?apiGetMaktabSabaqDhor(owner.id):apiGetMaktabDhor(owner.id),
      save:body=>apiFetch(path,{method:'POST',body:JSON.stringify({...body,student_id:owner.id})}),
      update:(id,body)=>apiFetch(path,{method:'PATCH',body:JSON.stringify({...body,id})})
    }];
  }));
  return Object.freeze({
    mode,student:owner,assertCurrent,afterSave,
    canEdit:entry=>!!entry && entry.id != null && (mode === 'maktab' || entry.source !== 'maktab' && entry.maktab_log_id == null) && (!entry.student_id || String(entry.student_id)===String(owner.id)),
    client:type=>clients[type],
    async readDate(date){
      if(mode === 'maktab') return maktabQuickEntryMapForDate(await apiMaktabSummary(date),owner.id);
      const rows=await Promise.all(Object.keys(JOURNAL_LOG_SCHEMA).map(type=>clients[type].get(date)));
      return Object.fromEntries(Object.keys(JOURNAL_LOG_SCHEMA).map((type,i)=>[type,(rows[i]||[]).filter(row=>row.date===date)]));
    },
    profile:()=>mode === 'maktab' ? loadMaktabSettings() : apiGetProfile(),
    position:()=>mode === 'maktab' ? apiGetMaktabPosition(owner.id) : apiGetPosition(),
    savePosition(value){assertCurrent();const copy={...value};delete copy.sabaqTo;delete copy.activeJuz;return mode === 'maktab' ? apiSaveMaktabPosition(owner.id,JSON.stringify(copy),null) : apiSavePosition(JSON.stringify(copy),null);},
    async savePool(pool){
      assertCurrent();
      if(mode === 'personal') return apiSaveProfile({baseline_selection:pool});
      const position=maktabQuickPositionBlob(await apiGetMaktabPosition(owner.id));
      assertCurrent();position.baselineSelection=pool;return apiSaveMaktabPosition(owner.id,JSON.stringify(position),null);
    },
    async detail(type,date,entry){
      assertCurrent();
      if(mode === 'maktab') await openMaktabDay(owner,date,type);
      else {clearLogContext();await showScreen('logDetail',type);applyLogDetailSharedDate(date,false);}
      if(entry && this.canEdit(entry) && typeof EDIT_HANDLERS !== 'undefined' && EDIT_HANDLERS[type]){
        const history=await clients[type].get();
        const latest=(history||[]).slice().sort((a,b)=>(b.date||'').localeCompare(a.date||'')||(b.id||0)-(a.id||0))[0];
        assertCurrent();EDIT_HANDLERS[type](entry,!!latest && latest.id===entry.id && this.canEdit(latest));
      }
    }
  });
}
