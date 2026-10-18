/* Hifzhelper build 5.2 | js/journalQuickEditor.js */
// One Quick Log/editor shared by Personal Journal and Maktab. Legacy DOM
// names remain stable for the existing styles and callers; no second form.
// ============================================================
// V4.2.12 / V4.2.12.1 — Summary Quick Log trial + compact card pass.
//
// Desktop/tablet keeps the direct per-cell Quick Log entry points. V4.2.12.1
// compacts all three sheets into the same two-line identity/date header and
// makes Dhor's Portion -> Juz/position/confirm flow read as one short form.
//
// On phones, the whole log area becomes one Quick Log target. The sheet then
// owns a Sabaq | Sabaq Dhor | Dhor selector, so the teacher does not have to
// hit one narrow log cell precisely. Name and attendance remain their own
// explicit destinations and keep stopping propagation.
//
// Writes still reuse the existing maktab log endpoints — no second backend or
// storage model. Dhor keeps the existing atomic pool merge. Sabaq's position
// metadata remains best-effort synced after the saved log.
// ============================================================
let maktabQuickLogState = null;

const MAKTAB_QUICK_LABEL = Object.fromEntries(Object.entries(JOURNAL_LOG_SCHEMA).map(([type,schema])=>[type,schema.label]));
let maktabQuickLogOpenToken = 0;

function maktabQuickEscape(value){
  return String(value == null ? '' : value).replace(/[&<>\"']/g, ch => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '\"':'&quot;', "'":'&#39;' }[ch]));
}

function maktabCloseQuickLog(){
  maktabQuickLogOpenToken++;
  const el = document.getElementById('maktabQuickLogSheet');
  if(el) el.remove();
  maktabQuickLogState = null;
}

function maktabQuickRefForMushaf(mushaf){
  return mushaf === '15line_madani' ? 'uthmani' : 'waterval';
}

function maktabQuickIsMobile(){
  return !!(window.matchMedia && window.matchMedia('(max-width: 767px)').matches);
}

function maktabQuickFormatDate(iso){
  const d = new Date(String(iso || '') + 'T00:00:00');
  if(Number.isNaN(d.getTime())) return String(iso || '');
  const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  return `${days[d.getDay()]} ${String(d.getDate()).padStart(2, '0')} ${months[d.getMonth()]}`;
}

// V4.2.14.4 — Quick Log date is a real native date control, using the
// app's shared direct-tap wrapper so it remains selectable on iOS as well as
// desktop. Changing date keeps the student + selected log type, reloads that
// student's existing entries for the new day, and clears the confirmation so
// a teacher cannot accidentally save a draft against a newly selected date.
function maktabQuickDateControl(id, date, label){
  return `<div class="maktab-quick-date-control"><input type="date" id="${id}" class="maktab-quick-date-input" value="${maktabQuickEscape(date)}" aria-label="${maktabQuickEscape(label)}"></div>`;
}

function maktabQuickEntryMapForDate(data, studentId){
  const sid = String(studentId == null ? '' : studentId);
  const own = rows => (Array.isArray(rows) ? rows : []).filter(r => String(r && r.student_id) === sid);
  return {
    sabaq: own(data && data.sabaq),
    sabaqDhor: own(data && data.sabaq_dhor),
    dhor: own(data && data.dhor)
  };
}

async function maktabQuickChangeDate(nextDate){
  const state = maktabQuickLogState;
  if(!state || state.saving || !nextDate || nextDate === state.date) return;
  state.loadingDate = true;
  state.date = nextDate;
  state.dateLoadToken = (state.dateLoadToken || 0) + 1;
  const token = state.dateLoadToken;

  // Never leave the previous day's rows visible under a new date while the
  // exact-day read is in flight.
  state.entriesByType = { sabaq: [], sabaqDhor: [], dhor: [] };
  state.sabaqDhorRows = [];
  maktabQuickRenderBody();
  const confirmBox = document.getElementById('maktabQuickLogConfirm');
  if(confirmBox) confirmBox.checked = false;
  const save = document.getElementById('maktabQuickLogSave');
  if(save) save.disabled = true;
  const err = document.getElementById('maktabQuickLogError');
  if(err) err.textContent = 'Loading selected date…';

  try{
    const [data, planning] = await Promise.all([
      state.context.readDate(nextDate),
      maktabQuickPlanningDefaults(state.student.id, state.ref, nextDate, state.context)
    ]);
    if(maktabQuickLogState !== state || token !== state.dateLoadToken) return;
    state.entriesByType = data;
    state.sabaqDhorRows = planning.sabaqDhorRows || [];
    state.addDefaults = planning.sabaqDefaults;
    if(!state.editing) state.drafts.sabaqDhor = {from:null, to:null};
    state.dateLoadFailed = false;
    maktabQuickRenderBody();
  } catch(e){
    if(maktabQuickLogState !== state || token !== state.dateLoadToken) return;
    state.entriesByType = { sabaq: [], sabaqDhor: [], dhor: [] };
    state.dateLoadFailed = true;
    maktabQuickRenderBody();
    const liveErr = document.getElementById('maktabQuickLogError');
    if(liveErr) liveErr.textContent = "Couldn't load existing logs for the selected date.";
  } finally {
    if(maktabQuickLogState === state && token === state.dateLoadToken){
      state.loadingDate = false;
      const liveSave = document.getElementById('maktabQuickLogSave');
      if(liveSave) liveSave.disabled = !!state.dateLoadFailed;
    }
  }
}

function maktabQuickExistingText(type, entries){
  if(!entries || !entries.length) return '';
  const context=maktabQuickLogState.context;
  const text=entries.map((entry,index)=>{
    const label=maktabQuickEscape(journalCellShorthand(type,[entry]).replace(/<[^>]+>/g,'').trim());
    return context.canEdit(entry)
      ? `<button type="button" class="quick-existing-entry" data-quick-edit="${index}" aria-label="Edit ${MAKTAB_QUICK_LABEL[type]} entry ${index+1}">${label}<small>Edit</small></button>`
      : `<div class="quick-existing-entry quick-readonly">${label}<small>${maktabQuickEscape(entry.teacher_name||entry.maktab_teacher||'Maktab')} · Read only</small></div>`;
  }).join('');
  return `<div class="maktab-quick-existing"><span>Already logged</span>${text}</div>`;
}

function maktabQuickTypeDraft(type){
  const state = maktabQuickLogState;
  return state && state.drafts ? state.drafts[type || state.type] : null;
}

function maktabQuickEntries(type){
  const state = maktabQuickLogState;
  if(!state) return [];
  return (state.entriesByType && state.entriesByType[type || state.type]) || [];
}

function maktabQuickCloneVerse(value){
  return value ? { surah: Number(value.surah), ayah: Number(value.ayah) } : null;
}

function maktabQuickPositionBlob(row){
  try{ return row && row.position_json ? (JSON.parse(row.position_json) || {}) : {}; }
  catch(e){ return {}; }
}

// V4.2.15 — copy the established detail-card prepopulation rather than
// inventing a second progression model in Quick Log. Sabaq uses the same
// computeActualSabaqFrontier + nextSabaqDefaults chain as renderSabaqScreen.
// Sabaq Dhor uses the same position/frontier + computeSabaqDhorRows model as
// its full card, intentionally rendered at the quarter level in Quick Log.
async function maktabQuickPlanningDefaults(studentId, ref, date, context){
  context=context||createJournalQuickContext('maktab',{id:studentId});
  const [sabaqHistory,dhorHistory,posRow,profile]=await Promise.all([context.client('sabaq').get(),context.client('dhor').get(),context.position(),context.profile()]);
  const sabaqRows=(sabaqHistory||[]).filter(e=>!date||e.date<=date);
  const frontier=computeActualSabaqFrontier(sabaqRows,ref);
  const position=maktabQuickPositionBlob(posRow);
  const baselineSelection=(context.mode==='maktab'?position.baselineSelection:profile.baseline_selection)||[];
  const decoratedPosition=sabaqDhorPositionAtDate(position,sabaqHistory,ref,date);
  return {sabaqHistory:sabaqRows,sabaqDefaults:nextSabaqDefaults(frontier,ref,(dhorHistory||[]).length>0),baselineSelection,
    sabaqDhorRows:computeSabaqDhorRows(decoratedPosition,ref,'quarters',baselineSelection)||[],sabaqDhorPosition:decoratedPosition};
}

function maktabQuickVerseField(side, label){
  return `<div class="maktab-quick-range-row">
    <label>${label}<br><span>ayah</span></label>
    <div class="verse-ref-field maktab-quick-verse-field">
      <button type="button" class="verse-ref-chevron" data-mql-surah="${side}" aria-label="Choose Surah for ${label}">&#x25B2;&#x25BC;</button>
      <span class="verse-ref-surah-label" id="mql_${side}_surah_label">—</span>
      <span class="verse-ref-ayah-cell">
        <span class="verse-ref-sep">:</span>
        <input type="number" inputmode="numeric" class="verse-ref-ayah" id="mql_${side}_ayah" aria-label="${label} ayah">
      </span>
      <span class="verse-ref-ayah-stepper">
        <button type="button" data-mql-step="${side}:1" aria-label="Increase ${label} ayah">&#x25B2;</button>
        <button type="button" data-mql-step="${side}:-1" aria-label="Decrease ${label} ayah">&#x25BC;</button>
      </span>
    </div>
  </div>`;
}

function maktabQuickConfirmControl(){
  return `<label class="maktab-quick-confirm maktab-quick-confirm-action">
    <input type="checkbox" id="maktabQuickLogConfirm" aria-label="Confirm selection">
  </label>`;
}

function maktabQuickRenderVerse(side){
  const draft = maktabQuickTypeDraft();
  if(!draft) return;
  const value = draft[side];
  const label = document.getElementById(`mql_${side}_surah_label`);
  const input = document.getElementById(`mql_${side}_ayah`);
  if(!label || !input) return;
  if(!value){
    label.textContent = '—'; input.value = ''; input.min = ''; input.max = '';
    return;
  }
  label.textContent = `${value.surah} ${surahName(value.surah)}`;
  input.min = '1'; input.max = String(maxAyahForSurah(value.surah)); input.value = String(value.ayah);
}

function maktabQuickReadVerse(side){
  const draft = maktabQuickTypeDraft();
  if(!draft) return null;
  const current = draft[side];
  const input = document.getElementById(`mql_${side}_ayah`);
  if(!current || !input || !input.value) return null;
  let ayah = parseInt(input.value, 10);
  if(!Number.isFinite(ayah)) return null;
  ayah = Math.max(1, Math.min(maxAyahForSurah(current.surah), ayah));
  draft[side] = { surah: current.surah, ayah };
  input.value = String(ayah);
  return draft[side];
}

function maktabQuickOpenSurahPicker(side){
  const draft = maktabQuickTypeDraft();
  if(!draft) return;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay surah-picker-modal maktab-quick-surah-modal';
  overlay.innerHTML = `<div class="modal-card">
    <button type="button" class="close-btn" aria-label="Close">&times;</button>
    <h2>Choose Surah</h2>
    <input type="search" class="maktab-quick-surah-search" placeholder="Search Surah" autocomplete="off" aria-label="Search Surahs">
    <div class="surah-picker-list"></div>
  </div>`;
  document.body.appendChild(overlay);
  const list = overlay.querySelector('.surah-picker-list');
  const search = overlay.querySelector('.maktab-quick-surah-search');

  // V4.2.15.11: the unified Quick Log Surah picker is searchable and gives
  // the teacher the Surah's total Ayah count before selection. The count is
  // derived from the same Quran reference data that already clamps Ayah From/To.
  const renderList = () => {
    const q = String(search && search.value || '').trim().toLowerCase();
    const rows = SURAHS.filter(([num, name]) => !q || String(num).includes(q) || name.toLowerCase().includes(q));
    list.innerHTML = rows.length
      ? rows.map(([num, name]) => `<button type="button" class="tajweed-tag surah-picker-row" data-surah="${num}"><span>${num}. ${name}</span><span class="maktab-quick-surah-ayah-count">${maxAyahForSurah(num)} ayahs</span></button>`).join('')
      : '<div class="maktab-quick-surah-empty">No matching Surah.</div>';
  };
  renderList();
  if(search){
    search.addEventListener('input', renderList);
    setTimeout(() => search.focus(), 0);
  }
  list.addEventListener('click', (e) => {
    const btn = e.target.closest && e.target.closest('[data-surah]');
    if(!btn) return;
    const surah = parseInt(btn.dataset.surah, 10);
    draft[side] = { surah, ayah: 1 };
    journalQuickClearConfirmation();
    maktabQuickRenderVerse(side);
    overlay.remove();
  });
  overlay.querySelector('.close-btn').addEventListener('click', () => overlay.remove());
  overlay.addEventListener('click', e => { if(e.target === overlay) overlay.remove(); });
}

function maktabQuickWireVerseFields(){
  ['from','to'].forEach(side => {
    const input = document.getElementById(`mql_${side}_ayah`);
    if(input) input.addEventListener('change', () => maktabQuickReadVerse(side));
  });
  document.querySelectorAll('[data-mql-surah]').forEach(btn => btn.addEventListener('click', () => maktabQuickOpenSurahPicker(btn.dataset.mqlSurah)));
  document.querySelectorAll('[data-mql-step]').forEach(btn => btn.addEventListener('click', () => {
    const [side, rawDelta] = btn.dataset.mqlStep.split(':');
    const value = maktabQuickReadVerse(side);
    if(!value) return;
    const next = Math.max(1, Math.min(maxAyahForSurah(value.surah), value.ayah + parseInt(rawDelta, 10)));
    const draft = maktabQuickTypeDraft();
    draft[side] = { surah: value.surah, ayah: next };
    maktabQuickRenderVerse(side);
  }));
}

function maktabQuickDhorControls(){
  const draft = maktabQuickTypeDraft('dhor') || { juz:null, unit:'quarter', position:1 };
  if(draft.editingRange) return journalQuickDhorRangeHtml(draft);
  const juzOptions = Array.from({length:30}, (_,i) => `<option value="${i+1}"${draft.juz === i+1 ? ' selected' : ''}>Juz ${i+1}</option>`).join('');
  return `<div class="maktab-quick-dhor-grid">
    <div class="maktab-quick-dhor-primary-row">
      <select id="mql_dhor_juz" aria-label="Juz selector"><option value="">Juz</option>${juzOptions}</select>
      <div class="unit-pill maktab-quick-unit-pill" id="mql_dhor_unit" aria-label="Juz portion">
        <button type="button" data-unit="quarter" class="${draft.unit === 'quarter' ? 'on' : ''}">Quarter</button>
        <button type="button" data-unit="half" class="${draft.unit === 'half' ? 'on' : ''}">Half</button>
        <button type="button" data-unit="full" class="${draft.unit === 'full' ? 'on' : ''}">Juz</button>
      </div>
      ${maktabQuickConfirmControl()}
    </div>
    <div class="maktab-quick-dhor-position-row" id="mql_dhor_position_row">
      <span class="maktab-quick-control-label">Portion number</span>
      <div class="unit-pill maktab-quick-position-pill" id="mql_dhor_position" aria-label="Portion number"></div>
    </div>
  </div>`;
}

function maktabQuickRenderDhorPosition(){
  const draft = maktabQuickTypeDraft('dhor');
  const pill = document.getElementById('mql_dhor_position');
  if(!draft || !pill) return;
  const unit = draft.unit || 'quarter';
  const row = document.getElementById('mql_dhor_position_row');
  if(unit === 'full'){
    pill.classList.add('hidden');
    if(row) row.classList.add('hidden');
    draft.position = 1;
    return;
  }
  pill.classList.remove('hidden');
  if(row) row.classList.remove('hidden');
  const count = unit === 'half' ? 2 : 4;
  if(draft.position > count) draft.position = 1;
  pill.innerHTML = Array.from({length:count}, (_,i) => `<button type="button" data-pos="${i+1}" class="${draft.position === i+1 ? 'on' : ''}">${i+1}</button>`).join('');
  pill.querySelectorAll('[data-pos]').forEach(btn => btn.addEventListener('click', () => {
    draft.position = parseInt(btn.dataset.pos, 10);
    maktabQuickRenderDhorPosition();
  }));
}

function maktabQuickWireDhor(){
  const draft = maktabQuickTypeDraft('dhor');
  if(!draft) return;
  if(draft.editingRange){
    document.querySelectorAll('[data-quick-dhor-side]').forEach(input=>input.addEventListener('change',()=>{
      const per=segmentsPerJuz(draft.ref);
      for(const side of ['from','to']){
        const juz=Number(document.getElementById('quick_dhor_'+side+'_juz').value);
        const portion=Number(document.getElementById('quick_dhor_'+side+'_portion').value);
        draft[side==='from'?'segmentFrom':'segmentTo']=(juz-1)*per+portion;
      }
    }));
    return;
  }
  const juz = document.getElementById('mql_dhor_juz');
  if(juz) juz.addEventListener('change', () => { draft.juz = parseInt(juz.value, 10) || null; });
  document.querySelectorAll('#mql_dhor_unit [data-unit]').forEach(btn => btn.addEventListener('click', () => {
    draft.unit = btn.dataset.unit;
    draft.position = 1;
    document.querySelectorAll('#mql_dhor_unit [data-unit]').forEach(b => b.classList.toggle('on', b === btn));
    maktabQuickRenderDhorPosition();
  }));
  maktabQuickRenderDhorPosition();
}

function maktabQuickSabaqDhorPickerHtml(){
  const state = maktabQuickLogState;
  const picker = state && state.sabaqDhorPicker ? state.sabaqDhorPicker : { juz: 1, quarter: 1 };
  const word = typeof quarterUnitWord === 'function' ? quarterUnitWord(state && state.ref) : 'Quarter';
  const juzOptions = Array.from({length:30}, (_, i) => `<option value="${i + 1}"${picker.juz === i + 1 ? ' selected' : ''}>Juz ${i + 1}</option>`).join('');
  const buttons = Array.from({length:4}, (_, i) => `<button type="button" data-mql-sd-quarter="${i + 1}" class="${picker.quarter === i + 1 ? 'on' : ''}">${i + 1}</button>`).join('');
  return `<div class="maktab-quick-sd-empty">
    <span class="form-hint">Select a portion</span>
    <div class="maktab-quick-sd-picker-row">
      <select id="mql_sd_juz" aria-label="Sabaq Dhor Juz">${juzOptions}</select>
      <div class="unit-pill maktab-quick-sd-quarter-pill" aria-label="${maktabQuickEscape(word)} position">${buttons}</div>
      <input type="checkbox" id="mql_sd_picker_confirm" aria-label="Confirm selected Sabaq Dhor portion">
    </div>
    <div class="maktab-quick-sd-preview" id="mql_sd_picker_preview"></div>
  </div>`;
}

function maktabQuickSabaqDhorHtml(){
  const state = maktabQuickLogState;
  const rows = state && Array.isArray(state.sabaqDhorRows) ? state.sabaqDhorRows : [];
  const rowsHtml = rows.map(r => `
    <label class="maktab-quick-sd-row" for="mql_sd_row_${maktabQuickEscape(r.id)}">
      <span class="maktab-quick-sd-row-pill">${maktabQuickEscape(sabaqDhorRowLabel(r, state.ref))}: ${r.fromSurah}:${r.fromAyah} – ${r.toSurah}:${r.toAyah}</span>
      <input type="checkbox" class="mql-sd-row-cb" id="mql_sd_row_${maktabQuickEscape(r.id)}" data-id="${maktabQuickEscape(r.id)}">
    </label>`).join('');

  return `<div class="maktab-quick-sd-layout">
    <div class="maktab-quick-sd-quarters">${rowsHtml}</div>
    <div class="maktab-quick-sd-manual">
      <div class="maktab-quick-sd-manual-line">${maktabQuickVerseField('from', 'From')}<span class="maktab-quick-sd-check-spacer"></span></div>
      <div class="maktab-quick-sd-manual-line">${maktabQuickVerseField('to', 'To')}<input type="checkbox" id="mql_sd_manual_confirm" aria-label="Confirm manual Sabaq Dhor range"></div>
    </div>
    ${maktabQuickSabaqDhorPickerHtml()}
  </div>`;
}

function maktabQuickSabaqDhorPickerBounds(){
  const state = maktabQuickLogState;
  const picker = state && state.sabaqDhorPicker;
  if(!state || !picker || typeof structuralQuarterBounds !== 'function') return null;
  try{ return structuralQuarterBounds(picker.juz, picker.quarter, state.ref); }
  catch(e){ return null; }
}

function maktabQuickUpdateSabaqDhorPickerPreview(){
  const el = document.getElementById('mql_sd_picker_preview');
  if(!el) return;
  const b = maktabQuickSabaqDhorPickerBounds();
  el.textContent = b ? `${b.startSurah}:${b.startAyah} – ${b.endSurah}:${b.endAyah}` : '';
}

function maktabQuickWireSabaqDhor(){
  maktabQuickWireVerseFields();
  maktabQuickRenderVerse('from');
  maktabQuickRenderVerse('to');
  const state = maktabQuickLogState;
  if(!state) return;
  const juz = document.getElementById('mql_sd_juz');
  if(juz) juz.addEventListener('change', () => {
    state.sabaqDhorPicker.juz = parseInt(juz.value, 10) || 1;
    maktabQuickUpdateSabaqDhorPickerPreview();
  });
  document.querySelectorAll('[data-mql-sd-quarter]').forEach(btn => btn.addEventListener('click', () => {
    state.sabaqDhorPicker.quarter = parseInt(btn.dataset.mqlSdQuarter, 10) || 1;
    document.querySelectorAll('[data-mql-sd-quarter]').forEach(b => b.classList.toggle('on', b === btn));
    maktabQuickUpdateSabaqDhorPickerPreview();
  }));
  maktabQuickUpdateSabaqDhorPickerPreview();
}

function maktabQuickReadSabaqDhorComposite(){
  const state = maktabQuickLogState;
  if(!state) return { error: 'Sabaq Dhor is not ready.' };
  const selected = [];
  const ids = Array.from(document.querySelectorAll('.mql-sd-row-cb:checked')).map(cb => cb.dataset.id);
  (state.sabaqDhorRows || []).forEach(r => { if(ids.includes(String(r.id))) selected.push(r); });

  const pickerConfirm = document.getElementById('mql_sd_picker_confirm');
  if(pickerConfirm && pickerConfirm.checked){
    const b = maktabQuickSabaqDhorPickerBounds();
    if(b) selected.push({ fromSurah:b.startSurah, fromAyah:b.startAyah, toSurah:b.endSurah, toAyah:b.endAyah });
  }

  const manualConfirm = document.getElementById('mql_sd_manual_confirm');
  if(manualConfirm && manualConfirm.checked){
    const from = maktabQuickReadVerse('from');
    const to = maktabQuickReadVerse('to');
    if(!from || !to) return { error: 'Please set both From and To for the checked manual range.' };
    selected.push({ fromSurah:from.surah, fromAyah:from.ayah, toSurah:to.surah, toAyah:to.ayah });
  }
  if(!selected.length) return { error: 'Please check at least one Sabaq Dhor section.' };

  let from = selected[0], to = selected[0];
  selected.forEach(r => {
    if(compareVerseKey(r.fromSurah, r.fromAyah, from.fromSurah, from.fromAyah) < 0) from = r;
    if(compareVerseKey(r.toSurah, r.toAyah, to.toSurah, to.toAyah) > 0) to = r;
  });
  return { range: { fromSurah:from.fromSurah, fromAyah:from.fromAyah, toSurah:to.toSurah, toAyah:to.toAyah } };
}

function maktabQuickRenderConfirmSlot(){
  const state = maktabQuickLogState;
  const host = document.getElementById('maktabQuickTajweed');
  if(!state || !host) return;
  if(!state.tajweed) state.tajweed = {sabaq:[], sabaqDhor:[], dhor:[]};
  renderTajweedPicker('maktabQuickTajweed', state.tajweed[state.type]);
}

function maktabQuickBodyHtml(type){
  if(type === 'dhor') return maktabQuickDhorControls();
  if(type === 'sabaqDhor') return maktabQuickSabaqDhorHtml();
  return `<div class="maktab-quick-range-grid">
    <div class="maktab-quick-sd-manual-line">${maktabQuickVerseField('from', 'From')}<span></span></div>
    <div class="maktab-quick-sd-manual-line">${maktabQuickVerseField('to', 'To')}${maktabQuickConfirmControl()}</div>
  </div>`;
}

function maktabQuickRenderBody(){
  const state = maktabQuickLogState;
  if(!state) return;
  const existing = document.getElementById('maktabQuickExisting');
  const body = document.getElementById('maktabQuickBody');
  const err = document.getElementById('maktabQuickLogError');
  if(existing) existing.innerHTML = maktabQuickExistingText(state.type, maktabQuickEntries(state.type));
  if(body) body.innerHTML = maktabQuickBodyHtml(state.type);
  if(err) err.textContent = '';
  journalQuickRenderMode();
  if(existing) existing.querySelectorAll('[data-quick-edit]').forEach(button=>button.addEventListener('click',()=>journalQuickEditEntry(maktabQuickEntries(state.type)[Number(button.dataset.quickEdit)])));
  document.querySelectorAll('[data-mql-type]').forEach(btn => btn.classList.toggle('on', btn.dataset.mqlType === state.type));
  maktabQuickRenderConfirmSlot();
  if(state.type === 'dhor') maktabQuickWireDhor();
  else if(state.type === 'sabaqDhor') maktabQuickWireSabaqDhor();
  else {
    maktabQuickWireVerseFields();
    maktabQuickRenderVerse('from');
    maktabQuickRenderVerse('to');
  }
}

function maktabQuickTypeSelector(){
  return `<div class="unit-pill maktab-quick-type-switch" id="maktabQuickTypeSwitch" aria-label="Quick Log type">
    <button type="button" data-mql-type="sabaq">Sabaq</button>
    <button type="button" data-mql-type="sabaqDhor">Sabaq Dhor</button>
    <button type="button" data-mql-type="dhor">Dhor</button>
  </div>`;
}

async function maktabQuickPost(path, payload, duplicateLabel, context, type){
  const send=body=>{if(context){context.assertCurrent();return context.client(type).save(body);}return apiFetch(path,{method:'POST',body:JSON.stringify(body)});};
  let result = await send(payload);
  if(result && result.isDuplicate && !result.id){
    const proceed = confirm(`${duplicateLabel} has already been saved. Select OK to save it again or CANCEL to abort.`);
    if(!proceed) return null;
    result = await send(Object.assign({}, payload, { force: true }));
  }
  return result;
}

async function maktabQuickSyncSabaqPosition(studentId, oldEntries, ref, context, editing){
  context=context||createJournalQuickContext('maktab',{id:studentId});
  const latest=(oldEntries||[]).slice().sort((a,b)=>(b.date||'').localeCompare(a.date||'')||(b.id||0)-(a.id||0))[0];
  // Correcting an older entry never advances the current personal position.
  if(editing && (!latest || latest.id!==editing.id || !context.canEdit(latest))) return;
  const position=maktabQuickPositionBlob(await context.position());
  const oldFrontier=computeActualSabaqFrontier(oldEntries||[],ref);
  const freshEntries=await context.client('sabaq').get();
  const next=advancePositionAfterSabaq(position,oldFrontier,computeActualSabaqFrontier(freshEntries,ref),ref);
  await context.savePosition(next);
  if(context.mode==='personal'){
    const profile=await context.profile();
    const moved=maybeAutoMoveToDhor(next,ref,profile.baseline_selection||[]);
    if(moved.moved){await context.savePosition(moved.position);await context.savePool(moved.baselineSelection);}
  }
  return;
}

async function maktabSaveQuickLog(){
  const state=maktabQuickLogState;
  if(!state || state.saving || state.loadingDate || state.dateLoadFailed) return;
  const err=document.getElementById('maktabQuickLogError'),save=document.getElementById('maktabQuickLogSave');
  const status=document.getElementById('maktabQuickLogStatus'),confirmBox=document.getElementById('maktabQuickLogConfirm');
  if(err) err.textContent='';if(status) status.textContent='';
  const context=state.context,editing=state.editing;
  try{context.assertCurrent();if(editing && !context.canEdit(editing)) throw Error('This entry is read only.');}
  catch(error){if(err) err.textContent=error.message;return;}
  if(!/^\d{4}-\d{2}-\d{2}$/.test(state.date)){if(err) err.textContent='Choose a valid date.';return;}
  if(state.type!=='sabaqDhor' && !confirmBox?.checked){if(err) err.textContent='Please confirm the selection before saving.';return;}
  let payload={date:state.date},duplicateLabel=MAKTAB_QUICK_LABEL[state.type];
  if(state.type==='sabaq'){
    const from=maktabQuickReadVerse('from'),to=maktabQuickReadVerse('to');
    if(!from||!to){if(err) err.textContent='Please set both Ayah From and Ayah To.';return;}
    if(!crossesAtMostOneJuzBoundary(from.surah,from.ayah,to.surah,to.ayah,state.ref)){
      if(err) err.textContent="This Sabaq range crosses more than one juz' boundary — please split it into separate entries.";return;
    }
    Object.assign(payload,{sabaq_from:formatVerseRef(from.surah,from.ayah),sabaq_to:formatVerseRef(to.surah,to.ayah)});
    // Preserve manually entered counts on a tag/date-only edit. A changed
    // range is measured by the same Quran data and page capacity as Detail.
    if(!editing || editing.sabaq_from!==payload.sabaq_from || editing.sabaq_to!==payload.sabaq_to){
      const ref=state.mushaf==='15line_indopak'?'indopak':state.ref;
      const count=getLinesForSpan(from.surah,from.ayah,to.surah,to.ayah,ref);
      if(count){payload.line_count=count.lineCount;payload.page_count=Math.floor(count.lineCount/(state.mushaf==='13line'?13:15)*4)/4;}
    }
  }else if(state.type==='sabaqDhor'){
    const selection=maktabQuickReadSabaqDhorComposite();
    if(selection.error){if(err) err.textContent=selection.error;return;}
    const r=selection.range;
    Object.assign(payload,{from_surah:r.fromSurah,from_ayah:r.fromAyah,to_surah:r.toSurah,to_ayah:r.toAyah});
  }else{
    const draft=maktabQuickTypeDraft('dhor');
    if(draft.editingRange){
      const max=segmentsPerJuz(draft.ref)*30;
      if(!Number.isInteger(draft.segmentFrom)||!Number.isInteger(draft.segmentTo)||draft.segmentFrom<1||draft.segmentTo>max||draft.segmentFrom>draft.segmentTo){if(err) err.textContent='Choose a valid Dhor range.';return;}
      Object.assign(payload,{segment_from:draft.segmentFrom,segment_to:draft.segmentTo,ref:draft.ref});
    }else{
      const juz=Number(document.getElementById('mql_dhor_juz').value)||draft.juz;
      if(!Number.isInteger(juz)||juz<1||juz>30){if(err) err.textContent='Please select a Juz.';return;}
      draft.juz=juz;
      const unit=draft.unit==='full'?'juz':draft.unit;
      const range=segmentRangeForUnitIndex(juz,draft.unit==='full'?1:draft.position,state.ref,unit);
      Object.assign(payload,range,{ref:state.ref});duplicateLabel=`Juz ${juz} ${unit}`;
    }
  }
  payload.tajweed_tag_ids=(state.tajweed?.[state.type]||[]).join(',');
  payload=journalContentChanges(state.type,payload,editing);
  if(editing && !Object.keys(payload).length){if(status) status.textContent='No changes to save.';return;}
  state.saving=true;
  const controls=Array.from(document.querySelectorAll('#maktabQuickLogSheet button, #maktabQuickLogSheet input, #maktabQuickLogSheet select'))
    .filter(el=>!el.classList.contains('close-btn')).map(el=>[el,el.disabled]);
  controls.forEach(([el])=>{el.disabled=true;});
  let saved=false,progressError=null;
  try{
    const oldSabaqHistory=state.type==='sabaq'?await context.client('sabaq').get():[];
    if(maktabQuickLogState!==state)return;
    context.assertCurrent();
    if(editing) await context.client(state.type).update(editing.id,payload);
    else{
      const path=(context.mode==='maktab'?'/maktab/':'/')+JOURNAL_LOG_SCHEMA[state.type].path;
      if(!await maktabQuickPost(path,payload,duplicateLabel,context,state.type)) return;
    }
    saved=true;
    if(state.type==='sabaq'){
      try{await maktabQuickSyncSabaqPosition(state.student.id,oldSabaqHistory,state.ref,context,editing);}
      catch(error){progressError=error;}
    }
    if(maktabQuickLogState!==state) return;
    context.assertCurrent();
    state.editing=null;
    if(state.tajweed) state.tajweed[state.type]=[];
    document.querySelectorAll('#maktabQuickLogSheet input[type="checkbox"]').forEach(el=>{el.checked=false;});
    if(status) status.textContent=`${MAKTAB_QUICK_LABEL[state.type]} ${editing?'updated':'saved'}. You can add another entry or close.`;
    let refreshError=null;
    try{
      state.entriesByType=await context.readDate(state.date);
      const planning=await maktabQuickPlanningDefaults(state.student.id,state.ref,state.date,context);
      if(maktabQuickLogState!==state) return;
      state.sabaqDhorRows=planning.sabaqDhorRows||[];
      state.addDefaults=planning.sabaqDefaults;
      if(state.type==='sabaq')state.drafts.sabaq={from:maktabQuickCloneVerse(planning.sabaqDefaults.from),to:maktabQuickCloneVerse(planning.sabaqDefaults.to)};
      if(editing && state.type==='dhor')state.drafts.dhor={juz:null,unit:'quarter',position:1};
      if(state.type==='sabaqDhor')state.drafts.sabaqDhor={from:null,to:null};
    }catch(error){refreshError=error;}
    if(maktabQuickLogState===state){
      context.assertCurrent();
      if(typeof state.afterSave==='function')await state.afterSave();
      else if(context.mode==='maktab')await renderMaktabSummaryScreen();
    }
    if(refreshError||progressError)throw refreshError||progressError;
  }catch(error){
    if(maktabQuickLogState===state && err)err.textContent=saved
      ? "Entry saved, but the latest details couldn't be refreshed. Close and reopen to reload them."
      : "Couldn't save: "+error.message;
  }finally{
    state.saving=false;
    if(maktabQuickLogState===state){
      const message=err?.textContent;
      if(saved)maktabQuickRenderBody();
      controls.forEach(([el,disabled])=>{if(el.isConnected)el.disabled=disabled;});
      if(save?.isConnected)save.disabled=!!state.dateLoadFailed;
      if(err)err.textContent=message||'';
    }
  }
}

async function maktabOpenQuickLog(student, date, type, entries, entriesByType, opts){
  try{
    const context=createJournalQuickContext('maktab',student,opts && opts.afterSave);
    return await openJournalQuickLog(context,date,type,entries,entriesByType,opts);
  }catch(error){showBanner("Couldn't open Quick Log: "+error.message);}
}

async function openJournalQuickLog(context, date, type, entries, entriesByType, opts){
  const student=context.student;
  context.assertCurrent();
  maktabCloseQuickLog();
  const openToken = ++maktabQuickLogOpenToken;
  let settings = null;
  settings = await context.profile();
  if(openToken !== maktabQuickLogOpenToken) return;
  const combined = !!(opts && opts.combined) || maktabQuickIsMobile();
  const entryMap = entriesByType || { sabaq: [], sabaqDhor: [], dhor: [] };
  if(!entriesByType) entryMap[type] = (entries || []).slice();
  const ref = maktabQuickRefForMushaf(settings && settings.mushaf);
  let planning = { sabaqDefaults:{from:null,to:null}, sabaqDhorRows:[] };
  try{ planning = await maktabQuickPlanningDefaults(student.id, ref, date, context); } catch(e){ /* prepopulation is convenience, never a blocker */ }
  if(openToken !== maktabQuickLogOpenToken) return;
  context.assertCurrent();
  const sabaqDefaults = planning.sabaqDefaults || { from:null, to:null };
  maktabQuickLogState = {
    student, date, type, combined, context, mushaf:settings && settings.mushaf, editing:null, dateLoadToken: 0,
    entriesByType: {
      sabaq: (entryMap.sabaq || []).slice(),
      sabaqDhor: (entryMap.sabaqDhor || []).slice(),
      dhor: (entryMap.dhor || []).slice()
    },
    drafts: {
      sabaq: { from:maktabQuickCloneVerse(sabaqDefaults.from), to:maktabQuickCloneVerse(sabaqDefaults.to) },
      sabaqDhor: { from:null, to:null },
      dhor: { juz:null, unit:'quarter', position:1 }
    },
    sabaqDhorRows: (planning.sabaqDhorRows || []).slice(),
    sabaqDhorPicker: { juz:1, quarter:1 },
    ref,
    addDefaults:sabaqDefaults,
    afterSave: context.afterSave || (opts && opts.afterSave)
  };
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay maktab-quick-log-modal';
  overlay.id = 'maktabQuickLogSheet';
  const desktopHeading = `<span class="maktab-quick-kind">${MAKTAB_QUICK_LABEL[type]} :</span>`;
  overlay.innerHTML = `<div class="modal-card maktab-quick-log-card" role="dialog" aria-modal="true" aria-label="Quick Log">
    <button type="button" class="close-btn" aria-label="Close">&times;</button>
    <div class="maktab-quick-heading${combined ? ' is-combined' : ''}">
      ${combined ? '' : desktopHeading}
      <span class="maktab-name-pill maktab-quick-student" title="${maktabQuickEscape(student.name)}">${maktabQuickEscape(student.name)}</span>
    </div>
    <div class="maktab-quick-date-row">
      ${maktabQuickDateControl('maktabQuickLogDate', date, 'Quick Log date')}
      <button type="button" class="maktab-quick-detail-action" id="maktabQuickLogDetails" aria-label="Open detail" title="Detail"><span class="maktab-quick-detail-icon">${iconHtml('detail')}</span><span>Detail</span></button>
    </div>
    ${combined ? maktabQuickTypeSelector() : ''}
    <div id="journalQuickMode" class="journal-quick-mode"></div>
    <div id="maktabQuickExisting"></div>
    <div id="maktabQuickBody"></div>
    <div class="form-hint" id="maktabQuickLogStatus" role="status" aria-live="polite"></div>
    <div class="form-error" id="maktabQuickLogError"></div>
    <div class="maktab-quick-actions" id="maktabQuickActions">
      <div id="maktabQuickTajweed" data-trigger-label="Tajweed"></div>
      <button type="button" class="primary maktab-quick-save" id="maktabQuickLogSave">Save</button>
    </div>
  </div>`;
  document.body.appendChild(overlay);
  const quickDateInput = document.getElementById('maktabQuickLogDate');
  if(typeof wireCustomDateDisplay === 'function') wireCustomDateDisplay('maktabQuickLogDate');
  if(quickDateInput) quickDateInput.addEventListener('change', () => {
    if(!maktabQuickLogState) return;
    if(!quickDateInput.value){ quickDateInput.value = maktabQuickLogState.date; return; }
    maktabQuickChangeDate(quickDateInput.value);
  });
  overlay.querySelector('.close-btn').addEventListener('click', maktabCloseQuickLog);
  overlay.addEventListener('click', e => { if(e.target === overlay) maktabCloseQuickLog(); });
  document.getElementById('maktabQuickLogSave').addEventListener('click', maktabSaveQuickLog);
  document.getElementById('maktabQuickLogDetails').addEventListener('click', () => {
    const snapshot = maktabQuickLogState;
    maktabCloseQuickLog();
    snapshot.context.detail(snapshot.type,snapshot.date,snapshot.editing).catch(error=>showBanner(error.message));
  });
  document.querySelectorAll('[data-mql-type]').forEach(btn => btn.addEventListener('click', () => {
    if(!maktabQuickLogState || maktabQuickLogState.saving) return;
    journalQuickAddMode(btn.dataset.mqlType);
  }));
  overlay.addEventListener('input',journalQuickInvalidateConfirmation);
  overlay.addEventListener('change',journalQuickInvalidateConfirmation);
  overlay.addEventListener('click',event=>{if(event.target.closest('[data-mql-step],[data-unit],[data-pos],[data-mql-sd-quarter]'))journalQuickClearConfirmation();});
  maktabQuickRenderBody();
  if(opts && opts.entry) journalQuickEditEntry(opts.entry);
}

function journalQuickParseVerse(raw){
  const parts=String(raw||'').split(':').map(Number);
  return parts.length===2 && parts.every(n=>Number.isInteger(n)&&n>0)?{surah:parts[0],ayah:parts[1]}:null;
}

function journalQuickClearConfirmation(){
  document.querySelectorAll('#maktabQuickLogSheet input[type="checkbox"]').forEach(input=>{input.checked=false;});
}
function journalQuickInvalidateConfirmation(event){
  if(event.target.matches('input[type="number"],input[type="date"],select'))journalQuickClearConfirmation();
}

function journalQuickRenderMode(){
  const state=maktabQuickLogState,host=document.getElementById('journalQuickMode');
  if(!state || !host) return;
  const text=state.editing?'Editing '+MAKTAB_QUICK_LABEL[state.type]+' entry':'Add '+MAKTAB_QUICK_LABEL[state.type]+' entry';
  host.innerHTML=`<strong>${text}</strong>${state.editing?'<button type="button" id="journalQuickAddNew">Add new entry</button>':''}`;
  const button=document.getElementById('journalQuickAddNew');
  if(button)button.addEventListener('click',()=>journalQuickAddMode(state.type));
  const save=document.getElementById('maktabQuickLogSave');
  if(save)save.textContent=state.editing?'Save changes':'Save';
}

function journalQuickAddMode(type){
  const state=maktabQuickLogState;
  if(!state || state.saving || state.loadingDate || !JOURNAL_LOG_SCHEMA[type])return;
  if(state.editing){
    // Leaving Edit must not turn a saved row's draft into an accidental Add.
    const editedType=state.type,defaults=state.addDefaults||{};
    state.drafts[editedType]=editedType==='sabaq'
      ?{from:maktabQuickCloneVerse(defaults.from),to:maktabQuickCloneVerse(defaults.to)}
      :editedType==='sabaqDhor'?{from:null,to:null}:{juz:null,unit:'quarter',position:1};
    if(state.tajweed)state.tajweed[editedType]=[];
  }
  state.type=type;state.editing=null;
  maktabQuickRenderBody();
}

function journalQuickEditEntry(entry){
  const state=maktabQuickLogState;
  if(!state || state.saving || state.loadingDate || !state.context.canEdit(entry))return;
  state.editing=Object.freeze({...entry});
  state.tajweed=state.tajweed||{};
  state.tajweed[state.type]=String(entry.tajweed_tag_ids||'').split(',').filter(Boolean);
  if(state.type==='sabaq')state.drafts.sabaq={from:journalQuickParseVerse(entry.sabaq_from),to:journalQuickParseVerse(entry.sabaq_to)};
  else if(state.type==='sabaqDhor')state.drafts.sabaqDhor={from:journalQuickParseVerse(entry.from_surah+':'+entry.from_ayah),to:journalQuickParseVerse(entry.to_surah+':'+entry.to_ayah)};
  else state.drafts.dhor={editingRange:true,segmentFrom:Number(entry.segment_from),segmentTo:Number(entry.segment_to),ref:entry.ref||state.ref};
  maktabQuickRenderBody();
  journalQuickClearConfirmation();
}

function journalQuickDhorRangeHtml(draft){
  const per=segmentsPerJuz(draft.ref),name=per===8?'Eighth':'Quarter';
  const row=side=>{
    const segment=draft[side==='from'?'segmentFrom':'segmentTo'];
    const juz=Math.floor((segment-1)/per)+1,portion=(segment-1)%per+1;
    const options=(count,selected,prefix)=>Array.from({length:count},(_,i)=>`<option value="${i+1}"${i+1===selected?' selected':''}>${prefix} ${i+1}</option>`).join('');
    return `<div class="journal-quick-dhor-range"><strong>${side==='from'?'From':'To'}</strong>
      <select id="quick_dhor_${side}_juz" data-quick-dhor-side="${side}" aria-label="${side} Juz">${options(30,juz,'Juz')}</select>
      <select id="quick_dhor_${side}_portion" data-quick-dhor-side="${side}" aria-label="${side} ${name}">${options(per,portion,name)}</select></div>`;
  };
  return `<div class="maktab-quick-dhor-grid">${row('from')}${row('to')}${maktabQuickConfirmControl()}</div>`;
}

async function openPersonalQuickLog(date,type='sabaq',entry=null){
  try{
    const student={id:currentUser.id,name:currentUser.name||currentUser.id};
    const context=createJournalQuickContext('personal',student,async()=>{
      await loadJournalData(JOURNAL_EXPANDED_DAYS+journalRollupDays);renderJournalTable();
    });
    await openJournalQuickLog(context,date,type,null,journalData[date]||{sabaq:[],sabaqDhor:[],dhor:[]},{combined:true,entry});
  }catch(error){showBanner("Couldn't open Quick Log: "+error.message);}
}
