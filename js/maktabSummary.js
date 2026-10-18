/* Hifzhelper build 5.2 | js/maktabSummary.js */
// ============================================================
// Hifzhelper -- Maktab summary screen (V3.61.0; first shipped V3.59.0,
// day-entry additions V3.60.0, this UI round from device screenshots
// confirmed in chat 2026-08-16).
// The teacher's view of ONE Hifz day: leading narrow haidh column,
// student names, then Sabaq | Sabaq Dhor | Dhor in the PJ journal's
// own cell shorthand (journalCellShorthand reused directly).
//
// V3.61.0 changes, all user-stated:
//   - DATE PICKER in line with the close icon (V3.50.1
//     native-input-as-tap-target pattern via wireCustomDateDisplay --
//     that pattern exists precisely because showPicker() no-ops on
//     iOS). Defaults to today; picking a past date re-renders the
//     grid for it, and the picked date FOLLOWS THROUGH to the day
//     view (backfill/corrections -- confirmed).
//   - Haidh control moved to its own NARROW LEADING column: a small
//     haidh icon (V3.76.0: a LINK to the student's haidh calendar,
//     showing the date's state; it was the haidh checkbox until then),
//     so the controls line up on the extreme left instead of trailing
//     variable-length names. Rendered ONLY for students with track_haidh (the same
//     Settings opt-in that gates the PJ's Haidh nav item) -- the
//     GLOBAL haidh-gating rule. It sits inside the whole-row tap
//     target, so it stops propagation -- the one deliberate
//     exception to the no-nested-controls rule the count badges
//     follow, because this control is an agreed requirement.
//   - Count badges stay downgraded to plain text (V3.59.0 decision).
// ============================================================

let maktabSummaryData = null;
let maktabSummarySelectedDate = null; // ISO; null until first render (defaults to today)

function maktabTodayISO(){
  const d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}

// journalCellShorthand keys sabaqDhor cells on from_surah/from_ayah/
// to_surah/to_ayah and dhor cells on segment_from/segment_to -- the
// maktab tables carry identical columns, so rows pass straight through.
function maktabCellHtml(type, entries){
  const html = journalCellShorthand(type, entries);
  // V3.74.2: the badge is a real button again. It had been downgraded to a
  // span, which is precisely WHY tapping it opened the day view — with no
  // button to catch the tap it fell through to the row. Now it opens a
  // read-only list of that cell's entries and stops there.
  return html.replace(
    /<button type="button" class="entry-count-badge" data-count-badge>(\+\d+)<\/button>/,
    `<button type="button" class="entry-count-badge" data-entry-peek="${type}">$1</button>`
  );
}


// Quick Log/editor is shared with Personal Journal in journalQuickEditor.js.

// V4.2.15: compact summary-level route to the full Attendance register.
const maktabSummaryAttendanceBtn = document.getElementById('maktabSummaryAttendanceBtn');
if(maktabSummaryAttendanceBtn){
  maktabSummaryAttendanceBtn.innerHTML = iconHtml('attendance') + '<span>Attendance</span>';
  maktabSummaryAttendanceBtn.addEventListener('click', () => showScreen('maktabAttendance'));
}

// A read-only peek at every entry in one cell — including the one already
// shown, so the list is the whole truth rather than "the others".
// Deliberately not tappable: the row still opens the day view, so no route
// is lost, and this stays a glance rather than a second way in.
function maktabCloseEntryPeek(){
  const el = document.getElementById('maktabEntryPeek');
  if(el) el.remove();
}

function maktabOpenEntryPeek(btn, type, entries){
  maktabCloseEntryPeek();
  const panel = document.createElement('div');
  panel.id = 'maktabEntryPeek';
  panel.className = 'maktab-entry-peek';
  panel.innerHTML = (entries || []).map(e =>
    `<div class="maktab-entry-peek-row">${journalCellShorthand(type, [e]).replace(/<[^>]+>/g, '')}</div>`
  ).join('') || '<div class="maktab-entry-peek-row">No entries</div>';
  document.body.appendChild(panel);
  const r = btn.getBoundingClientRect();
  // Anchored to the badge, flipped up when there is no room below —
  // summary rows sit near the bottom of the card on a short screen.
  const below = window.innerHeight - r.bottom;
  panel.style.left = Math.min(r.left, window.innerWidth - panel.offsetWidth - 8) + 'px';
  if(below < panel.offsetHeight + 12){
    panel.style.top = (r.top - panel.offsetHeight - 6) + 'px';
  } else {
    panel.style.top = (r.bottom + 6) + 'px';
  }
}

// V4.2.15.11: phone-only roster filter. Unlike the desktop Student-header
// search (which is navigation to a student's day), this field simply filters
// the cards already on the selected Maktab day. It lives directly below the
// date row and never changes the selected date or destination.
let maktabMobileSearchWired = false;
function maktabSummaryApplyMobileSearch(){
  const input = document.getElementById('maktabSummaryMobileSearch');
  const empty = document.getElementById('maktabSummaryMobileSearchEmpty');
  const isMobile = !!(window.matchMedia && window.matchMedia('(max-width: 767px)').matches);
  const q = isMobile && input ? input.value.trim().toLocaleLowerCase() : '';
  let visible = 0;
  document.querySelectorAll('#maktabSummaryBody tr[data-maktab-student-name]').forEach(row => {
    const show = !q || String(row.dataset.maktabStudentName || '').includes(q);
    row.classList.toggle('maktab-mobile-search-hidden', !show);
    if(show) visible++;
  });
  if(empty) empty.classList.toggle('hidden', !isMobile || !q || visible > 0);
}
function wireMaktabSummaryMobileSearch(){
  const input = document.getElementById('maktabSummaryMobileSearch');
  if(!input) return;
  if(!maktabMobileSearchWired){
    maktabMobileSearchWired = true;
    input.addEventListener('input', maktabSummaryApplyMobileSearch);
    window.addEventListener('resize', maktabSummaryApplyMobileSearch);
  }
  maktabSummaryApplyMobileSearch();
}

// V3.78.0 (item 9): search-to-student. Rebuilt each render with that
// render's roster and picked date, so a result always opens the day the
// summary is showing. The input keeps its text across renders (the render
// replaces only the results and the handler's data).
let maktabSearchWired = false;
function wireMaktabSummarySearch(students, date){
  const input = document.getElementById('maktabSummarySearch');
  const results = document.getElementById('maktabSummarySearchResults');
  if(!input || !results) return;
  input._students = students;
  input._date = date;
  if(maktabSearchWired) return;
  maktabSearchWired = true;
  const render = () => {
    const q = input.value.trim().toLowerCase();
    if(!q){ results.classList.add('hidden'); results.innerHTML = ''; return; }
    const matches = (input._students || []).filter(s => s.name.toLowerCase().includes(q)).slice(0, 8);
    results.innerHTML = '';
    if(!matches.length){
      const d = document.createElement('div');
      d.className = 'maktab-search-empty';
      d.textContent = 'No matching student.';
      results.appendChild(d);
    }
    matches.forEach(stu => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'maktab-search-result';
      btn.textContent = stu.name + (stu.group_name ? ' · ' + stu.group_name : '');
      btn.addEventListener('click', () => {
        input.value = '';
        results.classList.add('hidden');
        results.innerHTML = '';
        input.classList.add('hidden');                                    // V3.84.0: back to the label
        document.getElementById('maktabSummarySearchToggle').classList.remove('hidden');
        openMaktabDay(stu, input._date);
      });
      results.appendChild(btn);
    });
    results.classList.remove('hidden');
  };
  input.addEventListener('input', render);
  input.addEventListener('focus', render);
  // V3.84.0: tap-to-reveal — the green Student header cell is a label
  // until tapped; the tap swaps in the input (sized to the cell) and
  // focuses it. Esc, or a tap anywhere outside the cell, restores the
  // label and clears any open results. The reveal choice (vs an
  // always-visible field) was left to Claude and is easy to flip.
  const toggle = document.getElementById('maktabSummarySearchToggle');
  const restore = () => {
    input.classList.add('hidden');
    toggle.classList.remove('hidden');
    results.classList.add('hidden');
  };
  toggle.addEventListener('click', () => {
    toggle.classList.add('hidden');
    input.classList.remove('hidden');
    input.focus();
  });
  input.addEventListener('keydown', (e) => { if(e.key === 'Escape'){ input.value = ''; restore(); } });
  document.addEventListener('click', (e) => {
    if(!e.target.closest || (!e.target.closest('.maktab-search-cell'))){
      if(!input.classList.contains('hidden') || !results.classList.contains('hidden')) restore();
    }
  });
}

// V3.75.0 (item 4): this listener only CLOSES the peek now. Opening moved
// onto the badge button itself (see the render below) — delegated here it
// ran after the <tr>'s own click handler and could not stop the day view
// opening. A badge click never reaches document (the button stops it), so
// the click-away close cannot fire against the badge that just opened it.
document.addEventListener('click', (e) => {
  if(!e.target.closest || !e.target.closest('#maktabEntryPeek')) maktabCloseEntryPeek();
});

// V4.2.14.2 — Maktab Summary has its own intentionally simple ordering.
// For the DISPLAYED day only: every student with any Sabaq / Sabaq Dhor /
// Dhor log comes first in first-name alphabetical order; every student with
// no log follows in the same alphabetical order. Attendance %, Haidh state
// and Group do not participate in this screen's ordering.
function maktabSummaryNameKey(student){
  const full = String((student && student.name) || '').trim();
  const first = (full.split(/\s+/)[0] || '').toLocaleLowerCase();
  return { first, full: full.toLocaleLowerCase(), id: String((student && student.id) || '').toLocaleLowerCase() };
}

function maktabSummaryHasLog(studentId, byStudent){
  return ['sabaq', 'sabaqDhor', 'dhor'].some(type => ((byStudent[type] && byStudent[type][studentId]) || []).length > 0);
}

function maktabSummarySortBand(student, byStudent){
  return maktabSummaryHasLog(student.id, byStudent) ? 0 : 1;
}

function maktabSummaryCompareName(a, b){
  const aa = maktabSummaryNameKey(a), bb = maktabSummaryNameKey(b);
  return aa.first.localeCompare(bb.first, undefined, { sensitivity:'base', numeric:true })
    || aa.full.localeCompare(bb.full, undefined, { sensitivity:'base', numeric:true })
    || aa.id.localeCompare(bb.id, undefined, { sensitivity:'base', numeric:true });
}

function maktabSummarySortedStudents(students, byStudent){
  return (students || []).slice().sort((a, b) => {
    const band = maktabSummarySortBand(a, byStudent) - maktabSummarySortBand(b, byStudent);
    return band || maktabSummaryCompareName(a, b);
  });
}

function maktabSummaryWireDate(){
  const input = document.getElementById('maktabSummaryDatePicker');
  if(!input) return;
  if(!input.value) input.value = maktabSummarySelectedDate || maktabTodayISO();
  if(typeof wireCustomDateDisplay === 'function') wireCustomDateDisplay('maktabSummaryDatePicker');
  if(!input.dataset.maktabWired){
    input.dataset.maktabWired = 'true';
    input.addEventListener('change', () => {
      if(!input.value) return;
      maktabSummarySelectedDate = input.value;
      renderMaktabSummaryScreen();
    });
  }
}

async function renderMaktabSummaryScreen(){
  const host = document.getElementById('maktabSummaryBody');
  if(!maktabSummarySelectedDate) maktabSummarySelectedDate = maktabTodayISO();
  const date = maktabSummarySelectedDate;
  maktabSummaryWireDate();
  wireMaktabSummaryMobileSearch();
  const input = document.getElementById('maktabSummaryDatePicker');
  // programmatic sets keep the display pill in sync automatically --
  // wireCustomDateDisplay intercepts the value setter (the 2026-08-04
  // fix in customDate.js), no event needed.
  if(input && input.value !== date) input.value = date;

  // V4.2.5 (user): the names appeared only after the round trips finished,
  // though they have nothing to do with the day's data. The last roster is
  // cached and painted IMMEDIATELY — names, their pills and the attendance
  // icon — with the log cells left blank and a loading strip under the
  // header; the cells fill when the responses land.
  //
  // Deliberately the ROSTER ONLY, never the log cells: names change
  // rarely, a day's entries change constantly, and a stale entry on
  // screen is worse than a wait because a teacher could act on it.
  // Deliberately in MEMORY, not localStorage: it covers returning to the
  // screen within a session without leaving a maktab's student names on a
  // shared or borrowed device. A cold start still waits once.
  if(maktabRosterCache && maktabRosterCache.length){
    maktabSummaryPaintSkeleton(host, maktabRosterCache);
  } else {
    host.innerHTML = '<tr><td colspan="6" class="journal-cell journal-cell-empty">Loading\u2026</td></tr>';
  }
  maktabSummarySetLoading(true);

  // V3.59.1: respond() UNWRAPS on the worker (json(result.data)) -- the
  // response body IS the payload, no {data:...} envelope on the wire.
  // Shape-guarded so ANY malformed response renders the error row.
  let data, loadErr = null;
  try {
    data = await apiMaktabSummary(date);
  } catch (e) {
    data = null;
    loadErr = e;
  }
  if (!data || !Array.isArray(data.students)) {
    // V3.75.0 (item 6): carry the worker's message rather than a fixed
    // line. Set via textContent, so a message containing markup is text.
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'journal-cell journal-cell-empty';
    td.textContent = 'Could not load the maktab summary: ' + ((loadErr && loadErr.message) || 'unexpected response');
    maktabSummarySetLoading(false);   // V4.2.5
    host.innerHTML = '';
    const tr = document.createElement('tr'); tr.appendChild(td); host.appendChild(tr);
    return;
  }
  maktabSummaryData = data;
  maktabRosterCache = (data.students || []).map(s => ({ id: s.id, name: s.name, track_haidh: s.track_haidh }));   // V4.2.5

  // group each table's rows by student for O(1) cell lookup
  const byStudent = { sabaq: {}, sabaqDhor: {}, dhor: {} };
  (data.sabaq || []).forEach(r => (byStudent.sabaq[r.student_id] = byStudent.sabaq[r.student_id] || []).push(r));
  (data.sabaq_dhor || []).forEach(r => (byStudent.sabaqDhor[r.student_id] = byStudent.sabaqDhor[r.student_id] || []).push(r));
  (data.dhor || []).forEach(r => (byStudent.dhor[r.student_id] = byStudent.dhor[r.student_id] || []).push(r));

  // V4.2.14: consume the SAME normalized Attendance model used by the
  // register/calendar. There is deliberately no raw-Haidh fallback: if this
  // request fails, Summary omits Haidh state rather than surfacing stale data.
  let derived = {};
  let isMaktabDay = false;
  try {
    const att = await apiGetMaktabAttendance(date);
    if(att && att.attendance){
      derived = att.attendance;
      isMaktabDay = !!att.isMaktabDay;
    }
  } catch(e){ derived = {}; }

  host.innerHTML = '';
  const sortedStudents = maktabSummarySortedStudents(data.students || [], byStudent);
  // V4.2.14.2: no Group or Haidh separators here. The two ordering bands
  // are simply logged and unlogged, and each band remains alphabetical.
  sortedStudents.forEach((stu, rowIndex) => {
    const tr = document.createElement('tr');
    tr.className = 'maktab-summary-row';
    tr.dataset.maktabStudentName = String(stu.name || '').toLocaleLowerCase();

    // V3.61.0: leading narrow haidh column -- small haidh icon, ONLY for
    // haidh-tracking students (empty cell otherwise so the grid stays
    // aligned).
    // V3.76.0 (Phase 2): it is a LINK now, not a toggle. It still shows the
    // date's state (.marked), but tapping it opens the shared haidh calendar
    // for this student, on the month of the picked date, where haidh is
    // marked as a range. The single-day toggle with its 15-day confirm is
    // deleted (js/maktabDay.js). stopPropagation stays: the row itself
    // still opens the day view.
    // V3.80.0: the leading icon is ATTENDANCE, on EVERY student (was the
    // haidh icon, haa'idah only). V4.2.15 keeps it on every student but
    // routes it straight to the existing Student Attendance calendar.
    const haidhTd = document.createElement('td');
    haidhTd.className = 'maktab-haidh-col';
    const rowMeta = document.createElement('div');
    rowMeta.className = 'maktab-row-meta';
    const rowNumber = document.createElement('span');
    rowNumber.className = 'maktab-row-number';
    rowNumber.textContent = String(rowIndex + 1);
    rowNumber.setAttribute('aria-hidden', 'true');
    const btn = document.createElement('button');
    btn.type = 'button';
    // V4.2.15: the attendance icon opens the existing Student Attendance
    // calendar at this Summary date. That shared page already owns single-date
    // and start/end range selection plus Haidh / Absent actions.
    btn.className = 'maktab-haidh-check';
    btn.innerHTML = iconHtml('attendance');
    btn.setAttribute('aria-label', 'Attendance for ' + stu.name);
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      maktabOpenQuickAttendance(stu, date);
    });
    rowMeta.appendChild(btn);
    rowMeta.appendChild(rowNumber);
    haidhTd.appendChild(rowMeta);
    tr.appendChild(haidhTd);

    const nameTd = document.createElement('td');
    nameTd.className = 'cell-date maktab-student-name';
    const nameSpan = document.createElement('span');
    nameSpan.className = 'maktab-name-pill';   // V4.2.0 (user): reads as the button it already is
    nameSpan.textContent = stu.name;
    // V4.2.8 (user): every pill has the same width; long names are
    // visually ellipsised by CSS, so keep the full name available on hover.
    nameSpan.title = stu.name;
    nameTd.appendChild(nameSpan);
    // V3.85.0 (was V3.82.0's rail card): tapping the NAME opens her
    // STANDALONE student summary page. In V4.2.15.8 the rest of the row
    // is display-only; logging is isolated in the dedicated Log column.
    nameTd.addEventListener('click', (e) => {
      e.stopPropagation();
      openStudentSummaryPage({ id: stu.id, name: stu.name, mushaf: stu.mushaf || null, track_haidh: !!stu.track_haidh }, date);
    });
    // V3.72.0: the Setup chip is GONE from this row. Setup opens from the
    // Dhor card's own button now — it configures the Dhor pool and nothing
    // else, so it belongs with Dhor rather than on a row spanning all three
    // log types. The V3.66.0 concern that made it a small explicit control
    // (saving REPLACES her pool, so it must not be reachable by a mis-tap
    // meant for the day view) is satisfied differently: it is no longer on
    // the tappable row at all.
    tr.appendChild(nameTd);

    const hasAnyLog = ['sabaq', 'sabaqDhor', 'dhor'].some(t => (byStudent[t][stu.id] || []).length);
    const CELL_LABEL = { sabaq: 'Sabaq', sabaqDhor: 'Sabaq Dhor', dhor: 'Dhor' };
    ['sabaq', 'sabaqDhor', 'dhor'].forEach(type => {
      const td = document.createElement('td');
      td.className = 'journal-cell';
      td.setAttribute('data-label', CELL_LABEL[type]);   // V4.2.2: the mobile card's caption
      const d = derived[stu.id];
      // V4.2.14: the pink Haidh note is removed. Haidh may still affect the
      // normalized sort/attendance result, but the Sabaq cell stays visually
      // empty unless there is an explicit Absent result.
      if(type === 'sabaq' && !hasAnyLog && d && d.status === 'absent'){
        td.className = 'journal-cell journal-cell-absent';
        td.textContent = 'Absent';
      } else {
        // V4.2.8 / item 68: one summary-only wrapper makes the value +
        // its +N badge ONE grid item on mobile. Keep maktabCellHtml itself
        // unchanged because Maktab Journal reuses that helper too.
        td.innerHTML = `<span class="maktab-summary-cell-value">${maktabCellHtml(type, byStudent[type][stu.id])}</span>`;
        // V3.74.2: the peek reads its entries from the cell rather than
        // re-querying — the rows are already here, and re-deriving them
        // from the DOM would be parsing text back into data.
        td._peekEntries = byStudent[type][stu.id];
        // V3.75.0 (item 4): wired DIRECTLY on the badge. V3.74.2 handled it
        // by delegation on document, but the row's day-view handler is on
        // the <tr> itself — so during bubbling the row fired FIRST and
        // opened the day view, and the stopPropagation at document level
        // came too late to matter. A listener on the button runs before
        // the tap ever reaches the row. The rows are rebuilt on every
        // render, so this cannot leak: the old buttons go with the old
        // rows.
        const peekBtn = td.querySelector('[data-entry-peek]');
        if(peekBtn){
          peekBtn.addEventListener('click', (e) => {
            e.stopPropagation();   // keep the +N peek isolated from other controls
            maktabOpenEntryPeek(peekBtn, type, td._peekEntries);
          });
        }
      }
      // V4.2.15.8: activity cells are display/peek only. Logging is entered
      // through the dedicated Log column, which opens one unified selector.
      tr.appendChild(td);
    });

    // V4.2.15.8: one dedicated Log target on phone, tablet and desktop.
    // It always opens the unified selector card (Sabaq / Sabaq Dhor / Dhor).
    const mobileLogTd = document.createElement('td');
    mobileLogTd.className = 'maktab-mobile-log-col';
    const mobileLogBtn = document.createElement('button');
    mobileLogBtn.type = 'button';
    mobileLogBtn.className = 'maktab-mobile-log-action';
    mobileLogBtn.setAttribute('aria-label', 'Log activity for ' + stu.name);
    mobileLogBtn.innerHTML = `<span class="maktab-mobile-log-icon">${iconHtml('circlePlus')}</span><span>Log</span>`;
    mobileLogBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const student = { id: stu.id, name: stu.name, mushaf: stu.mushaf || null, track_haidh: !!stu.track_haidh };
      const entriesByType = {
        sabaq: byStudent.sabaq[stu.id] || [],
        sabaqDhor: byStudent.sabaqDhor[stu.id] || [],
        dhor: byStudent.dhor[stu.id] || []
      };
      maktabOpenQuickLog(student, date, 'sabaq', entriesByType.sabaq, entriesByType, { combined: true });
    });
    mobileLogTd.appendChild(mobileLogBtn);
    tr.insertBefore(mobileLogTd, nameTd.nextSibling);

    // attention flag: the row is tinted when a student has gone
    // absence_flag_days consecutive MAKTAB DAYS without an entry.
    if(derived[stu.id] && derived[stu.id].flagged) tr.classList.add('maktab-row-flagged');

    // V4.2.15.8: the row itself is deliberately inert. Name → Student
    // Summary, Attendance → Quick Attendance, +N → peek, Log → unified
    // Quick Log. No whitespace/data-cell tap can open an individual card.
    host.appendChild(tr);
  });
  // Search follows the visible ordering for predictable results, while its
  // destination remains the student's full day view on the selected date.
  wireMaktabSummarySearch(sortedStudents, date);
  maktabSummaryApplyMobileSearch();

  if (!(data.students || []).length) {
    host.innerHTML = '<tr><td colspan="6" class="journal-cell journal-cell-empty">No active students.</td></tr>';
  }
}

// ============================================================
// V4.2.5 — the roster cache, the skeleton paint and the loading strip.
// ============================================================
let maktabRosterCache = null;

function maktabSummarySetLoading(on){
  const row = document.querySelector('.maktab-summary-headers');
  if(!row) return;
  row.classList.toggle('is-loading', !!on);
}

// The cached paint: real names in real pills with the attendance icon, and
// EMPTY log cells — never stale ones. The cached Log control is intentionally
// non-interactive until the real render arrives, so no action runs on stale data.
function maktabSummaryPaintSkeleton(host, roster){
  host.innerHTML = '';
  roster.forEach((stu, rowIndex) => {
    const tr = document.createElement('tr');
    tr.className = 'journal-row maktab-summary-skeleton-row';
    tr.dataset.maktabStudentName = String(stu.name || '').toLocaleLowerCase();
    const haidhTd = document.createElement('td');
    haidhTd.className = 'maktab-haidh-col';
    const rowMeta = document.createElement('div');
    rowMeta.className = 'maktab-row-meta';
    const rowNumber = document.createElement('span');
    rowNumber.className = 'maktab-row-number';
    rowNumber.textContent = String(rowIndex + 1);
    rowNumber.setAttribute('aria-hidden', 'true');
    // V4.2.8.2: never paint iconHtml('attendance') naked. The real row
    // sizes that SVG through .maktab-haidh-check; the cached instant-name
    // paint used to omit the wrapper, so Safari briefly rendered the SVG at
    // its intrinsic/available size before fresh data replaced the row. Use
    // the same visual wrapper here (non-interactive until the real render).
    const attendanceGhost = document.createElement('span');
    attendanceGhost.className = 'maktab-haidh-check maktab-summary-skeleton-attendance';
    attendanceGhost.setAttribute('aria-hidden', 'true');
    attendanceGhost.innerHTML = typeof iconHtml === 'function' ? iconHtml('attendance') : '';
    rowMeta.appendChild(attendanceGhost);
    rowMeta.appendChild(rowNumber);
    haidhTd.appendChild(rowMeta);
    tr.appendChild(haidhTd);
    const nameTd = document.createElement('td');
    nameTd.className = 'cell-date maktab-student-name';
    const span = document.createElement('span');
    span.className = 'maktab-name-pill';
    span.textContent = stu.name;
    span.title = stu.name;
    nameTd.appendChild(span);
    tr.appendChild(nameTd);
    ['sabaq', 'sabaqDhor', 'dhor'].forEach(type => {
      const td = document.createElement('td');
      td.className = 'journal-cell';
      td.setAttribute('data-label', { sabaq: 'Sabaq', sabaqDhor: 'Sabaq Dhor', dhor: 'Dhor' }[type]);
      td.innerHTML = '<span class="journal-cell-skeleton"></span>';
      tr.appendChild(td);
    });
    const mobileLogTd = document.createElement('td');
    mobileLogTd.className = 'maktab-mobile-log-col';
    mobileLogTd.innerHTML = `<span class="maktab-mobile-log-action maktab-mobile-log-skeleton" aria-hidden="true"><span class="maktab-mobile-log-icon">${typeof iconHtml === 'function' ? iconHtml('circlePlus') : ''}</span><span>Log</span></span>`;
    tr.insertBefore(mobileLogTd, nameTd.nextSibling);
    host.appendChild(tr);
  });
}
