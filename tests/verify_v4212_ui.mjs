#!/usr/bin/env node
import {readSummarySource} from './helpers/journal-source.mjs';
// V4.2.12 — Maktab Summary Quick Log trial.
// Static/structural pins only so this runs in the bare checkout without jsdom.
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
let pass = 0, fail = 0;
const check = (label, cond, extra='') => { if(cond) pass++; else { fail++; console.log('FAIL:', label, extra); } };

const js = readSummarySource();
const css = read('css/journal-table.css');
const html = read('index.html');
const sw = read('js/sw.js');

check('activity cells are display-only and the dedicated Log action opens Quick Log',
  !/td\.addEventListener\('click',[\s\S]{0,420}maktabOpenQuickLog/.test(js)
  && /mobileLogBtn\.addEventListener\('click',[\s\S]{0,520}maktabOpenQuickLog\(student, date, 'sabaq', entriesByType\.sabaq, entriesByType, \{ combined: true \}\)/.test(js));
check('the +N entry peek remains a separate stop-propagating target',
  /peekBtn\.addEventListener\('click',[\s\S]{0,180}e\.stopPropagation\(\)/.test(js));
check('full detail cards remain reachable from the Quick Log sheet',
  /id="maktabQuickLogDetails"/.test(js) && /snapshot\.context\.detail\(snapshot\.type,snapshot\.date,snapshot\.editing\)/.test(js));

check('Sabaq and Sabaq Dhor expose From/To range controls with a Tajweed picker',
  /maktabQuickVerseField\('from', 'From'\)/.test(js)
  && /maktabQuickVerseField\('to', 'To'\)/.test(js)
  && /id="maktabQuickTajweed"/.test(js));
check('Sabaq Quick Log posts the existing minimal maktab fields',
  /sabaq: Object\.freeze\(\{label:'Sabaq',path:'sabaq'/.test(js));
check('Sabaq Dhor Quick Log posts the existing minimal maktab fields',
  /sabaqDhor: Object\.freeze\(\{label:'Sabaq Dhor',path:'sabaq-dhor'/.test(js));

check('Dhor has Juz plus Quarter / Half / Juz controls',
  /id="mql_dhor_juz"/.test(js)
  && /data-unit="quarter"[^>]*>Quarter</.test(js)
  && /data-unit="half"[^>]*>Half</.test(js)
  && /data-unit="full"[^>]*>Juz</.test(js));
check('Dhor range uses the shared segment arithmetic and existing maktab endpoint',
  /segmentRangeForUnitIndex\(juz,[^\n]+state\.ref/.test(js)
  && /dhor: Object\.freeze\(\{label:'Dhor',path:'dhor'/.test(js));

check('one confirmation checkbox gates one Save action',
  /id="maktabQuickLogConfirm"/.test(js)
  && /id="maktabQuickLogSave">Save<\/button>/.test(js)
  && /Please confirm the selection before saving/.test(js));
check('existing logs are made visible before adding another',
  /Already logged/.test(js) && /maktabQuickExistingText\(type, entries\)/.test(js));
check('duplicate protection is preserved with the established abortable force flow',
  /result\.isDuplicate && !result\.id/.test(js)
  && /confirm\(`\$\{duplicateLabel\} has already been saved/.test(js)
  && /force: true/.test(js));
check('successful Quick Log refreshes the caller or current summary instead of forcing a screen change',
  /if\(typeof state\.afterSave==='function'\)await state\.afterSave\(\);[\s\S]{0,120}else if\(context\.mode==='maktab'\)await renderMaktabSummaryScreen\(\)/.test(js));
check('Sabaq keeps its best-effort maktab position metadata sync after a quick save',
  /maktabQuickSyncSabaqPosition/.test(js)
  && /apiGetMaktabPosition\(owner\.id\)/.test(js)
  && /apiSaveMaktabPosition\(owner\.id/.test(js));

check('Quick Log has compact responsive sheet styling',
  /\.maktab-quick-log-card \{ max-width: 520px; \}/.test(css)
  && /@media \(max-width: 767px\)[\s\S]*\.maktab-quick-log-card/.test(css));
const v4212Versions = [...html.matchAll(/\?v=([0-9.]+)/g)].map(m => m[1]);
const v4212Cache = (sw.match(/CACHE_NAME = 'hifzhelper-v([0-9.]+)'/) || [])[1];
check('page/cache release keys advance together on later Quick Log overlays',
  v4212Versions.length > 0 && !!v4212Cache && v4212Versions.every(v => v === v4212Cache));

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
