import {readFileSync} from 'node:fs';
const read=name=>readFileSync(new URL('../../'+name,import.meta.url),'utf8');
export const readSummarySource=()=>['shared/journalSchema.js','js/journalQuickContext.js','js/journalQuickEditor.js','js/maktabSummary.js'].map(read).join('\n');
