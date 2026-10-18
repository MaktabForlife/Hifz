/* Hifzhelper build 5.2 | shared/journalSchema.js */
// Browser + Worker share the content contract. Provenance, permissions and
// attendance effects belong to each journal's existing authenticated service.
const JOURNAL_LOG_SCHEMA = Object.freeze({
  sabaq: Object.freeze({label:'Sabaq',path:'sabaq',fields:Object.freeze(['sabaq_from','sabaq_to','tajweed_tag_ids','line_count','page_count'])}),
  sabaqDhor: Object.freeze({label:'Sabaq Dhor',path:'sabaq-dhor',fields:Object.freeze(['zone','tajweed_tag_ids','mistakes','from_surah','from_ayah','to_surah','to_ayah'])}),
  dhor: Object.freeze({label:'Dhor',path:'dhor',fields:Object.freeze(['segment_from','segment_to','ref','tajweed_tag_ids','mistakes','duration_seconds','lap_times'])})
});
function journalContentChanges(type, payload, original){
  const schema = JOURNAL_LOG_SCHEMA[type];
  if(!schema) throw new Error('Unknown journal activity.');
  const result = {};
  for(const field of ['date',...schema.fields]){
    if(Object.prototype.hasOwnProperty.call(payload,field) && (!original || payload[field] !== original[field])) result[field]=payload[field];
  }
  return result;
}
if(typeof module !== 'undefined' && module.exports) module.exports={JOURNAL_LOG_SCHEMA,journalContentChanges};
