import {canonical} from './codec.mjs';
export function coversFloor(candidate,required){
 if(candidate.type!==required.type)return false;
 switch(required.type){
  case 'accountCutoff':return candidate.sub===required.sub&&(candidate.maxCe>required.maxCe||candidate.maxCe===required.maxCe&&candidate.maxAe>=required.maxAe);
  case 'credentialEpoch':return candidate.sub===required.sub&&candidate.newCe>=required.newCe;
  case 'browser':return candidate.bsid===required.bsid&&candidate.maxBv>=required.maxBv;
  case 'localEpoch':return candidate.app===required.app&&candidate.sub===required.sub&&candidate.ce===required.ce&&candidate.ae===required.ae&&candidate.maxLe>=required.maxLe;
  case 'dependency':return candidate.id===required.id&&candidate.ownerEpoch===required.ownerEpoch&&(candidate.revision>required.revision||candidate.revision===required.revision&&(required.effect==='INVALIDATE'||candidate.effect==='DENY'&&required.deniedActions.every(a=>candidate.deniedActions.includes(a))));
  case 'key':return candidate.purpose===required.purpose&&candidate.kid===required.kid&&candidate.registryRevision>=required.registryRevision;
  // Policy duration changes require history/clock receipts; revision alone is not coverage.
  default:return canonical(candidate)===canonical(required);
 }
}
export function compactFloors(records){
 const result=[];
 for(const record of records){
  if(result.some(current=>coversFloor(current,record)))continue;
  for(let i=result.length-1;i>=0;i--)if(coversFloor(record,result[i]))result.splice(i,1);
  result.push(record);
 }
 return result;
}
