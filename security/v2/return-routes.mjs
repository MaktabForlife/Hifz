import {requireThat} from './codec.mjs';
export function allowedReturn(registry,app,value){
 const list=registry[app]?.returns;if(!Array.isArray(list)||typeof value!=='string')return false;
 let u;try{u=new URL(value);}catch{return false;}
 if(u.origin!==registry[app].origin||u.username||u.password||u.hash)return false;
 if(list.includes(value))return true;
 if(app==='studio'&&u.pathname==='/builder/'&&list.includes(u.origin+u.pathname)){
  const entries=[...u.searchParams.entries()];return entries.length===1&&entries[0][0]==='website'&&/^[^\u0000-\u0020\u007f]{1,180}$/.test(entries[0][1]);
 }
 return false;
}
