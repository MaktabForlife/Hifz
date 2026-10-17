/* Hifzhelper build 5.1 | js/headerDate.js */
let hifzHeaderDateStarted=false;
function setupHifzHeaderDate(){
 if(hifzHeaderDateStarted)return;hifzHeaderDateStarted=true;
 'use strict';
 const hijri=document.getElementById('hifzHijriDate'),gregorian=document.getElementById('hifzGregorianDate');if(!hijri||!gregorian)return;
 const zone='Africa/Johannesburg';let shownDay='',lastAttempt=0,timer;
 const day=()=>{const parts=Object.fromEntries(new Intl.DateTimeFormat('en-GB',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date()).map(p=>[p.type,p.value]));return parts.year+'-'+parts.month+'-'+parts.day;};
 async function refresh(){
  const current=day();if(shownDay===current&&(hijri.textContent!=='Hijri date unavailable'||Date.now()-lastAttempt<900000))return;shownDay=current;lastAttempt=Date.now();clearTimeout(timer);timer=setTimeout(()=>{shownDay='';void refresh();},Math.max(1000,Date.parse(current+'T22:00:00Z')-Date.now()+1000));
  gregorian.dateTime=current;gregorian.textContent=new Intl.DateTimeFormat('en-GB',{timeZone:zone,day:'numeric',month:'long',year:'numeric'}).format(new Date());hijri.textContent='Hijri date unavailable';
  try{const cached=JSON.parse(sessionStorage.getItem('hh_header_date')||'null');if(cached?.gregorian===current&&cached.hijri&&Date.now()-cached.savedAt<900000){hijri.textContent=cached.hijri;return;}}catch{}
  try{const response=await fetch(API_BASE.replace(/\/$/,'')+'/api/header-date');const data=await response.json();if(shownDay===current&&response.ok&&data.gregorian===current&&typeof data.hijri==='string'&&data.hijri.length<=100){hijri.textContent=data.hijri;try{sessionStorage.setItem('hh_header_date',JSON.stringify({...data,savedAt:Date.now()}));}catch{}}}catch{}
 }
 void refresh();window.addEventListener('focus',refresh);document.addEventListener('visibilitychange',()=>{if(!document.hidden)void refresh();});
}
