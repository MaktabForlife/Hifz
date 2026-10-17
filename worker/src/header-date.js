/* Hifzhelper build 5.1 | worker/src/header-date.js */
const dateInTimezone=(now,timeZone)=>new Intl.DateTimeFormat('en-CA',{timeZone,year:'numeric',month:'2-digit',day:'2-digit'}).format(now);
export const dateSource='https://jamiat.org.za/';
const timezone='Africa/Johannesburg';
export function jamiatDate(html,today){
 const start=html.indexOf('class="dual-date-widget"');if(start<0)return null;
 const widget=html.slice(start,start+6000),part=name=>widget.match(new RegExp('data-site-'+name+'="(\\d+)"'))?.[1];
 if([part('y'),part('m')?.padStart(2,'0'),part('d')?.padStart(2,'0')].join('-')!==today)return null;
 const hijri=widget.match(/class="value islamic hd-out">([^<]{1,100})<\/div>/)?.[1]?.trim();
 return hijri&&/^\d{1,2} [A-Za-z ’'\-]+ \d{4}$/.test(hijri)?hijri:null;
}
export async function headerDate(request,{now=new Date(),fetcher=fetch,cache=globalThis.caches?.default}={}){
 const today=dateInTimezone(now,timezone),key=new Request(new URL('/api/header-date?day='+today,request.url));
 if(cache)try{const hit=await cache.match(key);if(hit)return hit;}catch{}
 let hijri=null;
 try{
  const upstream=await fetcher(dateSource,{headers:{Accept:'text/html','User-Agent':'HifzHelper/5.1 (+https://hifz.maktab4life.org/)'},redirect:'manual',signal:AbortSignal.timeout(15000),cf:{cacheTtl:900,cacheEverything:true}});
  if(!upstream.ok)throw Error('HTTP_'+upstream.status);
  const reader=upstream.body.getReader(),decoder=new TextDecoder();let html='',size=0;
  try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>512*1024)throw Error();html+=decoder.decode(value,{stream:true});}html+=decoder.decode();}finally{await reader.cancel().catch(()=>{});}
  hijri=jamiatDate(html,today);
 }catch(error){console.warn('Hifz header date source unavailable',{reason:error?.name==='TimeoutError'?'timeout':/^HTTP_\d{3}$/.test(error?.message||'')?error.message:'source-error'});/* Keep the source link available without inventing a Hijri date. */}
 const response=Response.json({success:true,gregorian:today,hijri,timezone,source:dateSource},{headers:{'Access-Control-Allow-Origin':'*','Cache-Control':'public, max-age='+(hijri?900:60)}});
 if(cache)try{await cache.put(key,response.clone());}catch{}
 return response;
}
