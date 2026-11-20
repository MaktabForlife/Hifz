import {requireThat} from './codec.mjs';
/**
 * The handshake authorises only the existing lease. Every byte and pending read
 * remains bounded by that same fixed deadline; a reconnect is a new protected
 * request under current own-app cookies. Already delivered bytes cannot be
 * recalled. This does not add a transport or renew authority.
 */
export function privateStreamDeadline(response,{deadline,clock=()=>Math.floor(Date.now()/1000),schedule=setTimeout,unschedule=clearTimeout}={}){
 if(!response.body||response.status===101)return response;
 requireThat(Number.isSafeInteger(deadline)&&clock()<deadline,'LEASE_EXPIRED',401);
 const reader=response.body.getReader();let ended=false,timer=null;
 const clear=()=>{if(timer!==null){unschedule(timer);timer=null;}};
 const cancel=reason=>Promise.resolve(reader.cancel(reason)).catch(()=>{});
 const expired=()=>clock()>=deadline;
 const body=new ReadableStream({
  start(controller){
   const stop=()=>{if(ended)return;ended=true;clear();const error=Object.assign(Error('Private stream authority expired'),{code:'LEASE_EXPIRED'});controller.error(error);void cancel(error);};
   timer=schedule(stop,Math.max(1,(deadline-clock())*1000));timer?.unref?.();
  },
  async pull(controller){
   if(ended)return;
   if(expired()){ended=true;clear();const error=Object.assign(Error('Private stream authority expired'),{code:'LEASE_EXPIRED'});controller.error(error);void cancel(error);return;}
   try{
    const result=await reader.read();if(ended)return;
    if(expired()){ended=true;clear();const error=Object.assign(Error('Private stream authority expired'),{code:'LEASE_EXPIRED'});controller.error(error);void cancel(error);return;}
    if(result.done){ended=true;clear();controller.close();return;}controller.enqueue(result.value);
   }catch(error){if(!ended){ended=true;clear();controller.error(error);}}
  },
  cancel(reason){if(ended)return;ended=true;clear();return cancel(reason);}
 });
 const headers=new Headers(response.headers);headers.set('X-UAA-Stream-Deadline',String(deadline*1000));
 // Retain original length/range so an interrupted transfer is observable. The
 // player must request the remaining range; no successful truncation is minted.
 return new Response(body,{status:response.status,statusText:response.statusText,headers});
}
