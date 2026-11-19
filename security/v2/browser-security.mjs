import {canonical,bytes,hmac,b64u,unb64u,sha256,hex,equal,requireThat,safeInt,uuid,strictJSON} from './codec.mjs';
import {ownOrigin} from './tokens.mjs';
const CONTEXT='app sub sid psid bsid bv ce ae le sv ue'.split(' ');
function csrfBody({config,purpose,context,operationId,expiresAt}){
 requireThat(['refresh','logout','switch','draft-key','status','bootstrap','browser-clear'].includes(purpose)&&uuid(operationId)&&safeInt(expiresAt),'INVALID_CSRF_CONTEXT',503);
 requireThat(context&&CONTEXT.every(k=>Object.hasOwn(context,k))&&context.app===config.app&&uuid(context.sid)&&uuid(context.psid)&&uuid(context.bsid),'INVALID_CSRF_CONTEXT',503);
 return canonical({schema:2,env:config.env,app:config.app,purpose,context:Object.fromEntries(CONTEXT.map(k=>[k,context[k]])),operationId,expiresAt});
}
export async function csrfProof(options){return b64u(await hmac(options.key,'uaa-csrf-v2\0'+csrfBody(options)));}
export async function verifyCSRF({request,proof,now,...options}){
 ownOrigin(request,options.config);requireThat(request.method==='POST','METHOD_NOT_ALLOWED',405);
 const site=request.headers.get('Sec-Fetch-Site');requireThat(!site||site==='same-origin','CROSS_ORIGIN',403);
 requireThat(safeInt(now)&&now<options.expiresAt,'CSRF_EXPIRED',403);unb64u(proof,32);
 requireThat(equal(proof,await csrfProof(options)),'CSRF_INVALID',403);return hex(await sha256(bytes(proof)));
}
export function verifyBootstrap(request,config){
 ownOrigin(request,config);requireThat(request.method==='POST'&&request.headers.get('X-UAA-Request')==='2','BOOTSTRAP_REQUEST_REQUIRED',403);
 requireThat(!request.headers.get('Sec-Fetch-Site')||request.headers.get('Sec-Fetch-Site')==='same-origin','CROSS_ORIGIN',403);
}
export async function browserBody(request,{maxBytes=4096}={}){
 const chunks=[];let length=0;const reader=request.body?.getReader();
 if(reader)for(;;){const {value,done}=await reader.read();if(done)break;length+=value.length;if(length>maxBytes){await reader.cancel();requireThat(false,'BODY_TOO_LARGE',413);}chunks.push(value);}
 const raw=new Uint8Array(length);let at=0;for(const c of chunks){raw.set(c,at);at+=c.length;}return strictJSON(raw,{maxBytes});
}
export const privateJSON=(value,status=200)=>new Response(canonical(value),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'private, no-store','Pragma':'no-cache','X-Content-Type-Options':'nosniff'}});
