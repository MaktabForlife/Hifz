export class SecurityError extends Error {
 constructor(code,status=401){super(code);this.code=code;this.status=status;}
}
export const reject=(code,status=401)=>{throw new SecurityError(code,status);};
export const requireThat=(value,code='INVALID_PROTOCOL',status=401)=>{if(!value)reject(code,status);};
export const bytes=value=>new TextEncoder().encode(value);
export function scalar(s){
 requireThat(typeof s==='string','INVALID_STRING');
 for(const c of s){const v=c.codePointAt(0);requireThat(v<0xd800||v>0xdfff,'INVALID_UNICODE');}
 return s;
}
export function strictJSON(input,{maxBytes=65536,maxDepth=32}={}){
 const raw=typeof input==='string'?bytes(input):new Uint8Array(input);
 requireThat(raw.length<=maxBytes,'BODY_TOO_LARGE',413);
 let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(raw);}catch{reject('INVALID_UTF8',400);}
 let i=0;
 const ws=()=>{while(/[ \r\n\t]/.test(text[i]||'!'))i++;};
 function str(){
  requireThat(text[i]==='"','INVALID_JSON',400);const start=i++;
  while(i<text.length){if(text[i]==='\\'){i+=2;continue;}if(text[i++]==='"'){try{return scalar(JSON.parse(text.slice(start,i)));}catch{reject('INVALID_JSON_STRING',400);}}}
  reject('INVALID_JSON',400);
 }
 function value(depth){
  requireThat(depth<=maxDepth,'JSON_DEPTH',400);ws();let v;
  if(text[i]==='"')return str();
  if(text[i]==='{'){
   i++;v=Object.create(null);ws();if(text[i]==='}'){i++;return v;}
   for(;;){ws();const key=str();requireThat(!Object.hasOwn(v,key),'DUPLICATE_MEMBER',400);ws();requireThat(text[i++]===':','INVALID_JSON',400);v[key]=value(depth+1);ws();const c=text[i++];if(c==='}')return v;requireThat(c===',','INVALID_JSON',400);}
  }
  if(text[i]==='['){
   i++;v=[];ws();if(text[i]===']'){i++;return v;}
   for(;;){v.push(value(depth+1));ws();const c=text[i++];if(c===']')return v;requireThat(c===',','INVALID_JSON',400);}
  }
  for(const [s,literal] of [['true',true],['false',false],['null',null]])if(text.startsWith(s,i)){i+=s.length;return literal;}
  const match=/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i));
  requireThat(match,'INVALID_JSON',400);i+=match[0].length;requireThat(/^-?(?:0|[1-9][0-9]*)$/.test(match[0]),'NON_INTEGER_JSON_NUMBER',400);v=Number(match[0]);requireThat(Number.isSafeInteger(v),'UNSAFE_JSON_NUMBER',400);return v;
 }
 const result=value(0);ws();requireThat(i===text.length,'INVALID_JSON',400);return result;
}
export function exact(object,keys){
 requireThat(object!==null&&typeof object==='object'&&!Array.isArray(object),'INVALID_OBJECT',400);
 const actual=Object.keys(object).sort(),expected=[...keys].sort();
 requireThat(actual.length===expected.length&&actual.every((k,i)=>k===expected[i]),'UNKNOWN_OR_MISSING_MEMBER',400);
 return object;
}
export const safeInt=(n,min=0)=>Number.isSafeInteger(n)&&n>=min;
export const uuid=s=>typeof s==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
export const ascii=(s,max=128)=>typeof s==='string'&&s.length>0&&s.length<=max&&/^[\x21-\x7e]+$/.test(s);
export function canonical(value){
 if(value===null||typeof value==='boolean')return JSON.stringify(value);
 if(typeof value==='number'){requireThat(Number.isSafeInteger(value),'UNSAFE_CANONICAL_NUMBER',400);return JSON.stringify(value);}
 if(typeof value==='string')return JSON.stringify(scalar(value));
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 requireThat(value&&typeof value==='object'&&[Object.prototype,null].includes(Object.getPrototypeOf(value)),'INVALID_CANONICAL_OBJECT',400);
 return '{'+Object.keys(value).sort().map(k=>JSON.stringify(scalar(k))+':'+canonical(value[k])).join(',')+'}';
}
export function b64u(raw){
 let s='';for(const b of new Uint8Array(raw))s+=String.fromCharCode(b);
 return btoa(s).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
}
export function unb64u(s,length){
 requireThat(typeof s==='string'&&s.length>0&&/^[A-Za-z0-9_-]+$/.test(s)&&s.length%4!==1,'INVALID_BASE64URL');
 let raw;try{raw=Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));}catch{reject('INVALID_BASE64URL');}
 requireThat(b64u(raw)===s&&(length===undefined||raw.length===length),'NONCANONICAL_BASE64URL');return raw;
}
export const hex=raw=>Array.from(new Uint8Array(raw),v=>v.toString(16).padStart(2,'0')).join('');
export const sha256=async raw=>new Uint8Array(await crypto.subtle.digest('SHA-256',typeof raw==='string'?bytes(raw):raw));
export const digest=async value=>hex(await sha256(bytes(canonical(value))));
export const domainDigest=async(label,value)=>hex(await sha256(bytes(label+'\0'+canonical(value))));
export async function hmac(key,raw){
 const k=key instanceof Uint8Array?await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign','verify']):key;
 return new Uint8Array(await crypto.subtle.sign('HMAC',k,typeof raw==='string'?bytes(raw):raw));
}
export function equal(a,b){
 const x=typeof a==='string'?bytes(a):a,y=typeof b==='string'?bytes(b):b;
 let diff=x.length^y.length;for(let i=0;i<Math.max(x.length,y.length);i++)diff|=(x[i]||0)^(y[i]||0);return diff===0;
}
export function opaque(){return b64u(crypto.getRandomValues(new Uint8Array(32)));}
export async function fingerprint(secret,{env,app}){
 requireThat(['feature','production'].includes(env)&&['academy','studio','hifz'].includes(app),'INVALID_NAMESPACE');
 const raw=unb64u(secret,32),prefix=bytes('uaa-refresh-v2\0'+env+'\0'+app+'\0'),input=new Uint8Array(prefix.length+32);
 input.set(prefix);input.set(raw,prefix.length);return hex(await sha256(input));
}
export function vector(entries){
 requireThat(Array.isArray(entries),'INVALID_VECTOR',400);
 const out=entries.map(entry=>{
  requireThat(Array.isArray(entry)&&entry.length===3&&ascii(entry[0])&&ascii(entry[1])&&safeInt(entry[2],1),'INVALID_VECTOR',400);return [...entry];
 }).sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
 requireThat(out.every((e,i)=>i===0||out[i-1][0]!==e[0]),'DUPLICATE_DEPENDENCY',400);return out;
}
export const vectorDigest=async entries=>b64u(await sha256(bytes(canonical(vector(entries)))));
export function compareVector(a,b){
 const left=vector(a),right=vector(b);requireThat(left.length===right.length,'RECONCILIATION_REQUIRED',409);
 let result=0;
 for(let i=0;i<left.length;i++){
  requireThat(left[i][0]===right[i][0]&&left[i][1]===right[i][1],'RECONCILIATION_REQUIRED',409);
  const d=Math.sign(left[i][2]-right[i][2]);if(d&&result&&result!==d)reject('INCOMPARABLE_VECTOR',409);if(d)result=d;
 }return result;
}
