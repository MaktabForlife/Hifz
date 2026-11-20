import {canonical,bytes,requireThat,safeInt} from './codec.mjs';
// Optional performance cache only. A hit still requires current durable controls
// and the original authority deadline; eviction cannot mint or prolong authority.
export class RightsMemo extends Map {
 #sizes=new Map();#bytes=0;#maxBytes;#maxEntries;
 constructor({maxBytes=4*1024*1024,maxEntries=32}={}){super();requireThat(safeInt(maxBytes,1)&&safeInt(maxEntries,1),'INVALID_RIGHTS_MEMO_BUDGET',503);this.#maxBytes=maxBytes;this.#maxEntries=maxEntries;}
 get(key){const value=super.get(key);if(value!==undefined){super.delete(key);super.set(key,value);}return value;}
 set(key,value){
  const size=bytes(canonical(value)).length;this.delete(key);
  if(size>this.#maxBytes)return this;
  while(this.size&&(this.size>=this.#maxEntries||this.#bytes+size>this.#maxBytes))this.delete(this.keys().next().value);
  super.set(key,value);this.#sizes.set(key,size);this.#bytes+=size;return this;
 }
 delete(key){if(super.delete(key)){this.#bytes-=this.#sizes.get(key)||0;this.#sizes.delete(key);return true;}return false;}
 clear(){super.clear();this.#sizes.clear();this.#bytes=0;}
 get budget(){return Object.freeze({entries:this.size,serializedPayloadBytes:this.#bytes,maxEntries:this.#maxEntries,maxSerializedPayloadBytes:this.#maxBytes});}
}
