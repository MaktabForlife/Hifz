import {isVerifiedPortalPeer} from './portal-business.mjs';
import {BINDING,ORIGINS} from './tokens.mjs';
import {canonical,exact,requireThat,safeInt,uuid,bytes,unb64u,scalar} from './codec.mjs';
const checked=new WeakMap();
const freeze=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};
export function markPortalCapability(body,{now,peer}){
 requireThat(isVerifiedPortalPeer(peer)&&peer.body===body,'PORTAL_VERIFIED_PEER_REQUIRED',403);
 requireThat(typeof body.delegationId==='string'&&/^[A-Za-z0-9_-]{43}$/.test(body.delegationId),'PORTAL_DELEGATION_REQUIRED',403);
 const b=body.binding;exact(b,BINDING);
 requireThat(b.ver===2&&b.env==='production'&&b.iss===ORIGINS.academy&&b.aud==='urn:uaa:production:academy:api:v2'&&b.sid===b.psid,'PORTAL_PARENT_INVALID',403);
 requireThat(typeof b.sub==='string'&&bytes(b.sub).length>0&&bytes(b.sub).length<=180&&!/[\u0000-\u0020\u007f]/.test(b.sub),'PORTAL_SUBJECT_INVALID',403);scalar(b.sub);
 for(const key of ['sid','psid','bsid'])requireThat(uuid(b[key]),'PORTAL_PARENT_INVALID',403);
 for(const key of ['bv','ce','ae','sv'])requireThat(safeInt(b[key],1),'PORTAL_PARENT_INVALID',403);
 for(const key of ['le','ue','vat','s_iat','s_exp'])requireThat(safeInt(b[key]),'PORTAL_PARENT_INVALID',403);
 unb64u(b.pv,32);requireThat(b.s_exp-b.s_iat===604800&&b.vat<=now+5&&now<Math.min(b.vat+900,b.s_exp)&&safeInt(body.deadline)&&body.deadline<=Math.min(b.vat+900,b.s_exp)&&body.expiresAt<=body.deadline&&now<body.expiresAt&&body.expiresAt-body.issuedAt<=10,'PORTAL_LEASE_INVALID',401);
 const h=body.head;exact(h,['sub','ce','ownerEpoch','revision','payloadDigest']);
 requireThat(h.sub===b.sub&&h.ce===b.ce&&typeof h.ownerEpoch==='string'&&safeInt(h.revision,1)&&/^[a-f0-9]{64}$/.test(h.payloadDigest),'PORTAL_HEAD_INVALID',403);
 const cap=freeze(structuredClone({delegationId:body.delegationId,binding:b,head:h,deadline:body.deadline,issuedAt:body.issuedAt,expiresAt:body.expiresAt,operation:body.operation}));checked.set(cap,canonical(cap));return cap;
}
export function assertPortalCapability(cap,{manifest=null,now}={}){
 requireThat(checked.get(cap)===canonical(cap)&&safeInt(now)&&now<Math.min(cap.expiresAt,cap.deadline,cap.binding.vat+900,cap.binding.s_exp),'PORTAL_CAPABILITY_EXPIRED',401);
 if(manifest)requireThat(manifest.sub===cap.head.sub&&manifest.ce===cap.head.ce&&manifest.ownerEpoch===cap.head.ownerEpoch&&manifest.revision===cap.head.revision&&manifest.payloadDigest===cap.head.payloadDigest,'PORTAL_MANIFEST_MISMATCH',403);
 return cap;
}
