// Private exact desktop snapshots. Deliberately separate from expiring phone exports.
import {sha256} from './mobile-export.js';
const MAX_BYTES = 1024 * 1024;
const headers = {'cache-control':'no-store','x-content-type-options':'nosniff'};
const reply = (body, status=200, type='application/json; charset=utf-8') => new Response(
  type.startsWith('application/json') ? JSON.stringify(body) : body,
  {status,headers:{...headers,'content-type':type}});
const random = n => Array.from(crypto.getRandomValues(new Uint8Array(n)), b=>b.toString(16).padStart(2,'0')).join('');
async function authorized(request, env) {
  if (!env.SUB_ACCESS_TOKEN) return false; // Missing management secret must fail closed.
  return await sha256(request.headers.get('authorization') || '') === await sha256('Bearer '+env.SUB_ACCESS_TOKEN);
}
function validLink(link) {
  try {
    if (link.startsWith('vmess://')) {
      const n=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(atob(link.slice(8)),c=>c.charCodeAt(0))));
      return typeof n.add==='string' && !!n.add && typeof n.id==='string' && !!n.id &&
        Number.isInteger(Number(n.port)) && Number(n.port)>0 && Number(n.port)<=65535;
    }
    const u=new URL(link);
    return ['vless:','trojan:'].includes(u.protocol) && !!u.hostname && !!u.username &&
      Number.isInteger(Number(u.port)) && Number(u.port)>0 && Number(u.port)<=65535;
  } catch {return false;}
}
export async function handleDesktopSources(request,env,url) {
  if (!await authorized(request,env)) return reply({error:'管理认证失败'},403);
  if (!env.SUB_STORE) return reply({error:'订阅存储尚未配置'},503);
  try {
    if (!(request.headers.get('content-type')||'').startsWith('application/json')) return reply({error:'需要 JSON'},415);
    if (Number(request.headers.get('content-length'))>MAX_BYTES) return reply({error:'内容过大'},413);
    const reader=request.body?.getReader(); if (!reader) return reply({error:'内容为空'},400);
    const chunks=[]; let count=0;
    while (true) {
      const {done,value}=await reader.read(); if(done)break;
      count+=value.byteLength; if(count>MAX_BYTES){await reader.cancel();return reply({error:'内容过大'},413);}
      chunks.push(value);
    }
    const bytes=new Uint8Array(count);let offset=0;
    for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
    const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    if(body.action==='revoke'){
      if(!/^[a-f0-9]{32}$/.test(body.id||''))return reply({error:'标识无效'},400);
      await env.SUB_STORE.delete('desktop:'+body.id);return reply({revoked:true});
    }
    if(body.action && body.action!=='create')return reply({error:'操作无效'},400);
    if(typeof body.subscriptionText!=='string')return reply({error:'订阅无效'},400);
    const lines=body.subscriptionText.split(/\r?\n/).filter(s=>s.trim());
    if(!lines.length || lines.length>500 || !lines.every(s=>s===s.trim() && validLink(s)) ||
      body.nodeCount!==lines.length || !Array.isArray(body.fingerprints) ||
      body.fingerprints.length!==lines.length || new Set(body.fingerprints).size!==lines.length ||
      !body.fingerprints.every(f=>/^[a-f0-9]{64}$/.test(f)) ||
      body.sha256!==await sha256(body.subscriptionText))return reply({error:'订阅校验失败'},400);
    const id=random(16),token=random(32);
    const record={subscriptionText:body.subscriptionText,sha256:body.sha256,nodeCount:lines.length,
      fingerprints:body.fingerprints,tokenHash:await sha256(token),createdAt:Date.now()/1000};
    await env.SUB_STORE.put('desktop:'+id,JSON.stringify(record)); // No TTL or expiration.
    const link=new URL('/sub/desktop-'+id,url.origin);link.searchParams.set('token',token);
    return reply({id,url:link.href,nodeCount:record.nodeCount,sha256:record.sha256,expiresAt:null});
  } catch {return reply({error:'桌面订阅操作失败'},400);}
}
export async function handleDesktopSub(url,env){
  const m=/^\/sub\/desktop-([a-f0-9]{32})$/.exec(url.pathname);
  if(!m || !env.SUB_STORE)return reply({error:'订阅不存在'},404);
  try{
    const raw=await env.SUB_STORE.get('desktop:'+m[1]);if(!raw)return reply({error:'订阅不存在'},404);
    const r=JSON.parse(raw),token=url.searchParams.get('token')||'';
    if(!/^[a-f0-9]{64}$/.test(token) || await sha256(token)!==r.tokenHash)return reply({error:'订阅令牌无效'},403);
    return reply(r.subscriptionText,200,'text/plain; charset=utf-8');
  }catch{return reply({error:'订阅暂不可用'},503);}
}
