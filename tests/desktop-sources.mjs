import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import {sha256} from '../src/mobile-export.js';
const entries=new Map(),puts=[];
const env={SUB_ACCESS_TOKEN:'fixture-management',SUB_STORE:{
  async get(k){return entries.get(k)||null;},
  async put(k,v,o){entries.set(k,v);puts.push({k,o});},async delete(k){entries.delete(k);}
},ASSETS:{async fetch(){return new Response('original');}}};
const node={v:'2',ps:'学校',add:'192.0.2.1',port:8080,id:'00000000-0000-4000-8000-000000000001',net:'ws',tls:'none',host:'example.com',path:'/fixture'};
const text='vmess://'+Buffer.from(JSON.stringify(node)).toString('base64')+'\n';
const payload={subscriptionText:text,nodeCount:1,fingerprints:['a'.repeat(64)],sha256:await sha256(text)};
const post=(b,secret='fixture-management',e=env)=>worker.fetch(new Request('https://fixture.example/api/desktop-sources',{
  method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+secret},body:JSON.stringify(b)}),e);
assert.equal((await post(payload,'wrong')).status,403);
assert.equal((await post(payload,'', {...env,SUB_ACCESS_TOKEN:undefined})).status,403);
assert.equal((await post(payload,'fixture-management',{...env,SUB_STORE:undefined})).status,503);
const r=await post(payload);assert.equal(r.status,200);const saved=await r.json();
assert.equal(saved.expiresAt,null);assert.equal(saved.nodeCount,1);assert.equal(puts[0].o,undefined);
const stored=JSON.parse(entries.get(puts[0].k));assert.equal(stored.subscriptionText,text);assert.equal(stored.sha256,payload.sha256);
assert.ok(!('token' in stored));assert.ok(!('expiresAt' in stored));
let get=await worker.fetch(new Request(saved.url),env);assert.equal(get.status,200);assert.equal(await get.text(),text);
assert.equal(get.headers.get('cache-control'),'no-store');
const bad=new URL(saved.url);bad.searchParams.set('token','0'.repeat(64));assert.equal((await worker.fetch(new Request(bad),env)).status,403);
const originalNow=Date.now;Date.now=()=>originalNow()+365*86400*1000;
try {assert.equal((await worker.fetch(new Request(saved.url),env)).status,200);}finally{Date.now=originalNow;}
for(const patch of [{nodeCount:2},{sha256:'bad'},{fingerprints:[]},{subscriptionText:'invalid'},{action:'unknown'}]){
  assert.equal((await post({...payload,...patch})).status,400);
}
const second=await (await post(payload)).json();assert.notEqual(second.url,saved.url);
assert.equal((await post({action:'revoke',id:saved.id},'wrong')).status,403);
assert.equal((await post({action:'revoke',id:saved.id})).status,200);
assert.equal((await worker.fetch(new Request(saved.url),env)).status,404);
assert.equal((await worker.fetch(new Request(second.url),env)).status,200);
console.log('desktop sources: auth, exact bytes, no expiry, validation, private tokens and revocation passed');
