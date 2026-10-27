import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import {sha256} from '../src/mobile-export.js';

const entries=new Map(), puts=[];
const env={SUB_ACCESS_TOKEN:'legacy-secret-unchanged',SUB_STORE:{
  async get(key){return entries.get(key)||null;},
  async put(key,value,options){entries.set(key,value);puts.push({key,options});}
},ASSETS:{async fetch(){return new Response('original page');}}};
const config={'proxies':[{name:'fixture',type:'vmess',server:'192.0.2.1',port:8080,
  uuid:'00000000-0000-4000-8000-000000000001',alterId:0,cipher:'auto',tls:false,network:'ws',
  'ws-opts':{path:'/fixture',headers:{Host:'example.com'}}}],
  'proxy-groups':[{name:'最低延迟',type:'url-test',proxies:['fixture']}],rules:['MATCH,最低延迟']};
const configText=JSON.stringify(config,null,2)+'\n', resultAt=1700000000;
const body={configText,nodeCount:1,resultAt,sha256:await sha256(configText)};
const post=async b=>worker.fetch(new Request('https://fixture.example/api/export',{
  method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}),env);
const response=await post(body);assert.equal(response.status,200);
const shared=await response.json();assert.equal(shared.nodeCount,1);assert.equal(shared.resultAt,resultAt);
assert.equal(shared.sha256,body.sha256);assert.ok(shared.expiresAt>Date.now()/1000+6.99*86400);
assert.equal(puts[0].options.expirationTtl,604800);
const record=JSON.parse(entries.get(puts[0].key));assert.ok(!('token' in record));
assert.equal(env.SUB_ACCESS_TOKEN,'legacy-secret-unchanged');
const get=async url=>worker.fetch(new Request(url),env);
const download=await get(shared.url);assert.equal(download.status,200);assert.equal(await download.text(),configText);
assert.equal(download.headers.get('cache-control'),'no-store');
const bad=new URL(shared.url);bad.searchParams.set('token','0'.repeat(64));
assert.equal((await get(bad)).status,403);bad.searchParams.delete('token');assert.equal((await get(bad)).status,403);
record.expiresAt=Date.now()/1000-1;entries.set(puts[0].key,JSON.stringify(record));
assert.equal((await get(shared.url)).status,410);entries.delete(puts[0].key);assert.equal((await get(shared.url)).status,404);
const second=await (await post(body)).json();assert.notEqual(shared.url,second.url);
for(const change of [{nodeCount:2},{sha256:'bad'},{configText:'not JSON'},{resultAt:0},
  {configText:JSON.stringify({...config,proxies:[]})}])assert.equal((await post({...body,...change})).status,400);
const huge=new Request('https://fixture.example/api/export',{method:'POST',headers:{'content-type':'application/json'},body:'x'.repeat(1048577)});
assert.equal((await worker.fetch(huge,env)).status,413);
assert.equal((await get('https://fixture.example/')).status,200);
assert.equal(await (await get('https://fixture.example/')).text(),'original page');
// Legacy global-token handling and legacy rendering remain intact.
entries.set('sub:legacy',JSON.stringify({nodes:[]}));
assert.equal((await get('https://fixture.example/sub/legacy?target=clash&token=bad')).status,403);
assert.equal((await get('https://fixture.example/sub/legacy?target=clash&token=legacy-secret-unchanged')).status,200);
console.log('mobile export: snapshot, exact download, random tokens, expiry, limits, legacy routes passed');
