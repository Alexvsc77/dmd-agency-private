import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { createHandler, validateRequest } from '../supabase/functions/dmd-api/index.ts';
const origin='https://alexvsc77.github.io';
const base='https://example.supabase.co';
const payload={name:'Тест DMD',contact:'demo@example.com',company:'Демо',budget:'Пока не определён',recipient:'С менеджером',task:'Проверка отправки заявки через облачный обработчик.',services:['website'],website:''};
const request=(path,body,headers={})=>new Request(base+'/functions/v1/dmd-api'+path,{method:body===undefined?'GET':'POST',headers:{Origin:origin,'Content-Type':'application/json',...headers},...(body===undefined?{}:{body:JSON.stringify(body)})});
const result=data=>new Response(JSON.stringify(data),{headers:{'Content-Type':'application/json'}});

test('rejects invalid contacts, removed services and tampered prices',()=>{
 for(const change of [{contact:'((((((('},{services:['assistant']},{services:['__proto__']},{budget:'anything'},{task:'x'},{website:'spam'}])assert.throws(()=>validateRequest({...payload,...change}));
 const clean=validateRequest({...payload,price:'1 ₽',services:['website','website']});
 assert.equal(clean.services.length,1);assert.equal(clean.services[0].price,'180–600 тыс. ₽');
});
test('cross-origin and unauthenticated reads never reach the database',async()=>{
 const handle=createHandler({base,serviceKey:'test-key',fetcher:()=>{throw Error('Database must not be called')}});
 assert.equal((await handle(request('/requests',payload,{Origin:'https://other.example'}))).status,403);
 assert.equal((await handle(request('/admin/requests'))).status,401);
 assert.equal((await handle(request('/admin/setup',{}))).status,401);
 const preflight=await handle(new Request(base+'/dmd-api/requests',{method:'OPTIONS',headers:{Origin:origin}}));
 assert.equal(preflight.status,204);assert.equal(preflight.headers.get('Access-Control-Allow-Origin'),origin);
});
test('public submission only returns a receipt after storage confirms success',async()=>{
 const calls=[];
 const handle=createHandler({base,serviceKey:'server-only',fetcher:async(url,options)=>{calls.push({url,options});return result(url.endsWith('dmd_rate_limit')?true:{created:true,received:true,id:'DMD-test'})}});
 const response=await handle(request('/requests',payload,{'Idempotency-Key':crypto.randomUUID()}));
 assert.equal(response.status,201);assert.deepEqual(await response.json(),{id:'DMD-test',received:true});
 assert.equal(calls.length,2);assert.ok(!calls[1].options.body.includes('server-only'));
});
test('rate limiting and conflicting retries return errors instead of false success',async()=>{
 for(const [allowed,submit,status] of [[false,{},429],[true,{conflict:true},409]]){
  const handle=createHandler({base,serviceKey:'test',fetcher:async url=>result(url.endsWith('dmd_rate_limit')?allowed:submit)});
  assert.equal((await handle(request('/requests',payload,{'Idempotency-Key':crypto.randomUUID()}))).status,status);
 }
});
test('valid Auth identity is insufficient without administrator membership',async()=>{
 const handle=createHandler({base,serviceKey:'test',fetcher:async url=>result(url.endsWith('/auth/v1/user')?{id:'1a17f540-e7e2-41e1-9a32-2498111218ea',email_confirmed_at:'2026-01-01'}:[])});
 assert.equal((await handle(request('/admin/requests',undefined,{Authorization:'Bearer test'}))).status,403);
});
test('revoked access tokens are rejected',async()=>{
 const handle=createHandler({base,serviceKey:'test',fetcher:async url=>result(url.endsWith('/auth/v1/user')?{id:'1a17f540-e7e2-41e1-9a32-2498111218ea',email_confirmed_at:'2026-01-01'}:[{}])});
 assert.equal((await handle(request('/admin/requests',undefined,{Authorization:'Bearer test'}))).status,401);
});
test('database failures cannot be mistaken for a saved request',async()=>{
 const handle=createHandler({base,serviceKey:'test',fetcher:async()=>new Response('failure',{status:500})});
 const response=await handle(request('/requests',payload,{'Idempotency-Key':crypto.randomUUID()}));
 assert.equal(response.status,503);assert.equal((await response.json()).received,undefined);
});
test('oversized body is rejected before database access',async()=>{
 const handle=createHandler({base,serviceKey:'test',fetcher:()=>{throw Error('Unexpected database call')}});
 assert.equal((await handle(request('/requests',{...payload,task:'x'.repeat(17000)}))).status,413);
});
test('logout handles empty storage responses and revokes the current token',async()=>{
 let revoked=false;
 const handle=createHandler({base,serviceKey:'test',fetcher:async(url,options)=>{
  if(url.endsWith('/auth/v1/user'))return result({id:'1a17f540-e7e2-41e1-9a32-2498111218ea',email_confirmed_at:'2026-01-01'});
  if(url.includes('dmd_admins?'))return result([{}]);
  if(url.includes('dmd_revoked_tokens?'))return result([]);
  if(url.endsWith('dmd_revoked_tokens')){assert.equal(options.method,'POST');revoked=true;return new Response(null,{status:201})}
  if(url.includes('/auth/v1/logout'))return new Response(null,{status:204});
  throw Error('Unexpected URL');
 }});
 const response=await handle(request('/admin/logout',{}, {Authorization:'Bearer test'}));
 assert.equal(response.status,200);assert.equal(revoked,true);
});

test('Sheets export fails closed until paired and requires a verified owner identity',async()=>{
 let calls=0;
 const settings={base,serviceKey:'test',fetcher:async()=>{calls++;return result([])}};
 assert.equal((await createHandler(settings)(request('/sheets/requests'))).status,503);
 const paired={...settings,googleAudience:'script-client',googleSubject:'owner-123'};
 assert.equal((await createHandler(paired)(request('/sheets/requests'))).status,401);
 for(const identity of [{sub:'other',email_verified:true},{sub:'owner-123',email_verified:false}]){
  const handle=createHandler({...paired,verifyIdentity:async()=>identity});
  assert.equal((await handle(request('/sheets/requests',undefined,{Authorization:'Bearer test'}))).status,403);
 }
 const badToken=createHandler({...paired,verifyIdentity:async()=>{throw Error('Invalid audience, signature or expiry')}});
 assert.equal((await badToken(request('/sheets/requests',undefined,{Authorization:'Bearer invalid'}))).status,401);
 assert.equal(calls,0);
});

test('Sheets export checks audience, pages immutable IDs and excludes private database fields',async()=>{
 const ids=Array.from({length:101},(_,i)=>'DMD-00000000-0000-4000-8000-'+String(i).padStart(12,'0'));
 let readUrl;
 const handle=createHandler({base,serviceKey:'server-only',googleAudience:'expected-client',googleSubject:'owner',
  verifyIdentity:async(token,audience)=>{assert.equal(token,'google-token');assert.equal(audience,'expected-client');return {sub:'owner',email_verified:true}},
  fetcher:async url=>{readUrl=url;return result(ids.map(id=>({id,payload:validateRequest(payload),created_at:'2026-11-06T10:00:00Z',request_key:'hidden',payload_hash:'hidden'})))}
 });
 const response=await handle(request('/sheets/requests?after='+ids[0],undefined,{Authorization:'Bearer google-token'}));
 assert.equal(response.status,200);
 const data=await response.json();assert.equal(data.items.length,100);assert.equal(data.next,ids[99]);
 assert.equal(data.items[0].request_key,undefined);assert.equal(data.items[0].payload_hash,undefined);
 assert.ok(readUrl.endsWith('&id=gt.'+ids[0]));assert.ok(readUrl.includes('order=id.asc&limit=101'));
 assert.equal((await handle(request('/sheets/requests?after=bad%26select=*',undefined,{Authorization:'Bearer google-token'}))).status,400);
 assert.equal((await handle(request('/sheets/requests',{}, {Authorization:'Bearer google-token'}))).status,405);
});

test('Google Sheets sync deduplicates pages and retries without overwriting manual status or notes',async()=>{
 const code=await readFile(new URL('../google-sheets/Code.gs',import.meta.url),'utf8');
 const first='DMD-00000000-0000-4000-8000-000000000001';
 const second='DMD-00000000-0000-4000-8000-000000000002';
 let rows=[['Дата','Номер заявки','Клиент','Компания','Контакт','Услуги','Задача','Бюджет','Получатель','Статус','Заметки'],
  [new Date(),first,'Клиент','','','','','','','В работе','Позвонить завтра']];
 const sheet={getLastRow:()=>rows.length,getMaxRows:()=>1000,
  getRange:(row,col,height,width)=>{
   const range={getDisplayValues:()=>rows.slice(row-1,row-1+height).map(r=>r.slice(col-1,col-1+width).map(String)),
    setValues:values=>{values.forEach((r,i)=>{rows[row-1+i]=[...r]});return range},
    setVerticalAlignment:()=>range,setWrap:()=>range,setNumberFormat:()=>range,setDataValidation:()=>range};
   return range;
  }
 };
 let release=0,failed=false,pages=0;
 const props=new Map();
 const context=vm.createContext({Date,Set,JSON,Error,encodeURIComponent,isNaN,
  LockService:{getScriptLock:()=>({tryLock:()=>true,releaseLock:()=>release++})},
  PropertiesService:{getScriptProperties:()=>({getProperty:key=>props.get(key),setProperty:(key,value)=>props.set(key,value)})},
  SpreadsheetApp:{getActiveSpreadsheet:()=>({getId:()=> 'book',getSheetByName:()=>sheet}),
   openById:()=>({getId:()=> 'book',getSheetByName:()=>sheet}),flush:()=>{},
   newDataValidation:()=>({requireValueInList(){return this},setAllowInvalid(){return this},build(){return {}}})}
 });
 vm.runInContext(code,context);
 context.dmdFetch_=()=>{
  pages++;
  if(pages===2&&!failed){failed=true;throw Error('Network failed after first page')}
  return {items:[{...validateRequest(payload),id:second,createdAt:'2026-11-06T10:00:00Z',task:'=IMPORTXML("https://example.com","x")'}],next:pages===1?second:null};
 };
 assert.throws(()=>context.syncDmdRequests(),/Network failed/);
 assert.equal(rows.length,3);assert.equal(props.has('DMD_LAST_SYNC'),false);
 context.syncDmdRequests();
 assert.equal(rows.length,3);assert.equal(rows[1][9],'В работе');assert.equal(rows[1][10],'Позвонить завтра');
 assert.ok(rows[2][6].startsWith("'="));assert.equal(rows[2][9],'Новая');
 assert.equal(release,2);assert.ok(props.has('DMD_LAST_SYNC'));
 assert.equal(context.dmdText_('+79991234567'),"'+79991234567");
 assert.equal(context.dmdText_('@telegram'),"'@telegram");
});
