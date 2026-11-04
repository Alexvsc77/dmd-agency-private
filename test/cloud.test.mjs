import { test } from 'node:test';
import assert from 'node:assert/strict';
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
