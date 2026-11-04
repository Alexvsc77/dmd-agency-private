// Dependency-free Supabase Edge Function. Secrets come only from runtime environment.
export const SERVICES = Object.freeze({
  automation: { title: 'AI-автоматизация процессов', price: '80–300 тыс. ₽', unit: 'за проект' },
  website: { title: 'Сайты и веб-разработка', price: '180–600 тыс. ₽', unit: 'за проект' },
  crm: { title: 'CRM и автоматизация продаж', price: '85–300 тыс. ₽', unit: 'за внедрение' },
  video: { title: 'AI-видео и рекламный контент', price: '60–150 тыс. ₽', unit: 'за ролик' },
  qa: { title: 'Тестирование сайтов и приложений', price: '30–100 тыс. ₽', unit: 'за этап' },
  saas: { title: 'SaaS и запуск цифрового продукта', price: '500 тыс.–1,5 млн ₽', unit: 'за MVP' }
});
const STATUSES = ['new', 'in_progress', 'done', 'archived'];
const BUDGETS = ['Пока не определён', 'До 100 000 ₽', '100 000–300 000 ₽', '300 000–700 000 ₽', '700 000–1 500 000 ₽', 'От 1 500 000 ₽'];
const RECIPIENTS = ['С менеджером', 'С руководителем проекта'];
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
function requireText(value, label, min, max) {
  if (typeof value !== 'string') throw new HttpError(400, `Проверь поле «${label}».`);
  const text = value.trim();
  if (text.length < min || text.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text)) throw new HttpError(400, `Проверь поле «${label}»: от ${min} до ${max} символов.`);
  return text;
}
export function validateRequest(body) {
  const name = requireText(body.name, 'Имя', 2, 80);
  const company = requireText(body.company ?? '', 'Компания', 0, 120);
  const contact = requireText(body.contact, 'Контакт', 5, 160);
  const phoneDigits = contact.replace(/\D/g, '');
  const phoneValid = /^\+?[\d\s()\-]{7,30}$/.test(contact) && phoneDigits.length >= 7 && phoneDigits.length <= 15;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contact) && !/^@[A-Za-z0-9_]{5,32}$/.test(contact) && !phoneValid) throw new HttpError(400, 'Укажи email, телефон или Telegram в формате @username.');
  const task = requireText(body.task, 'Задача', 10, 3000);
  if (!BUDGETS.includes(body.budget) || !RECIPIENTS.includes(body.recipient)) throw new HttpError(400, 'Выбери бюджет и получателя из списка.');
  if (!Array.isArray(body.services) || body.services.length > 6 || body.services.some(id => typeof id !== 'string' || !Object.hasOwn(SERVICES, id))) throw new HttpError(400, 'В списке есть недоступная услуга. Обнови страницу и выбери услуги заново.');
  if (body.website) throw new HttpError(400, 'Не удалось принять заявку.');
  const ids = [...new Set(body.services)].sort();
  return { name, company, contact, task, budget: body.budget, recipient: body.recipient, services: ids.map(id => ({ id, ...SERVICES[id] })) };
}

const ALLOWED_ORIGINS = new Set(['https://alexvsc77.github.io']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const digest = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))].map(x=>x.toString(16).padStart(2,'0')).join('');
async function readBody(req) {
  if (!req.headers.get('content-type')?.startsWith('application/json')) throw new HttpError(415,'Ожидается JSON.');
  const reader=req.body?.getReader(); if(!reader) throw new HttpError(400,'Нет данных.');
  let size=0; const parts=[];
  try { while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>16384)throw new HttpError(413,'Заявка слишком большая.');parts.push(value)} }
  finally { await reader.cancel().catch(()=>{}); }
  const bytes=new Uint8Array(size);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.length}
  try {const data=JSON.parse(new TextDecoder().decode(bytes));if(!data||typeof data!=='object'||Array.isArray(data))throw Error();return data}
  catch {throw new HttpError(400,'Некорректные данные.')}
}

export function createHandler({base,serviceKey,fetcher=fetch}) {
  async function rest(path,options={}) {
    const response=await fetcher(base+'/rest/v1/'+path,{...options,headers:{apikey:serviceKey,Authorization:'Bearer '+serviceKey,'Content-Type':'application/json',...options.headers}});
    if(!response.ok)throw new HttpError(503,'База временно недоступна. Повтори попытку позже.');
    const text=await response.text();return text?JSON.parse(text):null;
  }
  const rpc=(name,body)=>rest('rpc/'+name,{method:'POST',body:JSON.stringify(body)});
  async function authUser(req) {
    const header=req.headers.get('authorization')||'';
    if(!header.startsWith('Bearer '))throw new HttpError(401,'Войди в админку.');
    const token=header.slice(7);if(token.length>8192)throw new HttpError(401,'Войди снова.');
    const response=await fetcher(base+'/auth/v1/user',{headers:{apikey:serviceKey,Authorization:header}});
    if(!response.ok)throw new HttpError(401,'Сессия завершилась. Войди снова.');
    const user=await response.json();
    if(!user.email_confirmed_at||!UUID.test(user.id))throw new HttpError(403,'Нет доступа к админке.');
    const [admins,revoked]=await Promise.all([
      rest('dmd_admins?select=user_id&user_id=eq.'+user.id),
      rest('dmd_revoked_tokens?select=token_hash&token_hash=eq.'+await digest(token))
    ]);
    if(!admins.length)throw new HttpError(403,'У аккаунта нет доступа к админке DMD.');
    if(revoked.length)throw new HttpError(401,'Сессия завершилась. Войди снова.');
    return {user,token};
  }
  return async req=>{
    const origin=req.headers.get('origin');
    const cors=ALLOWED_ORIGINS.has(origin)?{'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Methods':'GET,POST,PATCH,OPTIONS','Access-Control-Allow-Headers':'content-type,authorization,idempotency-key,apikey','Access-Control-Max-Age':'600'}:{};
    const reply=(status,data)=>new Response(JSON.stringify(data),{status,headers:{...cors,'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Vary':'Origin','X-Content-Type-Options':'nosniff'}});
    try {
      if(origin&&!ALLOWED_ORIGINS.has(origin))throw new HttpError(403,'Этот адрес сайта не разрешён.');
      if(req.method==='OPTIONS')return new Response(null,{status:204,headers:cors});
      const url=new URL(req.url),path=url.pathname.replace(/^\/functions\/v1\/dmd-api/,'').replace(/^\/dmd-api/,'');
      if(req.method==='GET'&&path==='/health')return reply(200,{ok:true});
      if(req.method==='POST'&&path==='/requests'){
        const payload=validateRequest(await readBody(req)),key=req.headers.get('idempotency-key');
        if(!UUID.test(key||''))throw new HttpError(400,'Обнови страницу и повтори отправку.');
        // IP is used only as a salted hash in short-lived rate-limit buckets.
        const ip=req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()||'unknown';
        const allowed=await rpc('dmd_rate_limit',{p_key:'request:'+await digest(serviceKey+ip),p_limit:20});
        if(!allowed)throw new HttpError(429,'Слишком много отправок. Попробуй через 15 минут.');
        const result=await rpc('dmd_submit',{p_key:key,p_hash:await digest(JSON.stringify(payload)),p_payload:payload});
        if(result.conflict)throw new HttpError(409,'Состав заявки изменился. Отправь её повторно.');
        return reply(result.created?201:200,{id:result.id,received:true});
      }
      if(path.startsWith('/admin/')){
        if(path==='/admin/session'&&!req.headers.get('authorization'))return reply(200,{authenticated:false,setupRequired:false});
        const {user,token}=await authUser(req);
        if(req.method==='GET'&&path==='/admin/session')return reply(200,{authenticated:true,setupRequired:false,login:user.email});
        if(req.method==='POST'&&path==='/admin/logout'){
          await rest('dmd_revoked_tokens',{method:'POST',headers:{Prefer:'resolution=merge-duplicates'},body:JSON.stringify({token_hash:await digest(token),expires_at:new Date(Date.now()+24*3600000).toISOString()})});
          await fetcher(base+'/auth/v1/logout?scope=local',{method:'POST',headers:{apikey:serviceKey,Authorization:'Bearer '+token}});
          return reply(200,{ok:true});
        }
        if(req.method==='GET'&&path==='/admin/requests'){
          const status=url.searchParams.get('status')||'all',query=url.searchParams.get('q')||'',page=Number(url.searchParams.get('page')||1);
          if(!['all',...STATUSES].includes(status)||query.length>160||!Number.isInteger(page)||page<1||page>10000)throw new HttpError(400,'Некорректный фильтр.');
          return reply(200,await rpc('dmd_list',{p_status:status,p_query:query,p_page:page}));
        }
        const match=path.match(/^\/admin\/requests\/(DMD-[0-9a-f-]{36})$/i);
        if(req.method==='PATCH'&&match){
          const body=await readBody(req);if(!STATUSES.includes(body.status)||!Number.isInteger(body.version)||body.version<1)throw new HttpError(400,'Некорректный статус.');
          const rows=await rest('dmd_requests?id=eq.'+match[1]+'&version=eq.'+body.version,{method:'PATCH',headers:{Prefer:'return=representation'},body:JSON.stringify({status:body.status,version:body.version+1,updated_at:new Date().toISOString()})});
          if(!rows.length)throw new HttpError(409,'Заявка уже обновлена. Обнови список.');
          const r=rows[0];return reply(200,{...r.payload,id:r.id,status:r.status,version:r.version,createdAt:r.created_at,updatedAt:r.updated_at});
        }
      }
      throw new HttpError(404,'Страница не найдена.');
    }catch(error){return reply(error instanceof HttpError?error.status:500,{error:error instanceof HttpError?error.message:'Не удалось обработать запрос. Повтори попытку позже.'})}
  };
}
if(typeof Deno!=='undefined')Deno.serve(createHandler({base:Deno.env.get('SUPABASE_URL'),serviceKey:Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')}));
