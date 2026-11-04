-- Only the Edge Function's server-side service role can access these objects.
create table public.dmd_requests (
  id text primary key,
  request_key uuid not null unique,
  payload_hash text not null,
  payload jsonb not null,
  search_text text not null,
  status text not null default 'new' check (status in ('new','in_progress','done','archived')),
  version integer not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index dmd_requests_created on public.dmd_requests(created_at desc);
create index dmd_requests_status on public.dmd_requests(status);
create table public.dmd_admins (user_id uuid primary key references auth.users(id) on delete cascade);
create table public.dmd_rate_limits (key text primary key, hits integer not null, until_at timestamptz not null);
create index dmd_rate_expiry on public.dmd_rate_limits(until_at);
create table public.dmd_revoked_tokens (token_hash text primary key, expires_at timestamptz not null);
alter table public.dmd_requests enable row level security;
alter table public.dmd_admins enable row level security;
alter table public.dmd_rate_limits enable row level security;
alter table public.dmd_revoked_tokens enable row level security;
revoke all on public.dmd_requests, public.dmd_admins, public.dmd_rate_limits, public.dmd_revoked_tokens from public, anon, authenticated;
grant all on public.dmd_requests, public.dmd_admins, public.dmd_rate_limits, public.dmd_revoked_tokens to service_role;

create function public.dmd_rate_limit(p_key text, p_limit integer) returns boolean
language plpgsql security invoker set search_path = '' as $$
declare n integer;
begin
  delete from public.dmd_rate_limits where until_at < now() - interval '1 day';
  delete from public.dmd_revoked_tokens where expires_at < now();
  insert into public.dmd_rate_limits as r (key,hits,until_at) values (p_key,1,now()+interval '15 minutes')
  on conflict (key) do update set hits=case when r.until_at<now() then 1 else r.hits+1 end,
    until_at=case when r.until_at<now() then now()+interval '15 minutes' else r.until_at end
  returning hits into n;
  return n<=p_limit;
end $$;

create function public.dmd_submit(p_key uuid,p_hash text,p_payload jsonb) returns jsonb
language plpgsql security invoker set search_path = '' as $$
declare r public.dmd_requests; fresh boolean;
begin
  insert into public.dmd_requests(id,request_key,payload_hash,payload,search_text)
    values ('DMD-'||gen_random_uuid()::text,p_key,p_hash,p_payload,lower(p_payload::text))
    on conflict(request_key) do nothing returning * into r;
  fresh:=found;
  if not fresh then select * into r from public.dmd_requests where request_key=p_key; end if;
  if r.payload_hash<>p_hash then return jsonb_build_object('conflict',true); end if;
  return jsonb_build_object('id',r.id,'received',true,'created',fresh);
end $$;

create function public.dmd_list(p_status text,p_query text,p_page integer) returns jsonb
language sql security invoker set search_path = '' as $$
  with filtered as (
    select * from public.dmd_requests where (p_status='all' or status=p_status)
      and (p_query='' or position(lower(p_query) in search_text)>0 or position(lower(p_query) in lower(id))>0)
  ), paged as (select * from filtered order by created_at desc,id desc limit 30 offset (p_page-1)*30)
  select jsonb_build_object(
    'items',coalesce((select jsonb_agg(payload||jsonb_build_object('id',id,'status',status,'version',version,'createdAt',created_at,'updatedAt',updated_at) order by created_at desc,id desc) from paged),'[]'::jsonb),
    'total',(select count(*) from filtered),
    'pages',greatest(1,ceil((select count(*) from filtered)/30.0)),
    'counts',jsonb_build_object('new',(select count(*) from public.dmd_requests where status='new'),'in_progress',(select count(*) from public.dmd_requests where status='in_progress'),'done',(select count(*) from public.dmd_requests where status='done'),'archived',(select count(*) from public.dmd_requests where status='archived'))
  );
$$;
revoke all on function public.dmd_rate_limit(text,integer), public.dmd_submit(uuid,text,jsonb), public.dmd_list(text,text,integer) from public,anon,authenticated;
grant execute on function public.dmd_rate_limit(text,integer), public.dmd_submit(uuid,text,jsonb), public.dmd_list(text,text,integer) to service_role;
