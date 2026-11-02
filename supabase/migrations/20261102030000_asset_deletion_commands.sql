create function private.can_delete_assets(p_tenant uuid) returns boolean
language sql stable security definer set search_path='' as $$
 select coalesce(private.is_internal_admin(),false) or exists(
   select 1 from public.company_memberships m join public.companies c on c.id=m.company_id
   where m.company_id=p_tenant and m.user_id=auth.uid() and m.is_active and c.is_active and m.role in ('owner','admin'));
$$;
revoke all on function private.can_delete_assets(uuid) from public,anon;
grant execute on function private.can_delete_assets(uuid) to authenticated,service_role;

create table public.asset_deletion_requests (
 id uuid primary key,
 tenant_id uuid not null references public.companies(id),
 connection_id uuid not null references public.wazuh_connections(id),
 agent_id text not null check(agent_id ~ '^[0-9]{3,8}$' and agent_id !~ '^0+$'),
 agent_name text not null,
 registered_at timestamptz not null,
 ip_address text,
 api_url text,
 requested_by uuid not null references auth.users(id),
 reason text not null check(length(btrim(reason)) between 10 and 1000),
 status text not null default 'pending' check(status in ('pending','executing','succeeded','failed','uncertain','canceled')),
 is_demo boolean not null default false,
 result_code text,
 claim_token uuid,
 created_at timestamptz not null default now(),
 started_at timestamptz,
 finished_at timestamptz,
 expires_at timestamptz not null default now()+interval '15 minutes'
);
create unique index asset_deletion_one_pending on public.asset_deletion_requests(connection_id,tenant_id,agent_id)
 where status in ('pending','executing','uncertain');
create index asset_deletion_tenant_time on public.asset_deletion_requests(tenant_id,created_at desc);
alter table public.asset_deletion_requests enable row level security;
revoke all on public.asset_deletion_requests from public,anon,authenticated;
grant select(id,tenant_id,connection_id,agent_id,agent_name,registered_at,ip_address,requested_by,reason,status,is_demo,result_code,created_at,started_at,finished_at,expires_at) on public.asset_deletion_requests to authenticated;
grant all on public.asset_deletion_requests to service_role;
create policy asset_deletion_read on public.asset_deletion_requests for select to authenticated
 using(private.can_delete_assets(tenant_id));

create table public.asset_deletion_worker_heartbeats (
 connection_id uuid not null references public.wazuh_connections(id),
 tenant_id uuid not null references public.companies(id),
 observed_at timestamptz not null default now(),
 primary key(connection_id,tenant_id)
);
alter table public.asset_deletion_worker_heartbeats enable row level security;
revoke all on public.asset_deletion_worker_heartbeats from public,anon,authenticated;
grant all on public.asset_deletion_worker_heartbeats to service_role;

create function public.request_asset_deletion(p_request_id uuid,p_connection_id uuid,p_tenant_id uuid,p_agent_id text,p_confirmation text,p_reason text)
returns uuid language plpgsql security definer set search_path='' as $$
declare a public.asset_agents%rowtype; c public.wazuh_connections%rowtype; v_demo boolean; existing public.asset_deletion_requests%rowtype;
begin
 if auth.uid() is null or not private.can_delete_assets(p_tenant_id) then raise exception 'Somente administradores podem excluir ativos.' using errcode='42501'; end if;
 select * into existing from public.asset_deletion_requests where id=p_request_id;
 if found then
   if existing.requested_by=auth.uid() and existing.tenant_id=p_tenant_id and existing.connection_id=p_connection_id and existing.agent_id=p_agent_id then return existing.id; end if;
   raise exception 'Pedido inválido.';
 end if;
 select * into a from public.asset_agents where connection_id=p_connection_id and tenant_id=p_tenant_id and agent_id=p_agent_id for update;
 if not found or a.registered_at is null or a.agent_id !~ '^[0-9]{3,8}$' or a.agent_id ~ '^0+$' then raise exception 'Ativo indisponível ou sem identidade segura para exclusão.'; end if;
 if p_confirmation is distinct from 'EXCLUIR '||a.agent_name then raise exception 'Digite a confirmação exata do ativo.'; end if;
 if p_reason is null or length(btrim(p_reason)) not between 10 and 1000 then raise exception 'Informe um motivo entre 10 e 1000 caracteres.'; end if;
 select slug='demonstracao' into v_demo from public.companies where id=p_tenant_id and is_active;
 if v_demo is null then raise exception 'Empresa indisponível.'; end if;
 select * into c from public.wazuh_connections where id=p_connection_id;
 if not v_demo then
   if not c.is_active or c.asset_api_url is null or not exists(select 1 from public.asset_deletion_worker_heartbeats h where h.connection_id=p_connection_id and h.tenant_id=p_tenant_id and observed_at>now()-interval '3 minutes') then
     raise exception 'Coletor de exclusão indisponível. Nenhum pedido foi enviado.';
   end if;
   if c.mode='dedicated' and c.tenant_id is distinct from p_tenant_id or c.mode='shared' and not exists(select 1 from public.wazuh_agent_mappings m where m.connection_id=p_connection_id and m.tenant_id=p_tenant_id and m.is_active) then raise exception 'Ativo fora do vínculo autorizado.'; end if;
 end if;
 insert into public.asset_deletion_requests(id,tenant_id,connection_id,agent_id,agent_name,registered_at,ip_address,api_url,requested_by,reason,is_demo)
 values(p_request_id,p_tenant_id,p_connection_id,a.agent_id,a.agent_name,a.registered_at,a.ip_address,c.asset_api_url,auth.uid(),btrim(p_reason),v_demo);
 if v_demo then
   delete from public.asset_agents where connection_id=p_connection_id and tenant_id=p_tenant_id and agent_id=p_agent_id;
   update public.asset_deletion_requests set status='succeeded',result_code='demo_simulated',finished_at=now() where id=p_request_id;
 end if;
 return p_request_id;
end;
$$;
revoke all on function public.request_asset_deletion(uuid,uuid,uuid,text,text,text) from public,anon;
grant execute on function public.request_asset_deletion(uuid,uuid,uuid,text,text,text) to authenticated;

create function public.cancel_asset_deletion(p_id uuid) returns boolean
language plpgsql security definer set search_path='' as $$
begin
 update public.asset_deletion_requests set status='canceled',finished_at=now(),result_code='user_canceled'
 where id=p_id and status='pending' and private.can_delete_assets(tenant_id);
 return found;
end;
$$;
revoke all on function public.cancel_asset_deletion(uuid) from public,anon;
grant execute on function public.cancel_asset_deletion(uuid) to authenticated;

create function private.can_delete_assets_for_user(p_tenant uuid,p_user uuid) returns boolean
language sql stable security definer set search_path='' as $$
 select exists(select 1 from private.internal_admins where user_id=p_user) or exists(select 1 from public.company_memberships where company_id=p_tenant and user_id=p_user and is_active and role in ('owner','admin'));
$$;
revoke all on function private.can_delete_assets_for_user(uuid,uuid) from public,anon,authenticated;

create function public.claim_asset_deletion(p_connection uuid,p_tenant uuid,p_api_url text) returns jsonb
language plpgsql security definer set search_path='' as $$
declare r public.asset_deletion_requests%rowtype; token uuid:=gen_random_uuid();
begin
 if not exists(select 1 from public.wazuh_connections c join public.companies co on co.id=p_tenant where c.id=p_connection and c.is_active and co.is_active and co.slug<>'demonstracao' and c.asset_api_url=p_api_url and
   ((c.mode='dedicated' and c.tenant_id=p_tenant) or (c.mode='shared' and exists(select 1 from public.wazuh_agent_mappings m where m.connection_id=c.id and m.tenant_id=p_tenant and m.is_active)))) then return null; end if;
 insert into public.asset_deletion_worker_heartbeats(connection_id,tenant_id) values(p_connection,p_tenant)
 on conflict(connection_id,tenant_id) do update set observed_at=now();
 update public.asset_deletion_requests set status='failed',result_code='expired',finished_at=now() where connection_id=p_connection and tenant_id=p_tenant and status='pending' and expires_at<now();
 update public.asset_deletion_requests set status='uncertain',result_code='worker_timeout',finished_at=now() where connection_id=p_connection and tenant_id=p_tenant and status='executing' and started_at<now()-interval '5 minutes';
 select * into r from public.asset_deletion_requests where connection_id=p_connection and tenant_id=p_tenant and status='pending' order by created_at limit 1 for update skip locked;
 if not found then return null; end if;
 if not private.can_delete_assets_for_user(r.tenant_id,r.requested_by) then
   update public.asset_deletion_requests set status='failed',result_code='authorization_changed',finished_at=now() where id=r.id; return null;
 end if;
 if r.api_url is distinct from p_api_url or not exists(select 1 from public.asset_agents a where a.connection_id=r.connection_id and a.tenant_id=r.tenant_id and a.agent_id=r.agent_id and a.agent_name=r.agent_name and a.registered_at=r.registered_at and a.ip_address is not distinct from r.ip_address) then
   update public.asset_deletion_requests set status='failed',result_code='identity_changed',finished_at=now() where id=r.id; return null;
 end if;
 update public.asset_deletion_requests set status='executing',started_at=now(),claim_token=token where id=r.id;
 return jsonb_build_object('id',r.id,'claimToken',token,'agentId',r.agent_id,'agentName',r.agent_name,'registeredAt',r.registered_at,'ipAddress',r.ip_address);
end;
$$;

create function public.finish_asset_deletion(p_id uuid,p_connection uuid,p_tenant uuid,p_claim uuid,p_outcome text,p_code text) returns boolean
language plpgsql security definer set search_path='' as $$
declare r public.asset_deletion_requests%rowtype;
begin
 select * into r from public.asset_deletion_requests where id=p_id and connection_id=p_connection and tenant_id=p_tenant and claim_token=p_claim for update;
 if not found then return false; end if;
 if r.status='succeeded' then return p_outcome='succeeded'; end if;
 if r.status not in ('executing','uncertain') or p_outcome not in ('succeeded','failed','uncertain') then return false; end if;
 if p_outcome='succeeded' then
   delete from public.asset_agents where connection_id=r.connection_id and tenant_id=r.tenant_id and agent_id=r.agent_id and agent_name=r.agent_name and registered_at=r.registered_at;
 end if;
 update public.asset_deletion_requests set status=p_outcome,result_code=case when p_code in ('source_confirmed','source_denied','identity_changed','source_failed','network_uncertain','preflight_failed') then p_code else 'source_failed' end,finished_at=now() where id=r.id;
 return true;
end;
$$;
revoke all on function public.claim_asset_deletion(uuid,uuid,text),public.finish_asset_deletion(uuid,uuid,uuid,uuid,text,text) from public,anon,authenticated;
grant execute on function public.claim_asset_deletion(uuid,uuid,text),public.finish_asset_deletion(uuid,uuid,uuid,uuid,text,text) to service_role;

create function private.prevent_deleted_asset_reappearance() returns trigger language plpgsql security definer set search_path='' as $$
begin
 if exists(select 1 from public.asset_deletion_requests r where r.connection_id=new.connection_id and r.tenant_id=new.tenant_id and r.agent_id=new.agent_id and r.registered_at=new.registered_at and r.agent_name=new.agent_name and r.status='succeeded') then return null; end if;
 return new;
end;
$$;
revoke all on function private.prevent_deleted_asset_reappearance() from public,anon,authenticated;
create trigger asset_delete_tombstone before insert or update on public.asset_agents for each row execute function private.prevent_deleted_asset_reappearance();
