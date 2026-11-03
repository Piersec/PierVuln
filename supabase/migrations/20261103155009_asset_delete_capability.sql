create table public.asset_delete_capabilities (
 connection_id uuid not null references public.wazuh_connections(id) on delete cascade,
 tenant_id uuid not null references public.companies(id) on delete cascade,
 api_url text not null,
 status text not null check(status in ('allowed','restricted','denied','unknown')),
 reason text not null check(reason in ('policies','policies_unavailable','authentication_failed','network_error')),
 checked_at timestamptz not null default now(),
 primary key(connection_id,tenant_id)
);
alter table public.asset_delete_capabilities enable row level security;
revoke all on public.asset_delete_capabilities from public,anon,authenticated;
grant all on public.asset_delete_capabilities to service_role;

create function public.record_asset_delete_capability(p_connection uuid,p_tenant uuid,p_api_url text,p_status text,p_reason text)
returns boolean language plpgsql security definer set search_path='' as $$
begin
 if coalesce(auth.role(),'')<>'service_role' then raise exception 'Service role required' using errcode='42501'; end if;
 if not exists(select 1 from public.wazuh_connections c join public.companies co on co.id=p_tenant where c.id=p_connection and c.is_active and co.is_active and co.slug<>'demonstracao' and c.asset_api_url=p_api_url and
 ((c.mode='dedicated' and c.tenant_id=p_tenant) or (c.mode='shared' and exists(select 1 from public.wazuh_agent_mappings m where m.connection_id=c.id and m.tenant_id=p_tenant and m.is_active)))) then return false; end if;
 insert into public.asset_delete_capabilities(connection_id,tenant_id,api_url,status,reason,checked_at)
 values(p_connection,p_tenant,p_api_url,p_status,p_reason,now())
 on conflict(connection_id,tenant_id) do update set api_url=excluded.api_url,status=excluded.status,reason=excluded.reason,checked_at=excluded.checked_at;
 return true;
end;$$;
revoke all on function public.record_asset_delete_capability(uuid,uuid,text,text,text) from public,anon,authenticated;
grant execute on function public.record_asset_delete_capability(uuid,uuid,text,text,text) to service_role;

create function public.get_asset_delete_capability(p_connection uuid,p_tenant uuid)
returns jsonb language plpgsql stable security definer set search_path='' as $$
declare result public.asset_delete_capabilities%rowtype; endpoint text; revised timestamptz;
begin
 if auth.uid() is null or not private.can_delete_assets(p_tenant) then raise exception 'Administrative access required' using errcode='42501'; end if;
 if exists(select 1 from public.companies where id=p_tenant and slug='demonstracao' and is_active) then return jsonb_build_object('status','demo','reason','simulation','checked_at',null); end if;
 select c.asset_api_url,greatest(c.updated_at,t.updated_at,s.updated_at) into endpoint,revised
 from public.wazuh_connections c left join public.asset_api_tenant_secrets t on t.connection_id=c.id and t.tenant_id=p_tenant
 left join public.wazuh_connection_secrets s on s.connection_id=c.id
 where c.id=p_connection and c.is_active;
 select * into result from public.asset_delete_capabilities where connection_id=p_connection and tenant_id=p_tenant;
 if endpoint is null or result.checked_at is null or result.api_url is distinct from endpoint or result.checked_at<revised or result.checked_at<now()-interval '3 minutes' then
 return jsonb_build_object('status','unknown','reason','awaiting_check','checked_at',result.checked_at);
 end if;
 return jsonb_build_object('status',result.status,'reason',result.reason,'checked_at',result.checked_at);
end;$$;
revoke all on function public.get_asset_delete_capability(uuid,uuid) from public,anon;
grant execute on function public.get_asset_delete_capability(uuid,uuid) to authenticated;
notify pgrst,'reload schema';
