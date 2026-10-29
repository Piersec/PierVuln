alter table public.wazuh_connections
  add column asset_api_url text,
  add constraint wazuh_connections_asset_api_https
    check (asset_api_url is null or asset_api_url ~ '^https://');

create table public.asset_agents (
  connection_id uuid not null references public.wazuh_connections(id) on delete cascade,
  agent_id text not null check (length(agent_id) between 1 and 128),
  tenant_id uuid not null references public.companies(id) on delete cascade,
  agent_name text not null check (length(agent_name) between 1 and 256),
  ip_address text,
  host_os text,
  status text not null check (status in ('active', 'disconnected', 'never_connected', 'pending', 'unknown')),
  agent_groups text[] not null default '{}',
  registered_at timestamptz,
  last_keep_alive_at timestamptz,
  seen_run_id uuid not null,
  updated_at timestamptz not null default now(),
  primary key (connection_id, agent_id)
);

create index asset_agents_tenant_name_idx on public.asset_agents (tenant_id, agent_name);
create index asset_agents_tenant_status_idx on public.asset_agents (tenant_id, status);

alter table public.asset_agents enable row level security;
create policy asset_agents_read on public.asset_agents for select to authenticated
  using ((select private.is_internal_admin()) or private.has_company_membership(tenant_id));
grant select on public.asset_agents to authenticated;
grant select, insert, update, delete on public.asset_agents to service_role;

create table public.asset_sync_runs (
  id uuid primary key,
  connection_id uuid not null references public.wazuh_connections(id) on delete cascade,
  status text not null check (status in ('running', 'succeeded', 'failed')),
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  agents_received integer not null default 0,
  agents_stored integer not null default 0,
  error_summary text
);
create index asset_sync_runs_connection_started_idx on public.asset_sync_runs (connection_id, started_at desc);
alter table public.asset_sync_runs enable row level security;
revoke all on public.asset_sync_runs from anon, authenticated;
grant select, insert, update, delete on public.asset_sync_runs to service_role;

create function private.clear_asset_agents_on_company_deletion()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  delete from public.asset_agents where tenant_id = new.tenant_id;
  return new;
end;
$$;
revoke all on function private.clear_asset_agents_on_company_deletion() from public, anon, authenticated;
create trigger clear_asset_agents_on_company_deletion
  after insert on private.company_data_deletions
  for each row execute function private.clear_asset_agents_on_company_deletion();

create or replace view public.asset_inventory with (security_invoker = true) as
select a.tenant_id, a.connection_id, a.agent_id as agent_key,
  a.agent_id, a.agent_name, a.host_os,
  a.registered_at as first_detected_at,
  coalesce(a.last_keep_alive_at, a.updated_at) as last_seen_at,
  null::bigint as active_vulnerabilities,
  a.ip_address, a.status
from public.asset_agents a;
grant select on public.asset_inventory to authenticated;

notify pgrst, 'reload schema';
