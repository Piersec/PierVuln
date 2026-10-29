alter table public.asset_sync_runs
  add column if not exists tenant_id uuid references public.companies(id) on delete cascade;

update public.asset_sync_runs run
set tenant_id = source.tenant_id
from public.wazuh_connections source
where run.connection_id = source.id
  and run.tenant_id is null
  and source.mode = 'dedicated'
  and source.tenant_id is not null;

update public.asset_sync_runs
set status = 'failed',
    finished_at = coalesce(finished_at, now()),
    error_summary = coalesce(error_summary, 'Reinicie a coleta por empresa.')
where status = 'running' and tenant_id is null;

create index if not exists asset_sync_runs_connection_tenant_started_idx
  on public.asset_sync_runs (connection_id, tenant_id, started_at desc);

create table if not exists public.asset_api_tenant_secrets (
  connection_id uuid not null references public.wazuh_connections(id) on delete cascade,
  tenant_id uuid not null references public.companies(id) on delete cascade,
  nonce text not null,
  ciphertext text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (connection_id, tenant_id)
);

alter table public.asset_api_tenant_secrets enable row level security;
revoke all on public.asset_api_tenant_secrets from public, anon, authenticated;
grant select, insert, update, delete on public.asset_api_tenant_secrets to service_role;
