create index if not exists asset_api_tenant_secrets_tenant_idx
  on public.asset_api_tenant_secrets (tenant_id);

create index if not exists asset_sync_runs_tenant_started_idx
  on public.asset_sync_runs (tenant_id, started_at desc);
