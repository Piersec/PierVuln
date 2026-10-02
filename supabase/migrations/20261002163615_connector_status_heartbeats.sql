create table public.connector_status_heartbeats (
  connection_id uuid primary key references public.wazuh_connections(id) on delete cascade,
  observed_at timestamptz not null default now(),
  vpn_active boolean not null,
  indexer_reachable boolean not null,
  connector_active boolean not null,
  uptime_seconds bigint not null check (uptime_seconds >= 0),
  load_percent numeric(6, 1) not null check (load_percent >= 0 and load_percent <= 1000),
  memory_percent numeric(5, 1) not null check (memory_percent between 0 and 100),
  disk_percent numeric(5, 1) not null check (disk_percent between 0 and 100),
  indexer_latency_ms integer check (indexer_latency_ms between 0 and 60000)
);

alter table public.connector_status_heartbeats enable row level security;

create policy connector_status_heartbeats_read on public.connector_status_heartbeats
  for select to authenticated
  using (private.can_access_connection(connection_id));

revoke all on public.connector_status_heartbeats from anon, authenticated;
grant select on public.connector_status_heartbeats to authenticated;
grant all on public.connector_status_heartbeats to service_role;
