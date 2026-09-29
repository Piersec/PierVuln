-- Core multi-tenant schema for the Wazuh vulnerability portal.
-- PostgreSQL 17; all customer authorization is based on company membership.

create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated, service_role;

create extension if not exists pgcrypto with schema extensions;

create type public.connection_mode as enum ('dedicated', 'shared');
create type public.wazuh_match_type as enum ('agent_id', 'group');
create type public.vulnerability_source_state as enum ('active', 'resolved');
create type public.vulnerability_workflow_status as enum (
  'open', 'in_progress', 'awaiting_validation', 'resolved'
);
create type public.comment_visibility as enum ('shared', 'internal');
create type public.sync_run_status as enum ('running', 'succeeded', 'partial', 'failed');
create type public.archive_manifest_status as enum (
  'pending', 'verified', 'database_purged', 'expired'
);

create table public.companies (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(btrim(name)) between 2 and 160),
  slug text not null unique check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.user_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '' check (length(display_name) <= 160),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.company_memberships (
  id uuid primary key default gen_random_uuid(),
  company_id uuid not null references public.companies(id) on delete restrict,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'viewer'
    check (role in ('owner', 'admin', 'analyst', 'viewer')),
  is_active boolean not null default true,
  invited_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  unique (company_id, user_id)
);

create table private.internal_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id) on delete set null
);
alter table private.internal_admins enable row level security;
revoke all on private.internal_admins from public, anon, authenticated;
grant select, insert, update, delete on private.internal_admins to service_role;

create table public.wazuh_connections (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references public.companies(id) on delete restrict,
  name text not null check (length(btrim(name)) between 2 and 160),
  mode public.connection_mode not null,
  endpoint_url text not null check (endpoint_url ~ '^https://'),
  index_pattern text not null default 'wazuh-states-vulnerabilities-*'
    check (index_pattern ~ '^wazuh-states-vulnerabilities[-a-zA-Z0-9_*]*$'),
  is_active boolean not null default true,
  connector_version text,
  last_connected_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (
    (mode = 'dedicated' and tenant_id is not null)
    or (mode = 'shared' and tenant_id is null)
  )
);

create table public.wazuh_agent_mappings (
  id uuid primary key default gen_random_uuid(),
  connection_id uuid not null references public.wazuh_connections(id) on delete cascade,
  tenant_id uuid not null references public.companies(id) on delete restrict,
  match_type public.wazuh_match_type not null,
  match_value text not null check (length(btrim(match_value)) between 1 and 256),
  is_active boolean not null default true,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  unique (connection_id, match_type, match_value)
);

-- The connector token is only stored as a SHA-256 digest. This table is not
-- granted to browser roles; the ingestion Edge Function reads it as service_role.
create table public.wazuh_ingest_credentials (
  connection_id uuid primary key references public.wazuh_connections(id) on delete cascade,
  token_sha256 text not null check (token_sha256 ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  rotated_at timestamptz
);

create table public.sync_runs (
  id uuid primary key default gen_random_uuid(),
  connection_id uuid not null references public.wazuh_connections(id) on delete restrict,
  status public.sync_run_status not null default 'running',
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  pages_received integer not null default 0 check (pages_received >= 0),
  documents_received bigint not null default 0 check (documents_received >= 0),
  expected_pages integer check (expected_pages is null or expected_pages >= 0),
  expected_documents bigint check (expected_documents is null or expected_documents >= 0),
  findings_changed bigint not null default 0 check (findings_changed >= 0),
  indexer_version text,
  error_summary text check (error_summary is null or length(error_summary) <= 2000),
  full_snapshot boolean not null default false
);

-- Page keys make retries idempotent and prevent duplicate counters.
create table public.sync_run_pages (
  run_id uuid not null references public.sync_runs(id) on delete cascade,
  page_number integer not null check (page_number >= 0),
  payload_sha256 text not null check (payload_sha256 ~ '^[0-9a-f]{64}$'),
  document_count integer not null check (document_count >= 0),
  received_at timestamptz not null default now(),
  primary key (run_id, page_number)
);

create table public.wazuh_findings (
  id uuid primary key default gen_random_uuid(),
  connection_id uuid not null references public.wazuh_connections(id) on delete restrict,
  source_document_id text not null check (length(source_document_id) between 1 and 512),
  tenant_id uuid references public.companies(id) on delete restrict,
  agent_id text,
  agent_name text,
  agent_groups text[] not null default '{}',
  host_os text,
  package_name text,
  package_version text,
  package_type text,
  package_architecture text,
  vulnerability_id text not null,
  description text,
  severity text not null default 'Unknown'
    check (severity in ('Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown')),
  cvss_base numeric(3,1) check (cvss_base is null or cvss_base between 0 and 10),
  reference_urls text[] not null default '{}',
  source_status text,
  source_state public.vulnerability_source_state not null default 'active',
  first_detected_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  resolved_at timestamptz,
  last_seen_sync_run_id uuid references public.sync_runs(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (connection_id, source_document_id),
  unique (id, tenant_id),
  check ((source_state = 'resolved') = (resolved_at is not null))
);

create table public.vulnerability_cases (
  id uuid primary key default gen_random_uuid(),
  finding_id uuid not null references public.wazuh_findings(id) on delete restrict,
  tenant_id uuid not null references public.companies(id) on delete restrict,
  workflow_status public.vulnerability_workflow_status not null default 'open',
  assigned_to uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  closed_at timestamptz,
  unique (finding_id, tenant_id),
  unique (id, finding_id, tenant_id),
  check ((workflow_status = 'resolved') = (closed_at is not null))
);

create table public.vulnerability_comments (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null,
  finding_id uuid not null,
  tenant_id uuid not null references public.companies(id) on delete restrict,
  author_id uuid references auth.users(id) on delete set null,
  visibility public.comment_visibility not null default 'shared',
  body text not null check (length(btrim(body)) between 1 and 10000),
  created_at timestamptz not null default now(),
  foreign key (case_id, finding_id, tenant_id)
    references public.vulnerability_cases(id, finding_id, tenant_id) on delete restrict
);

create table public.finding_events (
  id uuid primary key default gen_random_uuid(),
  case_id uuid,
  finding_id uuid not null references public.wazuh_findings(id) on delete restrict,
  tenant_id uuid references public.companies(id) on delete restrict,
  actor_id uuid references auth.users(id) on delete set null,
  event_type text not null check (event_type in (
    'first_detected', 'reopened', 'confirmed_resolved', 'workflow_changed', 'tenant_mapping_changed'
  )),
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  foreign key (case_id, finding_id, tenant_id)
    references public.vulnerability_cases(id, finding_id, tenant_id) on delete restrict
);

create table public.archive_manifests (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.companies(id) on delete restrict,
  connection_id uuid not null references public.wazuh_connections(id) on delete restrict,
  bucket_name text not null default 'wazuh-vulnerability-archives'
    check (bucket_name = 'wazuh-vulnerability-archives'),
  object_path text not null unique,
  checksum_sha256 text not null check (checksum_sha256 ~ '^[0-9a-f]{64}$'),
  record_count integer not null check (record_count > 0),
  finding_ids uuid[] not null check (cardinality(finding_ids) > 0),
  period_start timestamptz not null,
  period_end timestamptz not null,
  archived_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '1 year'),
  status public.archive_manifest_status not null default 'pending',
  database_purged_at timestamptz,
  expired_at timestamptz,
  created_at timestamptz not null default now(),
  check (period_end >= period_start),
  check (expires_at > archived_at)
);

create index company_memberships_user_active_idx
  on public.company_memberships(user_id, company_id) where is_active;
create index wazuh_connections_tenant_idx
  on public.wazuh_connections(tenant_id) where tenant_id is not null;
create index wazuh_agent_mappings_tenant_idx
  on public.wazuh_agent_mappings(tenant_id, connection_id) where is_active;
create index sync_runs_connection_started_idx
  on public.sync_runs(connection_id, started_at desc);
create index wazuh_findings_tenant_active_idx
  on public.wazuh_findings(tenant_id, last_seen_at desc)
  where source_state = 'active' and tenant_id is not null;
create index wazuh_findings_cve_idx on public.wazuh_findings(vulnerability_id);
create index wazuh_findings_agent_idx on public.wazuh_findings(agent_id);
create index vulnerability_cases_tenant_status_updated_idx
  on public.vulnerability_cases(tenant_id, workflow_status, updated_at desc);
create index vulnerability_comments_case_created_idx
  on public.vulnerability_comments(case_id, created_at);
create index finding_events_finding_created_idx
  on public.finding_events(finding_id, created_at);
create index archive_manifests_expiry_idx
  on public.archive_manifests(expires_at) where status <> 'expired';
