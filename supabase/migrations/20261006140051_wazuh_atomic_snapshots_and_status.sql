set local lock_timeout = '5s';

create schema if not exists wazuh_internal;
revoke all on schema wazuh_internal from public, anon, authenticated, service_role;

create unlogged table wazuh_internal.snapshot_pages (
  run_id uuid not null references public.sync_runs(id) on delete cascade,
  page_number integer not null check (page_number >= 0),
  payload_sha256 text not null check (payload_sha256 ~ '^[0-9a-f]{64}$'),
  document_count integer not null check (document_count between 0 and 500),
  items jsonb not null check (jsonb_typeof(items) = 'array'),
  received_at timestamptz not null default now(),
  primary key (run_id, page_number)
);
alter table wazuh_internal.snapshot_pages enable row level security;
revoke all on table wazuh_internal.snapshot_pages from public, anon, authenticated, service_role;

alter table public.wazuh_connections
  add column published_sync_run_id uuid references public.sync_runs(id) on delete set null;
grant select (published_sync_run_id) on public.wazuh_connections to authenticated;

-- Preserve the existing mapping, normalization, and changed-only write logic as
-- an internal publisher. The public function below now accepts pages into staging.
alter function public.ingest_wazuh_batch(uuid, uuid, integer, text, jsonb)
  set schema wazuh_internal;
alter function wazuh_internal.ingest_wazuh_batch(uuid, uuid, integer, text, jsonb)
  rename to apply_wazuh_batch;
revoke all on function wazuh_internal.apply_wazuh_batch(uuid, uuid, integer, text, jsonb)
  from public, anon, authenticated, service_role;

alter function public.complete_wazuh_sync(uuid, uuid, integer, bigint, text)
  set schema wazuh_internal;
alter function wazuh_internal.complete_wazuh_sync(uuid, uuid, integer, bigint, text)
  rename to apply_complete_wazuh_sync;
revoke all on function wazuh_internal.apply_complete_wazuh_sync(uuid, uuid, integer, bigint, text)
  from public, anon, authenticated, service_role;

create function public.wazuh_snapshot_protocol()
returns smallint
language plpgsql
security definer
set search_path = ''
as $$
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;
  return 2;
end;
$$;
revoke all on function public.wazuh_snapshot_protocol() from public, anon, authenticated;
grant execute on function public.wazuh_snapshot_protocol() to service_role;

-- The client supplies a UUID so a lost HTTP response cannot strand an
-- unidentifiable running sync. Replaying the same start request returns its run.
alter function public.register_wazuh_sync(uuid, text) set schema wazuh_internal;
alter function wazuh_internal.register_wazuh_sync(uuid, text) rename to register_wazuh_sync_legacy;
revoke all on function wazuh_internal.register_wazuh_sync_legacy(uuid, text)
  from public, anon, authenticated, service_role;

create function public.register_wazuh_sync(
  p_connection_id uuid,
  p_indexer_version text,
  p_request_id uuid
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_run public.sync_runs%rowtype;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;
  if p_request_id is null then
    raise exception 'Sync request ID is required' using errcode = '22023';
  end if;

  select * into v_run
  from public.sync_runs sr
  where sr.id = p_request_id and sr.connection_id = p_connection_id
  for update;
  if found then
    if v_run.status = 'running' then return v_run.id; end if;
    raise exception 'Sync request ID is already closed' using errcode = 'P0002';
  end if;

  if not exists (
    select 1 from public.wazuh_connections wc
    where wc.id = p_connection_id and wc.is_active
  ) then
    raise exception 'Wazuh connection is missing or inactive' using errcode = 'P0002';
  end if;

  update public.sync_runs
  set status = 'partial',
      finished_at = now(),
      error_summary = 'Conector substituiu uma execução parada há mais de duas horas.'
  where connection_id = p_connection_id
    and status = 'running'
    and started_at < now() - interval '2 hours';

  insert into public.sync_runs (id, connection_id, indexer_version)
  values (p_request_id, p_connection_id, left(coalesce(p_indexer_version, 'unknown'), 160))
  on conflict (id) do nothing;

  select * into v_run
  from public.sync_runs sr
  where sr.id = p_request_id and sr.connection_id = p_connection_id
  for update;
  if not found or v_run.status <> 'running' then
    raise exception 'Sync request ID could not be registered' using errcode = '23505';
  end if;
  return v_run.id;
end;
$$;
revoke all on function public.register_wazuh_sync(uuid, text, uuid) from public, anon, authenticated;
grant execute on function public.register_wazuh_sync(uuid, text, uuid) to service_role;

create function public.ingest_wazuh_batch(
  p_connection_id uuid,
  p_run_id uuid,
  p_page_number integer,
  p_payload_sha256 text,
  p_items jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_run public.sync_runs%rowtype;
  v_page wazuh_internal.snapshot_pages%rowtype;
  v_document_count integer;
  v_inserted boolean;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;
  if p_page_number < 0 or p_payload_sha256 !~ '^[0-9a-f]{64}$'
     or jsonb_typeof(p_items) <> 'array' then
    raise exception 'Invalid page payload' using errcode = '22023';
  end if;
  v_document_count := jsonb_array_length(p_items);
  if v_document_count > 500 then
    raise exception 'A page may contain at most 500 documents' using errcode = '22023';
  end if;
  if exists (
    select 1
    from jsonb_array_elements(p_items) as item(value)
    where nullif(btrim(item.value ->> 'documentId'), '') is null
       or item.value ->> 'documentId' <> btrim(item.value ->> 'documentId')
       or length(btrim(item.value ->> 'documentId')) > 512
  ) then
    raise exception 'Indexer document is missing its stable _id' using errcode = '22023';
  end if;

  select * into v_run
  from public.sync_runs sr
  where sr.id = p_run_id
    and sr.connection_id = p_connection_id
    and sr.status = 'running'
  for update;
  if not found then
    raise exception 'Sync run is missing or already closed' using errcode = 'P0002';
  end if;
  if not exists (
    select 1 from public.wazuh_connections wc
    where wc.id = p_connection_id and wc.is_active
  ) then
    raise exception 'Wazuh connection is missing or inactive' using errcode = 'P0002';
  end if;

  insert into wazuh_internal.snapshot_pages (run_id, page_number, payload_sha256, document_count, items)
  values (p_run_id, p_page_number, p_payload_sha256, v_document_count, p_items)
  on conflict (run_id, page_number) do nothing;
  v_inserted := found;
  if not v_inserted then
    select * into v_page
    from wazuh_internal.snapshot_pages sp
    where sp.run_id = p_run_id and sp.page_number = p_page_number;
    if v_page.payload_sha256 is distinct from p_payload_sha256
       or v_page.document_count is distinct from v_document_count
       or v_page.items is distinct from p_items then
      raise exception 'A retry changed the content of an accepted page' using errcode = '22023';
    end if;
    return jsonb_build_object(
      'duplicate', true,
      'pagesReceived', v_run.pages_received,
      'documentsReceived', v_run.documents_received,
      'findingsChanged', 0
    );
  end if;

  update public.sync_runs sr
  set pages_received = pages_received + 1,
      documents_received = documents_received + v_document_count
  where sr.id = p_run_id
  returning * into v_run;

  return jsonb_build_object(
    'duplicate', false,
    'staged', true,
    'pagesReceived', v_run.pages_received,
    'documentsReceived', v_run.documents_received,
    'findingsChanged', 0
  );
end;
$$;
revoke all on function public.ingest_wazuh_batch(uuid, uuid, integer, text, jsonb)
  from public, anon, authenticated;
grant execute on function public.ingest_wazuh_batch(uuid, uuid, integer, text, jsonb)
  to service_role;

create or replace function public.complete_wazuh_sync(
  p_connection_id uuid,
  p_run_id uuid,
  p_expected_pages integer,
  p_expected_documents bigint,
  p_indexer_version text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_run public.sync_runs%rowtype;
  v_page record;
  v_staged_pages integer;
  v_staged_documents bigint;
  v_min_page integer;
  v_max_page integer;
  v_distinct_documents bigint;
  v_invalid_document boolean;
  v_legacy_receipts integer;
  v_publish_result jsonb;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;

  select * into v_run
  from public.sync_runs sr
  where sr.id = p_run_id and sr.connection_id = p_connection_id
  for update;
  if not found then
    raise exception 'Sync run is missing' using errcode = 'P0002';
  end if;
  if v_run.status = 'succeeded' and v_run.full_snapshot
     and v_run.expected_pages = p_expected_pages
     and v_run.expected_documents = p_expected_documents then
    return jsonb_build_object(
      'completed', true,
      'status', 'succeeded',
      'resolvedFindings', 0,
      'findingsChanged', v_run.findings_changed
    );
  end if;
  if v_run.status <> 'running' then
    raise exception 'Sync run is missing or already closed' using errcode = 'P0002';
  end if;

  select count(*)::integer, coalesce(sum(sp.document_count), 0)::bigint,
         min(sp.page_number), max(sp.page_number)
    into v_staged_pages, v_staged_documents, v_min_page, v_max_page
  from wazuh_internal.snapshot_pages sp
  where sp.run_id = p_run_id;

  select count(*)
    into v_legacy_receipts
  from public.sync_run_pages srp
  where srp.run_id = p_run_id;

  select count(distinct item.value ->> 'documentId')::bigint,
         coalesce(bool_or(nullif(btrim(item.value ->> 'documentId'), '') is null
           or item.value ->> 'documentId' <> btrim(item.value ->> 'documentId')
           or length(btrim(item.value ->> 'documentId')) > 512), false)
    into v_distinct_documents, v_invalid_document
  from wazuh_internal.snapshot_pages sp
  cross join lateral jsonb_array_elements(sp.items) as item(value)
  where sp.run_id = p_run_id;

  if p_expected_pages is null or p_expected_documents is null
     or p_expected_pages < 1 or p_expected_documents < 0
     or v_run.pages_received <> p_expected_pages
     or v_run.documents_received <> p_expected_documents
     or v_staged_pages <> p_expected_pages
     or v_staged_documents <> p_expected_documents
     or v_min_page <> 0 or v_max_page <> p_expected_pages - 1
     or v_legacy_receipts <> 0
     or v_invalid_document
     or v_distinct_documents <> p_expected_documents then
    update public.sync_runs
    set status = 'partial',
        expected_pages = p_expected_pages,
        expected_documents = p_expected_documents,
        finished_at = now(),
        full_snapshot = false,
        error_summary = case
          when v_legacy_receipts > 0 then 'A execução contém páginas gravadas pelo protocolo anterior e não pode ser publicada como snapshot atômico.'
          when v_invalid_document or v_distinct_documents <> p_expected_documents then 'O snapshot contém IDs de documentos duplicados ou inválidos.'
          else 'A sequência de páginas ou o total de documentos recebido não corresponde ao snapshot completo.'
        end
    where id = p_run_id;
    return jsonb_build_object(
      'completed', false,
      'status', 'partial',
      'pagesReceived', v_run.pages_received,
      'documentsReceived', v_run.documents_received
    );
  end if;

  update public.sync_runs
  set pages_received = 0,
      documents_received = 0,
      indexer_version = left(coalesce(p_indexer_version, 'unknown'), 160)
  where id = p_run_id;

  for v_page in
    select sp.page_number, sp.payload_sha256, sp.items
    from wazuh_internal.snapshot_pages sp
    where sp.run_id = p_run_id
    order by sp.page_number
  loop
    perform wazuh_internal.apply_wazuh_batch(
      p_connection_id, p_run_id, v_page.page_number, v_page.payload_sha256, v_page.items
    );
  end loop;

  if (select count(*) from public.sync_run_pages where run_id = p_run_id) <> p_expected_pages
     or (select pages_received from public.sync_runs where id = p_run_id) <> p_expected_pages
     or (select documents_received from public.sync_runs where id = p_run_id) <> p_expected_documents then
    raise exception 'Staged snapshot publication counters do not match the accepted pages' using errcode = '22023';
  end if;

  v_publish_result := wazuh_internal.apply_complete_wazuh_sync(
    p_connection_id, p_run_id, p_expected_pages, p_expected_documents, p_indexer_version
  );
  if coalesce((v_publish_result ->> 'completed')::boolean, false) is not true then
    return v_publish_result;
  end if;

  update public.wazuh_connections
  set published_sync_run_id = p_run_id
  where id = v_run.connection_id;
  select * into v_run from public.sync_runs where id = p_run_id;

  return v_publish_result || jsonb_build_object('findingsChanged', v_run.findings_changed);
end;
$$;
revoke all on function public.complete_wazuh_sync(uuid, uuid, integer, bigint, text)
  from public, anon, authenticated;
grant execute on function public.complete_wazuh_sync(uuid, uuid, integer, bigint, text)
  to service_role;

create or replace function private.cleanup_sync_run_pages()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.status = 'running' and new.status <> 'running' then
    delete from public.sync_run_pages where run_id = new.id;
    delete from wazuh_internal.snapshot_pages where run_id = new.id;
  end if;
  return new;
end;
$$;
revoke all on function private.cleanup_sync_run_pages() from public, anon, authenticated;

update public.sync_runs
set status = 'partial',
    finished_at = now(),
    full_snapshot = false,
    error_summary = 'Execução anterior encerrada durante a migração para publicação atômica. O próximo snapshot completo fará a reconciliação.'
where status = 'running';

drop function public.get_vulnerability_overview(uuid, text);
create function public.get_vulnerability_overview(
  p_company_id uuid default null,
  p_agent_name_prefix text default null
)
returns setof jsonb
language sql
stable
security invoker
as $$
  with scoped_findings as materialized (
    select f.id, f.tenant_id, f.vulnerability_id, f.severity, f.cvss_base,
      f.agent_id, f.agent_name, f.first_detected_at, f.source_state, f.resolved_at
    from public.wazuh_findings f
    where f.tenant_id is not null
      and (p_company_id is null or f.tenant_id = p_company_id)
      and (p_agent_name_prefix is null or f.agent_name like p_agent_name_prefix || '%')
  ), active as materialized (
    select *, greatest(0, floor(extract(epoch from (now() - first_detected_at)) / 86400)) as age_days
    from scoped_findings
    where source_state = 'active'
  ), case_workflow as materialized (
    select c.finding_id, c.workflow_status
    from public.vulnerability_cases c
    join active a on a.id = c.finding_id and a.tenant_id = c.tenant_id
  ), severity_counts as (
    select severity, count(*) as total from active group by severity
  ), age_counts as (
    select case when age_days <= 7 then 0 when age_days <= 30 then 1 when age_days <= 90 then 2 else 3 end as band,
      severity, count(*) as total
    from active group by 1, 2
  ), month_counts as (
    select to_char(first_detected_at at time zone 'UTC', 'YYYY-MM') as month,
      severity, count(*) as total
    from active
    where first_detected_at >= date_trunc('month', now()) - interval '6 months'
    group by 1, 2
  ), cve_groups as (
    select tenant_id, upper(vulnerability_id) as cve, coalesce(max(cvss_base), 0) as cvss,
      (array['Informational','Low','Medium','High','Critical'])[greatest(1, max(
        case severity when 'Critical' then 5 when 'High' then 4 when 'Medium' then 3 when 'Low' then 2 else 1 end
      ))] as severity,
      count(*) as cases,
      count(distinct coalesce(nullif(agent_id, ''), nullif(agent_name, ''))) as hosts
    from active
    group by tenant_id, upper(vulnerability_id)
  )
  select jsonb_build_object(
    'activeCount', (select count(*) from active),
    'caseCount', (select count(*) from active),
    'criticalHighCount', (select count(*) from active where severity in ('Critical', 'High')),
    'inProgressCount', (select count(*) from case_workflow where workflow_status in ('in_progress', 'awaiting_validation')),
    'corrected30', (select count(*) from scoped_findings where source_state = 'resolved' and resolved_at >= now() - interval '30 days'),
    'severityCounts', coalesce((select jsonb_object_agg(severity, total) from severity_counts), '{}'::jsonb),
    'ageCounts', coalesce((select jsonb_agg(jsonb_build_object('band', band, 'severity', severity, 'count', total)) from age_counts), '[]'::jsonb),
    'monthCounts', coalesce((select jsonb_agg(jsonb_build_object('month', month, 'severity', severity, 'count', total)) from month_counts), '[]'::jsonb),
    'groups', coalesce((select jsonb_agg(jsonb_build_object(
      'tenantId', tenant_id, 'cve', cve, 'severity', severity, 'cvss', cvss,
      'caseCount', cases, 'hostCount', hosts
    ) order by tenant_id, cve) from cve_groups), '[]'::jsonb)
  );
$$;
revoke execute on function public.get_vulnerability_overview(uuid, text) from public, anon;
grant execute on function public.get_vulnerability_overview(uuid, text) to authenticated;

notify pgrst, 'reload schema';
