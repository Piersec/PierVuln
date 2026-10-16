begin;

create unlogged table wazuh_internal.sync_run_document_ids (
  connection_id uuid not null references public.wazuh_connections(id) on delete cascade,
  document_id text not null check (length(document_id) between 1 and 512),
  primary key (connection_id, document_id)
);
alter table wazuh_internal.sync_run_document_ids enable row level security;
revoke all on wazuh_internal.sync_run_document_ids from public, anon, authenticated, service_role;

create unique index if not exists sync_runs_one_running_per_connection_idx
  on public.sync_runs(connection_id) where status = 'running';

create or replace function private.reset_sync_document_ids_before_run()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform pg_catalog.pg_advisory_xact_lock(1784511, 1);
  delete from wazuh_internal.sync_run_document_ids
  where connection_id = new.connection_id;
  return new;
end;
$$;
revoke all on function private.reset_sync_document_ids_before_run() from public, anon, authenticated, service_role;
create trigger sync_runs_reset_document_ids
  before insert on public.sync_runs
  for each row when (new.status = 'running')
  execute function private.reset_sync_document_ids_before_run();

create or replace function private.cleanup_sync_run_pages()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.status = 'running' and new.status <> 'running' then
    perform pg_catalog.pg_advisory_xact_lock(1784511, 1);
    delete from public.sync_run_pages where run_id = new.id;
    delete from wazuh_internal.snapshot_pages where run_id = new.id;
    delete from wazuh_internal.sync_run_document_ids where connection_id = new.connection_id;
    if not exists (select 1 from public.sync_runs where status = 'running') then
      truncate table wazuh_internal.sync_run_document_ids;
    end if;
  end if;
  return new;
end;
$$;
revoke all on function private.cleanup_sync_run_pages() from public, anon, authenticated, service_role;

alter table public.finding_events
  drop constraint finding_events_case_id_finding_id_tenant_id_fkey;
alter table public.vulnerability_comments
  drop constraint vulnerability_comments_case_id_finding_id_tenant_id_fkey;

update public.finding_events
set case_id = finding_id
where case_id is distinct from finding_id;
update public.vulnerability_comments
set case_id = finding_id
where case_id is distinct from finding_id;

delete from public.finding_events where event_type = 'first_detected';

alter table public.vulnerability_comments
  add constraint vulnerability_comments_finding_id_fkey
  foreign key (finding_id) references public.wazuh_findings(id) on delete restrict;

alter table public.vulnerability_cases
  drop constraint vulnerability_cases_id_finding_id_tenant_id_key;

create or replace function private.suppress_implicit_open_case()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.workflow_status = 'open'
     and new.assigned_to is null
     and new.closed_at is null
     and not exists (
       select 1 from public.vulnerability_cases c
       where c.finding_id = new.finding_id and c.tenant_id = new.tenant_id
     ) then
    return null;
  end if;
  return new;
end;
$$;
revoke all on function private.suppress_implicit_open_case() from public, anon, authenticated, service_role;
create trigger vulnerability_cases_suppress_implicit_open
  before insert on public.vulnerability_cases
  for each row execute function private.suppress_implicit_open_case();

delete from public.vulnerability_cases c
where c.workflow_status = 'open'
  and c.assigned_to is null
  and c.closed_at is null;

create or replace function private.audit_case_workflow_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'INSERT' then
    if new.workflow_status <> 'open' then
      insert into public.finding_events (
        case_id, finding_id, tenant_id, actor_id, event_type, details
      ) values (
        new.finding_id,
        new.finding_id,
        new.tenant_id,
        (select auth.uid()),
        case when new.workflow_status = 'resolved' then 'confirmed_resolved' else 'workflow_changed' end,
        jsonb_build_object('from', 'open', 'to', new.workflow_status)
      );
    end if;
    return new;
  end if;

  if old.workflow_status is distinct from new.workflow_status then
    if pg_catalog.current_setting('piervuln.source_transition_finding', true) = new.finding_id::text
       and (new.workflow_status = 'resolved' or
         (old.workflow_status = 'resolved' and new.workflow_status = 'open')) then
      perform pg_catalog.set_config('piervuln.source_transition_finding', '', true);
      return new;
    end if;
    insert into public.finding_events (
      case_id, finding_id, tenant_id, actor_id, event_type, details
    ) values (
      new.finding_id,
      new.finding_id,
      new.tenant_id,
      (select auth.uid()),
      case
        when new.workflow_status = 'resolved' then 'confirmed_resolved'
        when old.workflow_status = 'resolved' and new.workflow_status <> 'resolved' then 'reopened'
        else 'workflow_changed'
      end,
      jsonb_build_object('from', old.workflow_status, 'to', new.workflow_status)
    );
  end if;
  return new;
end;
$$;
revoke all on function private.audit_case_workflow_change() from public, anon, authenticated, service_role;
create trigger vulnerability_cases_audit_workflow_insert
  after insert on public.vulnerability_cases
  for each row execute function private.audit_case_workflow_change();

create or replace function private.audit_finding_source_state_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.tenant_id is not null and old.source_state is distinct from new.source_state then
    if old.source_state = 'active' and new.source_state = 'resolved' then
      insert into public.finding_events (
        case_id, finding_id, tenant_id, event_type, details
      ) values (
        new.id, new.id, new.tenant_id, 'confirmed_resolved',
        jsonb_build_object('from', 'active', 'to', 'resolved', 'source', 'complete_inventory')
      );
      perform pg_catalog.set_config('piervuln.source_transition_finding', new.id::text, true);
    elsif old.source_state = 'resolved' and new.source_state = 'active' then
      insert into public.finding_events (
        case_id, finding_id, tenant_id, event_type, details
      ) values (
        new.id, new.id, new.tenant_id, 'reopened',
        jsonb_build_object('from', 'resolved', 'to', 'active', 'source', 'complete_inventory')
      );
      perform pg_catalog.set_config('piervuln.source_transition_finding', new.id::text, true);
    end if;
  end if;
  return new;
end;
$$;
revoke all on function private.audit_finding_source_state_change() from public, anon, authenticated, service_role;
create trigger wazuh_findings_audit_source_state_change
  after update of source_state on public.wazuh_findings
  for each row execute function private.audit_finding_source_state_change();

create or replace function private.touch_finding_after_case_workflow_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.wazuh_findings
  set updated_at = now()
  where id = new.finding_id;
  return new;
end;
$$;
revoke all on function private.touch_finding_after_case_workflow_change() from public, anon, authenticated, service_role;
create trigger vulnerability_cases_touch_finding_after_workflow_change
  after insert or update of workflow_status on public.vulnerability_cases
  for each row execute function private.touch_finding_after_case_workflow_change();

create index if not exists wazuh_findings_tenant_updated_idx
  on public.wazuh_findings (tenant_id, updated_at desc, id);

create or replace view public.vulnerability_case_records
with (security_invoker = true)
as
select
  f.id,
  f.id as finding_id,
  f.tenant_id,
  case when f.source_state = 'resolved' then 'resolved'::public.vulnerability_workflow_status
    else coalesce(c.workflow_status, 'open'::public.vulnerability_workflow_status) end as workflow_status,
  coalesce(c.created_at, f.created_at) as created_at,
  f.updated_at,
  case when f.source_state = 'resolved' then f.resolved_at else c.closed_at end as closed_at,
  c.assigned_to,
  f.agent_id as finding_agent_id,
  f.agent_name as finding_agent_name,
  f.agent_groups as finding_agent_groups,
  f.host_os as finding_host_os,
  f.package_name as finding_package_name,
  f.package_version as finding_package_version,
  f.vulnerability_id as finding_vulnerability_id,
  public.finding_description(f) as finding_description,
  f.severity as finding_severity,
  f.cvss_base as finding_cvss_base,
  public.finding_references(f) as finding_reference_urls,
  f.source_state as finding_source_state,
  f.first_detected_at as finding_first_detected_at,
  public.finding_last_seen(f) as finding_last_seen_at
from public.wazuh_findings f
left join public.vulnerability_cases c
  on c.finding_id = f.id and c.tenant_id = f.tenant_id
where f.tenant_id is not null;
revoke all on public.vulnerability_case_records from public, anon;
grant select on public.vulnerability_case_records to authenticated, service_role;

create or replace function public.set_vulnerability_case_status(
  p_company_id uuid,
  p_finding_id uuid,
  p_status text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_source_state public.vulnerability_source_state;
  v_changed integer;
begin
  if (select auth.uid()) is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;
  if p_status not in ('open', 'in_progress', 'awaiting_validation') then
    raise exception 'Invalid workflow status' using errcode = '22023';
  end if;
  if not coalesce(private.is_internal_admin() or private.has_company_role(
    p_company_id, array['owner', 'admin', 'analyst']
  ), false) then
    raise exception 'Company access required' using errcode = '42501';
  end if;

  select f.source_state into v_source_state
  from public.wazuh_findings f
  where f.id = p_finding_id and f.tenant_id = p_company_id
  for update;
  if not found then raise exception 'Finding not found' using errcode = 'P0002'; end if;
  if v_source_state <> 'active' then
    raise exception 'Resolved findings cannot be changed manually' using errcode = '22023';
  end if;

  if p_status = 'open' then
    update public.vulnerability_cases c
    set workflow_status = 'open', closed_at = null
    where c.finding_id = p_finding_id and c.tenant_id = p_company_id
      and c.workflow_status <> 'open';
    get diagnostics v_changed = row_count;
    delete from public.vulnerability_cases c
    where c.finding_id = p_finding_id and c.tenant_id = p_company_id
      and c.workflow_status = 'open' and c.assigned_to is null and c.closed_at is null;
    return v_changed > 0;
  end if;

  insert into public.vulnerability_cases (finding_id, tenant_id, workflow_status)
  values (p_finding_id, p_company_id, p_status::public.vulnerability_workflow_status)
  on conflict (finding_id, tenant_id) do update
    set workflow_status = excluded.workflow_status, closed_at = null
    where public.vulnerability_cases.workflow_status is distinct from excluded.workflow_status;
  get diagnostics v_changed = row_count;
  return v_changed > 0;
end;
$$;
revoke all on function public.set_vulnerability_case_status(uuid, uuid, text) from public, anon;
grant execute on function public.set_vulnerability_case_status(uuid, uuid, text) to authenticated;

create or replace function public.move_kanban_group(p_company_id uuid, p_cve text, p_status text)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  changed integer;
begin
  if (select auth.uid()) is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;
  if p_status not in ('open', 'in_progress', 'awaiting_validation') then
    raise exception 'Invalid workflow status' using errcode = '22023';
  end if;
  if not coalesce(private.is_internal_admin() or private.has_company_role(
    p_company_id, array['owner', 'admin', 'analyst']
  ), false) then
    raise exception 'Company access required' using errcode = '42501';
  end if;

  if p_status = 'open' then
    update public.vulnerability_cases c
    set workflow_status = 'open', closed_at = null
    from public.wazuh_findings f
    where c.finding_id = f.id and c.tenant_id = p_company_id and f.tenant_id = p_company_id
      and upper(f.vulnerability_id) = upper(p_cve) and f.source_state = 'active'
      and c.workflow_status <> 'open';
    get diagnostics changed = row_count;
    delete from public.vulnerability_cases c
    using public.wazuh_findings f
    where c.finding_id = f.id and c.tenant_id = p_company_id and f.tenant_id = p_company_id
      and upper(f.vulnerability_id) = upper(p_cve) and f.source_state = 'active'
      and c.workflow_status = 'open' and c.assigned_to is null and c.closed_at is null;
    return changed;
  end if;

  insert into public.vulnerability_cases (finding_id, tenant_id, workflow_status)
  select f.id, f.tenant_id, p_status::public.vulnerability_workflow_status
  from public.wazuh_findings f
  where f.tenant_id = p_company_id and upper(f.vulnerability_id) = upper(p_cve)
    and f.source_state = 'active'
  on conflict (finding_id, tenant_id) do update
    set workflow_status = excluded.workflow_status, closed_at = null
    where public.vulnerability_cases.workflow_status is distinct from excluded.workflow_status;
  get diagnostics changed = row_count;
  return changed;
end;
$$;
revoke all on function public.move_kanban_group(uuid, text, text) from public, anon;
grant execute on function public.move_kanban_group(uuid, text, text) to authenticated;

create or replace function public.get_kanban_groups(p_company_id uuid default null, p_search text default '')
returns jsonb
language sql
stable
security invoker
set work_mem = '16MB'
set plan_cache_mode = 'force_custom_plan'
as $body$
  with scoped as materialized (
    select f.tenant_id, upper(f.vulnerability_id) as cve, f.cvss_base,
      coalesce(nullif(f.agent_id,''),nullif(f.agent_name,'')) as agent_key,
      f.agent_name, f.first_detected_at,
      f.source_state = 'active' and coalesce(c.workflow_status, 'open') <> 'resolved' as active,
      coalesce(c.workflow_status, 'open')::text as workflow
    from public.wazuh_findings f
    left join public.vulnerability_cases c on c.finding_id = f.id and c.tenant_id = f.tenant_id
    where f.tenant_id is not null and (p_company_id is null or f.tenant_id = p_company_id)
  ), grouped as (
    select s.tenant_id, s.cve, max(s.cvss_base) as cvss,
      count(*) as cases, count(distinct s.agent_key) as hosts,
      min(s.first_detected_at) as first_detected,
      bool_or(coalesce(a.is_critical,false)) as critical_asset,
      case when not bool_or(s.active) then 'resolved'
        when bool_or(s.active and s.workflow='awaiting_validation') then 'awaiting_validation'
        when bool_or(s.active and s.workflow='in_progress') then 'in_progress'
        else 'open' end as status
    from scoped s left join public.asset_classifications a on a.tenant_id=s.tenant_id and a.agent_key=s.agent_key
    group by s.tenant_id,s.cve
    having p_search='' or bool_or(s.cve ilike '%'||p_search||'%' or s.agent_name ilike '%'||p_search||'%')
  )
  select coalesce(jsonb_agg(jsonb_build_object('key',tenant_id||':'||cve,'tenantId',tenant_id,'cve',cve,
    'cvss',cvss,'severity',case when cvss>=9 then 'Critical' when cvss>=7 then 'High'
      when cvss>=4 then 'Medium' when cvss>=1 then 'Low' when cvss=0 then 'Informational' else 'Unknown' end,
    'hostCount',hosts,'caseCount',cases,'firstDetected',first_detected,'criticalAsset',critical_asset,'status',status)
    order by tenant_id,cve),'[]'::jsonb) from grouped;
$body$;
revoke all on function public.get_kanban_groups(uuid, text) from public, anon;
grant execute on function public.get_kanban_groups(uuid, text) to authenticated;

create or replace function public.ingest_wazuh_batch(
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
    select 1 from jsonb_array_elements(p_items) as item(value)
    where nullif(btrim(item.value ->> 'documentId'), '') is null
       or item.value ->> 'documentId' <> btrim(item.value ->> 'documentId')
       or length(btrim(item.value ->> 'documentId')) > 512
  ) then
    raise exception 'Indexer document is missing its stable _id' using errcode = '22023';
  end if;

  select * into v_run
  from public.sync_runs sr
  where sr.id = p_run_id and sr.connection_id = p_connection_id and sr.status = 'running'
  for update;
  if not found then raise exception 'Sync run is missing or already closed' using errcode = 'P0002'; end if;
  if not exists (
    select 1 from public.wazuh_connections wc where wc.id = p_connection_id and wc.is_active
  ) then
    raise exception 'Indexer connection is missing or inactive' using errcode = 'P0002';
  end if;

  insert into wazuh_internal.snapshot_pages (run_id, page_number, payload_sha256, document_count, items)
  values (p_run_id, p_page_number, p_payload_sha256, v_document_count, '[]'::jsonb)
  on conflict (run_id, page_number) do nothing;
  v_inserted := found;
  if not v_inserted then
    select * into v_page from wazuh_internal.snapshot_pages sp
    where sp.run_id = p_run_id and sp.page_number = p_page_number;
    if v_page.payload_sha256 is distinct from p_payload_sha256
       or v_page.document_count is distinct from v_document_count then
      raise exception 'A retry changed the content of an accepted page' using errcode = '22023';
    end if;
    return jsonb_build_object(
      'duplicate', true,
      'pagesReceived', v_run.pages_received,
      'documentsReceived', v_run.documents_received,
      'findingsChanged', 0
    );
  end if;

  insert into wazuh_internal.sync_run_document_ids (connection_id, document_id)
  select p_connection_id, item.value ->> 'documentId'
  from jsonb_array_elements(p_items) as item(value)
  on conflict (connection_id, document_id) do nothing;

  return wazuh_internal.apply_wazuh_batch(
    p_connection_id, p_run_id, p_page_number, p_payload_sha256, p_items
  );
end;
$$;
revoke all on function public.ingest_wazuh_batch(uuid, uuid, integer, text, jsonb) from public, anon, authenticated;
grant execute on function public.ingest_wazuh_batch(uuid, uuid, integer, text, jsonb) to service_role;

create or replace function public.complete_wazuh_sync(
  p_connection_id uuid,
  p_run_id uuid,
  p_expected_pages integer,
  p_expected_documents bigint,
  p_indexer_version text default 'unknown'
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_run public.sync_runs%rowtype;
  v_staged_pages integer;
  v_staged_documents bigint;
  v_min_page integer;
  v_max_page integer;
  v_applied_pages integer;
  v_distinct_documents bigint;
  v_result jsonb;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;
  select * into v_run from public.sync_runs sr
  where sr.id = p_run_id and sr.connection_id = p_connection_id for update;
  if not found then raise exception 'Execução não encontrada'; end if;
  if v_run.status = 'succeeded' then
    return jsonb_build_object('completed', true, 'findingsChanged', v_run.findings_changed);
  end if;
  if v_run.status <> 'running' then
    return jsonb_build_object('completed', false, 'pending', false);
  end if;
  if p_expected_pages is null or p_expected_documents is null
     or p_expected_pages < 1 or p_expected_documents < 0 then
    raise exception 'Contadores inválidos';
  end if;

  select count(*)::integer, coalesce(sum(sp.document_count), 0)::bigint,
         min(sp.page_number), max(sp.page_number)
  into v_staged_pages, v_staged_documents, v_min_page, v_max_page
  from wazuh_internal.snapshot_pages sp where sp.run_id = p_run_id;
  select count(*)::integer into v_applied_pages
  from public.sync_run_pages srp where srp.run_id = p_run_id;
  select count(*)::bigint into v_distinct_documents
  from wazuh_internal.sync_run_document_ids docs where docs.connection_id = p_connection_id;

  if p_expected_pages < 1 or v_staged_pages <> p_expected_pages
     or v_staged_documents <> p_expected_documents
     or v_min_page <> 0 or v_max_page <> p_expected_pages - 1
     or v_applied_pages <> p_expected_pages
     or v_run.pages_received <> p_expected_pages
     or v_run.documents_received <> p_expected_documents
     or v_distinct_documents <> p_expected_documents
     or exists (
       select 1 from wazuh_internal.snapshot_pages sp
       left join public.sync_run_pages srp on srp.run_id = sp.run_id and srp.page_number = sp.page_number
       where sp.run_id = p_run_id
         and (srp.run_id is null or srp.payload_sha256 is distinct from sp.payload_sha256
           or srp.document_count is distinct from sp.document_count)
     ) then
    update public.sync_runs
    set status = 'partial', expected_pages = p_expected_pages,
        expected_documents = p_expected_documents, finished_at = now(), full_snapshot = false,
        error_summary = case when v_distinct_documents <> p_expected_documents
          then 'O snapshot contém documentos duplicados.'
          else 'A sequência de páginas ou o total recebido não corresponde ao snapshot completo.' end
    where id = p_run_id;
    return jsonb_build_object('completed', false, 'status', 'partial',
      'pagesReceived', v_run.pages_received, 'documentsReceived', v_run.documents_received);
  end if;

  perform pg_catalog.set_config('piervuln.presence_run', p_run_id::text, true);
  perform pg_catalog.set_config('piervuln.presence_connection', p_connection_id::text, true);
  drop view if exists pg_temp.snapshot_presence;
  execute $view$
    create temporary view snapshot_presence as
    select docs.document_id
    from wazuh_internal.sync_run_document_ids docs
    where docs.connection_id = pg_catalog.current_setting('piervuln.presence_connection')::uuid
  $view$;

  v_result := wazuh_internal.apply_complete_wazuh_sync(
    p_connection_id, p_run_id, p_expected_pages, p_expected_documents, p_indexer_version
  );
  if coalesce((v_result ->> 'completed')::boolean, false) is not true then
    drop view if exists pg_temp.snapshot_presence;
    return v_result;
  end if;
  drop view if exists pg_temp.snapshot_presence;

  update public.wazuh_connections set published_sync_run_id = p_run_id where id = p_connection_id;
  select * into v_run from public.sync_runs where id = p_run_id;
  return v_result || jsonb_build_object('findingsChanged', v_run.findings_changed);
end;
$$;
revoke all on function public.complete_wazuh_sync(uuid, uuid, integer, bigint, text) from public, anon, authenticated;
grant execute on function public.complete_wazuh_sync(uuid, uuid, integer, bigint, text) to service_role;

notify pgrst, 'reload schema';
commit;
