-- A connection can have only one active full snapshot. A crashed run is
-- retired as partial when its replacement starts after two hours.
create unique index sync_one_running_per_connection
  on public.sync_runs(connection_id) where status = 'running';

create or replace function public.create_wazuh_connection(
  p_tenant_id uuid,
  p_name text,
  p_mode public.connection_mode,
  p_endpoint_url text,
  p_index_pattern text,
  p_token_sha256 text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_connection_id uuid;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;
  if (p_mode = 'dedicated' and p_tenant_id is null)
     or (p_mode = 'shared' and p_tenant_id is not null) then
    raise exception 'Tenant assignment does not match connection mode' using errcode = '22023';
  end if;
  if p_token_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception 'Invalid ingest token digest' using errcode = '22023';
  end if;

  insert into public.wazuh_connections (
    tenant_id, name, mode, endpoint_url, index_pattern
  ) values (
    p_tenant_id, p_name, p_mode, p_endpoint_url, p_index_pattern
  ) returning id into v_connection_id;

  insert into public.wazuh_ingest_credentials (connection_id, token_sha256)
  values (v_connection_id, p_token_sha256);

  return v_connection_id;
end;
$$;

create or replace function public.register_wazuh_sync(
  p_connection_id uuid,
  p_indexer_version text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_run_id uuid;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
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

  insert into public.sync_runs (connection_id, indexer_version)
  values (p_connection_id, left(p_indexer_version, 160))
  returning id into v_run_id;

  return v_run_id;
end;
$$;

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
  v_connection public.wazuh_connections%rowtype;
  v_item jsonb;
  v_groups jsonb;
  v_refs jsonb;
  v_document_id text;
  v_agent_id text;
  v_agent_name text;
  v_tenant_id uuid;
  v_agent_tenant_id uuid;
  v_group_tenant_id uuid;
  v_agent_tenant_count integer;
  v_group_tenant_count integer;
  v_finding_id uuid;
  v_case_id uuid;
  v_old public.wazuh_findings%rowtype;
  v_had_old boolean;
  v_case_inserted boolean;
  v_page_inserted boolean;
  v_document_count integer;
  v_page_hash text;
  v_changed integer := 0;
  v_severity text;
  v_score numeric;
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

  select * into v_run
  from public.sync_runs sr
  where sr.id = p_run_id
    and sr.connection_id = p_connection_id
    and sr.status = 'running'
  for update;
  if not found then
    raise exception 'Sync run is missing or already closed' using errcode = 'P0002';
  end if;
  select * into v_connection
  from public.wazuh_connections wc
  where wc.id = v_run.connection_id and wc.is_active;
  if not found then
    raise exception 'Wazuh connection is missing or inactive' using errcode = 'P0002';
  end if;

  insert into public.sync_run_pages (run_id, page_number, payload_sha256, document_count)
  values (p_run_id, p_page_number, p_payload_sha256, v_document_count)
  on conflict (run_id, page_number) do nothing;
  v_page_inserted := found;
  if not v_page_inserted then
    select srp.payload_sha256 into v_page_hash
    from public.sync_run_pages srp
    where srp.run_id = p_run_id and srp.page_number = p_page_number;
    if v_page_hash is distinct from p_payload_sha256 then
      raise exception 'A retry changed the content of an accepted page' using errcode = '22023';
    end if;
    return jsonb_build_object(
      'duplicate', true,
      'pagesReceived', v_run.pages_received,
      'documentsReceived', v_run.documents_received
    );
  end if;

  for v_item in select value from jsonb_array_elements(p_items)
  loop
    v_document_id := nullif(btrim(v_item ->> 'documentId'), '');
    v_agent_id := nullif(btrim(v_item ->> 'agentId'), '');
    v_agent_name := nullif(btrim(v_item ->> 'agentName'), '');
    if v_document_id is null then
      raise exception 'Indexer document is missing its stable _id' using errcode = '22023';
    end if;

    v_groups := case
      when jsonb_typeof(v_item -> 'agentGroups') = 'array' then v_item -> 'agentGroups'
      else '[]'::jsonb
    end;
    v_refs := case
      when jsonb_typeof(v_item -> 'references') = 'array' then v_item -> 'references'
      else '[]'::jsonb
    end;

    if v_connection.mode = 'dedicated' then
      v_tenant_id := v_connection.tenant_id;
    else
      select count(distinct wam.tenant_id)::integer,
             (array_agg(distinct wam.tenant_id))[1]
        into v_agent_tenant_count, v_agent_tenant_id
      from public.wazuh_agent_mappings wam
      join public.companies c on c.id = wam.tenant_id and c.is_active
      where wam.connection_id = v_connection.id
        and wam.is_active
        and wam.match_type = 'agent_id'
        and wam.match_value = coalesce(v_agent_id, '');

      if v_agent_tenant_count = 1 then
        v_tenant_id := v_agent_tenant_id;
      elsif v_agent_tenant_count > 1 then
        v_tenant_id := null;
      else
        select count(distinct wam.tenant_id)::integer,
               (array_agg(distinct wam.tenant_id))[1]
          into v_group_tenant_count, v_group_tenant_id
        from public.wazuh_agent_mappings wam
        join public.companies c on c.id = wam.tenant_id and c.is_active
        where wam.connection_id = v_connection.id
          and wam.is_active
          and wam.match_type = 'group'
          and wam.match_value = any(array(
            select jsonb_array_elements_text(v_groups)
          ));
        v_tenant_id := case when v_group_tenant_count = 1 then v_group_tenant_id else null end;
      end if;
    end if;

    select f.* into v_old
    from public.wazuh_findings f
    where f.connection_id = v_connection.id
      and f.source_document_id = v_document_id;
    v_had_old := found;

    v_severity := case lower(coalesce(v_item ->> 'severity', ''))
      when 'critical' then 'Critical'
      when 'high' then 'High'
      when 'medium' then 'Medium'
      when 'moderate' then 'Medium'
      when 'low' then 'Low'
      when 'informational' then 'Informational'
      when 'info' then 'Informational'
      else 'Unknown'
    end;
    v_score := nullif(v_item ->> 'cvssBase', '')::numeric;
    if v_score is not null and (v_score < 0 or v_score > 10) then
      v_score := null;
    end if;

    insert into public.wazuh_findings (
      connection_id, source_document_id, tenant_id, agent_id, agent_name,
      agent_groups, host_os, package_name, package_version, package_type,
      package_architecture, vulnerability_id, description, severity, cvss_base,
      reference_urls, source_status, source_state, first_detected_at,
      last_seen_at, resolved_at, last_seen_sync_run_id
    ) values (
      v_connection.id,
      v_document_id,
      v_tenant_id,
      v_agent_id,
      v_agent_name,
      array(select jsonb_array_elements_text(v_groups)),
      nullif(v_item ->> 'hostOs', ''),
      nullif(v_item ->> 'packageName', ''),
      nullif(v_item ->> 'packageVersion', ''),
      nullif(v_item ->> 'packageType', ''),
      nullif(v_item ->> 'packageArchitecture', ''),
      coalesce(nullif(btrim(v_item ->> 'vulnerabilityId'), ''), 'UNKNOWN'),
      nullif(v_item ->> 'description', ''),
      v_severity,
      v_score,
      array(select jsonb_array_elements_text(v_refs)),
      nullif(v_item ->> 'sourceStatus', ''),
      'active',
      now(),
      now(),
      null,
      p_run_id
    )
    on conflict (connection_id, source_document_id) do update set
      tenant_id = excluded.tenant_id,
      agent_id = excluded.agent_id,
      agent_name = excluded.agent_name,
      agent_groups = excluded.agent_groups,
      host_os = excluded.host_os,
      package_name = excluded.package_name,
      package_version = excluded.package_version,
      package_type = excluded.package_type,
      package_architecture = excluded.package_architecture,
      vulnerability_id = excluded.vulnerability_id,
      description = excluded.description,
      severity = excluded.severity,
      cvss_base = excluded.cvss_base,
      reference_urls = excluded.reference_urls,
      source_status = excluded.source_status,
      source_state = 'active',
      last_seen_at = now(),
      resolved_at = null,
      last_seen_sync_run_id = p_run_id
    returning id into v_finding_id;

    if not v_had_old
       or v_old.source_state = 'resolved'
       or v_old.tenant_id is distinct from v_tenant_id
       or row(
         v_old.agent_id, v_old.agent_name, v_old.agent_groups, v_old.host_os,
         v_old.package_name, v_old.package_version, v_old.package_type,
         v_old.package_architecture, v_old.vulnerability_id, v_old.description,
         v_old.severity, v_old.cvss_base, v_old.reference_urls, v_old.source_status
       ) is distinct from row(
         v_agent_id, v_agent_name,
         array(select jsonb_array_elements_text(v_groups)),
         nullif(v_item ->> 'hostOs', ''), nullif(v_item ->> 'packageName', ''),
         nullif(v_item ->> 'packageVersion', ''), nullif(v_item ->> 'packageType', ''),
         nullif(v_item ->> 'packageArchitecture', ''),
         coalesce(nullif(btrim(v_item ->> 'vulnerabilityId'), ''), 'UNKNOWN'),
         nullif(v_item ->> 'description', ''), v_severity, v_score,
         array(select jsonb_array_elements_text(v_refs)), nullif(v_item ->> 'sourceStatus', '')
       ) then
      v_changed := v_changed + 1;
    end if;

    if v_tenant_id is not null then
      insert into public.vulnerability_cases (finding_id, tenant_id)
      values (v_finding_id, v_tenant_id)
      on conflict (finding_id, tenant_id) do nothing
      returning id into v_case_id;
      v_case_inserted := found;

      if v_case_inserted then
        insert into public.finding_events (
          case_id, finding_id, tenant_id, event_type, details
        ) values (
          v_case_id,
          v_finding_id,
          v_tenant_id,
          case when v_had_old and v_old.tenant_id is distinct from v_tenant_id
            then 'tenant_mapping_changed' else 'first_detected' end,
          '{}'::jsonb
        );
      elsif v_had_old and v_old.source_state = 'resolved' then
        update public.vulnerability_cases vc
        set workflow_status = 'open', closed_at = null
        where vc.finding_id = v_finding_id
          and vc.tenant_id = v_tenant_id
          and vc.workflow_status = 'resolved';
      end if;
    end if;
  end loop;

  update public.sync_runs sr
  set pages_received = pages_received + 1,
      documents_received = documents_received + v_document_count,
      findings_changed = findings_changed + v_changed
  where sr.id = p_run_id;

  return jsonb_build_object(
    'duplicate', false,
    'pagesReceived', v_run.pages_received + 1,
    'documentsReceived', v_run.documents_received + v_document_count,
    'findingsChanged', v_changed
  );
end;
$$;

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
  v_resolved integer := 0;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
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

  if p_expected_pages < 1 or p_expected_documents < 0
     or v_run.pages_received <> p_expected_pages
     or v_run.documents_received <> p_expected_documents then
    update public.sync_runs
    set status = 'partial',
        expected_pages = p_expected_pages,
        expected_documents = p_expected_documents,
        finished_at = now(),
        full_snapshot = false,
        error_summary = 'A paginação recebida não corresponde à leitura completa do Indexer.'
    where id = p_run_id;
    return jsonb_build_object(
      'completed', false,
      'status', 'partial',
      'pagesReceived', v_run.pages_received,
      'documentsReceived', v_run.documents_received
    );
  end if;

  if (select count(*) from public.sync_run_pages srp where srp.run_id = p_run_id)
        <> p_expected_pages
     or (select min(srp.page_number) from public.sync_run_pages srp where srp.run_id = p_run_id)
        <> 0
     or (select max(srp.page_number) from public.sync_run_pages srp where srp.run_id = p_run_id)
        <> p_expected_pages - 1 then
    update public.sync_runs
    set status = 'partial',
        expected_pages = p_expected_pages,
        expected_documents = p_expected_documents,
        finished_at = now(),
        full_snapshot = false,
        error_summary = 'A sequência de páginas do Indexer está incompleta.'
    where id = p_run_id;
    return jsonb_build_object('completed', false, 'status', 'partial');
  end if;

  update public.wazuh_findings f
  set source_state = 'resolved', resolved_at = now()
  where f.connection_id = v_run.connection_id
    and f.source_state = 'active'
    and f.last_seen_sync_run_id is distinct from p_run_id;
  get diagnostics v_resolved = row_count;

  update public.vulnerability_cases vc
  set workflow_status = 'resolved', closed_at = now()
  where vc.workflow_status <> 'resolved'
    and exists (
      select 1 from public.wazuh_findings f
      where f.id = vc.finding_id
        and f.connection_id = v_run.connection_id
        and f.source_state = 'resolved'
        and f.last_seen_sync_run_id is distinct from p_run_id
    );

  update public.sync_runs
  set status = 'succeeded',
      expected_pages = p_expected_pages,
      expected_documents = p_expected_documents,
      finished_at = now(),
      full_snapshot = true,
      findings_changed = findings_changed + v_resolved,
      error_summary = null
  where id = p_run_id;

  update public.wazuh_connections
  set last_connected_at = now(),
      connector_version = left(p_indexer_version, 160)
  where id = v_run.connection_id;

  return jsonb_build_object(
    'completed', true,
    'status', 'succeeded',
    'resolvedFindings', v_resolved
  );
end;
$$;

create or replace function public.fail_wazuh_sync(
  p_connection_id uuid,
  p_run_id uuid,
  p_error_summary text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_updated integer;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;

  update public.sync_runs
  set status = case when pages_received > 0 then 'partial'::public.sync_run_status
                    else 'failed'::public.sync_run_status end,
      finished_at = now(),
      full_snapshot = false,
      error_summary = left(coalesce(p_error_summary, 'Sync failed'), 2000)
  where id = p_run_id
    and connection_id = p_connection_id
    and status = 'running';
  get diagnostics v_updated = row_count;
  return v_updated = 1;
end;
$$;

revoke all on function public.create_wazuh_connection(uuid, text, public.connection_mode, text, text, text)
  from public, anon, authenticated;
revoke all on function public.register_wazuh_sync(uuid, text)
  from public, anon, authenticated;
revoke all on function public.ingest_wazuh_batch(uuid, uuid, integer, text, jsonb)
  from public, anon, authenticated;
revoke all on function public.complete_wazuh_sync(uuid, uuid, integer, bigint, text)
  from public, anon, authenticated;
revoke all on function public.fail_wazuh_sync(uuid, uuid, text)
  from public, anon, authenticated;
grant execute on function public.create_wazuh_connection(uuid, text, public.connection_mode, text, text, text)
  to service_role;
grant execute on function public.register_wazuh_sync(uuid, text) to service_role;
grant execute on function public.ingest_wazuh_batch(uuid, uuid, integer, text, jsonb) to service_role;
grant execute on function public.complete_wazuh_sync(uuid, uuid, integer, bigint, text) to service_role;
grant execute on function public.fail_wazuh_sync(uuid, uuid, text) to service_role;
