set local lock_timeout = '5s';
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
  v_content_changed boolean;
  v_unchanged_ids uuid[] := '{}'::uuid[];
  v_unchanged_case_ids uuid[] := '{}'::uuid[];
  v_unchanged_tenants uuid[] := '{}'::uuid[];
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
          and (
            (wam.match_type = 'group'
              and wam.match_value = any(array(
                select jsonb_array_elements_text(v_groups)
              )))
            or (wam.match_type = 'agent_name_prefix'
              and v_agent_name is not null
              and wam.match_value ~ '^[A-Za-z0-9._-]+\*$'
              and left(lower(v_agent_name), char_length(wam.match_value) - 1)
                = lower(left(wam.match_value, char_length(wam.match_value) - 1)))
          );
        v_tenant_id := case when v_group_tenant_count = 1 then v_group_tenant_id else null end;
      end if;
    end if;

    if v_connection.mode = 'shared' and v_tenant_id is not null
       and exists (
         select 1 from public.wazuh_agent_mappings wam
         where wam.connection_id = v_connection.id
           and wam.tenant_id = v_tenant_id
           and wam.is_active
           and wam.match_type = 'agent_name_prefix'
       )
       and not exists (
         select 1 from public.wazuh_agent_mappings wam
         where wam.connection_id = v_connection.id
           and wam.tenant_id = v_tenant_id
           and wam.is_active
           and wam.match_type = 'agent_name_prefix'
           and v_agent_name is not null
           and wam.match_value ~ '^[A-Za-z0-9._-]+\*$'
           and left(lower(v_agent_name), char_length(wam.match_value) - 1)
             = lower(left(wam.match_value, char_length(wam.match_value) - 1))
       ) then
      v_tenant_id := null;
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

    v_content_changed := not v_had_old
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
       );
    if not v_content_changed then
      v_unchanged_ids := array_append(v_unchanged_ids, v_old.id);
      if v_tenant_id is not null then
        v_unchanged_case_ids := array_append(v_unchanged_case_ids, v_old.id);
        v_unchanged_tenants := array_append(v_unchanged_tenants, v_tenant_id);
      end if;
      continue;
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

    v_changed := v_changed + 1;

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

  -- Keep presence markers for complete_wazuh_sync without rewriting unchanged payloads.
  update public.wazuh_findings
  set last_seen_at = now(), last_seen_sync_run_id = p_run_id
  where id = any(v_unchanged_ids);

  with inserted_cases as (
    insert into public.vulnerability_cases (finding_id, tenant_id)
    select finding_id, tenant_id
    from unnest(v_unchanged_case_ids, v_unchanged_tenants) as present(finding_id, tenant_id)
    on conflict (finding_id, tenant_id) do nothing
    returning id, finding_id, tenant_id
  )
  insert into public.finding_events (case_id, finding_id, tenant_id, event_type, details)
  select id, finding_id, tenant_id, 'first_detected', '{}'::jsonb
  from inserted_cases;


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
