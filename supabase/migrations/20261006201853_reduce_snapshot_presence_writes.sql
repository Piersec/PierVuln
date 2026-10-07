set local lock_timeout = '3s';


create function private.store_finding_content()
returns trigger language plpgsql security definer set search_path = ''
as $body$
declare v_hash bytea; v_content public.finding_content;
begin
  -- ON CONFLICT runs this trigger again with the already-normalized excluded row.
  if new.content_id is not null and new.description is null and cardinality(new.reference_urls) = 0 then
    perform 1 from public.finding_content where id = new.content_id;
    if not found then raise exception 'Finding content is missing'; end if;
    return new;
  end if;
  v_hash := extensions.digest(convert_to(jsonb_build_array(new.description, to_jsonb(new.reference_urls))::text, 'UTF8'), 'sha256');
  select * into v_content from public.finding_content where content_hash = v_hash;
  if not found then
    insert into public.finding_content(content_hash, description, reference_urls)
    values(v_hash, new.description, new.reference_urls)
    on conflict(content_hash) do nothing;
    select * into strict v_content from public.finding_content where content_hash = v_hash;
  end if;
  if row(v_content.description, v_content.reference_urls) is distinct from row(new.description, new.reference_urls) then
    raise exception 'Content hash collision; original data was preserved';
  end if;
  new.content_id := v_content.id;
  new.description := null;
  new.reference_urls := '{}'::text[];
  return new;
end;
$body$;
revoke all on function private.store_finding_content() from public, anon, authenticated, service_role;

create trigger finding_content_store before insert or update of description, reference_urls
on public.wazuh_findings for each row execute function private.store_finding_content();

CREATE OR REPLACE FUNCTION wazuh_internal.apply_wazuh_batch(p_connection_id uuid, p_run_id uuid, p_page_number integer, p_payload_sha256 text, p_items jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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

      if v_group_tenant_count = 1 then
        v_tenant_id := v_group_tenant_id;
      elsif v_group_tenant_count > 1 then
        v_tenant_id := null;
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
        v_tenant_id := case when v_agent_tenant_count = 1 then v_agent_tenant_id else null end;
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
    if v_had_old and v_old.content_id is not null then
      select c.description, c.reference_urls into v_old.description, v_old.reference_urls
      from public.finding_content c where c.id = v_old.content_id;
      if not found then raise exception 'Finding content is missing'; end if;
    end if;

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
      content_id = excluded.content_id,
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

  -- Presence is checked against the complete staged document set at publication.

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
$function$;

CREATE OR REPLACE FUNCTION wazuh_internal.apply_complete_wazuh_sync(p_connection_id uuid, p_run_id uuid, p_expected_pages integer, p_expected_documents bigint, p_indexer_version text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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

  if current_setting('piervuln.presence_run', true) is distinct from p_run_id::text
     or to_regclass('pg_temp.snapshot_presence') is null then
    raise exception 'Complete snapshot presence set is required';
  end if;

  update public.wazuh_findings f
  set source_state = 'resolved', resolved_at = now(),
      last_seen_at = public.finding_last_seen(f)
  where f.connection_id = v_run.connection_id
    and f.source_state = 'active'
    and not exists (select 1 from pg_temp.snapshot_presence present where present.document_id = f.source_document_id);
  get diagnostics v_resolved = row_count;

  update public.vulnerability_cases vc
  set workflow_status = 'resolved', closed_at = now()
  where vc.workflow_status <> 'resolved'
    and exists (
      select 1 from public.wazuh_findings f
      where f.id = vc.finding_id
        and f.connection_id = v_run.connection_id
        and f.source_state = 'resolved'
        and not exists (select 1 from pg_temp.snapshot_presence present where present.document_id = f.source_document_id)
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
$function$;

CREATE OR REPLACE FUNCTION wazuh_internal.publish_wazuh_snapshot(p_connection_id uuid, p_run_id uuid, p_expected_pages integer, p_expected_documents bigint, p_indexer_version text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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

  create temporary table snapshot_presence (document_id text primary key) on commit drop;
  insert into pg_temp.snapshot_presence (document_id)
  select item.value ->> 'documentId'
  from wazuh_internal.snapshot_pages sp
  cross join lateral jsonb_array_elements(sp.items) as item(value)
  where sp.run_id = p_run_id;
  analyze pg_temp.snapshot_presence;
  perform set_config('piervuln.presence_run', p_run_id::text, true);

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
$function$;

revoke all on function wazuh_internal.apply_wazuh_batch(uuid,uuid,integer,text,jsonb),
  wazuh_internal.apply_complete_wazuh_sync(uuid,uuid,integer,bigint,text),
  wazuh_internal.publish_wazuh_snapshot(uuid,uuid,integer,bigint,text)
  from public,anon,authenticated,service_role;
notify pgrst, 'reload schema';

