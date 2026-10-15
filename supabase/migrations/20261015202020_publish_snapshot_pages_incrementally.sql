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

  return wazuh_internal.apply_wazuh_batch(
    p_connection_id, p_run_id, p_page_number, p_payload_sha256, p_items
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
  p_indexer_version text default 'unknown'
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $body$
declare
  v_run public.sync_runs%rowtype;
  v_queue wazuh_internal.publication_queue%rowtype;
  v_result jsonb;
  v_staged_pages integer;
  v_staged_documents bigint;
  v_min_page integer;
  v_max_page integer;
  v_applied_pages integer;
  v_distinct_documents bigint;
  v_invalid_document boolean;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;
  select * into v_run
  from public.sync_runs sr
  where sr.id = p_run_id and sr.connection_id = p_connection_id
  for update;
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
  from wazuh_internal.snapshot_pages sp
  where sp.run_id = p_run_id;
  if v_staged_pages <> p_expected_pages
     or v_staged_documents <> p_expected_documents
     or v_min_page <> 0 or v_max_page <> p_expected_pages - 1 then
    raise exception 'O snapshot ainda não recebeu todas as páginas';
  end if;

  select count(*)::integer into v_applied_pages
  from public.sync_run_pages srp
  where srp.run_id = p_run_id;

  if v_applied_pages > 0 then
    if v_applied_pages <> p_expected_pages
       or v_run.pages_received <> p_expected_pages
       or v_run.documents_received <> p_expected_documents
       or exists (
         select 1
         from wazuh_internal.snapshot_pages sp
         left join public.sync_run_pages srp
           on srp.run_id = sp.run_id and srp.page_number = sp.page_number
         where sp.run_id = p_run_id
           and (srp.run_id is null
             or srp.payload_sha256 is distinct from sp.payload_sha256
             or srp.document_count is distinct from sp.document_count)
       ) then
      raise exception 'As páginas publicadas não correspondem ao snapshot completo';
    end if;

    select count(distinct item.value ->> 'documentId')::bigint,
           coalesce(bool_or(nullif(btrim(item.value ->> 'documentId'), '') is null
             or item.value ->> 'documentId' <> btrim(item.value ->> 'documentId')
             or length(btrim(item.value ->> 'documentId')) > 512), false)
      into v_distinct_documents, v_invalid_document
    from wazuh_internal.snapshot_pages sp
    cross join lateral jsonb_array_elements(sp.items) as item(value)
    where sp.run_id = p_run_id;
    if v_invalid_document or v_distinct_documents <> p_expected_documents then
      raise exception 'O snapshot contém IDs de documentos duplicados ou inválidos';
    end if;

    create temporary table snapshot_presence (document_id text primary key) on commit drop;
    insert into pg_temp.snapshot_presence(document_id)
    select distinct item.value ->> 'documentId'
    from wazuh_internal.snapshot_pages sp
    cross join lateral jsonb_array_elements(sp.items) as item(value)
    where sp.run_id = p_run_id;
    perform set_config('piervuln.presence_run', p_run_id::text, true);

    v_result := wazuh_internal.apply_complete_wazuh_sync(
      p_connection_id, p_run_id, p_expected_pages, p_expected_documents, p_indexer_version
    );
    if coalesce((v_result ->> 'completed')::boolean, false) is not true then
      return v_result;
    end if;
    update public.wazuh_connections
    set published_sync_run_id = p_run_id
    where id = p_connection_id;
    select * into v_run from public.sync_runs where id = p_run_id;
    return v_result || jsonb_build_object('findingsChanged', v_run.findings_changed);
  end if;

  insert into wazuh_internal.publication_queue(
    run_id, connection_id, expected_pages, expected_documents, indexer_version
  )
  values (
    p_run_id, p_connection_id, p_expected_pages, p_expected_documents,
    left(coalesce(p_indexer_version, 'unknown'), 160)
  )
  on conflict (run_id) do nothing;
  select * into v_queue
  from wazuh_internal.publication_queue
  where run_id = p_run_id;
  if v_queue.connection_id <> p_connection_id
     or v_queue.expected_pages <> p_expected_pages
     or v_queue.expected_documents <> p_expected_documents then
    raise exception 'O pedido de publicação possui contadores diferentes';
  end if;
  return jsonb_build_object('completed', false, 'pending', v_queue.status = 'pending');
end;
$body$;

revoke all on function public.complete_wazuh_sync(uuid, uuid, integer, bigint, text)
  from public, anon, authenticated;
grant execute on function public.complete_wazuh_sync(uuid, uuid, integer, bigint, text)
  to service_role;
