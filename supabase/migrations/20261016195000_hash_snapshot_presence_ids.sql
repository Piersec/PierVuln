begin;

truncate table wazuh_internal.sync_run_document_ids;
alter table wazuh_internal.sync_run_document_ids
  drop constraint sync_run_document_ids_pkey;
alter table wazuh_internal.sync_run_document_ids
  drop column document_id;
alter table wazuh_internal.sync_run_document_ids
  add column document_hash bytea not null;
alter table wazuh_internal.sync_run_document_ids
  add constraint sync_run_document_ids_hash_length
  check (octet_length(document_hash) = 32);
alter table wazuh_internal.sync_run_document_ids
  add primary key (connection_id, document_hash);

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

  insert into wazuh_internal.sync_run_document_ids (connection_id, document_hash)
  select p_connection_id, pg_catalog.sha256(pg_catalog.convert_to(item.value ->> 'documentId', 'UTF8'))
  from jsonb_array_elements(p_items) as item(value)
  on conflict (connection_id, document_hash) do nothing;

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
    select f.source_document_id as document_id
    from public.wazuh_findings f
    join wazuh_internal.sync_run_document_ids docs
      on docs.connection_id = f.connection_id
     and docs.document_hash = pg_catalog.sha256(pg_catalog.convert_to(f.source_document_id, 'UTF8'))
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
