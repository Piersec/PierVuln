set local lock_timeout = '3s';

alter table private.company_data_deletions
  add column storage_status text not null default 'not_required'
    check (storage_status in ('not_required', 'queued', 'running', 'succeeded', 'failed')),
  add column storage_tables_before jsonb,
  add column storage_job_id bigint,
  add column storage_run_after bigint,
  add column storage_attempts integer not null default 0,
  add column storage_tables_done integer not null default 0,
  add column storage_reclaimed_bytes bigint not null default 0,
  add column storage_error text;

create unique index company_storage_reclamation_one_running
  on private.company_data_deletions ((true)) where storage_status = 'running';

create function private.queue_company_storage_reclamation(p_deletion_id uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform pg_advisory_xact_lock(hashtextextended('company_storage_reclamation', 0));
  update private.company_data_deletions set storage_status = 'queued', storage_error = null
  where id = p_deletion_id and status = 'succeeded' and findings_deleted > 0
    and storage_status = 'not_required';
  if found then
    perform cron.alter_job(jobid, active := true) from cron.job
    where jobname = 'piervuln-storage-reclamation-controller';
  end if;
end;$$;
revoke all on function private.queue_company_storage_reclamation(uuid) from public, anon, authenticated, service_role;

create function private.process_company_storage_reclamation()
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  j private.company_data_deletions%rowtype;
  r cron.job_run_details%rowtype;
  v_before jsonb;
  v_command text;
  v_job_id bigint;
  v_run_after bigint;
  v_done integer;
  v_reclaimed bigint;
begin
  if not pg_try_advisory_xact_lock(hashtextextended('company_storage_reclamation', 0)) then return null; end if;
  select * into j from private.company_data_deletions where storage_status in ('queued', 'running')
    order by (storage_status = 'running') desc, created_at, id limit 1 for update skip locked;
  if not found then
    if not exists(select 1 from private.company_data_deletions where storage_status in ('queued', 'running')) then
      perform cron.alter_job(jobid, active := false) from cron.job
      where jobname in ('piervuln-storage-reclamation-controller', 'piervuln-storage-reclamation-execute');
    end if;
    return null;
  end if;

  if j.storage_status = 'queued' then
    if exists(select 1 from private.company_data_deletions where status in ('queued', 'running')) then return j.id; end if;
    v_before := j.storage_tables_before;
    if v_before is null then
      select jsonb_agg(jsonb_build_object('name', c.relname, 'node', c.relfilenode,
        'bytes', pg_total_relation_size(c.oid)) order by c.relname) into v_before
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relname in
        ('wazuh_findings', 'vulnerability_cases', 'finding_events', 'vulnerability_comments');
    end if;
    select 'VACUUM (FULL, ANALYZE, SKIP_LOCKED) ' || string_agg(format('public.%I', c.relname), ', ' order by c.relname) || ';'
      into v_command
    from jsonb_array_elements(v_before) b join pg_class c on c.relname = b->>'name'
      join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relfilenode = (b->>'node')::oid
      and c.relname in ('wazuh_findings', 'vulnerability_cases', 'finding_events', 'vulnerability_comments');
    if v_command is null then
      update private.company_data_deletions set storage_status = 'succeeded', storage_tables_done = 4 where id = j.id;
      perform private.refresh_company_storage_snapshot();
      return j.id;
    end if;
    -- VACUUM must run as a standalone command, outside this function's transaction.
    v_job_id := cron.schedule('piervuln-storage-reclamation-execute', '* * * * *', v_command);
    select coalesce(max(runid), 0) into v_run_after from cron.job_run_details where jobid = v_job_id;
    update private.company_data_deletions set storage_status = 'running', storage_tables_before = v_before,
      storage_job_id = v_job_id, storage_run_after = v_run_after, storage_attempts = storage_attempts + 1
    where id = j.id;
    return j.id;
  end if;

  select * into r from cron.job_run_details where jobid = j.storage_job_id and runid > j.storage_run_after
    order by runid desc limit 1;
  if not found then return j.id; end if;
  -- Disable the schedule when the first execution starts; its current execution continues.
  perform cron.alter_job(j.storage_job_id, active := false);
  select count(*) filter (where c.relfilenode <> (b->>'node')::oid),
    coalesce(sum(greatest((b->>'bytes')::bigint - pg_total_relation_size(c.oid), 0)), 0)
  into v_done, v_reclaimed
  from jsonb_array_elements(j.storage_tables_before) b join pg_class c on c.relname = b->>'name'
    join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public';
  update private.company_data_deletions set storage_tables_done = v_done, storage_reclaimed_bytes = v_reclaimed where id = j.id;
  if r.status in ('starting', 'connecting', 'sending', 'running') then return j.id; end if;

  if r.status = 'succeeded' and v_done = 4 then
    update private.company_data_deletions set storage_status = 'succeeded', storage_error = null where id = j.id;
    perform private.refresh_company_storage_snapshot();
  elsif r.status = 'succeeded' and j.storage_attempts < 3 then
    -- An unchanged file identifier means SKIP_LOCKED skipped that table, not that it was compacted.
    update private.company_data_deletions set storage_status = 'queued' where id = j.id;
  else
    update private.company_data_deletions set storage_status = 'failed',
      storage_error = 'Os dados foram apagados, mas a compactação não concluiu. O espaço liberado continua disponível para reutilização.'
    where id = j.id;
  end if;
  return j.id;
exception when others then
  if j.id is null then raise; end if;
  if j.storage_job_id is not null then perform cron.alter_job(j.storage_job_id, active := false); end if;
  update private.company_data_deletions set storage_status = 'failed',
    storage_error = 'Os dados foram apagados, mas houve uma falha na compactação. Solicite uma revisão da manutenção.' where id = j.id;
  return j.id;
end;$$;
revoke all on function private.process_company_storage_reclamation() from public, anon, authenticated, service_role;

select cron.schedule('piervuln-storage-reclamation-controller', '10 seconds',
  $job$set statement_timeout = '45s'; set lock_timeout = '1s'; select private.process_company_storage_reclamation();$job$);
select cron.alter_job(jobid, active := false) from cron.job where jobname = 'piervuln-storage-reclamation-controller';

do $patch$
declare definition text; anchor text := '   update private.company_data_deletions set status=''succeeded'',updated_at=now(),error_message=null where id=j.id;';
begin
  select pg_get_functiondef('private.process_company_data_deletion()'::regprocedure) into definition;
  if position(anchor in definition) = 0 then raise exception 'Deletion worker definition changed'; end if;
  execute replace(definition, anchor, anchor || E'\n   perform private.queue_company_storage_reclamation(j.id);');
  select pg_get_functiondef('public.request_company_data_deletion(uuid,text)'::regprocedure) into definition;
  anchor := ' select * into v_job from private.company_data_deletions where tenant_id=p_tenant_id and status in (''queued'',''running'');';
  if position(anchor in definition) = 0 then raise exception 'Deletion request definition changed'; end if;
  execute replace(definition, anchor,
    ' select * into v_job from private.company_data_deletions where tenant_id=p_tenant_id and (status in (''queued'',''running'') or storage_status in (''queued'',''running''));');
end;$patch$;

create or replace function public.get_company_storage_usage()
returns jsonb language plpgsql stable security invoker set search_path = '' as $$
begin
  if auth.uid() is null or not private.is_internal_admin() then
    raise exception 'Administrative access required' using errcode = '42501';
  end if;
  return coalesce((select payload from private.company_storage_snapshot where singleton),
    jsonb_build_object('companies', '[]'::jsonb, 'measured_at', null, 'database_bytes', null, 'refresh_seconds', 300))
    || jsonb_build_object('deletions', (select coalesce(jsonb_agg(jsonb_build_object(
      'tenant_id', tenant_id, 'status', status, 'findings_deleted', findings_deleted, 'error_message', error_message,
      'storage_status', storage_status, 'storage_tables_done', storage_tables_done,
      'storage_reclaimed_bytes', storage_reclaimed_bytes, 'storage_error', storage_error)), '[]'::jsonb)
      from (select distinct on (tenant_id) * from private.company_data_deletions
        order by tenant_id, created_at desc) latest));
end;$$;
revoke all on function public.get_company_storage_usage() from public, anon, authenticated;
grant execute on function public.get_company_storage_usage() to authenticated;
notify pgrst, 'reload schema';
