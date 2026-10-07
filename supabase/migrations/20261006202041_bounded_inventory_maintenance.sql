set local lock_timeout = '3s';

create function private.normalize_finding_content_batch(p_limit integer default 500)
returns integer language plpgsql security definer set search_path = ''
as $$
declare v_changed integer;
begin
  if not pg_try_advisory_xact_lock(20261006, 1) then return 0; end if;
  if exists (select 1 from wazuh_internal.publication_queue where status = 'pending') then return 0; end if;
  with candidates as materialized (
    select id from public.wazuh_findings where content_id is null
    order by id limit least(greatest(p_limit, 1), 2000) for update skip locked
  )
  update public.wazuh_findings f
  set description = f.description, reference_urls = f.reference_urls
  from candidates c where f.id = c.id;
  get diagnostics v_changed = row_count;
  if v_changed = 0 and not exists (select 1 from public.wazuh_findings where content_id is null) then
    perform cron.unschedule('piervuln-normalize-content');
  end if;
  return v_changed;
end;
$$;
revoke all on function private.normalize_finding_content_batch(integer) from public, anon, authenticated, service_role;

create function private.inventory_maintenance()
returns void language plpgsql security definer set search_path = ''
as $$
begin
  if not pg_try_advisory_xact_lock(20261006, 2) then return; end if;

  update public.sync_runs sr set status = 'partial', finished_at = now(), full_snapshot = false,
    error_summary = 'Coleta abandonada; o último snapshot publicado foi preservado.'
  where sr.status = 'running' and sr.started_at < now() - interval '2 hours'
    and not exists (select 1 from wazuh_internal.publication_queue q where q.run_id = sr.id and q.status = 'pending');

  delete from wazuh_internal.snapshot_pages sp using public.sync_runs sr
  where sp.run_id = sr.id and sr.status <> 'running';

  delete from wazuh_internal.publication_queue
  where status <> 'pending' and finished_at < now() - interval '30 days';

  delete from public.sync_runs sr
  where sr.status <> 'running' and sr.finished_at < now() - interval '30 days'
    and not exists (select 1 from public.wazuh_connections c where c.published_sync_run_id = sr.id)
    and not exists (select 1 from public.wazuh_findings f where f.last_seen_sync_run_id = sr.id)
    and not exists (select 1 from wazuh_internal.publication_queue q where q.run_id = sr.id);

  delete from public.finding_content c where not exists (
    select 1 from public.wazuh_findings f where f.content_id = c.id
  );
end;
$$;
revoke all on function private.inventory_maintenance() from public, anon, authenticated, service_role;

select cron.schedule('piervuln-normalize-content', '*/2 * * * *',
  $job$set statement_timeout = '25s'; set lock_timeout = '1s'; select private.normalize_finding_content_batch(10);$job$);
select cron.schedule('piervuln-inventory-maintenance', '15 5 * * *',
  $job$set statement_timeout = '20s'; set lock_timeout = '1s'; select private.inventory_maintenance();$job$);
