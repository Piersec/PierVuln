set local lock_timeout = '3s';

do $migration$
declare
  v_job_id integer;
  v_definition text;
  v_refresh_value text := '''refresh_seconds'', 300';
begin
  select jobid into v_job_id
  from cron.job
  where jobname = 'piervuln-refresh-overview-snapshots';
  if v_job_id is null then
    raise exception 'Overview snapshot job is missing';
  end if;
  perform cron.alter_job(v_job_id, schedule := '2-57/5 * * * *');

  select jobid into v_job_id
  from cron.job
  where jobname = 'piervuln-company-storage';
  if v_job_id is null then
    raise exception 'Company storage snapshot job is missing';
  end if;
  perform cron.alter_job(v_job_id, schedule := '*/30 * * * *');

  select pg_get_functiondef('private.refresh_company_storage_snapshot()'::regprocedure)
  into v_definition;
  if position(v_refresh_value in v_definition) = 0 then
    raise exception 'Company storage snapshot definition changed';
  end if;
  execute replace(v_definition, v_refresh_value, '''refresh_seconds'', 1800');

  select pg_get_functiondef('public.get_company_storage_usage()'::regprocedure)
  into v_definition;
  if position(v_refresh_value in v_definition) = 0 then
    raise exception 'Company storage usage definition changed';
  end if;
  execute replace(v_definition, v_refresh_value, '''refresh_seconds'', 1800');

  update private.company_storage_snapshot
  set payload = jsonb_set(payload, '{refresh_seconds}', '1800'::jsonb, true)
  where singleton;

  notify pgrst, 'reload schema';
end;
$migration$;
