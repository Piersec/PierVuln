set local lock_timeout = '3s';

do $patch$
declare
  definition text;
  schedule_line text := $line$v_job_id := cron.schedule('piervuln-storage-reclamation-execute', '* * * * *', v_command);$line$;
  old_cursor text := 'select coalesce(max(runid), 0) into v_run_after from cron.job_run_details where jobid = v_job_id;';
  new_cursor text := $line$select coalesce(max(runid), 0) into v_run_after from cron.job_run_details where jobid = (select jobid from cron.job where jobname = 'piervuln-storage-reclamation-execute');$line$;
begin
  select pg_get_functiondef('private.process_company_storage_reclamation()'::regprocedure) into definition;
  if position(new_cursor in definition) > 0 then return; end if;
  if position(schedule_line in definition) = 0 or position(old_cursor in definition) = 0 then
    raise exception 'Storage reclamation function changed; review migration before applying';
  end if;
  execute replace(replace(definition, schedule_line, new_cursor || E'\n    ' || schedule_line), old_cursor, '');
end;
$patch$;
