do $$
declare
  v_job_id bigint;
begin
  select jobid into strict v_job_id
  from cron.job
  where jobname = 'piervuln-publish-snapshot';

  perform cron.alter_job(
    job_id := v_job_id,
    command := $job$
      set statement_timeout = '60min';
      select wazuh_internal.process_publication_queue();
    $job$
  );
end;
$$;
