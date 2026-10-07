do $$
begin
  if not exists (select 1 from cron.job where jobname = 'piervuln-normalize-content') then
    raise exception 'piervuln-normalize-content job is missing';
  end if;
  perform cron.alter_job(jobid,
    command := $job$set statement_timeout = '25s'; set lock_timeout = '1s'; select private.normalize_finding_content_batch(10);$job$
  ) from cron.job where jobname = 'piervuln-normalize-content';
end;
$$;
