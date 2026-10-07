do $$
begin
  if exists (select 1 from cron.job where jobname = 'piervuln-normalize-content') then
    perform cron.alter_job(
      (select jobid from cron.job where jobname = 'piervuln-normalize-content'),
      command := $job$set statement_timeout = '25s'; set lock_timeout = '1s'; select private.normalize_finding_content_batch(50);$job$
    );
  else
    raise exception 'piervuln-normalize-content job is missing';
  end if;
end;
$$;
