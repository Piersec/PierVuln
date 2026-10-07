set local lock_timeout='3s';
do $patch$
declare definition text; anchor text;
begin
 select pg_get_functiondef('private.process_company_data_deletion()'::regprocedure) into definition;
 anchor := '    perform 1 from cron.job where jobname=''piervuln-company-data-deletion'' for update;';
 if position(anchor in definition)=0 then raise exception 'Idle worker definition changed'; end if;
 execute replace(definition,anchor,'    perform pg_advisory_xact_lock(hashtextextended(''company_deletion_scheduler'',0));');
 select pg_get_functiondef('public.request_company_data_deletion(uuid,text)'::regprocedure) into definition;
 anchor := ' perform cron.alter_job(jobid, active := true) from cron.job where jobname=''piervuln-company-data-deletion'';';
 if position(anchor in definition)=0 then raise exception 'Deletion request definition changed'; end if;
 execute replace(definition,anchor,
 ' perform pg_advisory_xact_lock(hashtextextended(''company_deletion_scheduler'',0));' || E'\n' || anchor);
end;$patch$;

