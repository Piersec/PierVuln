set local lock_timeout='3s';
do $patch$
declare definition text; anchor text := ' insert into private.company_data_deletions(tenant_id,requested_by,rules) values(p_tenant_id,auth.uid(),v_rules) returning * into v_job;';
begin
 select pg_get_functiondef('public.request_company_data_deletion(uuid,text)'::regprocedure) into definition;
 if position(anchor in definition)=0 then raise exception 'Deletion request definition changed'; end if;
 execute replace(definition,anchor,anchor || E'\n perform cron.alter_job(jobid, active := true) from cron.job where jobname=''piervuln-company-data-deletion'';');
 select pg_get_functiondef('private.process_company_data_deletion()'::regprocedure) into definition;
 anchor := ' if not found then return null; end if;';
 if position(anchor in definition)=0 then raise exception 'Deletion worker definition changed'; end if;
 execute replace(definition,anchor,
 ' if not found then
    perform 1 from cron.job where jobname=''piervuln-company-data-deletion'' for update;
    if not exists(select 1 from private.company_data_deletions where status in (''queued'',''running'')) then
      perform cron.alter_job(jobid, active := false) from cron.job where jobname=''piervuln-company-data-deletion'';
    end if;
    return null;
  end if;');
end;$patch$;
select cron.alter_job(jobid, active := false) from cron.job
where jobname='piervuln-company-data-deletion'
and not exists(select 1 from private.company_data_deletions where status in ('queued','running'));

