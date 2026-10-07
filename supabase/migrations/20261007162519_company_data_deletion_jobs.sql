set local lock_timeout='3s';
create table private.company_data_deletions (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references public.companies(id),
 requested_by uuid not null references auth.users(id),
 status text not null default 'queued' check(status in ('queued','running','succeeded','failed')),
 rules jsonb not null default '[]',
 findings_deleted bigint not null default 0,
 cases_deleted bigint not null default 0,
 events_deleted bigint not null default 0,
 comments_deleted bigint not null default 0,
 error_message text,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);
create unique index company_data_deletions_one_active on private.company_data_deletions(tenant_id)
 where status in ('queued','running');
alter table private.company_data_deletions enable row level security;
revoke all on private.company_data_deletions from public,anon,authenticated;
grant select on private.company_data_deletions to authenticated;
create policy company_data_deletions_admin_read on private.company_data_deletions
 for select to authenticated using ((select private.is_internal_admin()));

create function public.request_company_data_deletion(p_tenant_id uuid,p_confirmation text)
returns jsonb language plpgsql security definer set search_path=''
as $$
declare v_company public.companies%rowtype; v_job private.company_data_deletions%rowtype; v_rules jsonb;
begin
 if auth.uid() is null or not private.is_internal_admin() then
  raise exception 'Administrative access required' using errcode='42501';
 end if;
 select * into v_company from public.companies where id=p_tenant_id for update;
 if not found or p_confirmation is distinct from v_company.name then
  raise exception 'Confirme o nome exato da empresa.' using errcode='22023';
 end if;
 select * into v_job from private.company_data_deletions where tenant_id=p_tenant_id and status in ('queued','running');
 if found then return jsonb_build_object('id',v_job.id,'status',v_job.status); end if;
 select coalesce(jsonb_agg(jsonb_build_object('connection_id',connection_id,'match_type',match_type,'match_value',match_value)),'[]')
 into v_rules from public.wazuh_agent_mappings where tenant_id=p_tenant_id;
 update public.companies set is_active=false where id=p_tenant_id;
 update public.wazuh_agent_mappings set is_active=false where tenant_id=p_tenant_id and is_active;
 update public.wazuh_connections set is_active=false where tenant_id=p_tenant_id and mode='dedicated' and is_active;
 insert into private.company_data_deletions(tenant_id,requested_by,rules) values(p_tenant_id,auth.uid(),v_rules) returning * into v_job;
 return jsonb_build_object('id',v_job.id,'status',v_job.status);
end;$$;
revoke all on function public.request_company_data_deletion(uuid,text) from public,anon,authenticated;
grant execute on function public.request_company_data_deletion(uuid,text) to authenticated;

create function private.process_company_data_deletion()
returns uuid language plpgsql security definer set search_path=''
as $$
declare j private.company_data_deletions%rowtype; ids uuid[]; nf bigint; nc bigint; ne bigint; nm bigint;
begin
 if not pg_try_advisory_xact_lock(hashtextextended('company_data_deletion_worker',0)) then return null; end if;
 select * into j from private.company_data_deletions where status in ('queued','running')
 order by updated_at,id limit 1 for update skip locked;
 if not found then return null; end if;
 begin
  perform 1 from public.sync_runs s
  where s.status='running' and (
   s.connection_id in (select (r->>'connection_id')::uuid from jsonb_array_elements(j.rules) r)
   or s.connection_id in (select id from public.wazuh_connections where tenant_id=j.tenant_id)
  ) for update nowait;

  select array_agg(id) into ids from (
   select f.id from public.wazuh_findings f
   where f.tenant_id=j.tenant_id or (f.tenant_id is null and (
    exists(select 1 from public.vulnerability_cases c where c.finding_id=f.id and c.tenant_id=j.tenant_id)
    or exists(select 1 from public.wazuh_connections c where c.id=f.connection_id and c.tenant_id=j.tenant_id and c.mode='dedicated')
    or exists(select 1 from jsonb_array_elements(j.rules) r where (r->>'connection_id')::uuid=f.connection_id and (
     (r->>'match_type'='agent_id' and r->>'match_value'=f.agent_id)
     or (r->>'match_type'='group' and r->>'match_value'=any(f.agent_groups))
     or (r->>'match_type'='agent_name_prefix' and right(r->>'match_value',1)='*' and length(r->>'match_value')>1
      and left(lower(f.agent_name),length(r->>'match_value')-1)=lower(left(r->>'match_value',length(r->>'match_value')-1)))
    ))
   )) limit 2000
  ) target;
  if ids is null then
   if exists(select 1 from public.vulnerability_cases where tenant_id=j.tenant_id)
     or exists(select 1 from public.finding_events where tenant_id=j.tenant_id)
     or exists(select 1 from public.vulnerability_comments where tenant_id=j.tenant_id) then
    raise exception 'Residual company relations require review';
   end if;
   update public.vulnerability_overview_snapshots
    set overview=(select * from public.get_vulnerability_overview_live(j.tenant_id,null) limit 1),
      refreshed_at=now(),stale=false where tenant_id=j.tenant_id;
   update private.company_data_deletions set status='succeeded',updated_at=now(),error_message=null where id=j.id;
   return j.id;
  end if;
  if exists(select 1 from public.vulnerability_cases where finding_id=any(ids) and tenant_id<>j.tenant_id)
   or exists(select 1 from public.finding_events where finding_id=any(ids) and tenant_id<>j.tenant_id)
   or exists(select 1 from public.vulnerability_comments where finding_id=any(ids) and tenant_id<>j.tenant_id) then
   raise exception 'Cross-company relations require review';
  end if;
  delete from public.vulnerability_comments where finding_id=any(ids) and (tenant_id=j.tenant_id or tenant_id is null); get diagnostics nm=row_count;
  delete from public.finding_events where finding_id=any(ids) and (tenant_id=j.tenant_id or tenant_id is null); get diagnostics ne=row_count;
  delete from public.vulnerability_cases where finding_id=any(ids) and tenant_id=j.tenant_id; get diagnostics nc=row_count;
  delete from public.wazuh_findings where id=any(ids) and (tenant_id=j.tenant_id or tenant_id is null); get diagnostics nf=row_count;
  update private.company_data_deletions set status='running',updated_at=now(),
   findings_deleted=findings_deleted+nf,cases_deleted=cases_deleted+nc,
   events_deleted=events_deleted+ne,comments_deleted=comments_deleted+nm where id=j.id;
 exception
  when lock_not_available then return j.id;
  when query_canceled then
   update private.company_data_deletions set status='failed',updated_at=now(),
    error_message='A limpeza excedeu o tempo limite. Os lotes concluídos foram preservados; tente novamente.' where id=j.id;
  when others then
   update private.company_data_deletions set status='failed',updated_at=now(),
    error_message='A limpeza foi interrompida para proteger os vínculos dos dados. Solicite uma revisão antes de tentar novamente.' where id=j.id;
 end;
 return j.id;
end;$$;
revoke all on function private.process_company_data_deletion() from public,anon,authenticated,service_role;

create or replace function public.get_company_storage_usage()
returns jsonb language plpgsql stable security invoker set search_path=''
as $$
begin
 if auth.uid() is null or not private.is_internal_admin() then
  raise exception 'Administrative access required' using errcode='42501';
 end if;
 return coalesce((select payload from private.company_storage_snapshot where singleton),
  jsonb_build_object('companies','[]'::jsonb,'measured_at',null,'database_bytes',null,'refresh_seconds',300))
  || jsonb_build_object('deletions',(select coalesce(jsonb_agg(jsonb_build_object(
    'tenant_id',tenant_id,'status',status,'findings_deleted',findings_deleted,'error_message',error_message)),'[]')
    from (select distinct on(tenant_id) tenant_id,status,findings_deleted,error_message
      from private.company_data_deletions order by tenant_id,created_at desc) latest));
end;$$;

do $patch$
declare definition text; anchor text := '  where s.tenant_id is null or s.stale or s.source_marker is distinct from v_source_marker';
begin
 select pg_get_functiondef('private.refresh_next_vulnerability_overview_snapshot()'::regprocedure) into definition;
 if position(anchor in definition)=0 then raise exception 'Snapshot refresh definition changed'; end if;
 execute replace(definition,anchor,
 '  where (s.tenant_id is null or s.stale or s.source_marker is distinct from v_source_marker)
    and not exists (select 1 from private.company_data_deletions d where d.tenant_id=c.id and d.status in (''queued'',''running''))');
end;$patch$;

select cron.schedule('piervuln-company-data-deletion','30 seconds',
 $job$set statement_timeout='25s'; set lock_timeout='1s'; select private.process_company_data_deletion();$job$);
notify pgrst,'reload schema';

