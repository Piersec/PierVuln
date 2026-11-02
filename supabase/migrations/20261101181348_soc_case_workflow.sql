create or replace function private.can_manage_soc_cases(p_tenant_id uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select (select private.is_internal_admin()) or exists (
    select 1 from public.company_memberships m
    join public.companies c on c.id = m.company_id
    where m.company_id = p_tenant_id and m.user_id = (select auth.uid())
      and m.is_active and c.is_active and m.role in ('owner','admin','analyst')
  );
$$;
revoke all on function private.can_manage_soc_cases(uuid) from public,anon;
grant execute on function private.can_manage_soc_cases(uuid) to authenticated,service_role;

create table public.soc_cases (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.companies(id) on delete cascade,
  title text not null check (length(btrim(title)) between 1 and 500),
  status text not null default 'open' check (status in ('open','analyzing','closed')),
  source_severity text check (source_severity is null or source_severity in ('critical','high','medium','low','informational','unknown')),
  case_severity text not null check (case_severity in ('critical','high','medium','low')),
  classification text not null default 'none' check (classification in ('none','positive','false_positive')),
  assigned_to uuid references auth.users(id) on delete set null,
  notes text not null default '' check (length(notes) <= 4000),
  created_by uuid references auth.users(id) on delete set null,
  first_ack_at timestamptz,
  resolved_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (status <> 'closed' or classification in ('positive','false_positive'))
);
create index soc_cases_tenant_created_idx on public.soc_cases(tenant_id,created_at desc,id desc);
create index soc_cases_tenant_status_idx on public.soc_cases(tenant_id,status,case_severity,updated_at desc);
create index soc_cases_assignee_idx on public.soc_cases(tenant_id,assigned_to,status);

create table public.soc_case_alerts (
  case_id uuid not null references public.soc_cases(id) on delete cascade,
  alert_id uuid not null unique references public.soc_alerts(id) on delete restrict,
  linked_by uuid references auth.users(id) on delete set null,
  linked_at timestamptz not null default now(),
  primary key(case_id,alert_id)
);
create index soc_case_alerts_alert_idx on public.soc_case_alerts(alert_id);

create table public.soc_case_events (
  id bigint generated always as identity primary key,
  case_id uuid not null references public.soc_cases(id) on delete cascade,
  actor_id uuid references auth.users(id) on delete set null,
  action text not null,
  changes jsonb not null default '{}' check (jsonb_typeof(changes) = 'object'),
  created_at timestamptz not null default now()
);
create index soc_case_events_case_idx on public.soc_case_events(case_id,created_at desc,id desc);

alter table public.soc_cases enable row level security;
alter table public.soc_case_alerts enable row level security;
alter table public.soc_case_events enable row level security;
revoke all on public.soc_cases,public.soc_case_alerts,public.soc_case_events from public,anon,authenticated;
grant select on public.soc_cases to authenticated;
grant update (title,status,case_severity,classification,assigned_to,notes) on public.soc_cases to authenticated;
grant select,insert,delete on public.soc_case_alerts to authenticated;
grant select on public.soc_case_events to authenticated;
grant all on public.soc_cases,public.soc_case_alerts,public.soc_case_events to service_role;

create policy soc_cases_read on public.soc_cases for select to authenticated
  using ((select private.is_internal_admin()) or (select private.has_company_membership(tenant_id)));
create policy soc_cases_change on public.soc_cases for update to authenticated
  using ((select private.can_manage_soc_cases(tenant_id)))
  with check ((select private.can_manage_soc_cases(tenant_id)));
create policy soc_case_alerts_read on public.soc_case_alerts for select to authenticated
  using (exists(select 1 from public.soc_cases c where c.id=case_id));
create policy soc_case_alerts_link on public.soc_case_alerts for insert to authenticated
  with check (exists(select 1 from public.soc_cases c where c.id=case_id and private.can_manage_soc_cases(c.tenant_id)));
create policy soc_case_alerts_unlink on public.soc_case_alerts for delete to authenticated
  using (exists(select 1 from public.soc_cases c where c.id=case_id and private.can_manage_soc_cases(c.tenant_id)));
create policy soc_case_events_read on public.soc_case_events for select to authenticated
  using (exists(select 1 from public.soc_cases c where c.id=case_id));

create function private.guard_soc_case_mutation() returns trigger language plpgsql
security definer set search_path = '' as $$
declare v_changes jsonb := '{}'::jsonb;
begin
  if tg_op = 'INSERT' then
    new.created_by := auth.uid();
    new.created_at := now();
    new.updated_at := now();
    new.first_ack_at := null;
    new.resolved_at := null;
    insert into public.soc_case_events(case_id,actor_id,action,changes)
      values(new.id,auth.uid(),'created',jsonb_build_object('status',new.status,'case_severity',new.case_severity,'classification',new.classification));
    return new;
  end if;
  if new.tenant_id is distinct from old.tenant_id then raise exception 'Tenant do caso não pode mudar' using errcode='23514'; end if;
  new.created_by := old.created_by;
  new.created_at := old.created_at;
  new.source_severity := old.source_severity;
  new.first_ack_at := old.first_ack_at;
  new.resolved_at := old.resolved_at;
  new.updated_at := now();
  if new.assigned_to is not null and not exists (
    select 1 from public.company_memberships m
    where m.company_id=old.tenant_id and m.user_id=new.assigned_to and m.is_active
  ) then raise exception 'Responsável não pertence à empresa' using errcode='23514'; end if;
  if old.status = 'open' and new.status = 'analyzing' and old.first_ack_at is null then new.first_ack_at := now(); end if;
  if new.status = 'closed' and old.status <> 'closed' then new.resolved_at := now(); end if;
  if new.status <> 'closed' and old.status = 'closed' then new.resolved_at := null; end if;
  if new.status is distinct from old.status then v_changes := v_changes || jsonb_build_object('status',jsonb_build_object('from',old.status,'to',new.status)); end if;
  if new.title is distinct from old.title then v_changes := v_changes || jsonb_build_object('title_updated',true); end if;
  if new.case_severity is distinct from old.case_severity then v_changes := v_changes || jsonb_build_object('case_severity',jsonb_build_object('from',old.case_severity,'to',new.case_severity)); end if;
  if new.classification is distinct from old.classification then v_changes := v_changes || jsonb_build_object('classification',jsonb_build_object('from',old.classification,'to',new.classification)); end if;
  if new.assigned_to is distinct from old.assigned_to then v_changes := v_changes || jsonb_build_object('assigned_to',jsonb_build_object('from',old.assigned_to,'to',new.assigned_to)); end if;
  if new.notes is distinct from old.notes then v_changes := v_changes || jsonb_build_object('notes_updated',true); end if;
  if v_changes <> '{}'::jsonb then
    insert into public.soc_case_events(case_id,actor_id,action,changes) values(new.id,auth.uid(),'updated',v_changes);
  end if;
  return new;
end;
$$;
revoke all on function private.guard_soc_case_mutation() from public,anon,authenticated;
create trigger soc_case_guard before insert or update on public.soc_cases
  for each row execute function private.guard_soc_case_mutation();

create function private.guard_soc_case_alert_tenant() returns trigger language plpgsql
security definer set search_path = '' as $$
declare v_case_tenant uuid; v_alert_tenant uuid;
begin
  select tenant_id into v_case_tenant from public.soc_cases where id=new.case_id;
  select tenant_id into v_alert_tenant from public.soc_alerts where id=new.alert_id;
  if v_case_tenant is null or v_alert_tenant is null or v_case_tenant <> v_alert_tenant then
    raise exception 'Alerta e caso precisam pertencer à mesma empresa' using errcode='23514';
  end if;
  if not private.can_manage_soc_cases(v_case_tenant) then raise exception 'Acesso não autorizado' using errcode='42501'; end if;
  insert into public.soc_case_events(case_id,actor_id,action,changes)
    values(new.case_id,auth.uid(),'alert_linked',jsonb_build_object('alert_id',new.alert_id));
  return new;
end;
$$;
revoke all on function private.guard_soc_case_alert_tenant() from public,anon,authenticated;
create trigger soc_case_alert_tenant_guard before insert on public.soc_case_alerts
  for each row execute function private.guard_soc_case_alert_tenant();

create function private.audit_soc_case_alert_unlink() returns trigger language plpgsql
security definer set search_path = '' as $$
begin
  insert into public.soc_case_events(case_id,actor_id,action,changes)
    values(old.case_id,auth.uid(),'alert_unlinked',jsonb_build_object('alert_id',old.alert_id));
  return old;
end;
$$;
revoke all on function private.audit_soc_case_alert_unlink() from public,anon,authenticated;
create trigger soc_case_alert_unlink_audit before delete on public.soc_case_alerts
  for each row execute function private.audit_soc_case_alert_unlink();

create function public.create_soc_case_from_alert(
  p_alert_id uuid,p_case_severity text,p_assigned_to uuid default null,p_notes text default ''
) returns uuid language plpgsql security definer set search_path = '' as $$
declare v_alert public.soc_alerts%rowtype; v_case_id uuid;
begin
  if auth.uid() is null or not (p_case_severity = any(array['critical','high','medium','low'])) then
    raise exception 'Dados do caso inválidos' using errcode='22023';
  end if;
  if length(coalesce(p_notes,'')) > 4000 then raise exception 'Notas excedem o limite permitido' using errcode='22023'; end if;
  select * into v_alert from public.soc_alerts where id=p_alert_id;
  if not found or not private.can_manage_soc_cases(v_alert.tenant_id) then
    raise exception 'Alerta indisponível para este usuário' using errcode='42501';
  end if;
  if p_assigned_to is not null and not exists(
    select 1 from public.company_memberships m where m.company_id=v_alert.tenant_id
      and m.user_id=p_assigned_to and m.is_active
  ) then raise exception 'Responsável não pertence à empresa' using errcode='23514'; end if;
  if v_alert.rule_id is not null or v_alert.src_ip is not null then
    perform pg_advisory_xact_lock(hashtextextended(
      v_alert.tenant_id::text || '|' || v_alert.source_id || '|' || coalesce(v_alert.rule_id,'') || '|' || coalesce(v_alert.src_ip,''), 0
    ));
    select c.id into v_case_id
    from public.soc_cases c
    join public.soc_case_alerts ca on ca.case_id=c.id
    join public.soc_alerts previous_alert on previous_alert.id=ca.alert_id
    where c.tenant_id=v_alert.tenant_id and c.status<>'closed'
      and previous_alert.source_id=v_alert.source_id
      and previous_alert.rule_id is not distinct from v_alert.rule_id
      and previous_alert.src_ip is not distinct from v_alert.src_ip
      and previous_alert.occurred_at between v_alert.occurred_at-interval '1 hour' and v_alert.occurred_at+interval '1 hour'
    order by c.created_at desc limit 1;
    if v_case_id is not null then
      insert into public.soc_case_alerts(case_id,alert_id,linked_by) values(v_case_id,v_alert.id,auth.uid());
      update public.soc_cases set updated_at=now() where id=v_case_id;
      return v_case_id;
    end if;
  end if;
  insert into public.soc_cases(tenant_id,title,source_severity,case_severity,assigned_to,notes)
    values(v_alert.tenant_id,v_alert.title,v_alert.severity,p_case_severity,p_assigned_to,coalesce(p_notes,''))
    returning id into v_case_id;
  insert into public.soc_case_alerts(case_id,alert_id,linked_by) values(v_case_id,v_alert.id,auth.uid());
  return v_case_id;
end;
$$;
revoke all on function public.create_soc_case_from_alert(uuid,text,uuid,text) from public,anon;
grant execute on function public.create_soc_case_from_alert(uuid,text,uuid,text) to authenticated,service_role;

create function public.get_soc_case_summary(p_tenant_id uuid,p_since timestamptz default null,p_until timestamptz default null)
returns jsonb language plpgsql stable security invoker set search_path = '' as $$
declare v_result jsonb;
begin
  if not (private.is_internal_admin() or (p_tenant_id is not null and private.has_company_membership(p_tenant_id))) then
    raise exception 'Acesso à empresa não autorizado' using errcode='42501';
  end if;
  if (p_since is null) <> (p_until is null) or (p_since is not null and p_until <= p_since) then
    raise exception 'Intervalo de datas inválido' using errcode='22023';
  end if;
  select jsonb_build_object(
    'as_of',now(),
    'open',count(*) filter(where status='open'),
    'analyzing',count(*) filter(where status='analyzing'),
    'closed_in_period',count(*) filter(where status='closed' and (p_since is null or (resolved_at>=p_since and resolved_at<p_until))),
    'assigned',count(*) filter(where status<>'closed' and assigned_to is not null),
    'unassigned',count(*) filter(where status<>'closed' and assigned_to is null),
    'assigned_severity',jsonb_build_object(
      'critical',count(*) filter(where status<>'closed' and assigned_to is not null and case_severity='critical'),
      'high',count(*) filter(where status<>'closed' and assigned_to is not null and case_severity='high'),
      'medium',count(*) filter(where status<>'closed' and assigned_to is not null and case_severity='medium'),
      'low',count(*) filter(where status<>'closed' and assigned_to is not null and case_severity='low')),
    'unassigned_severity',jsonb_build_object(
      'critical',count(*) filter(where status<>'closed' and assigned_to is null and case_severity='critical'),
      'high',count(*) filter(where status<>'closed' and assigned_to is null and case_severity='high'),
      'medium',count(*) filter(where status<>'closed' and assigned_to is null and case_severity='medium'),
      'low',count(*) filter(where status<>'closed' and assigned_to is null and case_severity='low')),
    'severity',jsonb_build_object(
      'critical',count(*) filter(where status<>'closed' and case_severity='critical'),
      'high',count(*) filter(where status<>'closed' and case_severity='high'),
      'medium',count(*) filter(where status<>'closed' and case_severity='medium'),
      'low',count(*) filter(where status<>'closed' and case_severity='low')),
    'severity_by_status',jsonb_build_object(
      'open',jsonb_build_object('critical',count(*) filter(where status='open' and case_severity='critical'),'high',count(*) filter(where status='open' and case_severity='high'),'medium',count(*) filter(where status='open' and case_severity='medium'),'low',count(*) filter(where status='open' and case_severity='low')),
      'analyzing',jsonb_build_object('critical',count(*) filter(where status='analyzing' and case_severity='critical'),'high',count(*) filter(where status='analyzing' and case_severity='high'),'medium',count(*) filter(where status='analyzing' and case_severity='medium'),'low',count(*) filter(where status='analyzing' and case_severity='low')),
      'closed',jsonb_build_object('critical',count(*) filter(where status='closed' and case_severity='critical' and (p_since is null or (resolved_at>=p_since and resolved_at<p_until))),'high',count(*) filter(where status='closed' and case_severity='high' and (p_since is null or (resolved_at>=p_since and resolved_at<p_until))),'medium',count(*) filter(where status='closed' and case_severity='medium' and (p_since is null or (resolved_at>=p_since and resolved_at<p_until))),'low',count(*) filter(where status='closed' and case_severity='low' and (p_since is null or (resolved_at>=p_since and resolved_at<p_until))))),
    'mtta_samples',count(*) filter(where first_ack_at is not null and (p_since is null or (created_at>=p_since and created_at<p_until))),
    'mtta_p50_seconds',percentile_cont(0.5) within group(order by extract(epoch from first_ack_at-created_at)) filter(where first_ack_at is not null and (p_since is null or (created_at>=p_since and created_at<p_until))),
    'mttr_samples',count(*) filter(where status='closed' and (p_since is null or (resolved_at>=p_since and resolved_at<p_until))),
    'mttr_p50_seconds',percentile_cont(0.5) within group(order by extract(epoch from resolved_at-created_at)) filter(where status='closed' and (p_since is null or (resolved_at>=p_since and resolved_at<p_until)))
  ) into v_result from public.soc_cases where p_tenant_id is null or tenant_id=p_tenant_id;
  return v_result;
end;
$$;
revoke all on function public.get_soc_case_summary(uuid,timestamptz,timestamptz) from public,anon;
grant execute on function public.get_soc_case_summary(uuid,timestamptz,timestamptz) to authenticated,service_role;

create function public.get_soc_fim_summary(p_tenant_id uuid,p_since timestamptz,p_until timestamptz)
returns jsonb language plpgsql stable security invoker set search_path = '' as $$
declare v_result jsonb;
begin
  if p_since is null or p_until is null or p_until<=p_since or p_since<now()-interval '30 days' or p_until>now()+interval '5 minutes' then
    raise exception 'Intervalo de integridade inválido' using errcode='22023';
  end if;
  if p_tenant_id is not null and not (private.is_internal_admin() or private.has_company_membership(p_tenant_id)) then
    raise exception 'Acesso à empresa não autorizado' using errcode='42501';
  end if;
  with filtered as (
    select a.* from public.soc_alerts a
    where (p_tenant_id is null or a.tenant_id=p_tenant_id)
      and a.occurred_at>=p_since and a.occurred_at<p_until
      and (a.file_path is not null or a.file_action is not null)
  ), buckets as (
    select date_trunc(case when p_until-p_since<=interval '48 hours' then 'hour' else 'day' end, occurred_at at time zone 'UTC') bucket,
      count(*) filter(where lower(coalesce(file_action,'')) in ('modified','modified attributes','changed')) modified,
      count(*) filter(where lower(coalesce(file_action,'')) in ('added','created')) added,
      count(*) filter(where lower(coalesce(file_action,'')) in ('deleted','removed')) deleted,
      count(*) filter(where lower(coalesce(file_action,'')) not in ('modified','modified attributes','changed','added','created','deleted','removed')) unknown
    from filtered group by 1
  )
  select jsonb_build_object(
    'queried_at',now(),'total',count(*),
    'modified',count(*) filter(where lower(coalesce(file_action,'')) in ('modified','modified attributes','changed')),
    'added',count(*) filter(where lower(coalesce(file_action,'')) in ('added','created')),
    'deleted',count(*) filter(where lower(coalesce(file_action,'')) in ('deleted','removed')),
    'unknown',count(*) filter(where lower(coalesce(file_action,'')) not in ('modified','modified attributes','changed','added','created','deleted','removed')),
    'series',coalesce((select jsonb_agg(jsonb_build_object('bucket',to_char(bucket,'YYYY-MM-DD"T"HH24:MI:SS"Z"'),'modified',modified,'added',added,'deleted',deleted,'unknown',unknown) order by bucket) from buckets),'[]'::jsonb),
    'top_hosts',coalesce((select jsonb_agg(jsonb_build_object('name',r.agent_name,'agent_id',r.agent_id,'count',r.total) order by r.total desc) from (select coalesce(agent_name,'Host não identificado') agent_name,agent_id,count(*)::bigint total from filtered group by agent_name,agent_id order by count(*) desc,agent_name limit 5) r),'[]'::jsonb),
    'top_rules',coalesce((select jsonb_agg(jsonb_build_object('name',r.rule_description,'id',r.rule_id,'count',r.total) order by r.total desc) from (select rule_description,rule_id,count(*)::bigint total from filtered group by rule_description,rule_id order by count(*) desc,rule_id limit 5) r),'[]'::jsonb),
    'top_users',coalesce((select jsonb_agg(jsonb_build_object('name',r.change_actor,'agent_id',r.agent_id,'agent_name',r.agent_name,'count',r.total) order by r.total desc) from (select change_actor,agent_id,agent_name,count(*)::bigint total from filtered where nullif(btrim(change_actor),'') is not null group by change_actor,agent_id,agent_name order by count(*) desc,change_actor limit 5) r),'[]'::jsonb),
    'owner_fields_present',count(*) filter(where file_owner_after is not null)
  ) into v_result from filtered;
  return v_result;
end;
$$;
revoke all on function public.get_soc_fim_summary(uuid,timestamptz,timestamptz) from public,anon;
grant execute on function public.get_soc_fim_summary(uuid,timestamptz,timestamptz) to authenticated,service_role;

create function public.get_soc_risk_summary(p_tenant_id uuid,p_since timestamptz,p_until timestamptz)
returns jsonb language plpgsql stable security invoker set search_path = '' as $$
declare v_result jsonb;
begin
  if p_since is null or p_until is null or p_until<=p_since or p_since<now()-interval '30 days' or p_until>now()+interval '5 minutes' then
    raise exception 'Intervalo de gravidade inválido' using errcode='22023';
  end if;
  if p_tenant_id is not null and not (private.is_internal_admin() or private.has_company_membership(p_tenant_id)) then
    raise exception 'Acesso à empresa não autorizado' using errcode='42501';
  end if;
  with filtered as (
    select a.* from public.soc_alerts a where (p_tenant_id is null or a.tenant_id=p_tenant_id)
      and a.occurred_at>=p_since and a.occurred_at<p_until
  ), hosts as (
    select agent_id,agent_name,count(*)::bigint total,
      count(*) filter(where severity='critical')::bigint critical,
      count(*) filter(where severity='high')::bigint high,
      count(*) filter(where severity='medium')::bigint medium,
      count(*) filter(where severity='low')::bigint low,
      count(*) filter(where severity in ('unknown','informational'))::bigint other
    from filtered where agent_id is not null or agent_name is not null
    group by agent_id,agent_name order by count(*) desc,agent_name limit 10
  )
  select jsonb_build_object(
    'queried_at',now(),'total',count(*),
    'severity',jsonb_build_object('critical',count(*) filter(where severity='critical'),'high',count(*) filter(where severity='high'),'medium',count(*) filter(where severity='medium'),'low',count(*) filter(where severity='low'),'informational',count(*) filter(where severity='informational'),'unknown',count(*) filter(where severity='unknown')),
    'hosts_without_identity',count(*) filter(where agent_id is null and agent_name is null),
    'hosts',coalesce((select jsonb_agg(jsonb_build_object('agent_id',agent_id,'agent_name',agent_name,'total',total,'critical',critical,'high',high,'medium',medium,'low',low,'other',other) order by total desc) from hosts),'[]'::jsonb),
    'firewall_events',count(*) filter(where lower(coalesce(source_category,''))='firewall'),
    'firewall_severity',jsonb_build_object('critical',count(*) filter(where lower(coalesce(source_category,''))='firewall' and severity='critical'),'high',count(*) filter(where lower(coalesce(source_category,''))='firewall' and severity='high'),'medium',count(*) filter(where lower(coalesce(source_category,''))='firewall' and severity='medium'),'low',count(*) filter(where lower(coalesce(source_category,''))='firewall' and severity='low'))
  ) into v_result from filtered;
  return v_result;
end;
$$;
revoke all on function public.get_soc_risk_summary(uuid,timestamptz,timestamptz) from public,anon;
grant execute on function public.get_soc_risk_summary(uuid,timestamptz,timestamptz) to authenticated,service_role;

create function public.get_soc_threat_summary(p_tenant_id uuid,p_since timestamptz,p_until timestamptz)
returns jsonb language plpgsql stable security invoker set search_path = '' as $$
declare v_result jsonb;
begin
  if p_since is null or p_until is null or p_until<=p_since or p_since<now()-interval '30 days' or p_until>now()+interval '5 minutes' then
    raise exception 'Intervalo de ameaças inválido' using errcode='22023';
  end if;
  if p_tenant_id is not null and not (private.is_internal_admin() or private.has_company_membership(p_tenant_id)) then
    raise exception 'Acesso à empresa não autorizado' using errcode='42501';
  end if;
  with filtered as (
    select a.* from public.soc_alerts a where (p_tenant_id is null or a.tenant_id=p_tenant_id)
      and a.occurred_at>=p_since and a.occurred_at<p_until
  ), tactics as (
    select t.value name,count(distinct f.id)::bigint total from filtered f cross join lateral unnest(f.mitre_tactics) t(value)
    group by t.value order by count(distinct f.id) desc,t.value limit 10
  ), techniques as (
    select x.value name,count(distinct f.id)::bigint total from filtered f cross join lateral unnest(f.mitre_techniques) x(value)
    group by x.value order by count(distinct f.id) desc,x.value limit 10
  ), events as (
    select id,occurred_at,title,source_name,agent_name,src_ip,dst_ip,mitre_ids,mitre_tactics,mitre_techniques
    from filtered order by occurred_at desc,id desc limit 20
  )
  select jsonb_build_object(
    'queried_at',now(),'total',count(*),
    'geolocation_available',false,
    'tactics',coalesce((select jsonb_agg(jsonb_build_object('name',name,'count',total) order by total desc) from tactics),'[]'::jsonb),
    'techniques',coalesce((select jsonb_agg(jsonb_build_object('name',name,'count',total) order by total desc) from techniques),'[]'::jsonb),
    'events',coalesce((select jsonb_agg(jsonb_build_object('id',id,'occurred_at',occurred_at,'title',title,'source_name',source_name,'agent_name',agent_name,'src_ip',src_ip,'dst_ip',dst_ip,'mitre_ids',mitre_ids,'mitre_tactics',mitre_tactics,'mitre_techniques',mitre_techniques) order by occurred_at desc) from events),'[]'::jsonb),
    'events_with_mitre',count(*) filter(where cardinality(mitre_ids)>0 or cardinality(mitre_tactics)>0 or cardinality(mitre_techniques)>0),
    'events_with_geo',0
  ) into v_result from filtered;
  return v_result;
end;
$$;
revoke all on function public.get_soc_threat_summary(uuid,timestamptz,timestamptz) from public,anon;
grant execute on function public.get_soc_threat_summary(uuid,timestamptz,timestamptz) to authenticated,service_role;

create function public.get_soc_collection_status(p_tenant_id uuid)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v_result jsonb;
begin
  if p_tenant_id is null or not (private.is_internal_admin() or private.has_company_membership(p_tenant_id)) then
    raise exception 'Acesso à empresa não autorizado' using errcode='42501';
  end if;
  select jsonb_build_object('queried_at',now(),'integrations',coalesce(jsonb_agg(jsonb_build_object(
    'name',name,'last_received_at',last_received_at,'last_batch_events',last_batch_events,
    'last_inserted',last_inserted,'last_duplicates',last_duplicates,'has_error',last_error is not null,
    'revoked',revoked_at is not null
  ) order by name),'[]'::jsonb)) into v_result
  from public.soc_ingest_credentials where tenant_id=p_tenant_id;
  return v_result;
end;
$$;
revoke all on function public.get_soc_collection_status(uuid) from public,anon;
grant execute on function public.get_soc_collection_status(uuid) to authenticated,service_role;
