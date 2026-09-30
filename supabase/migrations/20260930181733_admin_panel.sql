-- Auth data and private Pier membership are returned only to the protected Edge Function.
create or replace function public.admin_panel_data(p_search text default '', p_scope text default '', p_page integer default 0)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare result jsonb;
begin
  if (select auth.jwt()->>'role') is distinct from 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;
  with filtered_users as (
    select u.id, u.email, coalesce(nullif(p.display_name, ''), u.email) as display_name,
      u.email_confirmed_at, u.invited_at, u.last_sign_in_at, u.created_at,
      exists(select 1 from private.internal_admins ia where ia.user_id=u.id) as is_internal,
      coalesce((select jsonb_agg(jsonb_build_object('id',m.id,'company_id',m.company_id,'role',m.role,'is_active',m.is_active) order by m.created_at)
        from public.company_memberships m where m.user_id=u.id), '[]'::jsonb) as memberships
    from auth.users u left join public.user_profiles p on p.id=u.id
    where (coalesce(p_search,'')='' or u.email ilike '%'||p_search||'%' or p.display_name ilike '%'||p_search||'%')
      and (coalesce(p_scope,'')='' or (p_scope='pier' and exists(select 1 from private.internal_admins ia where ia.user_id=u.id))
        or exists(select 1 from public.company_memberships m where m.user_id=u.id and m.company_id::text=p_scope))
  )
  select jsonb_build_object(
    'stats', jsonb_build_object(
      'active_companies',(select count(*) from public.companies where is_active),
      'inactive_companies',(select count(*) from public.companies where not is_active),
      'users',(select count(*) from auth.users u where exists(select 1 from public.company_memberships m where m.user_id=u.id) or exists(select 1 from private.internal_admins ia where ia.user_id=u.id)),
      'connections',(select count(*) from public.wazuh_connections),
      'active_connections',(select count(*) from public.wazuh_connections where is_active)),
    'companies',coalesce((select jsonb_agg(to_jsonb(c) || jsonb_build_object(
      'user_count',(select count(*) from public.company_memberships m where m.company_id=c.id and m.is_active),
      'connection_count',(select count(distinct wc.id) from public.wazuh_connections wc where wc.tenant_id=c.id or exists(select 1 from public.wazuh_agent_mappings wam where wam.connection_id=wc.id and wam.tenant_id=c.id and wam.is_active))
    ) order by c.name) from public.companies c),'[]'::jsonb),
    'connections',coalesce((select jsonb_agg(to_jsonb(wc) || jsonb_build_object('latest_sync',
      (select jsonb_build_object('id',r.id,'status',r.status,'started_at',r.started_at,'finished_at',r.finished_at,'full_snapshot',r.full_snapshot,'documents_received',r.documents_received)
       from public.sync_runs r where r.connection_id=wc.id order by r.started_at desc limit 1)) order by wc.name)
      from public.wazuh_connections wc),'[]'::jsonb),
    'mappings',coalesce((select jsonb_agg(to_jsonb(wam) order by wam.created_at desc) from public.wazuh_agent_mappings wam),'[]'::jsonb),
    'users',coalesce((select jsonb_agg(to_jsonb(u)) from (select * from filtered_users order by created_at desc,id limit 50 offset greatest(p_page,0)*50) u),'[]'::jsonb),
    'user_count',(select count(*) from filtered_users),
    'archives',coalesce((select jsonb_agg(to_jsonb(a)) from (select * from public.archive_manifests order by archived_at desc limit 50) a),'[]'::jsonb)
  ) into result;
  return result;
end;
$$;
revoke all on function public.admin_panel_data(text,text,integer) from public,anon,authenticated;
grant execute on function public.admin_panel_data(text,text,integer) to service_role;

create or replace function public.admin_lookup_user(p_email text)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
begin
  if (select auth.jwt()->>'role') is distinct from 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;
  return (select jsonb_build_object('id',id,'email_confirmed',email_confirmed_at is not null) from auth.users where lower(email)=lower(p_email) limit 1);
end;
$$;
revoke all on function public.admin_lookup_user(text) from public,anon,authenticated;
grant execute on function public.admin_lookup_user(text) to service_role;
