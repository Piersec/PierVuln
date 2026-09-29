-- Remove the project-wide auto-RLS event trigger. RLS and access policies are
-- now explicit and reviewable in versioned migrations.
drop event trigger if exists ensure_rls;
drop function if exists public.rls_auto_enable();

create or replace function private.is_internal_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from private.internal_admins ia
    where ia.user_id = (select auth.uid())
  );
$$;

create or replace function private.has_company_membership(p_company_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.company_memberships m
    join public.companies c on c.id = m.company_id
    where m.company_id = p_company_id
      and m.user_id = (select auth.uid())
      and m.is_active
      and c.is_active
  );
$$;

create or replace function private.has_company_role(p_company_id uuid, p_roles text[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.company_memberships m
    join public.companies c on c.id = m.company_id
    where m.company_id = p_company_id
      and m.user_id = (select auth.uid())
      and m.is_active
      and c.is_active
      and m.role = any(p_roles)
  );
$$;

create or replace function private.can_access_connection(p_connection_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.is_internal_admin()
    or exists (
      select 1
      from public.wazuh_connections wc
      where wc.id = p_connection_id
        and wc.is_active
        and (
          private.has_company_membership(wc.tenant_id)
          or exists (
            select 1
            from public.wazuh_agent_mappings wam
            where wam.connection_id = wc.id
              and wam.is_active
              and private.has_company_membership(wam.tenant_id)
          )
        )
    );
$$;

create or replace function private.can_access_finding(
  p_finding_id uuid,
  p_tenant_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.is_internal_admin()
    or (
      private.has_company_membership(p_tenant_id)
      and exists (
        select 1
        from public.wazuh_findings f
        where f.id = p_finding_id
          and f.tenant_id = p_tenant_id
      )
    );
$$;

create or replace function public.current_user_context()
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := (select auth.uid());
  v_internal boolean;
  v_companies jsonb;
begin
  if v_user_id is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;

  v_internal := private.is_internal_admin();
  select coalesce(
    jsonb_agg(jsonb_build_object(
      'id', c.id,
      'name', c.name,
      'slug', c.slug,
      'role', m.role
    ) order by c.name),
    '[]'::jsonb
  ) into v_companies
  from public.company_memberships m
  join public.companies c on c.id = m.company_id
  where m.user_id = v_user_id and m.is_active and c.is_active;

  return jsonb_build_object(
    'user_id', v_user_id,
    'is_internal_admin', v_internal,
    'companies', v_companies
  );
end;
$$;

create or replace function private.touch_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

create or replace function private.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.user_profiles (id, display_name)
  values (
    new.id,
    left(coalesce(new.raw_user_meta_data ->> 'full_name', new.email, ''), 160)
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

create or replace function private.audit_case_workflow_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.workflow_status is distinct from new.workflow_status then
    insert into public.finding_events (
      case_id, finding_id, tenant_id, actor_id, event_type, details
    ) values (
      new.id,
      new.finding_id,
      new.tenant_id,
      (select auth.uid()),
      case
        when new.workflow_status = 'resolved' then 'confirmed_resolved'
        when old.workflow_status = 'resolved' and new.workflow_status <> 'resolved' then 'reopened'
        else 'workflow_changed'
      end,
      jsonb_build_object('from', old.workflow_status, 'to', new.workflow_status)
    );
  end if;
  return new;
end;
$$;

revoke all on function private.is_internal_admin() from public, anon;
revoke all on function private.has_company_membership(uuid) from public, anon;
revoke all on function private.has_company_role(uuid, text[]) from public, anon;
revoke all on function private.can_access_connection(uuid) from public, anon;
revoke all on function private.can_access_finding(uuid, uuid) from public, anon;
revoke all on function public.current_user_context() from public, anon;
revoke all on function private.touch_updated_at() from public, anon, authenticated;
revoke all on function private.handle_new_auth_user() from public, anon, authenticated;
revoke all on function private.audit_case_workflow_change() from public, anon, authenticated;
grant execute on function private.is_internal_admin() to authenticated, service_role;
grant execute on function private.has_company_membership(uuid) to authenticated, service_role;
grant execute on function private.has_company_role(uuid, text[]) to authenticated, service_role;
grant execute on function private.can_access_connection(uuid) to authenticated, service_role;
grant execute on function private.can_access_finding(uuid, uuid) to authenticated, service_role;
grant execute on function public.current_user_context() to authenticated;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function private.handle_new_auth_user();

create trigger companies_touch_updated_at before update on public.companies
  for each row execute function private.touch_updated_at();
create trigger user_profiles_touch_updated_at before update on public.user_profiles
  for each row execute function private.touch_updated_at();
create trigger wazuh_connections_touch_updated_at before update on public.wazuh_connections
  for each row execute function private.touch_updated_at();
create trigger wazuh_findings_touch_updated_at before update on public.wazuh_findings
  for each row execute function private.touch_updated_at();
create trigger vulnerability_cases_touch_updated_at before update on public.vulnerability_cases
  for each row execute function private.touch_updated_at();
create trigger vulnerability_cases_audit_workflow
  after update of workflow_status on public.vulnerability_cases
  for each row execute function private.audit_case_workflow_change();

alter table public.companies enable row level security;
alter table public.user_profiles enable row level security;
alter table public.company_memberships enable row level security;
alter table public.wazuh_connections enable row level security;
alter table public.wazuh_agent_mappings enable row level security;
alter table public.wazuh_ingest_credentials enable row level security;
alter table public.sync_runs enable row level security;
alter table public.sync_run_pages enable row level security;
alter table public.wazuh_findings enable row level security;
alter table public.vulnerability_cases enable row level security;
alter table public.vulnerability_comments enable row level security;
alter table public.finding_events enable row level security;
alter table public.archive_manifests enable row level security;

create policy companies_read on public.companies
  for select to authenticated
  using (private.is_internal_admin() or private.has_company_membership(id));
create policy companies_internal_manage on public.companies
  for all to authenticated
  using (private.is_internal_admin())
  with check (private.is_internal_admin());

create policy user_profiles_read on public.user_profiles
  for select to authenticated
  using (
    id = (select auth.uid())
    or private.is_internal_admin()
    or exists (
      select 1 from public.company_memberships self_membership
      join public.company_memberships shared_membership
        on shared_membership.company_id = self_membership.company_id
      where self_membership.user_id = (select auth.uid())
        and self_membership.is_active
        and shared_membership.user_id = user_profiles.id
        and shared_membership.is_active
    )
  );
create policy user_profiles_update_self on public.user_profiles
  for update to authenticated
  using (id = (select auth.uid()) or private.is_internal_admin())
  with check (id = (select auth.uid()) or private.is_internal_admin());

create policy company_memberships_read on public.company_memberships
  for select to authenticated
  using (
    user_id = (select auth.uid())
    or private.is_internal_admin()
    or private.has_company_membership(company_id)
  );

create policy wazuh_connections_read on public.wazuh_connections
  for select to authenticated
  using (private.can_access_connection(id));

create policy wazuh_agent_mappings_internal_read on public.wazuh_agent_mappings
  for select to authenticated
  using (private.is_internal_admin());

create policy sync_runs_read on public.sync_runs
  for select to authenticated
  using (private.is_internal_admin() or private.can_access_connection(connection_id));

create policy wazuh_findings_read on public.wazuh_findings
  for select to authenticated
  using (
    private.is_internal_admin()
    or (tenant_id is not null and private.can_access_finding(id, tenant_id))
  );

create policy vulnerability_cases_read on public.vulnerability_cases
  for select to authenticated
  using (
    private.is_internal_admin()
    or private.has_company_membership(tenant_id)
      and private.can_access_finding(finding_id, tenant_id)
  );
create policy vulnerability_cases_update_status on public.vulnerability_cases
  for update to authenticated
  using (
    private.is_internal_admin()
    or (
      private.has_company_role(tenant_id, array['owner', 'admin', 'analyst'])
      and private.can_access_finding(finding_id, tenant_id)
    )
  )
  with check (
    workflow_status in ('open', 'in_progress', 'awaiting_validation')
    and exists (
      select 1 from public.wazuh_findings f
      where f.id = vulnerability_cases.finding_id
        and f.source_state = 'active'
    )
    and (
      private.is_internal_admin()
      or (
        private.has_company_role(tenant_id, array['owner', 'admin', 'analyst'])
        and private.can_access_finding(finding_id, tenant_id)
      )
    )
  );

create policy vulnerability_comments_read on public.vulnerability_comments
  for select to authenticated
  using (
    private.is_internal_admin()
    or (
      visibility = 'shared'
      and private.has_company_membership(tenant_id)
      and private.can_access_finding(finding_id, tenant_id)
    )
  );
create policy vulnerability_comments_insert on public.vulnerability_comments
  for insert to authenticated
  with check (
    private.is_internal_admin()
    or (
      visibility = 'shared'
      and author_id = (select auth.uid())
      and private.has_company_role(tenant_id, array['owner', 'admin', 'analyst'])
      and private.can_access_finding(finding_id, tenant_id)
      and exists (
        select 1 from public.wazuh_findings f
        where f.id = vulnerability_comments.finding_id
          and (
            f.source_state = 'active'
            or f.resolved_at > now() - interval '90 days'
          )
      )
    )
  );

create policy finding_events_read on public.finding_events
  for select to authenticated
  using (
    private.is_internal_admin()
    or (
      tenant_id is not null
      and private.has_company_membership(tenant_id)
      and private.can_access_finding(finding_id, tenant_id)
    )
  );

create policy archive_manifests_internal_read on public.archive_manifests
  for select to authenticated
  using (private.is_internal_admin());

-- No browser role can access connector credentials, sync page receipts, or mutate
-- source findings, mappings, sync runs, events, or archive manifests.
revoke all on all tables in schema public from anon, authenticated;
grant select on public.companies, public.user_profiles, public.company_memberships,
  public.wazuh_agent_mappings, public.sync_runs,
  public.wazuh_findings, public.vulnerability_cases, public.vulnerability_comments,
  public.finding_events, public.archive_manifests to authenticated;
grant select (id, tenant_id, name, mode, is_active, connector_version, last_connected_at, created_at)
  on public.wazuh_connections to authenticated;
grant update (display_name) on public.user_profiles to authenticated;
grant update (workflow_status) on public.vulnerability_cases to authenticated;
grant insert (case_id, finding_id, tenant_id, author_id, visibility, body)
  on public.vulnerability_comments to authenticated;
grant all on all tables in schema public to service_role;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'wazuh-vulnerability-archives',
  'wazuh-vulnerability-archives',
  false,
  52428800,
  array['application/gzip', 'application/json']
)
on conflict (id) do update set
  public = false,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists wazuh_archive_internal_download on storage.objects;
create policy wazuh_archive_internal_download on storage.objects
  for select to authenticated
  using (
    bucket_id = 'wazuh-vulnerability-archives'
    and private.is_internal_admin()
  );
