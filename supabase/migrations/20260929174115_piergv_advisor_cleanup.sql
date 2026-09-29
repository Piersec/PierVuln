-- Keep the caller-context RPC under the caller's privileges. It only returns
-- that caller's own memberships, protected by the same RLS policies as tables.
alter function public.current_user_context() security invoker;

drop policy companies_internal_manage on public.companies;
create policy companies_internal_insert on public.companies
  for insert to authenticated
  with check (private.is_internal_admin());
create policy companies_internal_update on public.companies
  for update to authenticated
  using (private.is_internal_admin())
  with check (private.is_internal_admin());
create policy companies_internal_delete on public.companies
  for delete to authenticated
  using (private.is_internal_admin());

create policy internal_admins_deny_external on private.internal_admins
  for all to anon, authenticated
  using (false)
  with check (false);
create policy ingest_credentials_deny_browser on public.wazuh_ingest_credentials
  for all to anon, authenticated
  using (false)
  with check (false);
create policy sync_run_pages_deny_browser on public.sync_run_pages
  for all to anon, authenticated
  using (false)
  with check (false);

create index internal_admins_created_by_idx on private.internal_admins(created_by);
create index company_memberships_invited_by_idx on public.company_memberships(invited_by);
create index archive_manifests_connection_idx on public.archive_manifests(connection_id);
create index archive_manifests_tenant_idx on public.archive_manifests(tenant_id);
create index finding_events_actor_idx on public.finding_events(actor_id);
create index finding_events_tenant_idx on public.finding_events(tenant_id);
create index finding_events_case_finding_tenant_idx
  on public.finding_events(case_id, finding_id, tenant_id);
create index vulnerability_cases_assigned_to_idx on public.vulnerability_cases(assigned_to);
create index vulnerability_comments_author_idx on public.vulnerability_comments(author_id);
create index vulnerability_comments_tenant_idx on public.vulnerability_comments(tenant_id);
create index vulnerability_comments_case_finding_tenant_idx
  on public.vulnerability_comments(case_id, finding_id, tenant_id);
create index wazuh_agent_mappings_created_by_idx on public.wazuh_agent_mappings(created_by);
create index wazuh_findings_last_seen_sync_idx on public.wazuh_findings(last_seen_sync_run_id);
