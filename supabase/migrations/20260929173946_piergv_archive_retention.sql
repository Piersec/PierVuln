-- Archive jobs run in the connector/backend with a service-role key. The
-- function refuses to purge anything unless a verified manifest proves the
-- immutable archive was uploaded and read back successfully.
create or replace function public.verify_wazuh_archive(p_manifest_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_updated integer;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;

  update public.archive_manifests am
  set status = 'verified'
  where am.id = p_manifest_id
    and am.status = 'pending'
    and am.archived_at > now() - interval '1 day';
  get diagnostics v_updated = row_count;
  return v_updated = 1;
end;
$$;

create or replace function public.finalize_wazuh_archive(p_manifest_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_manifest public.archive_manifests%rowtype;
  v_deleted_findings integer := 0;
  v_deleted_cases integer := 0;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;

  select * into v_manifest
  from public.archive_manifests am
  where am.id = p_manifest_id
  for update;
  if not found or v_manifest.status <> 'verified' then
    raise exception 'Archive manifest is missing or not verified' using errcode = 'P0002';
  end if;

  if exists (
    select 1
    from unnest(v_manifest.finding_ids) archived(id)
    left join public.wazuh_findings f on f.id = archived.id
    where f.id is null
       or f.tenant_id is distinct from v_manifest.tenant_id
       or f.connection_id is distinct from v_manifest.connection_id
       or f.source_state <> 'resolved'
       or f.resolved_at > now() - interval '90 days'
  ) then
    raise exception 'Archive contains findings that are not eligible for purge' using errcode = '22023';
  end if;

  if exists (
    select 1
    from public.vulnerability_cases vc
    where vc.finding_id = any(v_manifest.finding_ids)
      and vc.tenant_id = v_manifest.tenant_id
      and (vc.workflow_status <> 'resolved' or vc.closed_at > now() - interval '90 days')
  ) then
    raise exception 'Archive contains cases that are not eligible for purge' using errcode = '22023';
  end if;

  delete from public.vulnerability_comments vc
  where vc.finding_id = any(v_manifest.finding_ids)
    and vc.tenant_id = v_manifest.tenant_id;
  delete from public.finding_events fe
  where fe.finding_id = any(v_manifest.finding_ids)
    and fe.tenant_id = v_manifest.tenant_id;
  delete from public.vulnerability_cases vc
  where vc.finding_id = any(v_manifest.finding_ids)
    and vc.tenant_id = v_manifest.tenant_id
    and vc.workflow_status = 'resolved'
    and vc.closed_at <= now() - interval '90 days';
  get diagnostics v_deleted_cases = row_count;

  delete from public.wazuh_findings f
  where f.id = any(v_manifest.finding_ids)
    and f.tenant_id = v_manifest.tenant_id
    and f.connection_id = v_manifest.connection_id
    and f.source_state = 'resolved'
    and f.resolved_at <= now() - interval '90 days';
  get diagnostics v_deleted_findings = row_count;

  if v_deleted_findings <> cardinality(v_manifest.finding_ids) then
    raise exception 'Not all archived findings were purged; transaction rolled back' using errcode = '40001';
  end if;

  update public.archive_manifests
  set status = 'database_purged', database_purged_at = now()
  where id = p_manifest_id;

  return jsonb_build_object(
    'manifestId', p_manifest_id,
    'findingsPurged', v_deleted_findings,
    'casesPurged', v_deleted_cases,
    'status', 'database_purged'
  );
end;
$$;

create or replace function public.expire_wazuh_archive(p_manifest_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_updated integer;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;

  update public.archive_manifests am
  set status = 'expired', expired_at = now()
  where am.id = p_manifest_id
    and am.status = 'database_purged'
    and am.expires_at <= now();
  get diagnostics v_updated = row_count;
  return v_updated = 1;
end;
$$;

revoke all on function public.verify_wazuh_archive(uuid) from public, anon, authenticated;
revoke all on function public.finalize_wazuh_archive(uuid) from public, anon, authenticated;
revoke all on function public.expire_wazuh_archive(uuid) from public, anon, authenticated;
grant execute on function public.verify_wazuh_archive(uuid) to service_role;
grant execute on function public.finalize_wazuh_archive(uuid) to service_role;
grant execute on function public.expire_wazuh_archive(uuid) to service_role;
