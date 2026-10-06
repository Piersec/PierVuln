set local lock_timeout = '3s';
alter table public.archive_manifests add column source_fingerprint text
  check (source_fingerprint is null or source_fingerprint ~ '^[0-9a-f]{64}$');

create function private.archive_source_bundle(p_ids uuid[], p_tenant uuid)
returns jsonb language sql stable security invoker set search_path = ''
as $$
  select jsonb_build_object(
    'findings', coalesce((select jsonb_agg((to_jsonb(f) - 'content_id') || jsonb_build_object(
      'description', public.finding_description(f), 'reference_urls', public.finding_references(f),
      'last_seen_at', public.finding_last_seen(f)) order by f.id)
      from public.wazuh_findings f where f.id = any(p_ids) and f.tenant_id = p_tenant), '[]'::jsonb),
    'cases', coalesce((select jsonb_agg(to_jsonb(c) order by c.id) from public.vulnerability_cases c
      where c.finding_id = any(p_ids) and c.tenant_id = p_tenant), '[]'::jsonb),
    'comments', coalesce((select jsonb_agg(to_jsonb(c) order by c.id) from public.vulnerability_comments c
      where c.finding_id = any(p_ids) and c.tenant_id = p_tenant), '[]'::jsonb),
    'events', coalesce((select jsonb_agg(to_jsonb(e) order by e.id) from public.finding_events e
      where e.finding_id = any(p_ids) and e.tenant_id = p_tenant), '[]'::jsonb)
  );
$$;
revoke all on function private.archive_source_bundle(uuid[],uuid) from public,anon,authenticated,service_role;

create function public.prepare_archive_source(p_finding_ids uuid[], p_tenant_id uuid)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_bundle jsonb;
begin
  if coalesce((select auth.role()), '') <> 'service_role' then
    raise exception 'Service role required' using errcode = '42501';
  end if;
  if cardinality(p_finding_ids) is null or cardinality(p_finding_ids) not between 1 and 100 then
    raise exception 'Archive batch must contain between 1 and 100 findings';
  end if;
  v_bundle := private.archive_source_bundle(p_finding_ids, p_tenant_id);
  if jsonb_array_length(v_bundle -> 'findings') <> cardinality(p_finding_ids) then
    raise exception 'Archive batch contains unavailable findings';
  end if;
  return v_bundle || jsonb_build_object('sourceFingerprint', encode(
    extensions.digest(convert_to(v_bundle::text, 'UTF8'), 'sha256'), 'hex'));
end;
$$;
revoke all on function public.prepare_archive_source(uuid[],uuid) from public,anon,authenticated;
grant execute on function public.prepare_archive_source(uuid[],uuid) to service_role;

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

  -- Parent row locks also block new comments/events through their foreign keys.
  perform 1 from public.wazuh_findings where id = any(v_manifest.finding_ids) order by id for update;
  perform 1 from public.vulnerability_cases where finding_id = any(v_manifest.finding_ids) order by id for update;
  perform 1 from public.vulnerability_comments where finding_id = any(v_manifest.finding_ids) order by id for update;
  perform 1 from public.finding_events where finding_id = any(v_manifest.finding_ids) order by id for update;

  if v_manifest.source_fingerprint is null or v_manifest.source_fingerprint is distinct from encode(
    extensions.digest(convert_to(private.archive_source_bundle(v_manifest.finding_ids, v_manifest.tenant_id)::text, 'UTF8'), 'sha256'), 'hex'
  ) then
    raise exception 'Archive source changed; database records were preserved' using errcode = '40001';
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

revoke all on function public.finalize_wazuh_archive(uuid) from public,anon,authenticated;
grant execute on function public.finalize_wazuh_archive(uuid) to service_role;
notify pgrst, 'reload schema';

