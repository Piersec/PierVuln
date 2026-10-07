create or replace function private.normalize_finding_content_batch(p_limit integer default 500)
returns integer language plpgsql security definer set search_path = ''
as $$
declare v_changed integer;
begin
  if not pg_try_advisory_xact_lock(20261006, 1) then return 0; end if;
  if exists (select 1 from wazuh_internal.publication_queue where status = 'pending') then return 0; end if;

  with candidates as materialized (
    select id from public.wazuh_findings where content_id is null
    order by id limit least(greatest(p_limit, 1), 2000) for update skip locked
  )
  update public.wazuh_findings f
  set description = f.description, reference_urls = f.reference_urls
  from candidates c where f.id = c.id;
  get diagnostics v_changed = row_count;
  if v_changed = 0 and not exists (select 1 from public.wazuh_findings where content_id is null) then
    perform cron.unschedule('piervuln-normalize-content');
  end if;
  return v_changed;
end;
$$;
revoke all on function private.normalize_finding_content_batch(integer) from public, anon, authenticated, service_role;
