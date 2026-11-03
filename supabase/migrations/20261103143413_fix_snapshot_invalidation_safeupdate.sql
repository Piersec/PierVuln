create or replace function private.mark_overview_snapshots_stale()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  update public.vulnerability_overview_snapshots
  set stale = true
  where not stale;
  return null;
end;
$$;
revoke all on function private.mark_overview_snapshots_stale() from public, anon, authenticated, service_role;
