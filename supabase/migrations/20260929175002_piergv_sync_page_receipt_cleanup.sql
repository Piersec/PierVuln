-- Receipts are retained only while a full snapshot is in progress. Runs and
-- counters remain as audit history after success, failure, partial status, or
-- stale-run retirement.
create or replace function private.cleanup_sync_run_pages()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.status = 'running' and new.status <> 'running' then
    delete from public.sync_run_pages where run_id = new.id;
  end if;
  return new;
end;
$$;

revoke all on function private.cleanup_sync_run_pages() from public, anon, authenticated;

create trigger sync_run_pages_cleanup_after_close
  after update of status on public.sync_runs
  for each row
  when (old.status = 'running' and new.status <> 'running')
  execute function private.cleanup_sync_run_pages();
