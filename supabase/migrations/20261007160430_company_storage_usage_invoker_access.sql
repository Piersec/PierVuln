grant select on private.company_storage_snapshot to authenticated;
create policy company_storage_snapshot_admin_read on private.company_storage_snapshot
  for select to authenticated using ((select private.is_internal_admin()));
alter function public.get_company_storage_usage() security invoker;
notify pgrst, 'reload schema';

