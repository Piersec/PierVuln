alter table public.asset_deletion_requests alter column requested_by drop not null;
alter table public.asset_deletion_requests drop constraint asset_deletion_requests_requested_by_fkey;
alter table public.asset_deletion_requests add constraint asset_deletion_requests_requested_by_fkey
 foreign key(requested_by) references auth.users(id) on delete set null;
