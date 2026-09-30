alter table public.user_profiles
  add column avatar_path text,
  add column disabled_notification_types text[] not null default '{}';

alter table public.user_profiles
  add constraint user_profiles_avatar_owned_path
    check (avatar_path is null or avatar_path like id::text || '/%'),
  add constraint user_profiles_notification_types_known
    check (disabled_notification_types <@ array[
      'actions', 'errors', 'admin_changes', 'sync', 'archives', 'connectivity', 'security'
    ]::text[]);

grant update (avatar_path, disabled_notification_types) on public.user_profiles to authenticated;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('profile-avatars', 'profile-avatars', false, 2097152, array['image/webp'])
on conflict (id) do update set
  public = false,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

create policy profile_avatars_read_own on storage.objects
  for select to authenticated
  using (bucket_id = 'profile-avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy profile_avatars_upload_own on storage.objects
  for insert to authenticated
  with check (bucket_id = 'profile-avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy profile_avatars_delete_own on storage.objects
  for delete to authenticated
  using (bucket_id = 'profile-avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
