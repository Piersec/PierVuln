alter table public.user_profiles
  add column onboarding_completed_at timestamptz;

update public.user_profiles as profile
set onboarding_completed_at = now()
from auth.users as account
where profile.id = account.id
  and nullif(account.encrypted_password, '') is not null;

grant update (onboarding_completed_at) on public.user_profiles to authenticated;

create function private.keep_onboarding_complete()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if old.onboarding_completed_at is not null
    and new.onboarding_completed_at is distinct from old.onboarding_completed_at then
    raise exception 'Completed onboarding cannot be reopened';
  end if;
  return new;
end;
$$;

create trigger user_profiles_keep_onboarding_complete
before update of onboarding_completed_at on public.user_profiles
for each row execute function private.keep_onboarding_complete();
