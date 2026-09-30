-- invited_at is written by the privileged Auth invitation flow, not by signup metadata.
create function private.grant_pier_auth_invite()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.invited_at is not null
     and lower(btrim(new.email)) ~ '^[^@[:space:]]+@piersec[.]com[.]br$' then
    insert into private.internal_admins (user_id)
    values (new.id)
    on conflict (user_id) do nothing;
  end if;
  return new;
end;
$$;

revoke all on function private.grant_pier_auth_invite() from public, anon, authenticated;

-- Auth first creates the user, then records invited_at when sending the invitation.
create trigger on_pier_auth_invite
after insert or update of invited_at on auth.users
for each row execute function private.grant_pier_auth_invite();

insert into private.internal_admins (user_id)
select id from auth.users
where invited_at is not null
  and lower(btrim(email)) ~ '^[^@[:space:]]+@piersec[.]com[.]br$'
on conflict (user_id) do nothing;
