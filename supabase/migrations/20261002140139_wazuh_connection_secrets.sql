-- Ciphertext is produced by the admin Edge Function with AES-256-GCM.
-- Plaintext Indexer credentials and ingest tokens are returned only to the
-- authenticated worker-config Edge Function.
create table public.wazuh_connection_secrets (
  connection_id uuid primary key
    references public.wazuh_connections(id) on delete cascade,
  nonce text not null check (nonce ~ '^[A-Za-z0-9+/]{16}$'),
  ciphertext text not null check (length(ciphertext) between 1 and 131072),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.wazuh_connection_secrets enable row level security;
revoke all on public.wazuh_connection_secrets from public, anon, authenticated;
grant select, insert, update, delete on public.wazuh_connection_secrets to service_role;

create policy wazuh_connection_secrets_deny_browser
  on public.wazuh_connection_secrets
  for all to anon, authenticated
  using (false)
  with check (false);

create trigger wazuh_connection_secrets_touch_updated_at
  before update on public.wazuh_connection_secrets
  for each row execute function private.touch_updated_at();

create or replace function public.store_wazuh_connection_secret(
  p_connection_id uuid,
  p_nonce text,
  p_ciphertext text,
  p_token_sha256 text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.role() <> 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;
  if p_nonce is null or p_ciphertext is null or p_token_sha256 is null
     or p_nonce !~ '^[A-Za-z0-9+/]{16}$'
     or length(p_ciphertext) not between 1 and 131072
     or p_token_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid encrypted connection config' using errcode = '22023';
  end if;
  if not exists (
    select 1 from public.wazuh_connections where id = p_connection_id
  ) then
    raise exception 'connection not found' using errcode = 'P0002';
  end if;

  insert into public.wazuh_connection_secrets (connection_id, nonce, ciphertext)
  values (p_connection_id, p_nonce, p_ciphertext)
  on conflict (connection_id) do update
    set nonce = excluded.nonce,
        ciphertext = excluded.ciphertext;

  insert into public.wazuh_ingest_credentials (connection_id, token_sha256, rotated_at)
  values (p_connection_id, p_token_sha256, now())
  on conflict (connection_id) do update
    set token_sha256 = excluded.token_sha256,
        rotated_at = now();
end;
$$;

revoke all on function public.store_wazuh_connection_secret(uuid, text, text, text)
  from public, anon, authenticated;
grant execute on function public.store_wazuh_connection_secret(uuid, text, text, text)
  to service_role;
