set local lock_timeout = '3s';

create table public.finding_content (
  id bigint generated always as identity primary key,
  content_hash bytea not null unique check (octet_length(content_hash) = 32),
  description text,
  reference_urls text[] not null default '{}'
);
alter table public.finding_content enable row level security;
revoke all on public.finding_content from public, anon, authenticated;
grant select on public.finding_content to authenticated;
grant all on public.finding_content to service_role;
grant usage, select on sequence public.finding_content_id_seq to service_role;

alter table public.wazuh_findings add column content_id bigint
  references public.finding_content(id) on delete restrict;
create index findings_content_id_idx on public.wazuh_findings(content_id);

create policy finding_content_read on public.finding_content
for select to authenticated using (
  exists (select 1 from public.wazuh_findings f where f.content_id = finding_content.id)
);

create function public.finding_description(public.wazuh_findings)
returns text language sql stable security invoker set search_path = ''
as $$
  select case when $1.content_id is null then $1.description
    else (select c.description from public.finding_content c where c.id = $1.content_id) end;
$$;

create function public.finding_references(public.wazuh_findings)
returns text[] language sql stable security invoker set search_path = ''
as $$
  select case when $1.content_id is null then $1.reference_urls
    else (select c.reference_urls from public.finding_content c where c.id = $1.content_id) end;
$$;

create function public.finding_last_seen(public.wazuh_findings)
returns timestamptz language sql stable security invoker set search_path = ''
as $$
  select case when $1.source_state = 'active' then greatest($1.last_seen_at, (
    select sr.finished_at from public.wazuh_connections wc
    join public.sync_runs sr on sr.id = wc.published_sync_run_id
    where wc.id = $1.connection_id and sr.status = 'succeeded' and sr.full_snapshot
  )) else $1.last_seen_at end;
$$;

revoke all on function public.finding_description(public.wazuh_findings),
  public.finding_references(public.wazuh_findings), public.finding_last_seen(public.wazuh_findings)
  from public, anon;
grant execute on function public.finding_description(public.wazuh_findings),
  public.finding_references(public.wazuh_findings), public.finding_last_seen(public.wazuh_findings)
  to authenticated, service_role;

notify pgrst, 'reload schema';
