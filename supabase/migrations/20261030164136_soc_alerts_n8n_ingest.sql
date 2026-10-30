create table public.soc_ingest_credentials (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.companies(id) on delete cascade,
  name text not null check (length(btrim(name)) between 1 and 80),
  token_prefix text not null check (length(token_prefix) between 8 and 24),
  token_sha256 text not null unique check (token_sha256 ~ '^[0-9a-f]{64}$'),
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  last_received_at timestamptz,
  last_batch_events integer not null default 0 check (last_batch_events >= 0),
  last_inserted integer not null default 0 check (last_inserted >= 0),
  last_duplicates integer not null default 0 check (last_duplicates >= 0),
  last_error text check (last_error is null or length(last_error) <= 240)
);

create index soc_ingest_credentials_tenant_active_idx
  on public.soc_ingest_credentials (tenant_id, created_at desc)
  where revoked_at is null;

create table public.soc_alerts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.companies(id) on delete cascade,
  source_id text not null check (length(btrim(source_id)) between 1 and 128),
  source_name text not null check (length(btrim(source_name)) between 1 and 160),
  source_category text,
  source_vendor text,
  source_product text,
  source_event_id text not null check (length(btrim(source_event_id)) between 1 and 512),
  source_index text,
  source_document_id text,
  occurred_at timestamptz not null,
  severity text not null check (severity in ('critical', 'high', 'medium', 'low', 'informational', 'unknown')),
  severity_original text,
  title text not null check (length(btrim(title)) between 1 and 500),
  message text,
  rule_id text,
  rule_description text,
  rule_level smallint check (rule_level is null or rule_level between 0 and 255),
  agent_id text,
  agent_name text,
  agent_ip text,
  src_ip text,
  dst_ip text,
  src_port integer check (src_port is null or src_port between 0 and 65535),
  dst_port integer check (dst_port is null or dst_port between 0 and 65535),
  network_protocol text,
  service text,
  src_user text,
  dst_user text,
  source_action text,
  normalized_action text,
  mitre_ids text[] not null default '{}',
  mitre_tactics text[] not null default '{}',
  mitre_techniques text[] not null default '{}',
  file_path text,
  file_action text,
  file_hash_before text,
  file_hash_after text,
  file_owner_after text,
  change_actor text,
  change_process text,
  raw_payload jsonb check (raw_payload is null or pg_column_size(raw_payload) <= 8192),
  first_received_at timestamptz not null default now(),
  last_received_at timestamptz not null default now(),
  delivery_count integer not null default 1 check (delivery_count >= 1),
  unique (tenant_id, source_id, source_event_id)
);

create index soc_alerts_tenant_time_idx
  on public.soc_alerts (tenant_id, occurred_at desc, id desc);
create index soc_alerts_tenant_severity_time_idx
  on public.soc_alerts (tenant_id, severity, occurred_at desc);
create index soc_alerts_tenant_source_time_idx
  on public.soc_alerts (tenant_id, source_id, occurred_at desc);
create index soc_alerts_retention_idx
  on public.soc_alerts (occurred_at);
create index soc_alerts_mitre_ids_gin_idx
  on public.soc_alerts using gin (mitre_ids);

create table public.soc_alert_daily_rollups (
  tenant_id uuid not null references public.companies(id) on delete cascade,
  alert_day date not null,
  severity text not null check (severity in ('critical', 'high', 'medium', 'low', 'informational', 'unknown')),
  alert_count bigint not null default 0 check (alert_count >= 0),
  updated_at timestamptz not null default now(),
  primary key (tenant_id, alert_day, severity)
);

alter table public.soc_ingest_credentials enable row level security;
alter table public.soc_alerts enable row level security;
alter table public.soc_alert_daily_rollups enable row level security;

revoke all on public.soc_ingest_credentials from public, anon, authenticated;
grant all on public.soc_ingest_credentials to service_role;

revoke all on public.soc_alerts from public, anon, authenticated;
grant select on public.soc_alerts to authenticated;
grant all on public.soc_alerts to service_role;
create policy soc_alerts_read_company on public.soc_alerts
  for select to authenticated
  using (private.is_internal_admin() or private.has_company_membership(tenant_id));

revoke all on public.soc_alert_daily_rollups from public, anon, authenticated;
grant select on public.soc_alert_daily_rollups to authenticated;
grant all on public.soc_alert_daily_rollups to service_role;
create policy soc_alert_daily_rollups_read_company on public.soc_alert_daily_rollups
  for select to authenticated
  using (private.is_internal_admin() or private.has_company_membership(tenant_id));

create or replace function public.ingest_soc_alert_batch(p_credential_id uuid, p_events jsonb)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_tenant_id uuid;
  v_event jsonb;
  v_id uuid;
  v_inserted integer := 0;
  v_duplicates integer := 0;
  v_total integer;
  v_severity text;
  v_source_id text;
  v_source_event_id text;
  v_occurred_at timestamptz;
begin
  if (select auth.jwt()->>'role') is distinct from 'service_role' then
    raise exception 'service role required' using errcode = '42501';
  end if;
  if p_events is null or jsonb_typeof(p_events) <> 'array' then
    raise exception 'events must be an array' using errcode = '22023';
  end if;
  v_total := jsonb_array_length(p_events);
  if v_total < 1 or v_total > 100 then
    raise exception 'batch size must be between 1 and 100' using errcode = '22023';
  end if;

  select c.tenant_id
    into v_tenant_id
    from public.soc_ingest_credentials c
    join public.companies co on co.id = c.tenant_id and co.is_active
   where c.id = p_credential_id and c.revoked_at is null;
  if v_tenant_id is null then
    raise exception 'credential unavailable' using errcode = '42501';
  end if;

  for v_event in
    select value from jsonb_array_elements(p_events) as batch(value)
  loop
    v_source_id := nullif(btrim(v_event->>'source_id'), '');
    v_source_event_id := nullif(btrim(v_event->>'source_event_id'), '');
    v_occurred_at := (v_event->>'occurred_at')::timestamptz;
    v_severity := v_event->>'severity';

    insert into public.soc_alerts (
      tenant_id, source_id, source_name, source_category, source_vendor, source_product,
      source_event_id, source_index, source_document_id, occurred_at, severity, severity_original,
      title, message, rule_id, rule_description, rule_level, agent_id, agent_name, agent_ip,
      src_ip, dst_ip, src_port, dst_port, network_protocol, service, src_user, dst_user,
      source_action, normalized_action, mitre_ids, mitre_tactics, mitre_techniques,
      file_path, file_action, file_hash_before, file_hash_after, file_owner_after,
      change_actor, change_process, raw_payload
    ) values (
      v_tenant_id, v_source_id, v_event->>'source_name', v_event->>'source_category',
      v_event->>'source_vendor', v_event->>'source_product', v_source_event_id,
      v_event->>'source_index', v_event->>'source_document_id', v_occurred_at, v_severity,
      v_event->>'severity_original', v_event->>'title', v_event->>'message',
      v_event->>'rule_id', v_event->>'rule_description', nullif(v_event->>'rule_level', '')::smallint,
      v_event->>'agent_id', v_event->>'agent_name', v_event->>'agent_ip',
      v_event->>'src_ip', v_event->>'dst_ip', nullif(v_event->>'src_port', '')::integer,
      nullif(v_event->>'dst_port', '')::integer, v_event->>'network_protocol', v_event->>'service',
      v_event->>'src_user', v_event->>'dst_user', v_event->>'source_action',
      v_event->>'normalized_action',
      array(select jsonb_array_elements_text(coalesce(v_event->'mitre_ids', '[]'::jsonb))),
      array(select jsonb_array_elements_text(coalesce(v_event->'mitre_tactics', '[]'::jsonb))),
      array(select jsonb_array_elements_text(coalesce(v_event->'mitre_techniques', '[]'::jsonb))),
      v_event->>'file_path', v_event->>'file_action', v_event->>'file_hash_before',
      v_event->>'file_hash_after', v_event->>'file_owner_after', v_event->>'change_actor',
      v_event->>'change_process',
      case when jsonb_typeof(v_event->'raw_payload') = 'object' then v_event->'raw_payload' else null end
    ) on conflict (tenant_id, source_id, source_event_id) do nothing
    returning id into v_id;

    if v_id is null then
      update public.soc_alerts
         set last_received_at = now(), delivery_count = delivery_count + 1
       where tenant_id = v_tenant_id
         and source_id = v_source_id
         and source_event_id = v_source_event_id;
      v_duplicates := v_duplicates + 1;
    else
      insert into public.soc_alert_daily_rollups (tenant_id, alert_day, severity, alert_count)
      values (v_tenant_id, (v_occurred_at at time zone 'UTC')::date, v_severity, 1)
      on conflict (tenant_id, alert_day, severity) do update
        set alert_count = public.soc_alert_daily_rollups.alert_count + 1,
            updated_at = now();
      v_inserted := v_inserted + 1;
    end if;
    v_id := null;
  end loop;

  update public.soc_ingest_credentials
     set last_received_at = now(), last_batch_events = v_total,
         last_inserted = v_inserted, last_duplicates = v_duplicates, last_error = null
   where id = p_credential_id;

  return jsonb_build_object('accepted', v_total, 'inserted', v_inserted, 'duplicates', v_duplicates);
end;
$function$;

revoke all on function public.ingest_soc_alert_batch(uuid, jsonb) from public, anon, authenticated;
grant execute on function public.ingest_soc_alert_batch(uuid, jsonb) to service_role;

create or replace function public.get_soc_alert_summary(
  p_tenant_id uuid,
  p_since timestamptz,
  p_until timestamptz
)
returns jsonb
language plpgsql
stable
security invoker
set search_path = ''
as $function$
declare
  v_unit text;
  v_step interval;
  v_start timestamp;
  v_end timestamp;
  v_result jsonb;
begin
  if p_since is null or p_until is null or p_until <= p_since
     or p_until > now() + interval '5 minutes'
     or p_since < now() - interval '30 days' then
    raise exception 'summary range must be inside the last 30 days' using errcode = '22023';
  end if;
  if p_tenant_id is not null
     and not (select private.is_internal_admin())
     and not (select private.has_company_membership(p_tenant_id)) then
    raise exception 'company access denied' using errcode = '42501';
  end if;

  v_unit := case when p_until - p_since <= interval '48 hours' then 'hour' else 'day' end;
  v_step := case when v_unit = 'hour' then interval '1 hour' else interval '1 day' end;
  v_start := date_trunc(v_unit, p_since at time zone 'UTC');
  v_end := date_trunc(v_unit, (p_until - interval '1 microsecond') at time zone 'UTC');

  with filtered as (
    select a.*
      from public.soc_alerts a
     where (p_tenant_id is null or a.tenant_id = p_tenant_id)
       and a.occurred_at >= p_since and a.occurred_at < p_until
  ),
  totals as (
    select count(*)::bigint as total,
           count(*) filter (where severity in ('critical', 'high'))::bigint as critical_high,
           count(*) filter (where severity = 'critical')::bigint as critical,
           count(*) filter (where severity = 'high')::bigint as high,
           count(*) filter (where severity = 'medium')::bigint as medium,
           count(*) filter (where severity = 'low')::bigint as low,
           count(*) filter (where severity = 'informational')::bigint as informational,
           count(*) filter (where severity = 'unknown')::bigint as unknown,
           count(distinct source_id)::bigint as sources
      from filtered
  ),
  buckets as (
    select generate_series(v_start, v_end, v_step) as bucket
  ),
  series as (
    select b.bucket, count(f.id)::bigint as total
      from buckets b
      left join filtered f
        on date_trunc(v_unit, f.occurred_at at time zone 'UTC') = b.bucket
     group by b.bucket
  )
  select jsonb_build_object(
    'total', t.total,
    'critical_high', t.critical_high,
    'unknown', t.unknown,
    'sources', t.sources,
    'severity', jsonb_build_object(
      'critical', t.critical, 'high', t.high, 'medium', t.medium,
      'low', t.low, 'informational', t.informational, 'unknown', t.unknown
    ),
    'series', coalesce((select jsonb_agg(jsonb_build_object(
      'bucket', to_char(s.bucket, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), 'count', s.total
    ) order by s.bucket) from series s), '[]'::jsonb),
    'top_sources', coalesce((
      select jsonb_agg(jsonb_build_object('id', ranked.source_id, 'name', ranked.source_name,
        'category', ranked.source_category, 'count', ranked.total) order by ranked.total desc)
        from (select source_id, max(source_name) as source_name, max(source_category) as source_category,
                     count(*)::bigint as total
                from filtered group by source_id order by count(*) desc, source_id limit 5) ranked
    ), '[]'::jsonb),
    'top_rules', coalesce((
      select jsonb_agg(jsonb_build_object('id', ranked.rule_id, 'name', ranked.rule_description,
        'count', ranked.total) order by ranked.total desc)
        from (select rule_id, max(rule_description) as rule_description, count(*)::bigint as total
                from filtered where rule_id is not null group by rule_id
                order by count(*) desc, rule_id limit 5) ranked
    ), '[]'::jsonb),
    'bucket_unit', v_unit,
    'queried_at', now()
  ) into v_result from totals t;

  return v_result;
end;
$function$;

revoke all on function public.get_soc_alert_summary(uuid, timestamptz, timestamptz) from public, anon;
grant execute on function public.get_soc_alert_summary(uuid, timestamptz, timestamptz) to authenticated, service_role;

do $publication$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
        where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'soc_alerts'
     ) then
    execute 'alter publication supabase_realtime add table public.soc_alerts';
  end if;
end;
$publication$;

do $retention$
declare
  v_job_id bigint;
begin
  select jobid into v_job_id from cron.job where jobname = 'piervuln-soc-alert-retention' limit 1;
  if v_job_id is not null then perform cron.unschedule(v_job_id); end if;
  perform cron.schedule(
    'piervuln-soc-alert-retention',
    '15 * * * *',
    $job$delete from public.soc_alerts
      where id in (
        select id from public.soc_alerts
         where occurred_at < now() - interval '30 days'
         order by occurred_at asc
         limit 5000
      )$job$
  );
end;
$retention$;
