create function public.get_customer_book_metrics(p_company_id uuid default null)
returns jsonb
language sql stable security invoker set search_path = ''
as $$
  with normalized as materialized (
    select
      nullif(btrim(f.vulnerability_id), '') as cve_id,
      case
        when nullif(btrim(f.agent_id), '') is not null then 'id:' || btrim(f.agent_id)
        when nullif(btrim(f.agent_name), '') is not null then 'name:' || lower(btrim(f.agent_name))
      end as host_key,
      case lower(btrim(f.severity))
        when 'critical' then 'Critical'
        when 'high' then 'High'
        when 'medium' then 'Medium'
        when 'low' then 'Low'
        else 'Other'
      end as severity,
      f.first_detected_at,
      greatest(0, floor(extract(epoch from (now() - f.first_detected_at)) / 86400))::integer as age_days,
      to_char(f.first_detected_at at time zone 'America/Sao_Paulo', 'YYYY-MM') as month_key
    from public.wazuh_findings f
    where f.source_state = 'active'
      and (p_company_id is null or f.tenant_id = p_company_id)
  ),
  totals as (
    select
      count(*) as total,
      count(distinct host_key) as affected_hosts,
      count(*) filter (where severity = 'Critical') as critical,
      count(*) filter (where severity = 'High') as high,
      count(*) filter (where severity = 'Medium') as medium,
      count(*) filter (where severity = 'Low') as low,
      count(*) filter (where severity = 'Other') as other_severity,
      count(*) filter (where age_days > 90) as over_90,
      count(*) filter (where age_days between 61 and 90) as days_61_90,
      count(*) filter (where age_days between 31 and 60) as days_31_60,
      count(*) filter (where age_days between 0 and 30) as days_0_30
    from normalized
  ),
  cves as (
    select cve_id, count(*) as count, count(distinct host_key) as hosts,
      min(first_detected_at) as first_detected
    from normalized
    where cve_id is not null
    group by cve_id
  )
  select jsonb_build_object(
    'total', t.total,
    'affected_hosts', t.affected_hosts,
    'critical_high', t.critical + t.high,
    'other_severity', t.other_severity,
    'prolonged', t.over_90,
    'severity', jsonb_build_object(
      'Critical', t.critical, 'High', t.high, 'Medium', t.medium, 'Low', t.low
    ),
    'ages', jsonb_build_object(
      'over90', t.over_90, 'days61to90', t.days_61_90,
      'days31to60', t.days_31_60, 'days0to30', t.days_0_30
    ),
    'unique_cves', (select count(*) from cves),
    'months', (
      select coalesce(jsonb_object_agg(month_key, count), '{}'::jsonb)
      from (select month_key, count(*) as count from normalized group by month_key) monthly
    ),
    'top', (
      select coalesce(jsonb_agg(jsonb_build_object(
        'id', cve_id, 'hosts', hosts, 'count', count, 'firstDetected', first_detected
      )), '[]'::jsonb)
      from (select * from cves order by hosts desc, count desc, cve_id limit 3) top_cves
    )
  )
  from totals t;
$$;

revoke all on function public.get_customer_book_metrics(uuid) from public, anon;
grant execute on function public.get_customer_book_metrics(uuid) to authenticated;
notify pgrst, 'reload schema';
