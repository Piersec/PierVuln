create or replace function public.get_soc_threat_summary(p_tenant_id uuid,p_since timestamptz,p_until timestamptz)
returns jsonb language plpgsql stable security invoker set search_path = '' as $$
declare v_result jsonb;
begin
  if p_since is null or p_until is null or p_until<=p_since or p_since<now()-interval '30 days 5 minutes' or p_until-p_since>interval '30 days' or p_until>now()+interval '5 minutes' then
    raise exception 'Intervalo de ameaças inválido' using errcode='22023';
  end if;
  if p_tenant_id is not null and not (private.is_internal_admin() or private.has_company_membership(p_tenant_id)) then
    raise exception 'Acesso à empresa não autorizado' using errcode='42501';
  end if;
  with filtered as (
    select a.*,case when c.slug='demonstracao' and a.raw_payload->>'demo'='true' then a.raw_payload->'demo_geo' end demo_geo from public.soc_alerts a join public.companies c on c.id=a.tenant_id where (p_tenant_id is null or a.tenant_id=p_tenant_id)
      and a.occurred_at>=p_since and a.occurred_at<p_until
  ), tactics as (
    select t.value name,count(distinct f.id)::bigint total from filtered f cross join lateral unnest(f.mitre_tactics) t(value)
    group by t.value order by count(distinct f.id) desc,t.value limit 10
  ), techniques as (
    select x.value name,count(distinct f.id)::bigint total from filtered f cross join lateral unnest(f.mitre_techniques) x(value)
    group by x.value order by count(distinct f.id) desc,x.value limit 10
  ), geo_routes as (
    select demo_geo->'origin' origin,demo_geo->'destination' destination,severity,count(*) total
    from filtered where demo_geo->>'simulated'='true'
    group by demo_geo->'origin',demo_geo->'destination',severity
    order by count(*) desc limit 100
  ), countries as (
    select demo_geo#>>'{origin,country}' name,count(*) total from filtered
    where demo_geo->>'simulated'='true' group by demo_geo#>>'{origin,country}' order by count(*) desc
  ), events as (
    select id,occurred_at,title,source_name,agent_name,src_ip,dst_ip,mitre_ids,mitre_tactics,mitre_techniques
    from filtered order by occurred_at desc,id desc limit 20
  )
  select jsonb_build_object(
    'queried_at',now(),'total',count(*),
    'geolocation_available',coalesce(bool_or(demo_geo->>'simulated'='true'),false),
    'geo_routes',coalesce((select jsonb_agg(jsonb_build_object('origin',origin,'destination',destination,'severity',severity,'count',total)) from geo_routes),'[]'::jsonb),
    'geo_countries',coalesce((select jsonb_agg(jsonb_build_object('name',name,'count',total)) from countries),'[]'::jsonb),
    'tactics',coalesce((select jsonb_agg(jsonb_build_object('name',name,'count',total) order by total desc) from tactics),'[]'::jsonb),
    'techniques',coalesce((select jsonb_agg(jsonb_build_object('name',name,'count',total) order by total desc) from techniques),'[]'::jsonb),
    'events',coalesce((select jsonb_agg(jsonb_build_object('id',id,'occurred_at',occurred_at,'title',title,'source_name',source_name,'agent_name',agent_name,'src_ip',src_ip,'dst_ip',dst_ip,'mitre_ids',mitre_ids,'mitre_tactics',mitre_tactics,'mitre_techniques',mitre_techniques) order by occurred_at desc) from events),'[]'::jsonb),
    'events_with_mitre',count(*) filter(where cardinality(mitre_ids)>0 or cardinality(mitre_tactics)>0 or cardinality(mitre_techniques)>0),
    'events_with_geo',count(*) filter(where demo_geo->>'simulated'='true')
  ) into v_result from filtered;
  return v_result;
end;
$$;
revoke all on function public.get_soc_threat_summary(uuid,timestamptz,timestamptz) from public,anon;
grant execute on function public.get_soc_threat_summary(uuid,timestamptz,timestamptz) to authenticated,service_role;
