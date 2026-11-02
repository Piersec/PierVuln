
-- Demo coordinates are explicitly simulated; documentation IPs are never geolocated.
with origins as (
  select jsonb_build_array(
    jsonb_build_object('city','São Paulo','country','Brasil','lat',-23.55,'lng',-46.63),
    jsonb_build_object('city','Nova York','country','Estados Unidos','lat',40.71,'lng',-74.00),
    jsonb_build_object('city','Toronto','country','Canadá','lat',43.65,'lng',-79.38),
    jsonb_build_object('city','Londres','country','Reino Unido','lat',51.51,'lng',-0.13),
    jsonb_build_object('city','Frankfurt','country','Alemanha','lat',50.11,'lng',8.68),
    jsonb_build_object('city','Tóquio','country','Japão','lat',35.68,'lng',139.69),
    jsonb_build_object('city','Sydney','country','Austrália','lat',-33.87,'lng',151.21),
    jsonb_build_object('city','Singapura','country','Singapura','lat',1.35,'lng',103.82),
    jsonb_build_object('city','Paris','country','França','lat',48.86,'lng',2.35),
    jsonb_build_object('city','Lisboa','country','Portugal','lat',38.72,'lng',-9.14),
    jsonb_build_object('city','Santiago','country','Chile','lat',-33.45,'lng',-70.67),
    jsonb_build_object('city','Cidade do Cabo','country','África do Sul','lat',-33.92,'lng',18.42)
  ) as cities
)
update public.soc_alerts a set raw_payload=a.raw_payload || jsonb_build_object('demo_geo',jsonb_build_object(
  'simulated',true,'origin',o.cities->((a.raw_payload->>'sequence')::int%12),
  'destination',jsonb_build_object('city','São Paulo','country','Brasil','lat',-23.55,'lng',-46.63)))
from origins o,public.companies c
where a.tenant_id=c.id and c.slug='demonstracao' and a.raw_payload->>'demo'='true'
  and a.raw_payload->>'sequence' ~ '^[0-9]{1,6}$';

create or replace function public.get_soc_threat_summary(p_tenant_id uuid,p_since timestamptz,p_until timestamptz)
returns jsonb language plpgsql stable security invoker set search_path = '' as $$
declare v_result jsonb;
begin
  if p_since is null or p_until is null or p_until<=p_since or p_since<now()-interval '30 days' or p_until>now()+interval '5 minutes' then
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
