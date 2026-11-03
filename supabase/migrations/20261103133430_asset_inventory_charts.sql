create function public.get_asset_inventory_charts(p_company_id uuid default null)
returns jsonb language sql stable security invoker set search_path = '' as $body$
with scoped as materialized (
  select a.tenant_id, a.agent_id, a.agent_name, a.connection_id, a.status, a.last_keep_alive_at,
    coalesce(nullif(trim(a.host_os), ''), 'Não informado') as host_os
  from public.asset_agents a
  where p_company_id is null or a.tenant_id = p_company_id
), statuses as (
  select status as name, count(*) as count from scoped group by status
), systems as (
  select host_os as name, count(*) as count from scoped group by host_os
  order by count(*) desc, host_os limit 5
), critical as (
  select s.agent_name as name, 1 as count, s.status as detail,
    s.status <> 'active' as offline, s.last_keep_alive_at, s.agent_id, s.connection_id
  from scoped s
  join public.asset_classifications c on c.tenant_id = s.tenant_id and c.agent_key = s.agent_id
  where c.is_critical
  order by offline desc, s.last_keep_alive_at asc nulls first, s.agent_name, s.agent_id, s.connection_id
  limit 5
)
select jsonb_build_object(
  'statuses', coalesce((select jsonb_agg(to_jsonb(s) order by array_position(array['active','disconnected','pending','never_connected','unknown'], s.name)) from statuses s), '[]'::jsonb),
  'systems', coalesce((select jsonb_agg(to_jsonb(s) order by s.count desc, s.name) from systems s), '[]'::jsonb),
  'critical_assets', coalesce((select jsonb_agg(jsonb_build_object('name', name, 'count', count, 'detail', detail) order by offline desc, last_keep_alive_at asc nulls first, name, agent_id, connection_id) from critical), '[]'::jsonb)
);
$body$;
revoke all on function public.get_asset_inventory_charts(uuid) from public, anon;
grant execute on function public.get_asset_inventory_charts(uuid) to authenticated;
notify pgrst, 'reload schema';
