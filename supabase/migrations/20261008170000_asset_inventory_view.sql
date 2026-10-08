create or replace view public.asset_inventory
with (security_invoker = true)
as
select
  f.tenant_id,
  f.connection_id,
  coalesce(nullif(f.agent_id, ''), nullif(f.agent_name, '')) as agent_key,
  max(f.agent_id) as agent_id,
  max(f.agent_name) as agent_name,
  max(f.host_os) as host_os,
  min(f.first_detected_at) as first_detected_at,
  max(public.finding_last_seen(f)) as last_seen_at,
  count(*) filter (where f.source_state = 'active') as active_vulnerabilities
from public.wazuh_findings f
where f.tenant_id is not null
  and (nullif(f.agent_id, '') is not null or nullif(f.agent_name, '') is not null)
group by f.tenant_id, f.connection_id,
  coalesce(nullif(f.agent_id, ''), nullif(f.agent_name, ''));

grant select on public.asset_inventory to authenticated;

notify pgrst, 'reload schema';
