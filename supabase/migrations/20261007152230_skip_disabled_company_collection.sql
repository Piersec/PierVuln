set local lock_timeout = '3s';
do $migration$
declare
  v_definition text;
  v_anchor text := '    select f.* into v_old';
  v_guard text := $guard$
    if v_connection.mode = 'shared' and v_tenant_id is null and exists (
      select 1
      from public.wazuh_agent_mappings mapping
      join public.companies company on company.id = mapping.tenant_id
      where mapping.connection_id = v_connection.id
        and (not mapping.is_active or not company.is_active)
        and (
          (mapping.match_type = 'agent_id' and mapping.match_value = coalesce(v_agent_id, ''))
          or (mapping.match_type = 'group'
            and mapping.match_value = any(array(select jsonb_array_elements_text(v_groups))))
          or (mapping.match_type = 'agent_name_prefix'
            and v_agent_name is not null
            and right(mapping.match_value, 1) = '*'
            and char_length(mapping.match_value) > 1
            and left(lower(v_agent_name), char_length(mapping.match_value) - 1)
              = lower(left(mapping.match_value, char_length(mapping.match_value) - 1)))
        )
    ) then
      continue;
    end if;
$guard$;
begin
  select pg_get_functiondef('wazuh_internal.apply_wazuh_batch(uuid,uuid,integer,text,jsonb)'::regprocedure)
  into v_definition;
  if position(v_guard in v_definition) > 0 then return; end if;
  if position(v_anchor in v_definition) = 0
    or position(v_anchor in substring(v_definition from position(v_anchor in v_definition) + char_length(v_anchor))) > 0 then
    raise exception 'Publisher definition does not contain exactly one expected insertion point';
  end if;
  execute replace(v_definition, v_anchor, v_guard || v_anchor);
end;
$migration$;
