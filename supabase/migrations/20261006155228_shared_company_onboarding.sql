set local lock_timeout = '5s';

-- A company and both routing rules are created in one transaction. Prefix/group
-- rules are authoritative; exact agent IDs remain as the fallback for exceptions.
create or replace function public.configure_shared_company(
  p_connection_id uuid,
  p_tenant_id uuid,
  p_company_name text,
  p_company_slug text,
  p_agent_name_prefix text,
  p_group text,
  p_created_by uuid
)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_connection_id uuid;
  v_tenant_id uuid;
  v_group_mapping_id uuid;
  v_prefix_mapping_id uuid;
  v_remapped_agent_ids integer := 0;
begin
  if p_connection_id is null
     or p_agent_name_prefix is null
     or p_agent_name_prefix !~ '^[A-Za-z0-9._-]{1,80}$'
     or p_group is null
     or p_group !~ '^[A-Za-z0-9._-]{1,160}$'
     or (p_tenant_id is null and (
       p_company_name is null
       or length(btrim(p_company_name)) not between 2 and 160
       or p_company_slug is null
       or p_company_slug !~ '^[a-z0-9]+(-[a-z0-9]+)*$'
     )) then
    raise exception 'Invalid shared company configuration' using errcode = '22023';
  end if;

  select wc.id into v_connection_id
  from public.wazuh_connections wc
  where wc.id = p_connection_id
    and wc.mode = 'shared'
    and wc.is_active
  for update;
  if not found then
    raise exception 'Shared connection is missing or inactive' using errcode = 'P0002';
  end if;

  if exists (
    select 1
    from public.wazuh_agent_mappings wam
    join public.companies c on c.id = wam.tenant_id and c.is_active
    where wam.connection_id = v_connection_id
      and wam.is_active
      and wam.match_type = 'agent_name_prefix'
      and (p_tenant_id is null or wam.tenant_id <> p_tenant_id)
      and (
        left(lower(left(wam.match_value, char_length(wam.match_value) - 1)), char_length(p_agent_name_prefix)) = lower(p_agent_name_prefix)
        or left(lower(p_agent_name_prefix), char_length(wam.match_value) - 1) = lower(left(wam.match_value, char_length(wam.match_value) - 1))
      )
      and wam.match_value ~ '^[A-Za-z0-9._-]+\*$'
  ) then
    raise exception 'Agent name prefix overlaps another company' using errcode = '23505';
  end if;

  if p_tenant_id is null then
    insert into public.companies (name, slug)
    values (btrim(p_company_name), p_company_slug)
    returning id into v_tenant_id;
  else
    select c.id into v_tenant_id
    from public.companies c
    where c.id = p_tenant_id and c.is_active;
    if not found then
      raise exception 'Company is missing or inactive' using errcode = 'P0002';
    end if;
  end if;

  insert into public.wazuh_agent_mappings (
    connection_id, tenant_id, match_type, match_value, is_active, created_by
  ) values (
    v_connection_id, v_tenant_id, 'group'::public.wazuh_match_type, p_group, true, p_created_by
  )
  on conflict (connection_id, match_type, match_value) do update
    set is_active = true,
        created_by = coalesce(excluded.created_by, public.wazuh_agent_mappings.created_by)
    where public.wazuh_agent_mappings.tenant_id = excluded.tenant_id
  returning id into v_group_mapping_id;
  if not found then
    raise exception 'Group is already assigned to another company' using errcode = '23505';
  end if;

  insert into public.wazuh_agent_mappings (
    connection_id, tenant_id, match_type, match_value, is_active, created_by
  ) values (
    v_connection_id, v_tenant_id, 'agent_name_prefix'::public.wazuh_match_type, p_agent_name_prefix || '*', true, p_created_by
  )
  on conflict (connection_id, match_type, match_value) do update
    set is_active = true,
        created_by = coalesce(excluded.created_by, public.wazuh_agent_mappings.created_by)
    where public.wazuh_agent_mappings.tenant_id = excluded.tenant_id
  returning id into v_prefix_mapping_id;
  if not found then
    raise exception 'Agent name prefix is already assigned to another company' using errcode = '23505';
  end if;

  -- Keep existing exact-ID fallback rules aligned with the explicit prefix.
  update public.wazuh_agent_mappings wam
  set tenant_id = v_tenant_id,
      created_by = coalesce(p_created_by, wam.created_by)
  where wam.connection_id = v_connection_id
    and wam.match_type = 'agent_id'
    and wam.is_active
    and wam.tenant_id <> v_tenant_id
    and exists (
      select 1
      from public.wazuh_findings f
      where f.connection_id = v_connection_id
        and f.agent_id = wam.match_value
        and f.agent_name is not null
        and left(lower(f.agent_name), char_length(p_agent_name_prefix)) = lower(p_agent_name_prefix)
    );
  get diagnostics v_remapped_agent_ids = row_count;

  return jsonb_build_object(
    'entityId', v_tenant_id,
    'tenantId', v_tenant_id,
    'name', coalesce(p_company_name, (select c.name from public.companies c where c.id = v_tenant_id)),
    'slug', coalesce(p_company_slug, (select c.slug from public.companies c where c.id = v_tenant_id)),
    'groupMappingId', v_group_mapping_id,
    'prefixMappingId', v_prefix_mapping_id,
    'remappedAgentIds', v_remapped_agent_ids
  );
end;
$function$;

revoke all on function public.configure_shared_company(uuid, uuid, text, text, text, text, uuid)
  from public, anon, authenticated;
grant execute on function public.configure_shared_company(uuid, uuid, text, text, text, text, uuid)
  to service_role;

-- Resolve by group/prefix first so an old exact-ID rule cannot route a host
-- away from the explicitly configured company.
do $migration$
declare
  v_definition text;
  v_updated_definition text;
  v_old text := $old$
      if v_agent_tenant_count = 1 then
        v_tenant_id := v_agent_tenant_id;
      elsif v_agent_tenant_count > 1 then
        v_tenant_id := null;
      else
        select count(distinct wam.tenant_id)::integer,
               (array_agg(distinct wam.tenant_id))[1]
          into v_group_tenant_count, v_group_tenant_id
        from public.wazuh_agent_mappings wam
        join public.companies c on c.id = wam.tenant_id and c.is_active
        where wam.connection_id = v_connection.id
          and wam.is_active
          and (
            (wam.match_type = 'group'
              and wam.match_value = any(array(
                select jsonb_array_elements_text(v_groups)
              )))
            or (wam.match_type = 'agent_name_prefix'
              and v_agent_name is not null
              and wam.match_value ~ '^[A-Za-z0-9._-]+\*$'
              and left(lower(v_agent_name), char_length(wam.match_value) - 1)
                = lower(left(wam.match_value, char_length(wam.match_value) - 1)))
          );
        v_tenant_id := case when v_group_tenant_count = 1 then v_group_tenant_id else null end;
      end if;
$old$;
  v_new text := $new$
      select count(distinct wam.tenant_id)::integer,
             (array_agg(distinct wam.tenant_id))[1]
        into v_group_tenant_count, v_group_tenant_id
      from public.wazuh_agent_mappings wam
      join public.companies c on c.id = wam.tenant_id and c.is_active
      where wam.connection_id = v_connection.id
        and wam.is_active
        and (
          (wam.match_type = 'group'
            and wam.match_value = any(array(
              select jsonb_array_elements_text(v_groups)
            )))
          or (wam.match_type = 'agent_name_prefix'
            and v_agent_name is not null
            and wam.match_value ~ '^[A-Za-z0-9._-]+\*$'
            and left(lower(v_agent_name), char_length(wam.match_value) - 1)
              = lower(left(wam.match_value, char_length(wam.match_value) - 1)))
        );

      if v_group_tenant_count = 1 then
        v_tenant_id := v_group_tenant_id;
      elsif v_group_tenant_count > 1 then
        v_tenant_id := null;
      else
        select count(distinct wam.tenant_id)::integer,
               (array_agg(distinct wam.tenant_id))[1]
          into v_agent_tenant_count, v_agent_tenant_id
        from public.wazuh_agent_mappings wam
        join public.companies c on c.id = wam.tenant_id and c.is_active
        where wam.connection_id = v_connection.id
          and wam.is_active
          and wam.match_type = 'agent_id'
          and wam.match_value = coalesce(v_agent_id, '');
        v_tenant_id := case when v_agent_tenant_count = 1 then v_agent_tenant_id else null end;
      end if;
$new$;
begin
  select pg_get_functiondef('wazuh_internal.apply_wazuh_batch(uuid,uuid,integer,text,jsonb)'::regprocedure)
    into v_definition;
  v_updated_definition := replace(v_definition, v_old, v_new);
  if v_updated_definition = v_definition then
    raise exception 'Could not safely update shared company routing precedence';
  end if;
  execute v_updated_definition;
end;
$migration$;

-- Seed the four known partitions on the currently active shared source. If a
-- fresh environment has no shared source yet, the admin flow configures it later.
do $seed$
declare
  v_connection_count integer;
  v_connection_id uuid;
  v_tenant_id uuid;
  v_active boolean;
  v_company record;
begin
  select count(*) into v_connection_count
  from public.wazuh_connections wc
  where wc.mode = 'shared' and wc.is_active;

  if v_connection_count = 0 then
    return;
  end if;
  if v_connection_count <> 1 then
    raise exception 'Expected one active shared source to configure the initial companies';
  end if;

  select wc.id into v_connection_id
  from public.wazuh_connections wc
  where wc.mode = 'shared' and wc.is_active;

  for v_company in
    select * from (values
      ('YAMAM', 'yamam', '100', 'yamam-tenant'),
      ('MAXIPARK', 'maxipark', '200', 'maxipark-tenant'),
      ('RELIANCE', 'reliance', '300', 'reliance-tenant'),
      ('AMALOG', 'amalog', '400', 'amalog-tenant')
    ) as known(name, slug, prefix, company_group)
  loop
    select c.id, c.is_active into v_tenant_id, v_active
    from public.companies c
    where c.slug = v_company.slug;

    if not found then
      select (public.configure_shared_company(
        v_connection_id, null, v_company.name, v_company.slug,
        v_company.prefix, v_company.company_group, null
      ) ->> 'tenantId')::uuid into v_tenant_id;
    else
      if not v_active then
        raise exception 'Company % already exists but is inactive', v_company.slug;
      end if;
      perform public.configure_shared_company(
        v_connection_id, v_tenant_id, null, null,
        v_company.prefix, v_company.company_group, null
      );
    end if;
  end loop;
end;
$seed$;
