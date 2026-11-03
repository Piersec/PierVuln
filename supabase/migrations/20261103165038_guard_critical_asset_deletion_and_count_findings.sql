alter table public.asset_deletion_requests
  add column vulnerability_count integer check (vulnerability_count is null or vulnerability_count >= 0);

grant select(vulnerability_count) on public.asset_deletion_requests to authenticated;

create or replace function private.guard_critical_asset_classification()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'UPDATE'
     and old.is_critical
     and not new.is_critical
     and auth.uid() is not null
     and coalesce(auth.jwt() ->> 'aal', '') <> 'aal2' then
    raise exception 'Autenticação multifator necessária para desativar a classificação crítica.' using errcode = '42501';
  end if;

  if new.is_critical
     and (tg_op = 'INSERT' or not old.is_critical)
     and exists (
       select 1
       from public.asset_deletion_requests r
       where r.tenant_id = new.tenant_id
         and r.agent_id = new.agent_key
         and r.status in ('pending', 'executing', 'uncertain')
     ) then
    raise exception 'Há uma exclusão em andamento para este ativo.' using errcode = '55000';
  end if;

  return new;
end;
$$;
revoke all on function private.guard_critical_asset_classification() from public, anon, authenticated, service_role;
create trigger asset_classification_require_mfa
  before insert or update on public.asset_classifications
  for each row execute function private.guard_critical_asset_classification();

create or replace function private.active_asset_vulnerability_count(
  p_connection_id uuid,
  p_tenant_id uuid,
  p_agent_id text,
  p_agent_name text
) returns integer
language sql
stable
security definer
set search_path = ''
as $$
  select count(*)::integer
  from public.wazuh_findings f
  left join public.vulnerability_cases c
    on c.finding_id = f.id and c.tenant_id = f.tenant_id
  where f.connection_id = p_connection_id
    and f.tenant_id = p_tenant_id
    and f.agent_id = p_agent_id
    and f.agent_name = p_agent_name
    and f.source_state = 'active'
    and coalesce(c.workflow_status, 'open'::public.vulnerability_workflow_status) <> 'resolved';
$$;
revoke all on function private.active_asset_vulnerability_count(uuid, uuid, text, text) from public, anon, authenticated;
grant execute on function private.active_asset_vulnerability_count(uuid, uuid, text, text) to service_role;

create or replace function private.resolve_asset_vulnerabilities(
  p_connection_id uuid,
  p_tenant_id uuid,
  p_agent_id text,
  p_agent_name text
) returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform pg_catalog.set_config('piervuln.source_transition_source', 'asset_removal', true);

  update public.vulnerability_cases c
  set workflow_status = 'resolved', closed_at = now(), updated_at = now()
  from public.wazuh_findings f
  where f.id = c.finding_id
    and f.tenant_id = c.tenant_id
    and f.connection_id = p_connection_id
    and f.tenant_id = p_tenant_id
    and f.agent_id = p_agent_id
    and f.agent_name = p_agent_name
    and f.source_state = 'active'
    and c.workflow_status <> 'resolved';

  update public.wazuh_findings f
  set source_state = 'resolved', resolved_at = now(), updated_at = now()
  where f.connection_id = p_connection_id
    and f.tenant_id = p_tenant_id
    and f.agent_id = p_agent_id
    and f.agent_name = p_agent_name
    and f.source_state = 'active';

  perform pg_catalog.set_config('piervuln.source_transition_source', '', true);
end;
$$;
revoke all on function private.resolve_asset_vulnerabilities(uuid, uuid, text, text) from public, anon, authenticated;
grant execute on function private.resolve_asset_vulnerabilities(uuid, uuid, text, text) to service_role;

create or replace function private.audit_finding_source_state_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_case_id uuid;
  v_source text := coalesce(nullif(pg_catalog.current_setting('piervuln.source_transition_source', true), ''), 'complete_inventory');
begin
  if new.tenant_id is not null and old.source_state is distinct from new.source_state then
    select c.id into v_case_id
    from public.vulnerability_cases c
    where c.finding_id = new.id and c.tenant_id = new.tenant_id;

    if old.source_state = 'active' and new.source_state = 'resolved' then
      insert into public.finding_events (case_id, finding_id, tenant_id, event_type, details)
      values (v_case_id, new.id, new.tenant_id, 'confirmed_resolved',
        jsonb_build_object('from', 'active', 'to', 'resolved', 'source', v_source));
      perform pg_catalog.set_config('piervuln.source_transition_finding', new.id::text, true);
    elsif old.source_state = 'resolved' and new.source_state = 'active' then
      insert into public.finding_events (case_id, finding_id, tenant_id, event_type, details)
      values (v_case_id, new.id, new.tenant_id, 'reopened',
        jsonb_build_object('from', 'resolved', 'to', 'active', 'source', v_source));
      perform pg_catalog.set_config('piervuln.source_transition_finding', new.id::text, true);
    end if;
  end if;
  return new;
end;
$$;
revoke all on function private.audit_finding_source_state_change() from public, anon, authenticated, service_role;

create function public.get_asset_deletion_preview(
  p_connection_id uuid,
  p_tenant_id uuid,
  p_agent_id text,
  p_expected_registration timestamptz,
  p_expected_ip text
) returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  a public.asset_agents%rowtype;
  v_critical boolean;
  v_vulnerabilities integer;
begin
  if auth.uid() is null or not private.can_delete_assets(p_tenant_id) then
    raise exception 'Somente administradores podem consultar esta exclusão.' using errcode = '42501';
  end if;

  select * into a
  from public.asset_agents
  where connection_id = p_connection_id and tenant_id = p_tenant_id and agent_id = p_agent_id;
  if not found or a.registered_at is distinct from p_expected_registration or a.ip_address is distinct from p_expected_ip then
    raise exception 'A identificação do ativo mudou. Atualize a lista e abra um novo pedido.';
  end if;

  select exists (
    select 1 from public.asset_classifications c
    where c.tenant_id = p_tenant_id and c.is_critical and c.agent_key in (a.agent_id, a.agent_name)
  ) into v_critical;
  v_vulnerabilities := private.active_asset_vulnerability_count(p_connection_id, p_tenant_id, a.agent_id, a.agent_name);

  return jsonb_build_object('is_critical', v_critical, 'active_vulnerabilities', v_vulnerabilities);
end;
$$;
revoke all on function public.get_asset_deletion_preview(uuid, uuid, text, timestamptz, text) from public, anon;
grant execute on function public.get_asset_deletion_preview(uuid, uuid, text, timestamptz, text) to authenticated;

create or replace function public.request_asset_deletion(
  p_request_id uuid,
  p_connection_id uuid,
  p_tenant_id uuid,
  p_agent_id text,
  p_confirmation text,
  p_reason text,
  p_expected_registration timestamptz,
  p_expected_ip text
) returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  a public.asset_agents%rowtype;
  c public.wazuh_connections%rowtype;
  v_demo boolean;
  v_count integer;
  existing public.asset_deletion_requests%rowtype;
begin
  if auth.uid() is null or not private.can_delete_assets(p_tenant_id) then
    raise exception 'Somente administradores podem excluir ativos.' using errcode = '42501';
  end if;

  select * into existing from public.asset_deletion_requests where id = p_request_id;
  if found then
    if existing.requested_by = auth.uid() and existing.tenant_id = p_tenant_id and existing.connection_id = p_connection_id and existing.agent_id = p_agent_id then return existing.id; end if;
    raise exception 'Pedido inválido.';
  end if;

  select * into a from public.asset_agents
  where connection_id = p_connection_id and tenant_id = p_tenant_id and agent_id = p_agent_id
  for update;
  if not found or a.registered_at is null or a.agent_id !~ '^[0-9]{3,8}$' or a.agent_id ~ '^0+$' then
    raise exception 'Ativo indisponível ou sem identidade segura para exclusão.';
  end if;
  if a.registered_at is distinct from p_expected_registration or a.ip_address is distinct from p_expected_ip then
    raise exception 'A identificação do ativo mudou. Atualize a lista e abra um novo pedido.';
  end if;
  if p_confirmation is distinct from 'EXCLUIR ' || a.agent_name then raise exception 'Digite a confirmação exata do ativo.'; end if;
  if p_reason is null or length(btrim(p_reason)) not between 10 and 1000 then raise exception 'Informe um motivo entre 10 e 1000 caracteres.'; end if;
  if exists (
    select 1 from public.asset_classifications ac
    where ac.tenant_id = p_tenant_id and ac.is_critical and ac.agent_key in (a.agent_id, a.agent_name)
  ) then raise exception 'Ativo crítico não pode ser excluído. Desative a classificação com MFA.'; end if;

  select slug = 'demonstracao' into v_demo from public.companies where id = p_tenant_id and is_active;
  if v_demo is null then raise exception 'Empresa indisponível.'; end if;
  select * into c from public.wazuh_connections where id = p_connection_id;
  if not v_demo then
    if not c.is_active or c.asset_api_url is null or not exists (
      select 1 from public.asset_deletion_worker_heartbeats h
      where h.connection_id = p_connection_id and h.tenant_id = p_tenant_id and observed_at > now() - interval '3 minutes'
    ) then raise exception 'Coletor de exclusão indisponível. Nenhum pedido foi enviado.'; end if;
    if c.mode = 'dedicated' and c.tenant_id is distinct from p_tenant_id
       or c.mode = 'shared' and not exists (
         select 1 from public.wazuh_agent_mappings m
         where m.connection_id = p_connection_id and m.tenant_id = p_tenant_id and m.is_active
       ) then raise exception 'Ativo fora do vínculo autorizado.'; end if;
  end if;

  v_count := private.active_asset_vulnerability_count(p_connection_id, p_tenant_id, a.agent_id, a.agent_name);
  insert into public.asset_deletion_requests(
    id, tenant_id, connection_id, agent_id, agent_name, registered_at, ip_address, api_url, requested_by, reason, is_demo, vulnerability_count
  ) values (
    p_request_id, p_tenant_id, p_connection_id, a.agent_id, a.agent_name, a.registered_at, a.ip_address, c.asset_api_url, auth.uid(), btrim(p_reason), v_demo, v_count
  );

  if v_demo then
    perform private.resolve_asset_vulnerabilities(p_connection_id, p_tenant_id, a.agent_id, a.agent_name);
    delete from public.asset_agents where connection_id = p_connection_id and tenant_id = p_tenant_id and agent_id = p_agent_id;
    update public.asset_deletion_requests set status = 'succeeded', result_code = 'demo_simulated', finished_at = now() where id = p_request_id;
  end if;
  return p_request_id;
end;
$$;
revoke all on function public.request_asset_deletion(uuid, uuid, uuid, text, text, text, timestamptz, text) from public, anon;
grant execute on function public.request_asset_deletion(uuid, uuid, uuid, text, text, text, timestamptz, text) to authenticated;

create or replace function public.claim_asset_deletion(p_connection uuid, p_tenant uuid, p_api_url text) returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  r public.asset_deletion_requests%rowtype;
  token uuid := gen_random_uuid();
begin
  if not exists (
    select 1 from public.wazuh_connections c join public.companies co on co.id = p_tenant
    where c.id = p_connection and c.is_active and co.is_active and co.slug <> 'demonstracao' and c.asset_api_url = p_api_url
      and ((c.mode = 'dedicated' and c.tenant_id = p_tenant) or (c.mode = 'shared' and exists (
        select 1 from public.wazuh_agent_mappings m where m.connection_id = c.id and m.tenant_id = p_tenant and m.is_active
      )))
  ) then return null; end if;

  insert into public.asset_deletion_worker_heartbeats(connection_id, tenant_id) values (p_connection, p_tenant)
  on conflict (connection_id, tenant_id) do update set observed_at = now();
  update public.asset_deletion_requests set status = 'failed', result_code = 'expired', finished_at = now()
  where connection_id = p_connection and tenant_id = p_tenant and status = 'pending' and expires_at < now();
  update public.asset_deletion_requests set status = 'uncertain', result_code = 'worker_timeout', finished_at = now()
  where connection_id = p_connection and tenant_id = p_tenant and status = 'executing' and started_at < now() - interval '5 minutes';

  select * into r from public.asset_deletion_requests
  where connection_id = p_connection and tenant_id = p_tenant and status = 'pending'
  order by created_at limit 1 for update skip locked;
  if not found then return null; end if;
  if not private.can_delete_assets_for_user(r.tenant_id, r.requested_by) then
    update public.asset_deletion_requests set status = 'failed', result_code = 'authorization_changed', finished_at = now() where id = r.id;
    return null;
  end if;
  if r.api_url is distinct from p_api_url or not exists (
    select 1 from public.asset_agents a
    where a.connection_id = r.connection_id and a.tenant_id = r.tenant_id and a.agent_id = r.agent_id
      and a.agent_name = r.agent_name and a.registered_at = r.registered_at and a.ip_address is not distinct from r.ip_address
  ) then
    update public.asset_deletion_requests set status = 'failed', result_code = 'identity_changed', finished_at = now() where id = r.id;
    return null;
  end if;
  if exists (
    select 1 from public.asset_classifications ac
    where ac.tenant_id = r.tenant_id and ac.is_critical and ac.agent_key in (r.agent_id, r.agent_name)
  ) then
    update public.asset_deletion_requests set status = 'failed', result_code = 'critical_protected', finished_at = now() where id = r.id;
    return null;
  end if;

  update public.asset_deletion_requests set status = 'executing', started_at = now(), claim_token = token where id = r.id;
  return jsonb_build_object('id', r.id, 'claimToken', token, 'agentId', r.agent_id, 'agentName', r.agent_name, 'registeredAt', r.registered_at, 'ipAddress', r.ip_address);
end;
$$;

create or replace function public.finish_asset_deletion(
  p_id uuid,
  p_connection uuid,
  p_tenant uuid,
  p_claim uuid,
  p_outcome text,
  p_code text
) returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  r public.asset_deletion_requests%rowtype;
  v_count integer;
begin
  select * into r from public.asset_deletion_requests
  where id = p_id and connection_id = p_connection and tenant_id = p_tenant and claim_token = p_claim
  for update;
  if not found then return false; end if;
  if r.status = 'succeeded' then return p_outcome = 'succeeded'; end if;
  if r.status not in ('executing', 'uncertain') or p_outcome not in ('succeeded', 'failed', 'uncertain') then return false; end if;
  if p_outcome = 'succeeded' then
    v_count := private.active_asset_vulnerability_count(r.connection_id, r.tenant_id, r.agent_id, r.agent_name);
    perform private.resolve_asset_vulnerabilities(r.connection_id, r.tenant_id, r.agent_id, r.agent_name);
    delete from public.asset_agents
    where connection_id = r.connection_id and tenant_id = r.tenant_id and agent_id = r.agent_id
      and agent_name = r.agent_name and registered_at = r.registered_at;
    update public.asset_deletion_requests set vulnerability_count = v_count where id = r.id;
  end if;
  update public.asset_deletion_requests
  set status = p_outcome,
      result_code = case when p_code in ('source_confirmed', 'source_denied', 'identity_changed', 'source_failed', 'network_uncertain', 'preflight_failed') then p_code else 'source_failed' end,
      finished_at = now()
  where id = r.id;
  return true;
end;
$$;
revoke all on function public.claim_asset_deletion(uuid, uuid, text), public.finish_asset_deletion(uuid, uuid, uuid, uuid, text, text) from public, anon, authenticated;
grant execute on function public.claim_asset_deletion(uuid, uuid, text), public.finish_asset_deletion(uuid, uuid, uuid, uuid, text, text) to service_role;
