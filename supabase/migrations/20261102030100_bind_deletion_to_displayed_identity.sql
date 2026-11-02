drop function public.request_asset_deletion(uuid,uuid,uuid,text,text,text);
create function public.request_asset_deletion(p_request_id uuid,p_connection_id uuid,p_tenant_id uuid,p_agent_id text,p_confirmation text,p_reason text,p_expected_registration timestamptz,p_expected_ip text)
returns uuid language plpgsql security definer set search_path='' as $$
declare a public.asset_agents%rowtype; c public.wazuh_connections%rowtype; v_demo boolean; existing public.asset_deletion_requests%rowtype;
begin
 if auth.uid() is null or not private.can_delete_assets(p_tenant_id) then raise exception 'Somente administradores podem excluir ativos.' using errcode='42501'; end if;
 select * into existing from public.asset_deletion_requests where id=p_request_id;
 if found then
   if existing.requested_by=auth.uid() and existing.tenant_id=p_tenant_id and existing.connection_id=p_connection_id and existing.agent_id=p_agent_id then return existing.id; end if;
   raise exception 'Pedido inválido.';
 end if;
 select * into a from public.asset_agents where connection_id=p_connection_id and tenant_id=p_tenant_id and agent_id=p_agent_id for update;
 if not found or a.registered_at is null or a.agent_id !~ '^[0-9]{3,8}$' or a.agent_id ~ '^0+$' then raise exception 'Ativo indisponível ou sem identidade segura para exclusão.'; end if;
 if a.registered_at is distinct from p_expected_registration or a.ip_address is distinct from p_expected_ip then raise exception 'A identificação do ativo mudou. Atualize a lista e abra um novo pedido.'; end if;
 if p_confirmation is distinct from 'EXCLUIR '||a.agent_name then raise exception 'Digite a confirmação exata do ativo.'; end if;
 if p_reason is null or length(btrim(p_reason)) not between 10 and 1000 then raise exception 'Informe um motivo entre 10 e 1000 caracteres.'; end if;
 select slug='demonstracao' into v_demo from public.companies where id=p_tenant_id and is_active;
 if v_demo is null then raise exception 'Empresa indisponível.'; end if;
 select * into c from public.wazuh_connections where id=p_connection_id;
 if not v_demo then
   if not c.is_active or c.asset_api_url is null or not exists(select 1 from public.asset_deletion_worker_heartbeats h where h.connection_id=p_connection_id and h.tenant_id=p_tenant_id and observed_at>now()-interval '3 minutes') then
     raise exception 'Coletor de exclusão indisponível. Nenhum pedido foi enviado.';
   end if;
   if c.mode='dedicated' and c.tenant_id is distinct from p_tenant_id or c.mode='shared' and not exists(select 1 from public.wazuh_agent_mappings m where m.connection_id=p_connection_id and m.tenant_id=p_tenant_id and m.is_active) then raise exception 'Ativo fora do vínculo autorizado.'; end if;
 end if;
 insert into public.asset_deletion_requests(id,tenant_id,connection_id,agent_id,agent_name,registered_at,ip_address,api_url,requested_by,reason,is_demo)
 values(p_request_id,p_tenant_id,p_connection_id,a.agent_id,a.agent_name,a.registered_at,a.ip_address,c.asset_api_url,auth.uid(),btrim(p_reason),v_demo);
 if v_demo then
   delete from public.asset_agents where connection_id=p_connection_id and tenant_id=p_tenant_id and agent_id=p_agent_id;
   update public.asset_deletion_requests set status='succeeded',result_code='demo_simulated',finished_at=now() where id=p_request_id;
 end if;
 return p_request_id;
end;
$$;
revoke all on function public.request_asset_deletion(uuid,uuid,uuid,text,text,text,timestamptz,text) from public,anon;
grant execute on function public.request_asset_deletion(uuid,uuid,uuid,text,text,text,timestamptz,text) to authenticated;
