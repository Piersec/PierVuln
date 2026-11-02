-- Explicitly run by an administrator to create the isolated fictional tenant.
-- Repeat executions leave the existing demo tenant and its operator changes intact.
begin;
do $seed$
declare
  v_tenant uuid; v_connection uuid; v_run uuid := gen_random_uuid();
  v_admin uuid; v_case uuid; v_alert record; v_overview jsonb; i integer;
begin
  if exists(select 1 from public.companies where slug='demonstracao') then
    raise notice 'Demo tenant already exists; no data changed';
    return;
  end if;
  select a.user_id into v_admin from private.internal_admins a
    order by a.created_at limit 1;
  if v_admin is null then raise exception 'An internal administrator is required'; end if;
  perform set_config('request.jwt.claim.sub',v_admin::text,true);
  perform set_config('request.jwt.claims',jsonb_build_object('sub',v_admin,'role','authenticated')::text,true);

  insert into public.companies(name,slug) values ('Demonstração — dados fictícios','demonstracao') returning id into v_tenant;
  insert into public.wazuh_connections(tenant_id,name,mode,endpoint_url,is_active)
    values(v_tenant,'DEMO — simulação sem coleta','dedicated','https://demo.invalid',false) returning id into v_connection;
  insert into public.sync_runs(id,connection_id,status,started_at,finished_at,pages_received,documents_received,full_snapshot)
    values(v_run,v_connection,'succeeded',now()-interval '5 minutes',now(),2,600,true);

  insert into public.asset_agents(connection_id,tenant_id,agent_id,agent_name,ip_address,host_os,status,agent_groups,registered_at,last_keep_alive_at,seen_run_id)
  select v_connection,v_tenant,lpad(g::text,3,'0'),'DEMO-'||(array['SRV','NOTE','FW','DB'])[1+g%4]||'-'||lpad(g::text,3,'0'),
    '192.0.2.'||g,(array['Ubuntu 24.04','Windows 11','Debian 12','Windows Server 2022'])[1+g%4],
    (array['active','active','active','disconnected','pending','never_connected'])[1+g%6],
    array['demo-tenant',(array['servidores','estacoes','firewall','banco'])[1+g%4]],now()-g*interval '1 day',
    case when g%6=5 then null else now()-g*interval '4 minutes' end,v_run
  from generate_series(1,80) g;
  insert into public.asset_sync_runs(id,connection_id,tenant_id,status,started_at,finished_at,agents_received,agents_stored)
    values(v_run,v_connection,v_tenant,'succeeded',now()-interval '5 minutes',now(),80,80);

  insert into public.wazuh_findings(connection_id,tenant_id,source_document_id,agent_id,agent_name,agent_groups,host_os,package_name,package_version,vulnerability_id,description,severity,cvss_base,source_state,resolved_at,first_detected_at,last_seen_at,last_seen_sync_run_id)
  select v_connection,v_tenant,'demo-finding-'||g,lpad((1+g%80)::text,3,'0'),
    'DEMO-'||(array['SRV','NOTE','FW','DB'])[1+(1+g%80)%4]||'-'||lpad((1+g%80)::text,3,'0'),
    array['demo-tenant'],'Ubuntu 24.04',(array['openssl','nginx','curl','openssh','linux-kernel'])[1+g%5],'1.0-demo',
    'DEMO-VULN-'||lpad((1+g%60)::text,4,'0'),'Registro fictício para testar filtros e tratamento. Nenhuma vulnerabilidade real é atribuída a estes ativos.',
    (array['Critical','High','Medium','Low','Informational'])[1+g%5],
    (array[9.8,8.1,5.5,3.1,0.0])[1+g%5],
    case when g%10=0 then 'resolved'::public.vulnerability_source_state else 'active'::public.vulnerability_source_state end,
    case when g%10=0 then now()-interval '2 days' else null end,
    now()-(1+g%160)*interval '1 day',now(),v_run
  from generate_series(1,600) g;
  insert into public.vulnerability_cases(finding_id,tenant_id,workflow_status,closed_at)
  select id,v_tenant,
    case when source_state='resolved' then 'resolved'::public.vulnerability_workflow_status
      when right(source_document_id,1)='1' then 'in_progress'::public.vulnerability_workflow_status
      when right(source_document_id,1)='2' then 'awaiting_validation'::public.vulnerability_workflow_status
      else 'open'::public.vulnerability_workflow_status end,
    case when source_state='resolved' then resolved_at else null end
  from public.wazuh_findings where tenant_id=v_tenant;
  update public.wazuh_connections set published_sync_run_id=v_run where id=v_connection;

  insert into public.soc_alerts(tenant_id,source_id,source_name,source_category,source_vendor,source_product,source_event_id,
    occurred_at,severity,severity_original,title,message,rule_id,rule_description,rule_level,agent_id,agent_name,agent_ip,
    src_ip,dst_ip,src_port,dst_port,network_protocol,service,src_user,source_action,normalized_action,
    mitre_ids,mitre_tactics,mitre_techniques,file_path,file_action,file_hash_before,file_hash_after,file_owner_after,change_actor,change_process,raw_payload,
    first_received_at,last_received_at)
  select v_tenant,'demo-'||(array['firewall','endpoint','identity','fim'])[1+g%4],
    'DEMO / '||(array['Firewall','Endpoint','Identidade','Integridade'])[1+g%4],
    (array['firewall','endpoint','identity','fim'])[1+g%4],'Simulador','PierVuln Demo','demo-event-'||g,
    now()-(g%672)*interval '1 hour'-(g%60)*interval '1 minute',
    (array['critical','high','medium','low','informational','unknown'])[1+g%6],
    'Simulação',
    '[DEMO] '||(array['Tentativas repetidas de autenticação','Execução de processo suspeito','Alteração de grupo administrativo','Alteração de arquivo monitorado','Conexão bloqueada pelo firewall','Novo serviço detectado'])[1+g%6],
    'Evento inteiramente fictício. Use este registro para testar busca, filtros, detalhes e abertura de incidentes.',
    'DEMO-RULE-'||(1+g%12),'Regra fictícia de demonstração',1+g%15,
    lpad((1+g%80)::text,3,'0'),'DEMO-'||(array['SRV','NOTE','FW','DB'])[1+(1+g%80)%4]||'-'||lpad((1+g%80)::text,3,'0'),'192.0.2.'||(1+g%80),
    '198.51.100.'||(1+g%240),'192.0.2.'||(1+g%80),1024+g,case when g%2=0 then 443 else 22 end,'tcp',case when g%2=0 then 'https' else 'ssh' end,
    'usuario.demo.'||(1+g%12),case when g%2=0 then 'deny' else 'alert' end,case when g%2=0 then 'blocked' else 'detected' end,
    array[(array['T1110','T1059','T1098','T1565'])[1+g%4]],
    array[(array['Credential Access','Execution','Persistence','Impact'])[1+g%4]],
    array[(array['Brute Force','Command and Scripting Interpreter','Account Manipulation','Data Manipulation'])[1+g%4]],
    case when g%4=3 then '/etc/demo/config-'||(1+g%8)||'.conf' end,
    case when g%4=3 then (array['modified','added','deleted'])[1+g%3] end,
    case when g%4=3 then md5('demo-before-'||g) end,
    case when g%4=3 then md5('demo-after-'||g) end,
    case when g%4=3 then 'root.demo' end,case when g%4=3 then 'analista.demo' end,
    case when g%4=3 then '/usr/bin/demo-editor' end,
    jsonb_build_object('demo',true,'notice','Dados fictícios','sequence',g),
    now()-(g%672)*interval '1 hour'+interval '2 minutes',now()-(g%672)*interval '1 hour'+interval '2 minutes'
  from generate_series(1,1200) g;
  insert into public.soc_alert_daily_rollups(tenant_id,alert_day,severity,alert_count)
  select tenant_id,(occurred_at at time zone 'UTC')::date,severity,count(*) from public.soc_alerts
  where tenant_id=v_tenant group by tenant_id,(occurred_at at time zone 'UTC')::date,severity;

  i:=0;
  for v_alert in select * from public.soc_alerts where tenant_id=v_tenant order by source_event_id limit 60 loop
    i:=i+1;
    insert into public.soc_cases(tenant_id,title,source_severity,case_severity,notes)
      values(v_tenant,'[DEMO] Incidente '||i||' — '||v_alert.title,v_alert.severity,(array['critical','high','medium','low'])[1+i%4],
        'Cenário fictício para treinamento. Evidências simuladas; nenhuma ação foi executada em sistemas reais.') returning id into v_case;
    insert into public.soc_case_alerts(case_id,alert_id,linked_by) values(v_case,v_alert.id,v_admin);
    if i%3=1 then update public.soc_cases set status='analyzing' where id=v_case;
    elsif i%3=2 then update public.soc_cases set status='closed',classification=case when i%2=0 then 'positive' else 'false_positive' end where id=v_case;
    end if;
  end loop;
  select overview into v_overview from public.get_vulnerability_overview_live(v_tenant,null) as live(overview) limit 1;
  if v_overview is not null then
    insert into public.vulnerability_overview_snapshots(tenant_id,overview,source_marker)
      values(v_tenant,v_overview,'[]'::jsonb) on conflict(tenant_id) do nothing;
  end if;
end
$seed$;
commit;
