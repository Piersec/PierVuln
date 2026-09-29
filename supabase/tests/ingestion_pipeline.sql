-- Exercises the same service-only RPCs used by wazuh-ingest. The transaction
-- leaves no fixture data in the Supabase project.
begin;

insert into public.companies (id, name, slug)
values ('00000000-0000-4000-8000-000000000210', 'Ingest Test', 'ingest-test');
insert into public.wazuh_connections (id, tenant_id, name, mode, endpoint_url)
values (
  '00000000-0000-4000-8000-000000000310',
  '00000000-0000-4000-8000-000000000210',
  'Ingest Test Wazuh', 'dedicated', 'https://indexer.example.test:9200'
);

set local role service_role;
select set_config('request.jwt.claim.role', 'service_role', true);
select set_config('request.jwt.claims', '{"role":"service_role"}', true);

do $$
declare
  v_run uuid;
  v_reply jsonb;
  v_finding_id uuid;
  v_item jsonb := jsonb_build_array(jsonb_build_object(
    'documentId', 'indexer-doc-001',
    'agentId', '001',
    'agentName', 'test-agent',
    'agentGroups', jsonb_build_array('test-linux'),
    'hostOs', 'Test Linux',
    'packageName', 'openssl',
    'packageVersion', '3.0.0',
    'packageType', 'deb',
    'packageArchitecture', 'amd64',
    'vulnerabilityId', 'CVE-TEST-INGEST',
    'description', 'Synthetic pipeline test',
    'severity', 'High',
    'cvssBase', 8.1,
    'references', jsonb_build_array('https://example.test/cve'),
    'sourceStatus', 'Active'
  ));
begin
  -- First full snapshot creates one finding and one case.
  v_run := public.register_wazuh_sync('00000000-0000-4000-8000-000000000310', 'test-indexer');
  v_reply := public.ingest_wazuh_batch(
    '00000000-0000-4000-8000-000000000310', v_run, 0, repeat('a', 64), v_item
  );
  if (v_reply ->> 'duplicate')::boolean is distinct from false then
    raise exception 'First page must be accepted';
  end if;
  v_reply := public.ingest_wazuh_batch(
    '00000000-0000-4000-8000-000000000310', v_run, 0, repeat('a', 64), v_item
  );
  if (v_reply ->> 'duplicate')::boolean is distinct from true then
    raise exception 'Retried page must be idempotent';
  end if;
  if (select count(*) from public.wazuh_findings where connection_id = '00000000-0000-4000-8000-000000000310') <> 1
     or (select documents_received from public.sync_runs where id = v_run) <> 1 then
    raise exception 'Retry created a duplicate finding or page count';
  end if;
  v_reply := public.complete_wazuh_sync(
    '00000000-0000-4000-8000-000000000310', v_run, 1, 1, 'test-indexer'
  );
  if (v_reply ->> 'completed')::boolean is distinct from true then
    raise exception 'Complete initial snapshot was rejected';
  end if;
  select id into v_finding_id from public.wazuh_findings
  where connection_id = '00000000-0000-4000-8000-000000000310';

  -- A short page count cannot close a finding that was not read in the run.
  v_run := public.register_wazuh_sync('00000000-0000-4000-8000-000000000310', 'test-indexer');
  perform public.ingest_wazuh_batch(
    '00000000-0000-4000-8000-000000000310', v_run, 0, repeat('b', 64), '[]'::jsonb
  );
  v_reply := public.complete_wazuh_sync(
    '00000000-0000-4000-8000-000000000310', v_run, 1, 1, 'test-indexer'
  );
  if (v_reply ->> 'completed')::boolean is distinct from false
     or (select source_state from public.wazuh_findings where id = v_finding_id) <> 'active'
     or (select workflow_status from public.vulnerability_cases where finding_id = v_finding_id) <> 'open' then
    raise exception 'Partial pagination closed a finding or case';
  end if;

  -- Only an exact, complete empty snapshot confirms absence and resolves the case.
  v_run := public.register_wazuh_sync('00000000-0000-4000-8000-000000000310', 'test-indexer');
  perform public.ingest_wazuh_batch(
    '00000000-0000-4000-8000-000000000310', v_run, 0, repeat('c', 64), '[]'::jsonb
  );
  v_reply := public.complete_wazuh_sync(
    '00000000-0000-4000-8000-000000000310', v_run, 1, 0, 'test-indexer'
  );
  if (v_reply ->> 'completed')::boolean is distinct from true
     or (select source_state from public.wazuh_findings where id = v_finding_id) <> 'resolved'
     or (select workflow_status from public.vulnerability_cases where finding_id = v_finding_id) <> 'resolved' then
    raise exception 'Complete empty snapshot did not resolve the finding and case';
  end if;

  -- When Wazuh reports the same source document again, its case reopens in place.
  v_run := public.register_wazuh_sync('00000000-0000-4000-8000-000000000310', 'test-indexer');
  perform public.ingest_wazuh_batch(
    '00000000-0000-4000-8000-000000000310', v_run, 0, repeat('d', 64), v_item
  );
  v_reply := public.complete_wazuh_sync(
    '00000000-0000-4000-8000-000000000310', v_run, 1, 1, 'test-indexer'
  );
  if (v_reply ->> 'completed')::boolean is distinct from true
     or (select count(*) from public.wazuh_findings where connection_id = '00000000-0000-4000-8000-000000000310') <> 1
     or (select source_state from public.wazuh_findings where id = v_finding_id) <> 'active'
     or (select workflow_status from public.vulnerability_cases where finding_id = v_finding_id) <> 'open'
     or (select count(*) from public.finding_events where finding_id = v_finding_id and event_type = 'reopened') <> 1 then
    raise exception 'Reappearance did not reopen the existing finding and preserve its event';
  end if;
end;
$$;

reset role;
rollback;
