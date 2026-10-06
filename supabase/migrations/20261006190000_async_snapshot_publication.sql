alter function public.complete_wazuh_sync(uuid,uuid,integer,bigint,text) rename to publish_wazuh_snapshot;
alter function public.publish_wazuh_snapshot(uuid,uuid,integer,bigint,text) set schema wazuh_internal;

create table wazuh_internal.publication_queue (
  run_id uuid primary key references public.sync_runs(id) on delete cascade,
  connection_id uuid not null references public.wazuh_connections(id),
  expected_pages integer not null check (expected_pages > 0),
  expected_documents bigint not null check (expected_documents >= 0),
  indexer_version text not null,
  status text not null default 'pending' check (status in ('pending','succeeded','failed')),
  requested_at timestamptz not null default now(),
  finished_at timestamptz,
  error_summary text
);
revoke all on wazuh_internal.publication_queue from public,anon,authenticated,service_role;

create function public.complete_wazuh_sync(p_connection_id uuid,p_run_id uuid,p_expected_pages integer,p_expected_documents bigint,p_indexer_version text default 'unknown')
returns jsonb language plpgsql security definer set search_path=''
as $body$
declare v_run public.sync_runs; v_queue wazuh_internal.publication_queue;
begin
  select * into v_run from public.sync_runs where id=p_run_id and connection_id=p_connection_id;
  if not found then raise exception 'Execução não encontrada'; end if;
  if v_run.status='succeeded' then return jsonb_build_object('completed',true,'findingsChanged',v_run.findings_changed); end if;
  if v_run.status<>'running' then return jsonb_build_object('completed',false,'pending',false); end if;
  if p_expected_pages<=0 or p_expected_documents<0 or p_expected_pages is null or p_expected_documents is null then
    raise exception 'Contadores inválidos';
  end if;
  if (select count(*) from wazuh_internal.snapshot_pages where run_id=p_run_id)<>p_expected_pages
    or (select coalesce(sum(document_count),0) from wazuh_internal.snapshot_pages where run_id=p_run_id)<>p_expected_documents then
    raise exception 'O snapshot ainda não recebeu todas as páginas';
  end if;
  insert into wazuh_internal.publication_queue(run_id,connection_id,expected_pages,expected_documents,indexer_version)
  values(p_run_id,p_connection_id,p_expected_pages,p_expected_documents,left(coalesce(p_indexer_version,'unknown'),160))
  on conflict(run_id) do nothing;
  select * into v_queue from wazuh_internal.publication_queue where run_id=p_run_id;
  if v_queue.connection_id<>p_connection_id or v_queue.expected_pages<>p_expected_pages or v_queue.expected_documents<>p_expected_documents then
    raise exception 'O pedido de publicação possui contadores diferentes';
  end if;
  return jsonb_build_object('completed',false,'pending',v_queue.status='pending');
end;
$body$;
revoke all on function public.complete_wazuh_sync(uuid,uuid,integer,bigint,text) from public,anon,authenticated;
grant execute on function public.complete_wazuh_sync(uuid,uuid,integer,bigint,text) to service_role;

create function wazuh_internal.process_publication_queue() returns void
language plpgsql security definer set search_path=''
as $body$
declare job wazuh_internal.publication_queue; result jsonb;
begin
  select * into job from wazuh_internal.publication_queue where status='pending'
    order by requested_at for update skip locked limit 1;
  if not found then return; end if;
  begin
    result:=wazuh_internal.publish_wazuh_snapshot(job.connection_id,job.run_id,job.expected_pages,job.expected_documents,job.indexer_version);
    if coalesce((result->>'completed')::boolean,false) is not true then raise exception 'A publicação não foi concluída'; end if;
    update wazuh_internal.publication_queue set status='succeeded',finished_at=now() where run_id=job.run_id;
  exception when others or query_canceled then
    update wazuh_internal.publication_queue set status='failed',finished_at=now(),error_summary=left(sqlerrm,1500) where run_id=job.run_id;
    perform public.fail_wazuh_sync(job.connection_id,job.run_id,left(sqlerrm,1500));
  end;
end;
$body$;
revoke all on function wazuh_internal.process_publication_queue() from public,anon,authenticated,service_role;
select cron.schedule('piervuln-publish-snapshot','* * * * *',
  $command$set statement_timeout='10min'; select wazuh_internal.process_publication_queue();$command$);
