create or replace function wazuh_internal.process_publication_queue() returns void
language plpgsql security definer set search_path=''
as $body$
declare job wazuh_internal.publication_queue; result jsonb;
begin
  select * into job from wazuh_internal.publication_queue where status='pending'
    order by requested_at for update skip locked limit 1;
  if not found then return; end if;
  perform set_config('request.jwt.claim.role','service_role',true);
  perform set_config('request.jwt.claims','{"role":"service_role"}',true);
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
