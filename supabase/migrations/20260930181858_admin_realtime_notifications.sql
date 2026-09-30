-- Broadcast only a small allowlist of fields, never connection endpoints or credentials.
create or replace function private.broadcast_admin_change()
returns trigger language plpgsql security definer set search_path = '' as $$
declare row_data jsonb; entity_id text; label text;
begin
  if tg_op='UPDATE' and to_jsonb(new)=to_jsonb(old) then return null; end if;
  row_data := case when tg_op='DELETE' then to_jsonb(old) else to_jsonb(new) end;
  entity_id := case when tg_table_name in ('company_memberships','internal_admins') then row_data->>'user_id' else row_data->>'id' end;
  label := left(coalesce(row_data->>'name',row_data->>'display_name',row_data->>'match_value',''),160);
  perform realtime.send(jsonb_build_object(
    'id',gen_random_uuid(),'table',tg_table_name,'operation',tg_op,'entity_id',entity_id,
    'label',label,'status',row_data->>'status','is_active',row_data->'is_active',
    'connection_id',row_data->>'connection_id','created_at',now()
  ),'admin_change','pier-admin',true);
  return null;
end;
$$;
revoke all on function private.broadcast_admin_change() from public,anon,authenticated;

create trigger admin_change after insert or update or delete on public.companies for each row execute function private.broadcast_admin_change();
create trigger admin_change after insert or update or delete on public.user_profiles for each row execute function private.broadcast_admin_change();
create trigger admin_change after insert or update or delete on public.company_memberships for each row execute function private.broadcast_admin_change();
create trigger admin_change after insert or update or delete on private.internal_admins for each row execute function private.broadcast_admin_change();
create trigger admin_change after insert or update or delete on public.wazuh_connections for each row execute function private.broadcast_admin_change();
create trigger admin_change after insert or update or delete on public.wazuh_agent_mappings for each row execute function private.broadcast_admin_change();
create trigger admin_change after insert or update or delete on public.archive_manifests for each row execute function private.broadcast_admin_change();
create trigger admin_change after insert or update of status on public.sync_runs for each row execute function private.broadcast_admin_change();

create policy pier_admin_receive on realtime.messages for select to authenticated
using (extension='broadcast' and topic='pier-admin' and private.is_internal_admin());
