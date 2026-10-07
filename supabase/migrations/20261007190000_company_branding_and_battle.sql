alter table public.companies
  add column logo_dark_path text,
  add column logo_light_path text;

create or replace function public.current_user_context()
returns jsonb language plpgsql stable security definer set search_path = ''
as $$
declare
  v_user_id uuid := (select auth.uid());
  v_internal boolean;
  v_companies jsonb;
begin
  if v_user_id is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  v_internal := private.is_internal_admin();
  select coalesce(jsonb_agg(jsonb_build_object(
    'id', c.id, 'name', c.name, 'slug', c.slug, 'role', m.role,
    'logo_dark_path', c.logo_dark_path, 'logo_light_path', c.logo_light_path
  ) order by c.name), '[]'::jsonb) into v_companies
  from public.company_memberships m
  join public.companies c on c.id = m.company_id
  where m.user_id = v_user_id and m.is_active and c.is_active;
  return jsonb_build_object('user_id', v_user_id, 'is_internal_admin', v_internal, 'companies', v_companies);
end;
$$;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('company-logos', 'company-logos', true, 1048576, array['image/png', 'image/jpeg', 'image/webp'])
on conflict (id) do update set public = true, file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

create or replace function public.admin_battle_data()
returns jsonb language sql stable security invoker set search_path = ''
as $$
  select coalesce(jsonb_agg(jsonb_build_object(
    'id', c.id, 'name', c.name, 'slug', c.slug,
    'case_count', coalesce((s.overview->>'caseCount')::integer, 0),
    'critical_high_count', coalesce((s.overview->>'criticalHighCount')::integer, 0),
    'in_progress_count', coalesce((s.overview->>'inProgressCount')::integer, 0),
    'corrected_30', coalesce((s.overview->>'corrected30')::integer, 0),
    'refreshed_at', s.refreshed_at, 'stale', coalesce(s.stale, true)
  ) order by c.name), '[]'::jsonb)
  from public.companies c
  left join public.vulnerability_overview_snapshots s on s.tenant_id = c.id
  where c.is_active;
$$;
revoke all on function public.admin_battle_data() from public, anon, authenticated;
grant execute on function public.admin_battle_data() to service_role;

notify pgrst, 'reload schema';
