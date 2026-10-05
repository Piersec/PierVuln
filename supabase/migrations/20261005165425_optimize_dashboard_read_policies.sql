set local lock_timeout = '5s';
do $$
declare
  policy_row record;
begin
  for policy_row in
    select schemaname, tablename, policyname, qual
    from pg_catalog.pg_policies
    where schemaname = 'public'
      and (tablename, policyname) in (
        ('wazuh_findings', 'wazuh_findings_read'),
        ('vulnerability_cases', 'vulnerability_cases_read')
      )
      and qual like '%private.is_internal_admin()%'
  loop
    execute format(
      'alter policy %I on %I.%I using (%s)',
      policy_row.policyname, policy_row.schemaname, policy_row.tablename,
      replace(policy_row.qual, 'private.is_internal_admin()', '(select private.is_internal_admin())')
    );
  end loop;
end;
$$;
