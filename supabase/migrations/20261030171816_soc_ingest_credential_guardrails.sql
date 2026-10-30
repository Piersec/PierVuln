create index soc_ingest_credentials_created_by_idx
  on public.soc_ingest_credentials (created_by)
  where created_by is not null;

create policy soc_ingest_credentials_no_client_access on public.soc_ingest_credentials
  for all to anon, authenticated
  using (false)
  with check (false);
