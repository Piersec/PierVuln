create index if not exists cases_tenant_updated_page_idx
on public.vulnerability_cases (tenant_id, updated_at desc)
include (id, finding_id, workflow_status, created_at, closed_at);

create index if not exists cases_updated_page_idx
on public.vulnerability_cases (updated_at desc)
include (id, finding_id, tenant_id, workflow_status, created_at, closed_at);

