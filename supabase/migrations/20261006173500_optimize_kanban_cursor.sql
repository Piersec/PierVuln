create index if not exists cases_tenant_cursor_idx
on public.vulnerability_cases (tenant_id, id)
include (finding_id, workflow_status, closed_at);
