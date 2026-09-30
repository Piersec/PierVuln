-- Row visibility remains governed by each table's existing tenant RLS policies.
alter publication supabase_realtime add table public.sync_runs, public.finding_events, public.vulnerability_comments;
