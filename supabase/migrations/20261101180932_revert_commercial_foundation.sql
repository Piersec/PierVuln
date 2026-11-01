drop function if exists public.set_commercial_lead_selection(uuid, uuid, uuid[]);
drop table if exists public.commercial_lead_terms;
drop table if exists public.commercial_leads;
drop table if exists public.commercial_extras;
drop table if exists public.commercial_plans;
drop table if exists public.commercial_audit_events;
drop function if exists private.audit_commercial_change();
