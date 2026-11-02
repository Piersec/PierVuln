-- The creation audit runs in the case BEFORE INSERT trigger; validate its parent at commit.
alter table public.soc_case_events alter constraint soc_case_events_case_id_fkey deferrable initially deferred;
