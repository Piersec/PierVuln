-- The overview reads tables already protected by tenant-aware RLS.
alter function public.get_vulnerability_overview_period(uuid, text, timestamptz, timestamptz)
  security invoker;
