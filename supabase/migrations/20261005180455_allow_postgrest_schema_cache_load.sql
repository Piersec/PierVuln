-- Schema loading queries (including pg_timezone_names) exceed 8s on this instance.
-- Client roles retain their own 3s/8s limits; only the connection role gets room to load metadata.
alter role authenticator set statement_timeout = '60s';
notify pgrst, 'reload config';
notify pgrst, 'reload schema';
