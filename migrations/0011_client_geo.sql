-- Where each device last checked in from (country ISO code + city), for the
-- device map. Resolved from a GeoIP database or CDN geo headers; the IP
-- itself is never stored.
ALTER TABLE clients ADD COLUMN country TEXT;
ALTER TABLE clients ADD COLUMN city TEXT;
CREATE INDEX idx_clients_country ON clients (app_id, country);
