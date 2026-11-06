-- Stable id of each audit event, the same as on the stdout line (empty
-- for events recorded before it existed).
ALTER TABLE audit ADD COLUMN event_id TEXT NOT NULL DEFAULT '';
