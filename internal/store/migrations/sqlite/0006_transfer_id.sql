-- Last ownership transfer request that moved each entry (idempotent retries).
ALTER TABLE ownership ADD COLUMN transfer_id TEXT NOT NULL DEFAULT '';
