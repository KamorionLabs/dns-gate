-- RRset plans (MCP plan_rrset_change, POST /api/v1/zones/{zone}/plan),
-- taken once by their subject before expires_at.
CREATE TABLE rrset_plan (
    id           TEXT   PRIMARY KEY,
    subject      TEXT   NOT NULL,
    zone         TEXT   NOT NULL,
    changes      TEXT   NOT NULL,
    zone_version BIGINT NOT NULL,
    created_at   BIGINT NOT NULL,
    expires_at   BIGINT NOT NULL
);

CREATE INDEX rrset_plan_expires ON rrset_plan (expires_at);
