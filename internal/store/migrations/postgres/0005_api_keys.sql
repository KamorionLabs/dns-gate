-- Gate-issued API keys (/api/v1/api-keys): only the SHA-256 of each key is
-- stored. Revoked keys are kept for the listing and the audit trail.
CREATE TABLE api_key (
    id                  TEXT   PRIMARY KEY,
    name                TEXT   NOT NULL DEFAULT '',
    description         TEXT   NOT NULL DEFAULT '',
    team                TEXT   NOT NULL,
    role                TEXT   NOT NULL,
    secret_hash         TEXT   NOT NULL,
    previous_hash       TEXT   NOT NULL DEFAULT '',
    previous_expires_at BIGINT,
    expires_at          BIGINT,
    allowed_cidrs       TEXT   NOT NULL DEFAULT '[]',
    created_at          BIGINT NOT NULL,
    created_by          TEXT   NOT NULL DEFAULT '',
    created_by_name     TEXT   NOT NULL DEFAULT '',
    rotated_at          BIGINT,
    revoked_at          BIGINT,
    revoked_by          TEXT   NOT NULL DEFAULT '',
    last_used_at        BIGINT,
    last_used_ip        TEXT   NOT NULL DEFAULT '',
    version             BIGINT NOT NULL
);

CREATE INDEX api_key_created ON api_key (created_at, id);

-- acme-dns registrations of an API key: the subdomain sent to /update maps
-- to the domain whose _acme-challenge TXT RRset is written, txt_values are
-- the values written, oldest first (two kept, as acme-dns does).
CREATE TABLE acme_registration (
    key_id     TEXT   NOT NULL REFERENCES api_key (id),
    subdomain  TEXT   NOT NULL,
    domain     TEXT   NOT NULL,
    allow_from TEXT   NOT NULL DEFAULT '[]',
    txt_values TEXT   NOT NULL DEFAULT '[]',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    version    BIGINT NOT NULL,
    PRIMARY KEY (key_id, subdomain)
);
