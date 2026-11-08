-- Gate authorization server (oauth.clients): one grant per client and
-- subject, holding the session snapshot the delegated tokens are issued
-- from and the SHA-256 of the current and previous refresh tokens.
CREATE TABLE oauth_grant (
    id              TEXT   PRIMARY KEY,
    client_id       TEXT   NOT NULL,
    subject         TEXT   NOT NULL,
    subject_name    TEXT   NOT NULL DEFAULT '',
    issuer          TEXT   NOT NULL,
    session_data    TEXT   NOT NULL DEFAULT '',
    auth_time       BIGINT NOT NULL DEFAULT 0,
    scopes          TEXT   NOT NULL DEFAULT '[]',
    created_at      BIGINT NOT NULL,
    consented_at    BIGINT NOT NULL,
    last_used_at    BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    claims_at       BIGINT NOT NULL,
    generation      BIGINT NOT NULL DEFAULT 0,
    base_generation BIGINT NOT NULL DEFAULT 0,
    refresh_hash    TEXT   NOT NULL DEFAULT '',
    previous_hash   TEXT   NOT NULL DEFAULT '',
    rotated_at      BIGINT,
    pending         TEXT   NOT NULL DEFAULT '',
    revoked_at      BIGINT,
    revoked_by      TEXT   NOT NULL DEFAULT '',
    revoke_reason   TEXT   NOT NULL DEFAULT '',
    version         BIGINT NOT NULL
);

CREATE INDEX oauth_grant_client ON oauth_grant (client_id, subject);
CREATE INDEX oauth_grant_subject ON oauth_grant (subject);

-- Single-use authorization codes, by SHA-256 of the code (2 minutes).
CREATE TABLE oauth_code (
    hash       TEXT   PRIMARY KEY,
    client_id  TEXT   NOT NULL,
    data       TEXT   NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX oauth_code_expires ON oauth_code (expires_at);

-- Ids of the client assertions (private_key_jwt) seen until they expire.
CREATE TABLE oauth_jti (
    jti        TEXT   PRIMARY KEY,
    expires_at BIGINT NOT NULL
);

CREATE INDEX oauth_jti_expires ON oauth_jti (expires_at);
