-- Timestamps are unix microseconds, UTC.
CREATE TABLE ownership (
    zone                TEXT    NOT NULL,
    host                TEXT    NOT NULL,
    type                TEXT    NOT NULL,
    owner               TEXT    NOT NULL,
    created_by          TEXT    NOT NULL DEFAULT '',
    created_by_name     TEXT    NOT NULL DEFAULT '',
    created_by_category TEXT    NOT NULL DEFAULT '',
    updated_by          TEXT    NOT NULL DEFAULT '',
    updated_by_name     TEXT    NOT NULL DEFAULT '',
    updated_by_category TEXT    NOT NULL DEFAULT '',
    created_at          BIGINT  NOT NULL,
    updated_at          BIGINT  NOT NULL,
    request_id          TEXT    NOT NULL DEFAULT '',
    content_hash        TEXT    NOT NULL DEFAULT '',
    pending_hash        TEXT    NOT NULL DEFAULT '',
    state               TEXT    NOT NULL,
    adopted             INTEGER NOT NULL DEFAULT 0,
    expires_at          BIGINT,
    version             BIGINT  NOT NULL,
    PRIMARY KEY (zone, host, type)
);

CREATE TABLE zone_meta (
    zone    TEXT   PRIMARY KEY,
    version BIGINT NOT NULL
);

CREATE TABLE zone_lock (
    zone       TEXT   PRIMARY KEY,
    holder     TEXT   NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE TABLE audit (
    id BIGSERIAL PRIMARY KEY,
    time             BIGINT NOT NULL,
    request_id       TEXT   NOT NULL DEFAULT '',
    zone             TEXT   NOT NULL DEFAULT '',
    subject          TEXT   NOT NULL DEFAULT '',
    subject_name     TEXT   NOT NULL DEFAULT '',
    subject_category TEXT   NOT NULL DEFAULT '',
    decision         TEXT   NOT NULL DEFAULT '',
    event            TEXT   NOT NULL
);

CREATE INDEX audit_time ON audit (time, id);
CREATE INDEX audit_zone_time ON audit (zone, time);
CREATE INDEX audit_subject_time ON audit (subject, time);
CREATE INDEX audit_decision_time ON audit (decision, time);
