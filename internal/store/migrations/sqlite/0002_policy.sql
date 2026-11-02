-- Managed-policy revisions. Document is immutable after insert.
CREATE TABLE policy_revision (
    id            TEXT   PRIMARY KEY,
    parent_id     TEXT   NOT NULL DEFAULT '',
    document      TEXT   NOT NULL,
    author        TEXT   NOT NULL DEFAULT '',
    author_name   TEXT   NOT NULL DEFAULT '',
    author_cat    TEXT   NOT NULL DEFAULT '',
    created_at    BIGINT NOT NULL,
    comment       TEXT   NOT NULL DEFAULT '',
    status        TEXT   NOT NULL,
    approvals     TEXT   NOT NULL DEFAULT '[]',
    activated_at  BIGINT,
    activated_by  TEXT   NOT NULL DEFAULT '',
    version       BIGINT NOT NULL
);

CREATE INDEX policy_revision_created ON policy_revision (created_at, id);
CREATE INDEX policy_revision_status ON policy_revision (status, created_at);

-- Single row (k = 1) pointing at the active revision.
CREATE TABLE policy_active (
    k           INTEGER PRIMARY KEY CHECK (k = 1),
    revision_id TEXT    NOT NULL REFERENCES policy_revision (id)
);
