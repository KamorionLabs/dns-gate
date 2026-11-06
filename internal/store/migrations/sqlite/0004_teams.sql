-- Team selected by the subject of a plan (X-DNS-Gate-Team, team field).
ALTER TABLE rrset_plan ADD COLUMN team TEXT NOT NULL DEFAULT '';

-- Deleted RRsets reserved for the team that owned them until expires_at.
CREATE TABLE ownership_tombstone (
    zone                TEXT   NOT NULL,
    host                TEXT   NOT NULL,
    type                TEXT   NOT NULL,
    team                TEXT   NOT NULL,
    content_hash        TEXT   NOT NULL DEFAULT '',
    deleted_by          TEXT   NOT NULL DEFAULT '',
    deleted_by_name     TEXT   NOT NULL DEFAULT '',
    deleted_by_category TEXT   NOT NULL DEFAULT '',
    deleted_at          BIGINT NOT NULL,
    expires_at          BIGINT NOT NULL,
    request_id          TEXT   NOT NULL DEFAULT '',
    PRIMARY KEY (zone, host, type)
);

CREATE INDEX ownership_tombstone_expires ON ownership_tombstone (expires_at);

-- Ownership transfer requests, document is the JSON of the whole request.
CREATE TABLE ownership_transfer (
    id         TEXT   PRIMARY KEY,
    zone       TEXT   NOT NULL DEFAULT '',
    status     TEXT   NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    document   TEXT   NOT NULL,
    version    BIGINT NOT NULL
);

CREATE INDEX ownership_transfer_created ON ownership_transfer (created_at, id);
CREATE INDEX ownership_transfer_expires ON ownership_transfer (expires_at);
