CREATE TABLE polls (
    poll_id TEXT PRIMARY KEY,
    manifest_hash TEXT NOT NULL UNIQUE,
    manifest BLOB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'closed', 'tallied')),
    created_at TEXT NOT NULL,
    closed_at TEXT,
    aggregate_hash TEXT UNIQUE,
    aggregate BLOB
) STRICT;

CREATE TABLE audit_events (
    poll_id TEXT NOT NULL REFERENCES polls(poll_id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    event_hash TEXT NOT NULL UNIQUE,
    event BLOB NOT NULL,
    accepted_at TEXT NOT NULL,
    PRIMARY KEY (poll_id, sequence)
) STRICT;

CREATE TABLE ballots (
    poll_id TEXT NOT NULL REFERENCES polls(poll_id) ON DELETE RESTRICT,
    ballot_hash TEXT NOT NULL,
    nullifier TEXT NOT NULL,
    artifact BLOB NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    accepted_at TEXT NOT NULL,
    PRIMARY KEY (poll_id, ballot_hash),
    CONSTRAINT ballots_nullifier_unique UNIQUE (poll_id, nullifier),
    CONSTRAINT ballots_sequence_unique UNIQUE (poll_id, sequence),
    FOREIGN KEY (poll_id, sequence) REFERENCES audit_events(poll_id, sequence)
        DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE checkpoints (
    poll_id TEXT NOT NULL REFERENCES polls(poll_id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    checkpoint_hash TEXT NOT NULL UNIQUE,
    artifact BLOB NOT NULL,
    PRIMARY KEY (poll_id, sequence),
    FOREIGN KEY (poll_id, sequence) REFERENCES audit_events(poll_id, sequence)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE trustee_shares (
    poll_id TEXT NOT NULL REFERENCES polls(poll_id) ON DELETE RESTRICT,
    trustee_id TEXT NOT NULL,
    aggregate_hash TEXT NOT NULL,
    artifact_hash TEXT NOT NULL UNIQUE,
    artifact BLOB NOT NULL,
    submitted_at TEXT NOT NULL,
    PRIMARY KEY (poll_id, trustee_id)
) STRICT;

CREATE TABLE tallies (
    poll_id TEXT PRIMARY KEY REFERENCES polls(poll_id) ON DELETE RESTRICT,
    aggregate_hash TEXT NOT NULL,
    evidence_hash TEXT NOT NULL UNIQUE,
    artifact BLOB NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX ballots_poll_sequence_idx ON ballots (poll_id, sequence);
CREATE INDEX events_poll_sequence_idx ON audit_events (poll_id, sequence);
CREATE INDEX shares_poll_idx ON trustee_shares (poll_id, trustee_id);
