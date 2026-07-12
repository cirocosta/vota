CREATE TABLE polls (
    poll_id TEXT PRIMARY KEY,
    artifact_hash TEXT NOT NULL UNIQUE,
    artifact BLOB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('open', 'closed')),
    created_at TEXT NOT NULL,
    closes_at TEXT NOT NULL,
    closed_at TEXT,
    issuer_key_id TEXT NOT NULL,
    eligibility_commitment TEXT NOT NULL
) STRICT;

CREATE TABLE poll_choices (
    poll_id TEXT NOT NULL REFERENCES polls(poll_id) ON DELETE RESTRICT,
    choice_id TEXT NOT NULL,
    label TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    PRIMARY KEY (poll_id, choice_id),
    UNIQUE (poll_id, position)
) STRICT;

CREATE TABLE poll_credits (
    poll_id TEXT NOT NULL REFERENCES polls(poll_id) ON DELETE RESTRICT,
    ssh_fingerprint TEXT NOT NULL,
    ssh_public_key TEXT NOT NULL,
    issuance_request_id TEXT,
    blinded_message_hash TEXT,
    blind_signature BLOB,
    claimed_at TEXT,
    PRIMARY KEY (poll_id, ssh_fingerprint),
    UNIQUE (poll_id, ssh_public_key),
    CHECK (
        (issuance_request_id IS NULL AND blinded_message_hash IS NULL AND blind_signature IS NULL AND claimed_at IS NULL)
        OR
        (issuance_request_id IS NOT NULL AND blinded_message_hash IS NOT NULL AND blind_signature IS NOT NULL AND claimed_at IS NOT NULL)
    )
) STRICT;

CREATE TABLE credit_events (
    poll_id TEXT NOT NULL REFERENCES polls(poll_id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    artifact BLOB NOT NULL,
    signature BLOB NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (poll_id, sequence),
    UNIQUE (event_hash)
) STRICT;

CREATE TABLE ballot_events (
    poll_id TEXT NOT NULL REFERENCES polls(poll_id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    event_type TEXT NOT NULL CHECK (event_type IN ('poll_created', 'ballot_accepted', 'poll_closed')),
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    artifact BLOB NOT NULL,
    receipt BLOB,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (poll_id, sequence),
    UNIQUE (event_hash),
    CHECK ((event_type = 'ballot_accepted' AND receipt IS NOT NULL) OR (event_type != 'ballot_accepted' AND receipt IS NULL))
) STRICT;

CREATE TABLE spent_credentials (
    poll_id TEXT NOT NULL REFERENCES polls(poll_id) ON DELETE RESTRICT,
    credential_hash TEXT NOT NULL,
    ballot_sequence INTEGER NOT NULL,
    PRIMARY KEY (poll_id, credential_hash),
    UNIQUE (poll_id, ballot_sequence),
    FOREIGN KEY (poll_id, ballot_sequence) REFERENCES ballot_events(poll_id, sequence)
        DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE poll_tallies (
    poll_id TEXT PRIMARY KEY REFERENCES polls(poll_id) ON DELETE RESTRICT,
    artifact BLOB NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE sequencer_checkpoints (
    poll_id TEXT NOT NULL REFERENCES polls(poll_id) ON DELETE RESTRICT,
    ballot_sequence INTEGER NOT NULL,
    event_hash TEXT NOT NULL,
    artifact BLOB NOT NULL,
    PRIMARY KEY (poll_id, ballot_sequence),
    FOREIGN KEY (poll_id, ballot_sequence) REFERENCES ballot_events(poll_id, sequence)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX credit_events_poll_sequence_idx ON credit_events (poll_id, sequence);
CREATE INDEX ballot_events_poll_sequence_idx ON ballot_events (poll_id, sequence);
