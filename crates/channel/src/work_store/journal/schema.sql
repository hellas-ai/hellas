-- What the journal is about, and the state its live records replay from.
-- Exactly one row; `checkpoint` is NULL until the first rotation.
CREATE TABLE journal (
    key BLOB NOT NULL,
    kind INTEGER NOT NULL,
    role INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    checkpoint BLOB
) STRICT;

-- Every record appended since the checkpoint, in append order.
CREATE TABLE record (
    seq INTEGER PRIMARY KEY,
    payload BLOB NOT NULL
) STRICT;
