-- KNB1 draft schema. No compatibility or writer acceptance before codec review.
-- Markers are deliberately absent: the writer may publish them only atomically
-- with the complete verified original member and exact initial loss history.
CREATE TABLE bundle_identity (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    bundle BLOB NOT NULL CHECK(typeof(bundle)='blob' AND length(bundle)=32),
    observer TEXT NOT NULL CHECK(typeof(observer)='text' AND length(observer) BETWEEN 56 AND 80),
    profile INTEGER NOT NULL CHECK(typeof(profile)='integer' AND profile IN (2,3)),
    archive BLOB NOT NULL CHECK(typeof(archive)='blob' AND length(archive)=32),
    scope BLOB NOT NULL CHECK(typeof(scope)='blob' AND length(scope)=32),
    issuer TEXT NOT NULL CHECK(typeof(issuer)='text' AND length(issuer) BETWEEN 56 AND 80)
);
CREATE TABLE member_records (
    sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 1 AND 9007199254740991),
    manifest BLOB NOT NULL CHECK(typeof(manifest)='blob' AND length(manifest) BETWEEN 1 AND 65536),
    receipt BLOB NOT NULL CHECK(typeof(receipt)='blob' AND length(receipt) BETWEEN 1 AND 65536),
    envelope BLOB NOT NULL CHECK(typeof(envelope)='blob' AND length(envelope) BETWEEN 1 AND 16384)
);
CREATE TABLE member_objects (
    cid TEXT PRIMARY KEY CHECK(typeof(cid)='text' AND length(cid) BETWEEN 1 AND 128),
    bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes) BETWEEN 0 AND 4194304)
) WITHOUT ROWID;
CREATE TABLE member_plan (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    envelope BLOB NOT NULL CHECK(typeof(envelope)='blob' AND length(envelope) BETWEEN 1 AND 4096)
);
CREATE TABLE member_membership (
    cid TEXT PRIMARY KEY CHECK(typeof(cid)='text' AND length(cid) BETWEEN 1 AND 128),
    length INTEGER NOT NULL CHECK(typeof(length)='integer' AND length BETWEEN 1 AND 4194304)
) WITHOUT ROWID;
CREATE TABLE observations (
    sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 1 AND 9007199254740991),
    envelope BLOB NOT NULL CHECK(typeof(envelope)='blob' AND length(envelope) BETWEEN 1 AND 16384)
);
CREATE TABLE restored_objects (
    cid TEXT PRIMARY KEY CHECK(typeof(cid)='text' AND length(cid) BETWEEN 1 AND 128),
    bytes BLOB NOT NULL CHECK(typeof(bytes)='blob' AND length(bytes) BETWEEN 1 AND 4194304)
) WITHOUT ROWID;
