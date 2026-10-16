//! Facts the persistence owners expose to the read/write-surface conformance
//! test. These declarations say only *what exists*; the committed catalog in
//! `tests/fixtures/read-write-surface.tsv` independently says what each value
//! means. Keeping fact and judgment on opposite sides is what lets the test
//! detect an uncataloged store instead of letting code classify itself.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SurfaceValue {
    pub artifact: &'static str,
    pub value: &'static str,
}

impl SurfaceValue {
    pub const fn new(artifact: &'static str, value: &'static str) -> Self {
        Self { artifact, value }
    }
}

/// Experimental v2 artifacts; schema columns are also inspected from SQLite in feature tests.
pub const EVIDENCE_VALUES: &[SurfaceValue] = &[
    SurfaceValue::new("evidence-db:archive.sqlite", "*"),
    SurfaceValue::new("evidence-db:archive.sqlite-wal", "*"),
    SurfaceValue::new("evidence-db:archive.sqlite-journal", "*"),
    SurfaceValue::new("evidence-db:archive.sqlite-shm", "*"),
    SurfaceValue::new("evidence-backup:archive.sqlite", "*"),
    SurfaceValue::new("evidence-backup:archive.sqlite-journal", "*"),
    SurfaceValue::new("evidence-recovery:archive.sqlite", "*"),
    SurfaceValue::new("evidence-recovery:archive.sqlite-journal", "*"),
    SurfaceValue::new("evidence-sqlite:objects", "cid"),
    SurfaceValue::new("evidence-sqlite:objects", "bytes"),
    SurfaceValue::new("evidence-sqlite:commits", "sequence"),
    SurfaceValue::new("evidence-sqlite:commits", "cid"),
    SurfaceValue::new("evidence-sqlite:commits", "scope"),
    SurfaceValue::new("evidence-sqlite:commits", "writer"),
    SurfaceValue::new("evidence-sqlite:commits", "operation"),
    SurfaceValue::new("evidence-sqlite:commits", "position"),
    SurfaceValue::new("evidence-sqlite:commits", "previous"),
    SurfaceValue::new("evidence-sqlite:commits", "manifest"),
    SurfaceValue::new("evidence-sqlite:commits", "receipt"),
    SurfaceValue::new("evidence-sqlite:bindings", "scope"),
    SurfaceValue::new("evidence-sqlite:bindings", "writer"),
    SurfaceValue::new("evidence-sqlite:bindings", "slot"),
    SurfaceValue::new("evidence-sqlite:bindings", "ciphertext"),
    SurfaceValue::new("evidence-sqlite:bindings", "length"),
    SurfaceValue::new("evidence-sqlite:bindings", "first_manifest"),
];
