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
