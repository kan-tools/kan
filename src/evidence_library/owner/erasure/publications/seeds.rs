//! Minimal cumulative lineage is paged independently of deletion authorities.
use super::*;
fn key(job: &str, n: usize) -> String {
    format!("erasure:{job}:lineage:{n}")
}
impl Seeds {
    pub(super) fn load(journal: &Workspace, job: &str) -> Result<(Self, usize), Failure> {
        let count = first_unused(|n| Ok(journal.get("owner-result", &key(job, n))?.is_some()))?;
        let mut seeds = Self::default();
        for n in 0..count {
            let page: Self = serde_json::from_value(
                journal
                    .get("owner-result", &key(job, n))?
                    .ok_or(Failure::Corrupt)?,
            )
            .map_err(invalid)?;
            if page.coordinates.len() > 32 || page.identities.len() > 32 {
                return Err(Failure::Corrupt);
            }
            seeds.coordinates.extend(page.coordinates);
            seeds.identities.extend(page.identities);
        }
        Ok((seeds, count))
    }
    pub(super) fn persist(&self, journal: &Workspace, job: &str) -> Result<usize, Failure> {
        let (old, mut count) = Self::load(journal, job)?;
        let mut coordinates = self
            .coordinates
            .difference(&old.coordinates)
            .cloned()
            .peekable();
        let mut identities = self
            .identities
            .difference(&old.identities)
            .cloned()
            .peekable();
        while coordinates.peek().is_some() || identities.peek().is_some() {
            let page = Self {
                coordinates: coordinates.by_ref().take(32).collect(),
                identities: identities.by_ref().take(32).collect(),
            };
            journal.put(
                "owner-result",
                &key(job, count),
                serde_json::to_value(page).map_err(invalid)?,
            )?;
            count = count.checked_add(1).ok_or(Failure::Unavailable)?;
        }
        Ok(count)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maximum_publication_batch_fits_the_owner_journal_with_paged_lineage() {
        // Exercise the actual Plan codec with all 16 destinations authorized.
        // 128-byte ASCII identifiers conservatively exceed generated CIDs and
        // supported signing DIDs; numeric fields use their widest wire values.
        let binding = json!({"profile":"admitted","archive":"a".repeat(64),
            "scope":"b".repeat(64),"issuer":"i".repeat(128)});
        let mut destinations = Vec::new();
        for _ in 0..16 {
            let targets = (0..MAX_SELECTED / 16)
                .map(|n| {
                    json!({
                        "sequence":crate::evidence::MAX_SAFE_INTEGER as u64 - n as u64,
                        "manifest":"m".repeat(128),"object":"o".repeat(128),"length":usize::MAX
                    })
                })
                .collect::<Vec<_>>();
            destinations.push(json!({"binding":binding,
                "frontier":{"through":"9007199254740991","manifest":"m".repeat(128),"attestation":"a".repeat(128)},
                "authorization":{"change":{"version":1,"binding":binding,"owner":"w".repeat(128),
                    "sequence":"9007199254740991","previous":"p".repeat(64),"nonce":"n".repeat(64),"recorded_at":"9007199254740991",
                    "erasure":{"plan":{"version":1,"archive":"a".repeat(64),"scope":"b".repeat(64),"issuer":"i".repeat(128),
                        "through":9007199254740991u64,"tip":"t".repeat(128),"previous":"p".repeat(64),"nonce":"n".repeat(64),
                        "recorded_at":9007199254740991u64,"targets":targets},"signature":"s".repeat(128)}},"signature":"s".repeat(128)}
            }));
        }
        let plan: Plan = serde_json::from_value(json!({"version":1,"job":"j".repeat(64),"parent":"p".repeat(64),
            "destinations":destinations,"identities":[],"prior_coordinates":[],"more":true,"seed_pages":usize::MAX})).unwrap();
        let bytes = serde_json::to_vec(&plan).unwrap();
        assert!(
            bytes.len() <= MAX_PLAN_BYTES,
            "maximum publication batch uses {} bytes",
            bytes.len()
        );
    }
    #[test]
    fn lineage_larger_than_one_owner_record_survives_restart_and_idempotent_extension() {
        #[cfg(unix)]
        let dir = {
            use std::os::unix::fs::PermissionsExt;
            tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap()
        };
        #[cfg(not(unix))]
        let dir = tempfile::tempdir().unwrap();
        let signing = dir.path().join("signer.key");
        Identity::generate().save(&signing).unwrap();
        let database = dir.path().join("owner.sqlite");
        let open = || {
            Workspace::open(
                &database,
                Identity::load_existing(&signing).unwrap(),
                [37; 32],
            )
            .unwrap()
        };
        let journal = open();
        let author = journal.author();
        let mut selected = Seeds::default();
        for n in 0..1500 {
            selected
                .identities
                .insert((author.clone(), format!("{n:064x}"), "a".repeat(64)));
            selected
                .coordinates
                .insert(format!("source-coordinate-{n}"));
        }
        assert!(serde_json::to_vec(&selected).unwrap().len() > 250 * 1024);
        let count = selected.persist(&journal, "job").unwrap();
        assert!(count > 1);
        assert_eq!(selected.persist(&journal, "job").unwrap(), count);
        drop(journal);
        let journal = open();
        let (mut restored, retained) = Seeds::load(&journal, "job").unwrap();
        assert_eq!(retained, count);
        assert_eq!(restored.identities, selected.identities);
        assert_eq!(restored.coordinates, selected.coordinates);
        restored
            .identities
            .insert((author, "b".repeat(64), "c".repeat(64)));
        assert_eq!(restored.persist(&journal, "job").unwrap(), count + 1);
        assert_eq!(
            Seeds::load(&journal, "job").unwrap().0.identities.len(),
            1501
        );
        assert!(Seeds::load(&journal, "different-job")
            .unwrap()
            .0
            .identities
            .is_empty());
    }
}
