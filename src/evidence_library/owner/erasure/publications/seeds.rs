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
    fn lineage_larger_than_one_owner_record_survives_restart_and_idempotent_extension() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
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
