//! Incremental authenticated capture membership. Each checkpoint retains only
//! new ordinal/sequence pairs; content-addressed pages make interrupted writes
//! harmless. Old inline checkpoints remain readable.
use super::*;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    format: String,
    header: storage::CaptureScan,
    delta: Option<String>,
    members: usize,
    previous: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Members {
    context: String,
    entries: Vec<(u64, u64)>,
}
fn key(context: &str, n: usize) -> String {
    format!("capture-discovery:{context}:{n}")
}
fn page_key(hash: &str) -> String {
    format!("capture-discovery-members:{hash}")
}
pub(super) fn read(
    journal: &Workspace,
    context: &str,
    count: usize,
) -> Result<Option<storage::CaptureScan>, Failure> {
    let mut members = BTreeMap::new();
    let mut header = None;
    let mut previous = None;
    let mut paged = false;
    for n in 0..count {
        let value = journal
            .get("owner-result", &key(context, n))?
            .ok_or(Failure::Corrupt)?;
        let hash = Owner::hash(&value)?;
        if value.get("format").is_some() {
            paged = true;
            let checkpoint: Checkpoint = serde_json::from_value(value).map_err(invalid)?;
            if checkpoint.format != "kan-capture-discovery/2"
                || checkpoint.previous != previous
                || checkpoint.header.member_count() != 0
            {
                return Err(Failure::Corrupt);
            }
            if let Some(hash) = checkpoint.delta {
                fixed(&hash)?;
                let value = journal
                    .get("owner-result", &page_key(&hash))?
                    .ok_or(Failure::Corrupt)?;
                if Owner::hash(&value)? != hash {
                    return Err(Failure::Corrupt);
                }
                let page: Members = serde_json::from_value(value).map_err(invalid)?;
                if page.context != context || page.entries.is_empty() || page.entries.len() > 512 {
                    return Err(Failure::Corrupt);
                }
                for (ordinal, sequence) in page.entries {
                    if members.insert(ordinal, sequence).is_some() {
                        return Err(Failure::Corrupt);
                    }
                }
            }
            if checkpoint.members != members.len() {
                return Err(Failure::Corrupt);
            }
            header = Some(checkpoint.header);
        } else {
            if paged {
                return Err(Failure::Corrupt);
            }
            let legacy: storage::CaptureScan = serde_json::from_value(value).map_err(invalid)?;
            members = legacy.member_delta(0).into_iter().collect();
            header = Some(legacy.checkpoint());
        }
        previous = Some(hash);
    }
    header
        .map(|h| h.restore_members(members).map_err(Failure::from))
        .transpose()
}
pub(super) fn write(
    journal: &Workspace,
    context: &str,
    n: usize,
    scan: &storage::CaptureScan,
    first_sequence: u64,
) -> Result<(), Failure> {
    let entries = scan.member_delta(first_sequence);
    if entries.len() > 512 {
        return Err(Failure::Invalid);
    }
    let delta = if entries.is_empty() {
        None
    } else {
        let value = serde_json::to_value(Members {
            context: context.into(),
            entries,
        })
        .map_err(invalid)?;
        let hash = Owner::hash(&value)?;
        journal.put("owner-result", &page_key(&hash), value)?;
        Some(hash)
    };
    let previous = if n == 0 {
        None
    } else {
        Some(Owner::hash(
            &journal
                .get("owner-result", &key(context, n - 1))?
                .ok_or(Failure::Corrupt)?,
        )?)
    };
    let value = serde_json::to_value(Checkpoint {
        format: "kan-capture-discovery/2".into(),
        header: scan.checkpoint(),
        delta,
        members: scan.member_count(),
        previous,
    })
    .map_err(invalid)?;
    journal.put("owner-result", &key(context, n), value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scan(count: u64) -> storage::CaptureScan {
        serde_json::from_value(json!({
            "capture":{"writer":"test-writer","observer":"gateway","attempt":"a".repeat(64)},
            "binding":["a".repeat(64),"b".repeat(64),"test-issuer"],
            "through":6000,"tip":"pinned-tip","next":count+1,
            "found":(0..count).map(|n|(n.to_string(),json!(n+1))).collect::<serde_json::Map<_,_>>(),
            "gap":false,"started":true,"terminal":null
        }))
        .unwrap()
    }
    #[test]
    fn incremental_membership_restarts_beyond_inline_capacity_and_reads_legacy_prefix() {
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
                [38; 32],
            )
            .unwrap()
        };
        let journal = open();
        // An existing inline checkpoint transitions to delta pages without
        // rewriting historical records or treating a missing page as empty.
        journal
            .put(
                "owner-result",
                &key("selection", 0),
                serde_json::to_value(scan(512)).unwrap(),
            )
            .unwrap();
        for n in 1..10 {
            write(
                &journal,
                "selection",
                n,
                &scan((n as u64 + 1) * 512),
                n as u64 * 512 + 1,
            )
            .unwrap();
            let value = journal
                .get("owner-result", &key("selection", n))
                .unwrap()
                .unwrap();
            assert!(serde_json::to_vec(&value).unwrap().len() < 2048);
        }
        drop(journal);
        let journal = open();
        let restored = read(&journal, "selection", 10).unwrap().unwrap();
        assert_eq!(restored.member_count(), 5120);
        assert_eq!(restored.next_sequence(), 5121);
        assert_eq!(
            restored.member_delta(5119),
            vec![(5118, 5119), (5119, 5120)]
        );
        assert!(read(&journal, "selection", 11).is_err());
        // Same checkpoint is an idempotent interrupted-write retry.
        write(&journal, "selection", 9, &scan(5120), 4609).unwrap();
        assert_eq!(
            read(&journal, "selection", 10)
                .unwrap()
                .unwrap()
                .member_count(),
            5120
        );
        let value = journal
            .get("owner-result", &key("selection", 9))
            .unwrap()
            .unwrap();
        let mut missing = value.clone();
        missing["previous"] = Value::Null;
        missing["delta"] = json!("f".repeat(64));
        journal
            .put("owner-result", &key("missing", 0), missing)
            .unwrap();
        assert!(read(&journal, "missing", 1).is_err());
        let mut transplanted = value;
        transplanted["previous"] = Value::Null;
        journal
            .put("owner-result", &key("other-context", 0), transplanted)
            .unwrap();
        assert!(read(&journal, "other-context", 1).is_err());
        let mut wrong_count = journal
            .get("owner-result", &key("selection", 0))
            .unwrap()
            .unwrap();
        wrong_count["found"]["0"] = json!(0);
        journal
            .put("owner-result", &key("bad-membership", 0), wrong_count)
            .unwrap();
        assert!(read(&journal, "bad-membership", 1).is_err());
    }
}
