//! Content-addressed exact coordinates; a compact manifest commits every page.
use super::*;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Page {
    context: String,
    index: usize,
    previous: Option<String>,
    pub(super) targets: Vec<storage::Target>,
}
fn page_key(hash: &str) -> String {
    format!("erasure-selection-page:{hash}")
}
fn key(hash: &str) -> String {
    format!("erasure-selection:{hash}")
}
fn context(manifest: &Manifest) -> Result<String, Failure> {
    Owner::hash(
        &json!({"target":manifest.target,"binding":manifest.binding,"owner":manifest.owner,"selector":manifest.selector,
        "through":manifest.through,"tip":manifest.tip,"custody":manifest.custody}),
    )
}
pub(super) fn check_target(target: &Target, manifest: &Manifest) -> Result<(), Failure> {
    let Configured { history, .. } = configured(target)?;
    if manifest.target != Owner::hash(&serde_json::to_value(target).map_err(invalid)?)?
        || manifest.binding != history.binding
        || manifest.owner != history.owner
    {
        return Err(Failure::Conflict);
    }
    Ok(())
}
pub(super) fn retain(
    journal: &Workspace,
    target: &Target,
    selector: Selector,
    coordinates: &storage::Coordinates,
    custody: String,
    gap: Option<bool>,
    coverage: &str,
) -> Result<Manifest, Failure> {
    if coordinates.targets.is_empty() {
        return Err(Failure::Invalid);
    }
    let Configured { history, .. } = configured(target)?;
    let mut manifest = Manifest {
        version: 1,
        target: Owner::hash(&serde_json::to_value(target).map_err(invalid)?)?,
        binding: history.binding.clone(),
        owner: history.owner.clone(),
        selector,
        through: coordinates.through,
        tip: coordinates.tip.clone(),
        custody,
        root: String::new(),
        pages: 0,
        objects: coordinates.targets.len(),
        bytes: "0".into(),
        recording_gap: gap,
        coverage: coverage.into(),
    };
    let context = context(&manifest)?;
    let mut previous = None;
    let mut bytes = 0u64;
    for (index, targets) in coordinates.targets.chunks(PAGE).enumerate() {
        for target in targets {
            bytes = bytes
                .checked_add(u64::try_from(target.length).map_err(invalid)?)
                .ok_or(Failure::Invalid)?;
        }
        let value = serde_json::to_value(Page {
            context: context.clone(),
            index,
            previous,
            targets: targets.to_vec(),
        })
        .map_err(invalid)?;
        let hash = Owner::hash(&value)?;
        journal.put("owner-result", &page_key(&hash), value)?;
        previous = Some(hash);
        manifest.pages += 1;
    }
    manifest.root = previous.ok_or(Failure::Invalid)?;
    manifest.bytes = bytes.to_string();
    let value = serde_json::to_value(&manifest).map_err(invalid)?;
    journal.put("owner-result", &key(&Owner::hash(&value)?), value)?;
    Ok(manifest)
}
pub(super) fn read(journal: &Workspace, selection: &str) -> Result<(Manifest, Vec<Page>), Failure> {
    fixed(selection)?;
    let value = journal
        .get("owner-result", &key(selection))?
        .ok_or(Failure::Missing)?;
    if Owner::hash(&value)? != selection {
        return Err(Failure::Corrupt);
    }
    let manifest: Manifest = serde_json::from_value(value).map_err(invalid)?;
    if manifest.version != 1
        || manifest.pages == 0
        || manifest.objects == 0
        || manifest.through == 0
        || manifest.pages != manifest.objects.div_ceil(PAGE)
    {
        return Err(Failure::Corrupt);
    }
    let expected = context(&manifest)?;
    let mut cursor = Some(manifest.root.clone());
    let mut pages = Vec::new();
    for index in (0..manifest.pages).rev() {
        let hash = cursor.take().ok_or(Failure::Corrupt)?;
        fixed(&hash)?;
        let value = journal
            .get("owner-result", &page_key(&hash))?
            .ok_or(Failure::Corrupt)?;
        if Owner::hash(&value)? != hash {
            return Err(Failure::Corrupt);
        }
        let page: Page = serde_json::from_value(value).map_err(invalid)?;
        if page.index != index
            || page.context != expected
            || page.targets.is_empty()
            || page.targets.len() > PAGE
            || (index + 1 < manifest.pages && page.targets.len() != PAGE)
        {
            return Err(Failure::Corrupt);
        }
        cursor = page.previous.clone();
        pages.push(page);
    }
    if cursor.is_some() {
        return Err(Failure::Corrupt);
    }
    pages.reverse();
    let mut bytes = 0u64;
    let mut count = 0usize;
    let mut last = 0;
    let mut objects = std::collections::BTreeSet::new();
    for target in pages.iter().flat_map(|p| &p.targets) {
        if target.sequence <= last
            || target.sequence > manifest.through
            || target.length == 0
            || !objects.insert(&target.object)
        {
            return Err(Failure::Corrupt);
        }
        last = target.sequence;
        count = count.checked_add(1).ok_or(Failure::Corrupt)?;
        bytes = bytes
            .checked_add(u64::try_from(target.length).map_err(invalid)?)
            .ok_or(Failure::Corrupt)?;
    }
    if count != manifest.objects || bytes.to_string() != manifest.bytes {
        return Err(Failure::Corrupt);
    }
    Ok((manifest, pages))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn large_selection_is_committed_by_compact_manifest_and_missing_pages_fail_closed() {
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
        let signer = dir.path().join("signer.key");
        Identity::generate().save(&signer).unwrap();
        let open = || {
            Workspace::open(
                &dir.path().join("owner.sqlite"),
                Identity::load_existing(&signer).unwrap(),
                [39; 32],
            )
            .unwrap()
        };
        let journal = open();
        let author = journal.author();
        let target:Target=serde_json::from_value(json!({"kind":"capture-erasure","id":"test","root":dir.path(),"history":{"directory":dir.path(),"binding":{"profile":"admitted","archive":"a".repeat(64),"scope":"b".repeat(64),"issuer":author},"owner":author,"minimum":"c".repeat(64)},"signing_key":signer,"issuer_key":signer,"private_keys":[signer]})).unwrap();
        // Conservative identifier lengths exercise the actual journal codec;
        // physical coordinate authenticity is covered by API integration tests.
        let coordinates = storage::Coordinates {
            through: 5000,
            tip: "t".repeat(128),
            targets: (1..=5000)
                .map(|n| storage::Target {
                    sequence: n,
                    manifest: format!("{n:0128x}"),
                    object: format!("{n:0128x}"),
                    length: 1024,
                })
                .collect(),
        };
        assert!(serde_json::to_vec(&coordinates).unwrap().len() > 1024 * 1024);
        let manifest = retain(
            &journal,
            &target,
            Selector::ArchivePrefix,
            &coordinates,
            "c".repeat(64),
            None,
            "test pinned archive",
        )
        .unwrap();
        let value = serde_json::to_value(&manifest).unwrap();
        let selection = Owner::hash(&value).unwrap();
        assert!(serde_json::to_vec(&value).unwrap().len() < 4096);
        assert_eq!(manifest.pages, 10);
        drop(journal);
        let journal = open();
        let (restored, pages) = read(&journal, &selection).unwrap();
        assert_eq!(restored.objects, 5000);
        assert_eq!(
            pages
                .into_iter()
                .flat_map(|p| p.targets)
                .collect::<Vec<_>>(),
            coordinates.targets
        );
        let reference = Reference {
            selection: selection.clone(),
        };
        let c = contract(&target, &reference, &restored).unwrap();
        assert!(serde_json::to_vec(&c).unwrap().len() < 8192);
        let mut missing = value.clone();
        missing["root"] = json!("f".repeat(64));
        let hash = Owner::hash(&missing).unwrap();
        journal.put("owner-result", &key(&hash), missing).unwrap();
        assert!(read(&journal, &hash).is_err());
        let mut changed = value;
        changed["objects"] = json!(5001);
        let hash = Owner::hash(&changed).unwrap();
        journal.put("owner-result", &key(&hash), changed).unwrap();
        assert!(read(&journal, &hash).is_err());
        let id = Owner::hash(&c).unwrap();
        journal
            .put(
                "owner-job",
                &id,
                json!({"id":id,"contract":c,"owner_signature":"0".repeat(128)}),
            )
            .unwrap();
        assert!(
            execution::verify_job(&journal, &target, &id).is_err(),
            "authenticated selection pages do not replace owner consent"
        );
    }
}
