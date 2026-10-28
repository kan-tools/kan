//! The compiler-resolved boundary for filesystem mutations.
//!
//! Clippy forbids these operations everywhere else, including through import
//! aliases. Call sites remain annotated with the catalog artifact they mutate;
//! this module supplies capability, not authority classification.

#![allow(clippy::disallowed_methods)]
#![allow(clippy::disallowed_types)]

use std::{io::Write, path::Path};

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum SurfaceWrite {
    Container,
    IdentityKeyMaterial,
    IdentityPointer,
    IdentitySeed,
    IdentityBackup,
    IdentityLedger,
    IdentityProfiles,
    ScopeIdentity,
    RepositoryTransportIdentity,
    SystemCredentials,
    LocalLogCar,
    LocalLogDamaged,
    LocalLogRepair,
    LocalLogHead,
    LocalLogHeadTemp,
    LocalLogLock,
    GitTree,
    Overlay,
    Sqlite,
    EvidenceSpool,
    EvidenceArchive,
    EvidenceBackup,
    EvidenceRecovery,
    EvidenceRecoverySource,
    EvidenceRestore,
    Count,
}

impl SurfaceWrite {
    pub const ALL: &'static [Self] = &[
        Self::Container,
        Self::IdentityKeyMaterial,
        Self::IdentityPointer,
        Self::IdentitySeed,
        Self::IdentityBackup,
        Self::IdentityLedger,
        Self::IdentityProfiles,
        Self::ScopeIdentity,
        Self::RepositoryTransportIdentity,
        Self::SystemCredentials,
        Self::LocalLogCar,
        Self::LocalLogDamaged,
        Self::LocalLogRepair,
        Self::LocalLogHead,
        Self::LocalLogHeadTemp,
        Self::LocalLogLock,
        Self::GitTree,
        Self::Overlay,
        Self::Sqlite,
        Self::EvidenceSpool,
        Self::EvidenceArchive,
        Self::EvidenceBackup,
        Self::EvidenceRecovery,
        Self::EvidenceRecoverySource,
        Self::EvidenceRestore,
    ];

    /// Catalog artifacts a capability is permitted to mutate. This match is
    /// compiler-exhaustive; `Count` makes omission from `ALL` mechanically
    /// visible as well. The conformance suite binds both sides to the catalog.
    pub const fn artifacts(self) -> &'static [&'static str] {
        match self {
            Self::Container => &["container:workspace"],
            Self::IdentityKeyMaterial => &[
                "identity:identity",
                "identity:roles.d",
                "identity:role-key-path",
                "identity:seed",
            ],
            Self::IdentityPointer => &["identity:seed-id", "identity:identity-id"],
            Self::IdentitySeed => &["identity:seed"],
            Self::IdentityBackup => &[
                "identity:seed.replaced-*",
                "identity:seed.protected-*",
                "identity:identity.protected-*",
            ],
            Self::IdentityLedger => &[
                "identity-ledger:events/*.cbor",
                "identity-ledger:events/.tmp-*",
            ],
            Self::IdentityProfiles => &[
                "identity-profiles:profiles/*.json",
                "identity-profiles:default",
                "identity-profiles:.tmp-*",
                "identity-profiles:LOCK",
                "identity-profiles:enrollment-nonce",
            ],
            Self::ScopeIdentity => &[
                "scope-identity:inception.cbor",
                "scope-identity:initialization-nonce",
                "scope-identity:LOCK",
                "scope-identity:.tmp-*",
            ],
            Self::RepositoryTransportIdentity => &["repository-transport:identity"],
            Self::SystemCredentials => &["credentials:owner-only-file"],
            Self::LocalLogCar => &["local-log:repo.car"],
            Self::LocalLogDamaged => &["local-log:repo.car.damaged-*"],
            Self::LocalLogRepair => &["local-log:repo.repair"],
            Self::LocalLogHead => &["local-log:HEAD"],
            Self::LocalLogHeadTemp => &["local-log:HEAD.tmp"],
            Self::LocalLogLock => &["local-log:LOCK"],
            Self::GitTree => &["git-tree:.claims"],
            Self::Overlay => &[
                "overlay:repo.car",
                "overlay:repo.car.damaged-*",
                "overlay:repo.repair",
                "overlay:HEAD",
                "overlay:HEAD.tmp",
                "overlay:LOCK",
            ],
            Self::Sqlite => &["sqlite:meta"],
            Self::EvidenceSpool => &[
                "evidence-spool:database",
                "evidence-spool:database-wal",
                "evidence-spool:database-shm",
                "evidence-spool:database-journal",
            ],
            Self::EvidenceArchive => &[
                "evidence-crypto:chunk",
                "evidence-service:request",
                "evidence-db:archive.sqlite",
                "evidence-db:archive.sqlite-wal",
                "evidence-db:archive.sqlite-journal",
                "evidence-db:archive.sqlite-shm",
            ],
            Self::EvidenceBackup => &[
                "evidence-backup:archive.sqlite",
                "evidence-backup:archive.sqlite-journal",
                "evidence-backup:archive.sqlite-wal",
                "evidence-backup:archive.sqlite-shm",
            ],
            Self::EvidenceRecovery => &[
                "evidence-recovery:archive.sqlite",
                "evidence-recovery:archive.sqlite-journal",
            ],
            Self::EvidenceRecoverySource => &[
                "evidence-recovery-source:database-wal",
                "evidence-recovery-source:database-shm",
            ],
            Self::EvidenceRestore => &[
                "evidence-restore:files",
                "evidence-restore:plan.json",
                "evidence-restore:report.json",
            ],
            Self::Count => &[],
        }
    }
}

/// SQLite may initialize WAL coordination files even with a read-only handle.
/// It cannot rewrite source records or recover a hot rollback journal in this mode.
#[cfg(feature = "v2-storage")]
pub fn open_sqlite_recovery_source(
    _surface: SurfaceWrite,
    path: &Path,
) -> rusqlite::Result<rusqlite::Connection> {
    rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
}

pub fn create_dir_all(_surface: SurfaceWrite, path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

pub fn write(_surface: SurfaceWrite, path: &Path, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

pub fn rename(_surface: SurfaceWrite, from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to)
}

pub fn remove_file(_surface: SurfaceWrite, path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path)
}

pub fn remove_dir_all(_surface: SurfaceWrite, path: &Path) -> std::io::Result<()> {
    std::fs::remove_dir_all(path)
}

pub fn set_permissions(
    _surface: SurfaceWrite,
    path: &Path,
    permissions: std::fs::Permissions,
) -> std::io::Result<()> {
    std::fs::set_permissions(path, permissions)
}

pub fn open_lock_file(_surface: SurfaceWrite, path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
}

pub fn write_new_owner_only(
    _surface: SurfaceWrite,
    path: &Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

pub async fn create_dir_all_async(_surface: SurfaceWrite, path: &Path) -> std::io::Result<()> {
    tokio::fs::create_dir_all(path).await
}

pub async fn copy_async(_surface: SurfaceWrite, from: &Path, to: &Path) -> std::io::Result<u64> {
    tokio::fs::copy(from, to).await
}

pub async fn create_file_async(
    _surface: SurfaceWrite,
    path: &Path,
) -> std::io::Result<tokio::fs::File> {
    tokio::fs::File::create(path).await
}

pub async fn rename_async(_surface: SurfaceWrite, from: &Path, to: &Path) -> std::io::Result<()> {
    tokio::fs::rename(from, to).await
}

pub async fn open_append_async(
    _surface: SurfaceWrite,
    path: &Path,
) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}

/// Create a single private directory, refusing any existing entry.
pub fn create_dir_owner_only(_surface: SurfaceWrite, path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}
/// Create a private streaming output without following or replacing an existing entry.
pub fn open_new_owner_only(_surface: SurfaceWrite, path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
