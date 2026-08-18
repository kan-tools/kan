//! The compiler-resolved boundary for filesystem mutations.
//!
//! Clippy forbids these operations everywhere else, including through import
//! aliases. Call sites remain annotated with the catalog artifact they mutate;
//! this module supplies capability, not authority classification.

#![allow(clippy::disallowed_methods)]
#![allow(clippy::disallowed_types)]

use std::path::Path;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum SurfaceWrite {
    Container,
    IdentityKeyMaterial,
    IdentityPointer,
    IdentitySeed,
    IdentityBackup,
    IdentityLedger,
    LocalLogCar,
    LocalLogDamaged,
    LocalLogRepair,
    LocalLogHead,
    LocalLogHeadTemp,
    LocalLogLock,
    GitTree,
    Overlay,
    Sqlite,
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
        Self::LocalLogCar,
        Self::LocalLogDamaged,
        Self::LocalLogRepair,
        Self::LocalLogHead,
        Self::LocalLogHeadTemp,
        Self::LocalLogLock,
        Self::GitTree,
        Self::Overlay,
        Self::Sqlite,
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
            Self::Count => &[],
        }
    }
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
