//! The compiler-resolved boundary for filesystem mutations.
//!
//! Clippy forbids these operations everywhere else, including through import
//! aliases. Call sites remain annotated with the catalog artifact they mutate;
//! this module supplies capability, not authority classification.

#![allow(clippy::disallowed_methods)]

use std::path::Path;

#[derive(Clone, Copy, Debug)]
pub enum SurfaceWrite {
    Container,
    IdentityKeyMaterial,
    IdentityPointer,
    IdentitySeed,
    IdentityBackup,
    LocalLogCar,
    LocalLogDamaged,
    LocalLogRepair,
    LocalLogHead,
    LocalLogHeadTemp,
    LocalLogLock,
    GitTree,
    Overlay,
    Sqlite,
}

impl SurfaceWrite {
    pub const ALL_ARTIFACTS: &'static [&'static str] = &[
        "identity:identity",
        "identity:roles.d",
        "identity:role-key-path",
        "identity:seed-id",
        "identity:identity-id",
        "identity:seed",
        "identity:seed.replaced-*",
        "identity:seed.protected-*",
        "identity:identity.protected-*",
        "local-log:repo.car",
        "local-log:repo.car.damaged-*",
        "local-log:repo.repair",
        "local-log:HEAD",
        "local-log:HEAD.tmp",
        "local-log:LOCK",
        "git-tree:.claims",
        "overlay:repo.car",
        "sqlite:meta",
    ];
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
