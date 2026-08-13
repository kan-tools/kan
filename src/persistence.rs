//! The compiler-resolved boundary for filesystem mutations.
//!
//! Clippy forbids these operations everywhere else, including through import
//! aliases. Call sites remain annotated with the catalog artifact they mutate;
//! this module supplies capability, not authority classification.

#![allow(clippy::disallowed_methods)]

use std::path::Path;

pub fn create_dir_all(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

pub fn write(path: &Path, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

pub fn rename(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to)
}

pub fn remove_file(path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path)
}

pub fn remove_dir_all(path: &Path) -> std::io::Result<()> {
    std::fs::remove_dir_all(path)
}

pub fn set_permissions(path: &Path, permissions: std::fs::Permissions) -> std::io::Result<()> {
    std::fs::set_permissions(path, permissions)
}

pub fn open_lock_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
}

pub async fn create_dir_all_async(path: &Path) -> std::io::Result<()> {
    tokio::fs::create_dir_all(path).await
}

pub async fn copy_async(from: &Path, to: &Path) -> std::io::Result<u64> {
    tokio::fs::copy(from, to).await
}

pub async fn create_file_async(path: &Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::File::create(path).await
}

pub async fn rename_async(from: &Path, to: &Path) -> std::io::Result<()> {
    tokio::fs::rename(from, to).await
}

pub async fn open_append_async(path: &Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}
