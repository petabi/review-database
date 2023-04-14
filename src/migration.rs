//! Routines to check the database format version and migrate it if necessary.

use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use bincode::Options;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

/// The version requirement for the database format to be compatible with the
/// current version. When the database format changes, this requirement must be
/// updated to match the new version, and the migration code must be added to
/// the `migrate_data_dir` function.
const DATABASE_VERSION_REQ: &str = ">=0.3.0,<0.5.0-alpha.4";

/// Migrates the data directory to the up-to-date format if necessary.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format incompatible with the
/// current version.
pub fn migrate_data_dir<P: AsRef<Path>>(data_dir: P, backup_dir: P) -> Result<()> {
    let data_dir = data_dir.as_ref();
    let backup_dir = backup_dir.as_ref();

    let compatible = VersionReq::parse(DATABASE_VERSION_REQ).expect("valid version requirement");

    let (data, data_ver) = retrieve_or_create_version(data_dir)?;
    let (backup, backup_ver) = retrieve_or_create_version(backup_dir)?;

    if data_ver != backup_ver {
        return Err(anyhow!(
            "mismatched database version {data_ver} and backup version {backup_ver}"
        ));
    }

    let mut version = data_ver;
    if compatible.matches(&version) {
        // updates version on file to current

        create_version_file(&backup).context("failed to update VERSION")?;
        return create_version_file(&data).context("failed to update VERSION");
    }

    let migration = vec![(
        VersionReq::parse(">=0.2,<0.5.0-alpha").expect("valid version requirement"),
        Version::parse("0.4.0").expect("valid version"),
        migrate_0_2_to_0_3,
    )];
    while let Some((_req, to, m)) = migration
        .iter()
        .find(|(req, _to, _m)| req.matches(&version))
    {
        m(data_dir, backup_dir)?;
        version = to.clone();
        if compatible.matches(&version) {
            create_version_file(&backup).context("failed to update VERSION")?;
            return create_version_file(&data).context("failed to update VERSION");
        }
    }

    Err(anyhow!(
        "incompatible version {version}, require {compatible}"
    ))
}

/// Recursively creates `path` if not existed, creates the VERSION file
/// under `path` if missing with current version number. Returns VERSION
/// file path with VERSION number written on file.
///
/// # Errors
///
/// Returns an error if VERSION cannot be retrieved or created.
fn retrieve_or_create_version<P: AsRef<Path>>(path: P) -> Result<(PathBuf, Version)> {
    let path = path.as_ref();
    let file = path.join("VERSION");

    if !path.exists() {
        create_dir_all(path)?;
    }
    if path
        .read_dir()
        .context("cannot read data dir")?
        .next()
        .is_none()
    {
        create_version_file(&file)?;
    }

    let version = read_version_file(&file)?;
    Ok((file, version))
}

/// Creates the VERSION file in the data directory.
///
/// # Errors
///
/// Returns an error if the VERSION file cannot be created or written.
fn create_version_file(path: &Path) -> Result<()> {
    let mut f = File::create(path).context("cannot create VERSION")?;
    f.write_all(env!("CARGO_PKG_VERSION").as_bytes())
        .context("cannot write VERSION")?;
    Ok(())
}

/// Reads the VERSION file in the data directory and returns its contents.
///
/// # Errors
///
/// Returns an error if the VERSION file cannot be read or parsed.
fn read_version_file(path: &Path) -> Result<Version> {
    let mut ver = String::new();
    File::open(path)
        .context("cannot open VERSION")?
        .read_to_string(&mut ver)
        .context("cannot read VERSION")?;
    Version::parse(&ver).context("cannot parse VERSION")
}

/// Migrate the data base from 0.2 to 0.3.
///
/// # Errors
///
/// Returns an error if database migration fails.
pub(crate) fn migrate_0_2_to_0_3<P: AsRef<Path>>(path: P, backup: P) -> Result<()> {
    use super::{
        account::{Account, PasswordHashAlgorithm, Role, SaltedPassword},
        IterableMap,
    };
    use chrono::{DateTime, Utc};
    use std::net::IpAddr;

    #[derive(Deserialize, Serialize)]
    struct OldAccount {
        username: String,
        password: SaltedPassword,
        role: Role,
        name: String,
        department: String,
        creation_time: DateTime<Utc>,
        last_signin_time: Option<DateTime<Utc>>,
        allow_access_from: Option<Vec<IpAddr>>,
        max_parallel_sessions: Option<u32>,
    }

    impl From<&OldAccount> for Account {
        fn from(input: &OldAccount) -> Self {
            Self {
                username: input.username.clone(),
                password: input.password.clone(),
                role: input.role,
                name: input.name.clone(),
                department: input.department.clone(),
                creation_time: input.creation_time,
                last_signin_time: input.last_signin_time,
                allow_access_from: input.allow_access_from.clone(),
                max_parallel_sessions: input.max_parallel_sessions,
                password_hash_algorithm: PasswordHashAlgorithm::default(),
            }
        }
    }

    let store = super::Store::new(path.as_ref(), backup.as_ref())?;
    store.backup(1)?;
    let account_map = store.account_map();

    for (k, v) in account_map.iter_forward()? {
        let old: OldAccount = bincode::DefaultOptions::new().deserialize::<OldAccount>(&v)?;
        let account: Account = (&old).into();
        let new = bincode::DefaultOptions::new().serialize(&account)?;
        account_map.update((&k, &v), (&k, &new))?;
    }

    store.purge_old_backups(0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use semver::{Version, VersionReq};

    use super::DATABASE_VERSION_REQ;

    #[test]
    fn version() {
        let version_req = VersionReq::parse(DATABASE_VERSION_REQ).expect("valid semver");

        // The current version must match the version requirement.
        let version = Version::parse(env!("CARGO_PKG_VERSION")).expect("valid semver");
        assert!(version_req.matches(&version));

        // An incompatible version must not match the version requirement.
        let version = Version::parse("0.2.0").expect("valid semver");
        assert!(!version_req.matches(&version));
    }
}
