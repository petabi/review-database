//! Routines to check the database format version and migrate it if necessary.

use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::Path,
};

use anyhow::{anyhow, Context, Result};
use semver::{Version, VersionReq};

/// The version requirement for the database format to be compatible with the
/// current version. When the database format changes, this requirement must be
/// updated to match the new version, and the migration code must be added to
/// the `migrate_data_dir` function.
const DATABASE_VERSION_REQ: &str = ">=0.2, <=0.3.0-alpha.1";

/// Migrates the data directory to the up-to-date format if necessary.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format incompatible with the
/// current version.
pub fn migrate_data_dir(data_dir: &Path) -> Result<()> {
    let version_req = VersionReq::parse(DATABASE_VERSION_REQ).expect("valid version requirement");

    let version_path = data_dir.join("VERSION");
    if data_dir.exists() {
        if data_dir
            .read_dir()
            .context("cannot read data dir")?
            .next()
            .is_none()
        {
            return create_version_file(&version_path);
        }
    } else {
        create_dir_all(data_dir)?;
        return create_version_file(&version_path);
    }

    let database_version = read_version_file(&version_path)?;
    if version_req.matches(&database_version) {
        Ok(())
    } else {
        // Add migration code here if necessary
        Err(anyhow!("incompatible version"))
    }
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
    }
}
