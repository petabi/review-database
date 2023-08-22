//! Routines to check the database format version and migrate it if necessary.
#![allow(clippy::too_many_lines)]

use anyhow::{anyhow, Context, Result};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};
use tracing::info;

/// The range of versions that use the current database format.
///
/// The range should include all the earlier, released versions that use the current database
/// format, and exclude the first future version that uses a new database format.
///
/// # Examples
///
/// ```rust
/// // The current version is 0.4.1 and the database format hasn't been changed since 0.3.0.
/// // This should include future patch versions such as 0.4.2, 0.4.3, etc. since they won't
/// // change the database format.
/// const COMPATIBLE_VERSION: &str = ">=0.3,<0.5.0-alpha";
/// ```
///
/// ```rust
/// // The current version is 0.5.0-alpha.4 and the database format hasn't been changed since
/// // 0.5.0-alpha.2. This shouldn't include any future version since we cannot guarantee that
/// // the database format won't be changed in the future alpha or beta versions.
/// const COMPATIBLE_VERSION: &str = ">=0.5.0-alpha.2,<=0.5.0-alpha.4";
/// ```
const COMPATIBLE_VERSION_REQ: &str = ">=0.16.0,<=0.17.1";

/// Migrates the data directory to the up-to-date format if necessary.
///
/// Migration is supported between released versions only. The prelease versions (alpha, beta,
/// etc.) should be assumed to be incompatible with each other.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format incompatible with the
/// current version.
pub fn migrate_data_dir<P: AsRef<Path>>(data_dir: P, backup_dir: P) -> Result<()> {
    let data_dir = data_dir.as_ref();
    let backup_dir = backup_dir.as_ref();

    let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).expect("valid version requirement");

    let (data, data_ver) = retrieve_or_create_version(data_dir)?;
    let (backup, backup_ver) = retrieve_or_create_version(backup_dir)?;

    if data_ver != backup_ver {
        return Err(anyhow!(
            "mismatched database version {data_ver} and backup version {backup_ver}"
        ));
    }

    let mut version = data_ver;
    if compatible.matches(&version) {
        return Ok(());
    }

    // A list of migrations where each item is a tuple of (version requirement, to version,
    // migration function).
    //
    // * The "version requirement" should include all the earlier, released versions that use the
    //   database format the migration function can handle, and exclude the first future version
    //   that uses a new database format.
    // * The "to version" should be the first future version that uses a new database format.
    // * The "migration function" should migrate the database from the version before "to version"
    //   to "to version". The function name should be in the form of "migrate_A_to_B" where A is
    //   the first version (major.minor) in the "version requirement" and B is the "to version"
    //   (major.minor). (NOTE: Once we release 1.0.0, A and B will contain the major version only.)
    let migration: Vec<(_, _, fn(_) -> Result<_, _>)> = vec![(
        VersionReq::parse(">=0.12.0,<0.16.0").expect("valid version requirement"),
        Version::parse("0.16.0").expect("valid version"),
        migrate_0_12_to_0_16,
    )];

    let mut store = super::Store::new(data_dir, backup_dir)?;
    store.backup(false, 1)?;

    while let Some((_req, to, m)) = migration
        .iter()
        .find(|(req, _to, _m)| req.matches(&version))
    {
        info!("Migrating database to {to}");
        m(&store)?;
        version = to.clone();
        if compatible.matches(&version) {
            create_version_file(&backup).context("failed to update VERSION")?;
            return create_version_file(&data).context("failed to update VERSION");
        }
    }

    store.purge_old_backups(0)?;
    Err(anyhow!("migration from {version} is not supported",))
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

// Update FtpBruteForce, LdapBruteForce, RdpBruteForce fields.
fn migrate_0_12_to_0_16(store: &super::Store) -> Result<()> {
    use crate::{
        event::{FtpBruteForceFields, LdapBruteForceFields, RdpBruteForceFields},
        EventKind,
    };
    use chrono::{DateTime, TimeZone, Utc};
    use num_traits::FromPrimitive;

    #[derive(Deserialize, Serialize)]
    struct OldRdpBruteForceFields {
        pub source: String,
        pub src_addr: IpAddr,
        pub src_port: u16,
        pub dst_addr: IpAddr,
        pub dst_port: u16,
        pub proto: u8,
    }

    impl From<(OldRdpBruteForceFields, DateTime<Utc>)> for RdpBruteForceFields {
        fn from(input: (OldRdpBruteForceFields, DateTime<Utc>)) -> Self {
            let (input, time) = input;
            Self {
                src_addr: input.src_addr,
                dst_addrs: vec![input.dst_addr],
                start_time: time,
                last_time: time,
                proto: input.proto,
            }
        }
    }

    #[derive(Deserialize, Serialize)]
    struct OldFtpBruteForceFields {
        pub source: String,
        pub src_addr: IpAddr,
        pub dst_addr: IpAddr,
        pub dst_port: u16,
        pub proto: u8,
        pub user_list: Vec<String>,
        pub start_time: DateTime<Utc>,
        pub last_time: DateTime<Utc>,
        pub is_internal: bool,
    }

    impl From<OldFtpBruteForceFields> for FtpBruteForceFields {
        fn from(input: OldFtpBruteForceFields) -> Self {
            Self {
                src_addr: input.src_addr,
                dst_addr: input.dst_addr,
                dst_port: input.dst_port,
                proto: input.proto,
                user_list: input.user_list,
                start_time: input.start_time,
                last_time: input.last_time,
                is_internal: input.is_internal,
            }
        }
    }

    #[derive(Deserialize, Serialize)]
    struct OldLdapBruteForceFields {
        pub source: String,
        pub src_addr: IpAddr,
        pub dst_addr: IpAddr,
        pub dst_port: u16,
        pub proto: u8,
        pub user_pw_list: Vec<(String, String)>,
        pub start_time: DateTime<Utc>,
        pub last_time: DateTime<Utc>,
    }

    impl From<OldLdapBruteForceFields> for LdapBruteForceFields {
        fn from(input: OldLdapBruteForceFields) -> Self {
            Self {
                src_addr: input.src_addr,
                dst_addr: input.dst_addr,
                dst_port: input.dst_port,
                proto: input.proto,
                user_pw_list: input.user_pw_list,
                start_time: input.start_time,
                last_time: input.last_time,
            }
        }
    }

    let event_db = store.events();
    for item in event_db.raw_iter_forward() {
        let (k, v) = item.context("Failed to read events Database")?;
        let key: [u8; 16] = if let Ok(key) = k.as_ref().try_into() {
            key
        } else {
            return Err(anyhow!("Failed to migrate events: invalid event key"));
        };
        let key = i128::from_be_bytes(key);
        let key_timestamp = (key >> 64) as i64;
        let kind_num = (key & 0xffff_ffff_0000_0000) >> 32;
        let Some(kind) = EventKind::from_i128(kind_num) else {
            return Err(anyhow!("Failed to migrate events: invalid event key"));
        };
        match kind {
            EventKind::FtpBruteForce => {
                let Ok(fields) = bincode::deserialize::<OldFtpBruteForceFields>(v.as_ref()) else {
                    return Err(anyhow!("Failed to migrate events: invalid event value"));
                };
                let ftp_event: FtpBruteForceFields = fields.into();
                let new = bincode::serialize(&ftp_event).unwrap_or_default();
                event_db.update((&k, &v), (&k, &new))?;
            }
            EventKind::LdapBruteForce => {
                let Ok(fields) = bincode::deserialize::<OldLdapBruteForceFields>(v.as_ref()) else {
                    return Err(anyhow!("Failed to migrate events: invalid event value"));
                };
                let ldap_event: LdapBruteForceFields = fields.into();
                let new = bincode::serialize(&ldap_event).unwrap_or_default();
                event_db.update((&k, &v), (&k, &new))?;
            }
            EventKind::RdpBruteForce => {
                let Ok(fields) = bincode::deserialize::<OldRdpBruteForceFields>(v.as_ref()) else {
                    return Err(anyhow!("Failed to migrate events: invalid event value"));
                };
                let dt = Utc.timestamp_nanos(key_timestamp);
                let rdp_event: RdpBruteForceFields = (fields, dt).into();
                let new = bincode::serialize(&rdp_event).unwrap_or_default();
                event_db.update((&k, &v), (&k, &new))?;
            }
            _ => continue,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::COMPATIBLE_VERSION_REQ;
    use crate::Store;
    use semver::{Version, VersionReq};

    struct TestSchema {
        db_dir: tempfile::TempDir,
        backup_dir: tempfile::TempDir,
        store: Store,
    }

    impl TestSchema {
        fn new() -> Self {
            let db_dir = tempfile::tempdir().unwrap();
            let backup_dir = tempfile::tempdir().unwrap();
            let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();
            TestSchema {
                db_dir,
                backup_dir,
                store,
            }
        }

        fn new_with_dir(db_dir: tempfile::TempDir, backup_dir: tempfile::TempDir) -> Self {
            let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();
            TestSchema {
                db_dir,
                backup_dir,
                store,
            }
        }

        fn close(self) -> (tempfile::TempDir, tempfile::TempDir) {
            (self.db_dir, self.backup_dir)
        }
    }

    #[test]
    fn version() {
        let compatible = VersionReq::parse(COMPATIBLE_VERSION_REQ).expect("valid semver");
        let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("valid semver");

        // The current version must match the compatible version requirement.
        if current.pre.is_empty() {
            assert!(compatible.matches(&current));
        } else if current.major == 0 && current.patch != 0 || current.major >= 1 {
            // A pre-release for a backward-compatible version.
            let non_pre = Version::new(current.major, current.minor, current.patch);
            assert!(compatible.matches(&non_pre));
        } else {
            assert!(compatible.matches(&current));
        }

        // A future, backward-incompatible version must not match the compatible version.
        let breaking = {
            let mut breaking = current;
            if breaking.major == 0 {
                breaking.minor += 1;
            } else {
                breaking.major += 1;
            }
            breaking
        };
        assert!(!compatible.matches(&breaking));
    }

    #[test]
    fn migrate_0_12_to_0_16() {
        use crate::{EventKind, EventMessage};
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Serialize};
        use std::net::IpAddr;

        let settings = TestSchema::new();
        #[derive(Deserialize, Serialize)]
        struct OldRdpBruteForceFields {
            source: String,
            src_addr: IpAddr,
            src_port: u16,
            dst_addr: IpAddr,
            dst_port: u16,
            proto: u8,
        }

        let time = Utc::now();
        let value = OldRdpBruteForceFields {
            source: "source_1".to_string(),
            src_addr: "192.168.4.100".parse::<IpAddr>().unwrap(),
            src_port: 40000,
            dst_addr: "31.3.245.100".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 10,
        };

        let message = EventMessage {
            time,
            kind: EventKind::RdpBruteForce,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        #[derive(Deserialize, Serialize)]
        struct OldFtpBruteForceFields {
            source: String,
            src_addr: IpAddr,
            dst_addr: IpAddr,
            dst_port: u16,
            proto: u8,
            user_list: Vec<String>,
            start_time: DateTime<Utc>,
            last_time: DateTime<Utc>,
            is_internal: bool,
        }

        let value = OldFtpBruteForceFields {
            source: "source_1".to_string(),
            src_addr: "192.168.4.100".parse::<IpAddr>().unwrap(),
            dst_addr: "31.3.245.100".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 10,
            user_list: vec!["user_name".to_string()],
            start_time: time,
            last_time: time,
            is_internal: false,
        };

        let message = EventMessage {
            time,
            kind: EventKind::FtpBruteForce,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        #[derive(Deserialize, Serialize)]
        struct OldLdapBruteForceFields {
            source: String,
            src_addr: IpAddr,
            dst_addr: IpAddr,
            dst_port: u16,
            proto: u8,
            user_pw_list: Vec<(String, String)>,
            start_time: DateTime<Utc>,
            last_time: DateTime<Utc>,
        }

        let value = OldLdapBruteForceFields {
            source: "source_1".to_string(),
            src_addr: "192.168.4.100".parse::<IpAddr>().unwrap(),
            dst_addr: "31.3.245.100".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 10,
            user_pw_list: vec![("user_name".to_string(), "".to_string())],
            start_time: time,
            last_time: time,
        };

        let message = EventMessage {
            time,
            kind: EventKind::LdapBruteForce,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_12_to_0_16(&settings.store).is_ok());
    }
}
