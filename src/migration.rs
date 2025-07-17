//! Routines to check the database format version and migrate it if necessary.
#![allow(clippy::too_many_lines)]

mod migrate_classifiers_to_filesystem;
mod migrate_column_stats;
mod migration_structures;

use std::{
    fs::{File, create_dir_all},
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{ExternalService, Indexed, IterableMap};

/// The range of versions that use the current database format.
///
/// The range should include all the earlier, released versions that use the
/// current database format, and exclude the first future version that uses a
/// new database format.
///
/// # Examples
///
/// ```rust
/// // [Case 1: Stable Patch Version, No Format Change]
/// // The current version is 0.4.1 and the database format hasn't been changed
/// // since 0.3.0. This should include future patch versions such as 0.4.2,
/// // 0.4.3, etc. since they won't change the database format.
/// const COMPATIBLE_VERSION: &str = ">=0.3,<0.5.0-alpha";
/// ```
///
/// ```rust
/// // [Case 2: Alpha Patch Version, No RocksDB Format Change]
/// // The current version is 3.4.6-alpha.2 and the database format hasn't been
/// // changed since 1.0.0. Future pre-release versions such as 3.4.6-alpha.3
/// // are compatible since they won't change the database format.
/// const COMPATIBLE_VERSION: &str = ">=1.0.0,<3.5.0-alpha";
/// ```
///
/// ```rust
/// // [Case 3: Transition to New Alpha Version, No RocksDB Format Change]
/// // The current version is 3.4.5 and the database format hasn't been changed
/// // since 1.0.0. The next version to pre-release is 3.5.0-alpha.1, if no
/// // database format change is involved, then compatible version should be
/// // extended to 3.5.0-alpha.1.
/// const COMPATIBLE_VERSION: &str = ">=1.0.0,<=3.5.0-alpha.1";
/// ```
///
/// ```rust
/// // [Case 4: Transition to Stable Major Version, No RocksDB Format Change]
/// // The current version is 3.4.5 and the database format hasn't been changed
/// // since 1.0.0. The next version to release is 3.5.0 (stable), if no
/// // database format change is involved, then migration is not needed, while
/// // compatible version should be extended to 3.5.0., including all future
/// // patch versions.
/// const COMPATIBLE_VERSION: &str = ">=1.0.0,<3.6.0-alpha";
/// ```
///
/// ```rust
/// // [Case 5: Transition from Alpha to Stable Version, No RocksDB Format Change]
/// // The current version is 3.4.5-alpha.3 and the database format hasn't been
/// // changed since 1.0.0. The next version to release is 3.5.0 (stable), with
/// // compatibility extended to future patch versions.
/// const COMPATIBLE_VERSION: &str = ">=1.0.0,<3.6.0-alpha";
/// ```
///
/// ```rust
/// // [Case 6: Transition to New Alpha Version, RocksDB Format Change]
/// // The current version is 3.4.5 and the database format is changing in
/// // 3.5.0-alpha.1. The compatibility is now restricted to 3.5.0-alpha.1,
/// // requiring a migration from the 1.0.0 format.
/// const COMPATIBLE_VERSION: &str = ">=3.5.0-alpha.1,<3.5.0-alpha.2";
/// // Migration: `migrate_1_0_to_3_5` must handle changes from 1.0.0 to
/// // 3.5.0-alpha.1.
/// ```
///
/// ```rust
/// // [Case 7: Transition Between Alpha Versions, RocksDB Format Change]
/// // The current version is 3.5.0-alpha.2 and the database format is changing in
/// // 3.5.0-alpha.3. The compatibility is now restricted to 3.5.0-alpha.3,
/// // requiring a migration from the 1.0.0 format.
/// const COMPATIBLE_VERSION: &str = ">=3.5.0-alpha.3,<3.5.0-alpha.4";
/// // Migration: `migrate_1_0_to_3_5` must handle changes from 1.0.0 to
/// // 3.5.0-alpha.3, including prior alpha changes.
///```
///
/// ```rust
/// // [Case 8: Transition from Alpha to Stable Version, RocksDB Format Finalized]
/// // The current version is 3.5.0-alpha.2 and the database format is
/// // finalized in 3.5.0. The compatibility is extended to all 3.5.0 versions,
/// // requiring a migration from the 1.0.0 format.
/// const COMPATIBLE_VERSION: &str = ">=3.5.0,<3.6.0-alpha";
/// // Migration: `migrate_1_0_to_3_5` must handle changes from 1.0.0 (last
/// // release that involves database format change) to 3.5.0, including
/// // all alpha changes finalized in 3.5.0.
/// ```
const COMPATIBLE_VERSION_REQ: &str = ">=0.40.0-alpha.1,<0.40.0-alpha.2";

/// Migrates data exists in `PostgresQL` to Rocksdb if necessary.
///
/// Migration is supported for current released version only. And the migrated data
/// and related interface should be removed from `PostgresQL` database in the next released
/// version.
///
/// # Errors
///
/// Returns an error if the data hasn't been migrated successfully to Rocksdb.
pub async fn migrate_backend<P: AsRef<Path>>(
    database: &super::Database,
    store: &super::Store,
    data_dir: P,
) -> Result<()> {
    // Below is an example for cases when data migration between `PostgreSQL`
    // and RocksDB is needed.
    // let path = data_dir.as_ref();
    // let file = path.join("VERSION");

    // let version = read_version_file(&file)?;

    // let Ok(compatible) = VersionReq::parse(COMPATIBLE_VERSION_REQ) else {
    //     unreachable!("COMPATIBLE_VERSION_REQ must be valid")
    // };
    // if compatible.matches(&version) {
    //     backend_0_23(db, store).await?;
    // }

    let path = data_dir.as_ref();
    let file = path.join("VERSION");

    let version = read_version_file(&file)?;

    let Ok(compatible) = VersionReq::parse(COMPATIBLE_VERSION_REQ) else {
        unreachable!("COMPATIBLE_VERSION_REQ must be valid")
    };

    migrate_classifiers_to_filesystem::run_migration(database).await?;
    if compatible.matches(&version) {
        migrate_column_stats::run(database, store).await?;
    }

    Ok(())
}

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
    type Migration = (VersionReq, Version, fn(&crate::Store) -> anyhow::Result<()>);

    let data_dir = data_dir.as_ref();
    let backup_dir = backup_dir.as_ref();

    let Ok(compatible) = VersionReq::parse(COMPATIBLE_VERSION_REQ) else {
        unreachable!("COMPATIBLE_VERSION_REQ must be valid")
    };

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
    let migration: Vec<Migration> = vec![
        (
            VersionReq::parse(">=0.30.0,<0.34.0")?,
            Version::parse("0.34.0")?,
            migrate_0_30_to_0_34_0,
        ),
        (
            VersionReq::parse(">=0.34.0,<0.36.0")?,
            Version::parse("0.36.0")?,
            migrate_0_34_0_to_0_36,
        ),
        (
            VersionReq::parse(">=0.36.0,<0.37.0")?,
            Version::parse("0.37.0")?,
            migrate_0_36_0_to_0_37,
        ),
        (
            VersionReq::parse(">=0.37.0,<0.38.0")?,
            Version::parse("0.38.0")?,
            migrate_0_37_to_0_38_0,
        ),
        (
            VersionReq::parse(">=0.38.0,<0.39.0")?,
            Version::parse("0.39.0")?,
            migrate_0_38_to_0_39_0,
        ),
    ];

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

fn migrate_0_37_to_0_38_0(store: &super::Store) -> Result<()> {
    migrate_0_38_node(store)
}

fn migrate_0_38_to_0_39_0(store: &super::Store) -> Result<()> {
    migrate_0_39_account(store)
}

fn migrate_0_39_account(store: &super::Store) -> Result<()> {
    use bincode::Options;

    use crate::{migration::migration_structures::AccountV36, types::Account};

    let map = store.account_map();
    let raw = map.raw();
    for (key, old_value) in raw.iter_forward()? {
        let old = bincode::DefaultOptions::new().deserialize::<AccountV36>(&old_value)?;
        let new: Account = old.into();
        let new_value = bincode::DefaultOptions::new().serialize::<Account>(&new)?;
        raw.update((&key, &old_value), (&key, &new_value))?;
    }
    Ok(())
}

fn migrate_0_38_node(store: &super::Store) -> Result<()> {
    use bincode::Options;
    use migration_structures::OldInnerFromV29BeforeV37;

    use crate::{
        IterableMap,
        tables::{InnerNode, UniqueKey, Value},
    };

    let map = store.node_map();
    let node_raw = map.raw();
    let external_service_raw = map.external_service_raw();
    for (_key, old_value) in node_raw.iter_forward()? {
        let old_inner_node = bincode::DefaultOptions::new()
            .deserialize::<OldInnerFromV29BeforeV37>(&old_value)
            .context("Failed to migrate node database: invalid node value")?;
        if let Some(ref config) = old_inner_node.giganto {
            let external_service = ExternalService {
                node: old_inner_node.id,
                key: "giganto".to_string(),
                kind: crate::ExternalServiceKind::DataStore,
                status: config.status,
                draft: config.draft.clone(),
            };
            external_service_raw.insert(
                external_service.unique_key().as_ref(),
                external_service.value().as_ref(),
            )?;
        }
        let new_inner_node: InnerNode = old_inner_node.into();
        node_raw.overwrite(&new_inner_node)?;
    }
    Ok(())
}

fn migrate_0_36_0_to_0_37(store: &super::Store) -> Result<()> {
    migrate_0_37_event_struct(store)
}

fn migrate_0_37_event_struct(store: &super::Store) -> Result<()> {
    use migration_structures::BlocklistTlsFieldsBeforeV37;
    use num_traits::FromPrimitive;

    use crate::event::{BlocklistTlsFields, EventKind};

    let event_db = store.events();
    let iter = event_db.raw_iter_forward();
    for event in iter {
        let (k, v) = event.map_err(|e| anyhow!("Failed to read events database: {e:?}"))?;
        let key: [u8; 16] = if let Ok(key) = k.as_ref().try_into() {
            key
        } else {
            return Err(anyhow!("Failed to migrate events: invalid event key"));
        };
        let key = i128::from_be_bytes(key);
        let kind = (key & 0xffff_ffff_0000_0000) >> 32;
        let Some(event_kind) = EventKind::from_i128(kind) else {
            return Err(anyhow!("Failed to migrate events: invalid event kind"));
        };

        match event_kind {
            EventKind::SuspiciousTlsTraffic | EventKind::BlocklistTls => {
                update_event_db_with_new_event::<BlocklistTlsFieldsBeforeV37, BlocklistTlsFields>(
                    &k, &v, &event_db,
                )?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn migrate_0_34_0_to_0_36(store: &super::Store) -> Result<()> {
    migrate_0_36_account(store)
}

fn migrate_0_36_account(store: &super::Store) -> Result<()> {
    use bincode::Options;

    use crate::migration::migration_structures::{AccountBeforeV36, AccountV36};

    let map = store.account_map();
    let raw = map.raw();
    for (key, old_value) in raw.iter_forward()? {
        let old = bincode::DefaultOptions::new().deserialize::<AccountBeforeV36>(&old_value)?;
        let intermediate: AccountV36 = old.into();
        let new_value = bincode::DefaultOptions::new().serialize::<AccountV36>(&intermediate)?;
        raw.update((&key, &old_value), (&key, &new_value))?;
    }
    Ok(())
}

fn migrate_0_30_to_0_34_0(store: &super::Store) -> Result<()> {
    migrate_0_34_account(store)?;
    migrate_0_34_events(store)
}

fn migrate_0_34_events(store: &super::Store) -> Result<()> {
    use migration_structures::{
        ExtraThreatBeforeV34, HttpThreatBeforeV34, NetworkThreatBeforeV34, WindowsThreatBeforeV34,
    };
    use num_traits::FromPrimitive;

    use crate::event::{EventKind, ExtraThreat, HttpThreatFields, NetworkThreat, WindowsThreat};

    let event_db = store.events();
    let iter = event_db.raw_iter_forward();
    for event in iter {
        let (k, v) = event.map_err(|e| anyhow!("Failed to read events database: {e:?}"))?;
        let key: [u8; 16] = if let Ok(key) = k.as_ref().try_into() {
            key
        } else {
            return Err(anyhow!("Failed to migrate events: invalid event key"));
        };
        let key = i128::from_be_bytes(key);
        let kind = (key & 0xffff_ffff_0000_0000) >> 32;
        let Some(event_kind) = EventKind::from_i128(kind) else {
            return Err(anyhow!("Failed to migrate events: invalid event kind"));
        };

        match event_kind {
            EventKind::HttpThreat => {
                update_event_db_with_new_event::<HttpThreatBeforeV34, HttpThreatFields>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::NetworkThreat => {
                update_event_db_with_new_event::<NetworkThreatBeforeV34, NetworkThreat>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::ExtraThreat => {
                update_event_db_with_new_event::<ExtraThreatBeforeV34, ExtraThreat>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::WindowsThreat => {
                update_event_db_with_new_event::<WindowsThreatBeforeV34, WindowsThreat>(
                    &k, &v, &event_db,
                )?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn migrate_0_34_account(store: &super::Store) -> Result<()> {
    use bincode::Options;
    use chrono::{DateTime, Utc};

    use crate::{
        account::{PasswordHashAlgorithm, Role, SaltedPassword},
        migration::migration_structures::AccountBeforeV36,
    };

    #[derive(Deserialize, Serialize)]
    pub struct OldAccount {
        pub username: String,
        password: SaltedPassword,
        pub role: Role,
        pub name: String,
        pub department: String,
        pub language: Option<String>,
        creation_time: DateTime<Utc>,
        last_signin_time: Option<DateTime<Utc>>,
        pub allow_access_from: Option<Vec<IpAddr>>,
        pub max_parallel_sessions: Option<u32>,
        password_hash_algorithm: PasswordHashAlgorithm,
        password_last_modified_at: DateTime<Utc>,
    }

    impl From<OldAccount> for AccountBeforeV36 {
        fn from(input: OldAccount) -> Self {
            Self {
                username: input.username,
                password: input.password,
                role: input.role,
                name: input.name,
                department: input.department,
                language: input.language,
                theme: None,
                creation_time: input.creation_time,
                last_signin_time: input.last_signin_time,
                allow_access_from: input.allow_access_from,
                max_parallel_sessions: input
                    .max_parallel_sessions
                    .and_then(|v| u8::try_from(v).ok()),
                password_hash_algorithm: input.password_hash_algorithm,
                password_last_modified_at: input.password_last_modified_at,
            }
        }
    }

    let map = store.account_map();
    let raw = map.raw();
    for (key, old_value) in raw.iter_forward()? {
        let old = bincode::DefaultOptions::new().deserialize::<OldAccount>(&old_value)?;
        let new: AccountBeforeV36 = old.into();
        let new_value = bincode::DefaultOptions::new().serialize::<AccountBeforeV36>(&new)?;
        raw.update((&key, &old_value), (&key, &new_value))?;
    }
    Ok(())
}

fn update_event_db_with_new_event<'a, T, K>(
    k: &[u8],
    v: &'a [u8],
    event_db: &crate::EventDb,
) -> Result<()>
where
    T: Deserialize<'a> + Into<K>,
    K: Serialize,
{
    let Ok(from_event) = bincode::deserialize::<T>(v) else {
        return Err(anyhow!("Failed to migrate events: invalid event value"));
    };
    let to_event: K = from_event.into();
    let new = bincode::serialize(&to_event).unwrap_or_default();
    event_db.update((k, v), (k, &new))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use semver::{Version, VersionReq};

    use super::COMPATIBLE_VERSION_REQ;
    use crate::{Store, migration::migration_structures::AccountBeforeV36};

    #[allow(dead_code)]
    struct TestSchema {
        db_dir: tempfile::TempDir,
        backup_dir: tempfile::TempDir,
        store: Store,
    }

    impl TestSchema {
        #[allow(dead_code)]
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

        #[allow(dead_code)]
        fn new_with_dir(db_dir: tempfile::TempDir, backup_dir: tempfile::TempDir) -> Self {
            let store = Store::new(db_dir.path(), backup_dir.path()).unwrap();
            TestSchema {
                db_dir,
                backup_dir,
                store,
            }
        }

        #[allow(dead_code)]
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
    fn migrate_0_34_account() {
        use std::net::IpAddr;

        use bincode::Options;
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Serialize};

        use crate::{
            IterableMap,
            account::{PasswordHashAlgorithm, Role, SaltedPassword},
        };

        #[derive(Deserialize, Serialize)]
        pub struct OldAccount {
            pub username: String,
            password: SaltedPassword,
            pub role: Role,
            pub name: String,
            pub department: String,
            pub language: Option<String>,
            creation_time: DateTime<Utc>,
            last_signin_time: Option<DateTime<Utc>>,
            pub allow_access_from: Option<Vec<IpAddr>>,
            pub max_parallel_sessions: Option<u32>,
            password_hash_algorithm: PasswordHashAlgorithm,
            password_last_modified_at: DateTime<Utc>,
        }

        impl From<OldAccount> for AccountBeforeV36 {
            fn from(input: OldAccount) -> Self {
                Self {
                    username: input.username,
                    password: input.password,
                    role: input.role,
                    name: input.name,
                    department: input.department,
                    language: input.language,
                    theme: None,
                    creation_time: input.creation_time,
                    last_signin_time: input.last_signin_time,
                    allow_access_from: input.allow_access_from,
                    max_parallel_sessions: input
                        .max_parallel_sessions
                        .and_then(|v| u8::try_from(v).ok()),
                    password_hash_algorithm: input.password_hash_algorithm,
                    password_last_modified_at: input.password_last_modified_at,
                }
            }
        }

        impl From<AccountBeforeV36> for OldAccount {
            fn from(input: AccountBeforeV36) -> Self {
                Self {
                    username: input.username,
                    password: input.password,
                    role: input.role,
                    name: input.name,
                    department: input.department,
                    language: input.language,
                    creation_time: input.creation_time,
                    last_signin_time: input.last_signin_time,
                    allow_access_from: input.allow_access_from,
                    max_parallel_sessions: input.max_parallel_sessions.map(u32::from),
                    password_hash_algorithm: input.password_hash_algorithm,
                    password_last_modified_at: input.password_last_modified_at,
                }
            }
        }

        let settings = TestSchema::new();
        let map = settings.store.account_map();
        let raw = map.raw();

        let now = Utc::now();
        let new_account = AccountBeforeV36 {
            username: "test".to_string(),
            password: SaltedPassword::new_with_hash_algorithm(
                "password",
                &PasswordHashAlgorithm::Argon2id,
            )
            .unwrap(),
            role: Role::SecurityAdministrator,
            name: "name".to_string(),
            department: "department".to_string(),
            language: None,
            theme: None,
            creation_time: now,
            last_signin_time: None,
            allow_access_from: None,
            max_parallel_sessions: None,
            password_hash_algorithm: PasswordHashAlgorithm::Argon2id,
            password_last_modified_at: now,
        };

        let old: OldAccount = new_account.clone().into();
        let value = bincode::DefaultOptions::new()
            .serialize(&old)
            .expect("serializable");

        assert!(raw.put(old.username.as_bytes(), &value).is_ok());

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);

        assert!(super::migrate_0_34_account(&settings.store).is_ok());

        let map = settings.store.account_map();
        let raw = map.raw();
        let (_, value) = raw.iter_forward().unwrap().next().unwrap();
        let result_account = bincode::DefaultOptions::new()
            .deserialize::<AccountBeforeV36>(&value)
            .unwrap();

        assert_eq!(new_account, result_account);
    }

    #[test]
    fn migrate_0_30_to_0_34_events() {
        use std::net::IpAddr;

        use crate::{EventKind, EventMessage};

        let settings = TestSchema::new();
        let event_db = settings.store.events();

        let value = super::migration_structures::HttpThreatBeforeV34 {
            time: chrono::Utc::now(),
            sensor: "sensor_1".to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 17,
            duration: 1,
            method: "POST".to_string(),
            host: "cluml".to_string(),
            uri: "/cluml.gif".to_string(),
            referer: "cluml.com".to_string(),
            version: "version".to_string(),
            user_agent: "review-database".to_string(),
            request_len: 0,
            response_len: 0,
            status_code: 200,
            status_msg: "status_msg".to_string(),
            username: "username".to_string(),
            password: "password".to_string(),
            cookie: "cookie".to_string(),
            content_encoding: "content_encoding".to_string(),
            content_type: "content_type".to_string(),
            cache_control: "cache_control".to_string(),
            orig_filenames: vec!["orig_filenames".to_string()],
            orig_mime_types: vec!["orig_mime_types".to_string()],
            resp_filenames: vec!["resp_filenames".to_string()],
            resp_mime_types: vec!["resp_mime_types".to_string()],
            post_body: vec![],
            state: "state".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 10,
            matched_to: "matched_to".to_string(),
            cluster_id: 200,
            attack_kind: "attack_kind".to_string(),
            confidence: 0.3,
            category: crate::EventCategory::Reconnaissance,
        };
        let message = EventMessage {
            time: value.time,
            kind: EventKind::HttpThreat,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        assert!(event_db.put(&message).is_ok());

        let value = super::migration_structures::NetworkThreatBeforeV34 {
            time: chrono::Utc::now(),
            sensor: "sensor_1".to_string(),
            orig_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            orig_port: 46378,
            resp_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            resp_port: 80,
            proto: 6,
            service: "service".to_string(),
            last_time: 1,
            content: "content".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 200_101,
            matched_to: "matched_to".to_string(),
            cluster_id: 11,
            attack_kind: "attack_kind".to_string(),
            confidence: 0.3,
            triage_scores: None,
            category: crate::EventCategory::Reconnaissance,
        };
        let message = EventMessage {
            time: value.time,
            kind: EventKind::NetworkThreat,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        assert!(event_db.put(&message).is_ok());

        let value = super::migration_structures::WindowsThreatBeforeV34 {
            time: chrono::Utc::now(),
            sensor: "sensor_1".to_string(),
            service: "service".to_string(),
            agent_name: "agent_name".to_string(),
            agent_id: "agent_id".to_string(),
            process_guid: "process_guid".to_string(),
            process_id: 1001,
            image: "image".to_string(),
            user: "user".to_string(),
            content: "content".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 200_101,
            matched_to: "matched_to".to_string(),
            cluster_id: 10,
            attack_kind: "attack_kind".to_string(),
            confidence: 0.3,
            triage_scores: None,
            category: crate::EventCategory::Reconnaissance,
        };

        let message = EventMessage {
            time: value.time,
            kind: EventKind::WindowsThreat,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        assert!(event_db.put(&message).is_ok());

        let value = super::migration_structures::ExtraThreatBeforeV34 {
            time: chrono::Utc::now(),
            sensor: "sensor_1".to_string(),
            service: "service".to_string(),
            content: "content".to_string(),
            db_name: "db_name".to_string(),
            rule_id: 200_101,
            matched_to: "matched_to".to_string(),
            cluster_id: 15,
            attack_kind: "attack_kind".to_string(),
            confidence: 0.3,
            triage_scores: None,
            category: crate::EventCategory::Reconnaissance,
        };

        let message = EventMessage {
            time: value.time,
            kind: EventKind::ExtraThreat,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_30_to_0_34_0(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_36_account() {
        use bincode::Options;
        use chrono::Utc;

        use crate::{
            account::{PasswordHashAlgorithm, Role, SaltedPassword},
            migration::migration_structures::AccountV36,
        };

        let settings = TestSchema::new();
        let map = settings.store.account_map();
        let raw = map.raw();

        let old_account = AccountBeforeV36 {
            username: "test".to_string(),
            password: SaltedPassword::new_with_hash_algorithm(
                "password",
                &PasswordHashAlgorithm::Argon2id,
            )
            .unwrap(),
            role: Role::SecurityAdministrator,
            name: "name".to_string(),
            department: "department".to_string(),
            language: None,
            theme: None,
            creation_time: Utc::now(),
            last_signin_time: None,
            allow_access_from: None,
            max_parallel_sessions: None,
            password_hash_algorithm: PasswordHashAlgorithm::Argon2id,
            password_last_modified_at: Utc::now(),
        };
        let new_account = AccountV36::from(old_account.clone());
        let value = bincode::DefaultOptions::new()
            .serialize(&old_account)
            .expect("serializable");

        assert!(raw.put(old_account.username.as_bytes(), &value).is_ok());

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);

        assert!(super::migrate_0_36_account(&settings.store).is_ok());

        let map = settings.store.account_map();
        let raw = map.raw();
        let res = raw.get(old_account.username.as_bytes()).unwrap().unwrap();
        let account = bincode::DefaultOptions::new()
            .deserialize::<AccountV36>(res.as_ref())
            .unwrap();

        assert_eq!(account, new_account);
    }

    #[test]
    fn migrate_0_36_0_to_0_37() {
        use std::net::IpAddr;

        use num_traits::FromPrimitive;

        use crate::{EventKind, EventMessage, event::BlocklistTlsFields};

        let value = super::migration_structures::BlocklistTlsFieldsBeforeV37 {
            sensor: "sensor_1".to_string(),
            src_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            src_port: 46378,
            dst_addr: "192.168.4.76".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            last_time: 1,
            server_name: "server_name".to_string(),
            alpn_protocol: "alpn_protocol".to_string(),
            ja3: "ja3".to_string(),
            version: "version".to_string(),
            client_cipher_suites: vec![1, 2, 3],
            client_extensions: vec![1, 2, 3],
            cipher: 1,
            extensions: vec![1, 2, 3],
            ja3s: "ja3".to_string(),
            serial: "serial".to_string(),
            subject_country: "subject_country".to_string(),
            subject_org_name: "subject_org_name".to_string(),
            subject_common_name: "subject_common_name".to_string(),
            validity_not_before: 1,
            validity_not_after: 1,
            subject_alt_name: "subject_alt_name".to_string(),
            issuer_country: "issuer_country".to_string(),
            issuer_org_name: "issuer_org_name".to_string(),
            issuer_org_unit_name: "issuer_org_unit_name".to_string(),
            issuer_common_name: "issuer_common_name".to_string(),
            last_alert: 1,
            category: crate::EventCategory::InitialAccess,
        };
        let message = EventMessage {
            time: chrono::Utc::now(),
            kind: EventKind::BlocklistTls,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let settings = TestSchema::new();
        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let message = EventMessage {
            time: chrono::Utc::now(),
            kind: EventKind::SuspiciousTlsTraffic,
            fields: bincode::serialize(&value).unwrap_or_default(),
        };

        let settings = TestSchema::new();
        let event_db = settings.store.events();
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_36_0_to_0_37(&settings.store).is_ok());

        let event_db = settings.store.events();
        let iter = event_db.raw_iter_forward();
        for event in iter {
            let kv = event;
            assert!(kv.is_ok());
            let (k, v) = kv.unwrap();
            let key: [u8; 16] = k.as_ref().try_into().unwrap();
            let key = i128::from_be_bytes(key);
            let kind = (key & 0xffff_ffff_0000_0000) >> 32;
            let event_kind = EventKind::from_i128(kind);
            assert!(event_kind.is_some());
            let event_kind = event_kind.unwrap();

            match event_kind {
                EventKind::SuspiciousTlsTraffic | EventKind::BlocklistTls => {
                    let message = bincode::deserialize::<BlocklistTlsFields>(v.as_ref());
                    assert!(message.is_ok());
                    let message = message.unwrap();
                    assert_eq!(message.sensor, value.sensor);
                    assert_eq!(message.src_addr, value.src_addr);
                    assert_eq!(format!("{:.1}", message.confidence), "0.0".to_string());
                    assert_eq!(message.category, value.category);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn migrate_0_37_to_0_38_node() {
        use std::{
            net::{IpAddr, SocketAddr},
            str::FromStr,
        };

        use chrono::Utc;

        use super::migration_structures::{
            DumpItem, OldInnerFromV29BeforeV37, OldNodeFromV29BeforeV37,
        };
        use crate::{
            Agent, NodeProfile,
            collections::Indexed,
            migration::migration_structures::{Giganto, GigantoConfig, HogConfig, PigletConfig},
            tables::{UniqueKey, Value},
        };
        let agent_status = crate::AgentStatus::Enabled;
        let external_service_status = crate::ExternalServiceStatus::Enabled;

        let hog_config = HogConfig {
            active_protocols: Some(Vec::new()),
            active_sources: Some(Vec::new()),
            giganto_publish_srv_addr: Some(SocketAddr::new(
                IpAddr::from_str("1.1.1.1").unwrap(),
                3050,
            )),
            cryptocurrency_mining_pool: String::new(),
            log_dir: String::new(),
            export_dir: String::new(),
            services_path: String::new(),
        };

        let hog_agent = Agent {
            node: 0,
            key: "hog".to_string(),
            kind: crate::AgentKind::SemiSupervised,
            status: agent_status,
            config: None,
            draft: Some(toml::to_string(&hog_config).unwrap().try_into().unwrap()),
        };

        let piglet_config = PigletConfig {
            dpdk_args: String::new(),
            dpdk_input: Vec::new(),
            dpdk_output: Vec::new(),
            src_mac: String::new(),
            dst_mac: String::new(),
            log_dir: String::new(),
            dump_dir: String::new(),
            dump_items: Some(vec![DumpItem::Pcap]),
            dump_http_content_types: Some(Vec::new()),
            giganto_ingest_srv_addr: SocketAddr::new(IpAddr::from_str("1.1.1.2").unwrap(), 3030),
            giganto_name: String::new(),
            pcap_max_size: 4_294_967_295,
        };

        let piglet_agent = Agent {
            node: 0,
            key: "piglet".to_string(),
            kind: crate::AgentKind::Sensor,
            status: agent_status,
            config: None,
            draft: Some(toml::to_string(&piglet_config).unwrap().try_into().unwrap()),
        };

        let giganto_config = GigantoConfig {
            ingest_srv_addr: SocketAddr::new(IpAddr::from_str("0.0.0.0").unwrap(), 3030),
            publish_srv_addr: SocketAddr::new(IpAddr::from_str("0.0.0.0").unwrap(), 3050),
            graphql_srv_addr: SocketAddr::new(IpAddr::from_str("0.0.0.0").unwrap(), 5050),
            data_dir: String::new(),
            log_dir: String::new(),
            export_dir: String::new(),
            retention: {
                let days = u64::from(100_u16);
                std::time::Duration::from_secs(days * 24 * 60 * 60)
            },
            max_open_files: i32::MAX,
            max_mb_of_level_base: u64::MIN,
            num_of_thread: i32::MAX,
            max_sub_compactions: u32::MAX,
            ack_transmission: u16::MAX,
        };

        let old_node = OldNodeFromV29BeforeV37 {
            id: 0,
            name: "name".to_string(),
            name_draft: None,
            profile: None,
            profile_draft: Some(NodeProfile {
                customer_id: 20,
                description: "description".to_string(),
                hostname: "host".to_string(),
            }),
            agents: vec![hog_agent.clone(), piglet_agent.clone()],
            giganto: Some(Giganto {
                status: external_service_status,
                draft: Some(
                    toml::to_string(&giganto_config)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                ),
            }),
            creation_time: Utc::now(),
        };

        let settings = TestSchema::new();
        let map = settings.store.node_map();
        let node_db = map.raw();
        let agent_db = map.agent_raw();

        let hog_res = agent_db.insert(hog_agent.unique_key().as_ref(), hog_agent.value().as_ref());
        assert!(hog_res.is_ok());
        let piglet_res = agent_db.insert(
            piglet_agent.unique_key().as_ref(),
            piglet_agent.value().as_ref(),
        );
        assert!(piglet_res.is_ok());
        let old_inner_node: OldInnerFromV29BeforeV37 = old_node.clone().into();
        let res = node_db.insert(old_inner_node);
        assert!(res.is_ok());

        let id = res.unwrap();
        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);

        assert!(super::migrate_0_38_node(&settings.store).is_ok());

        let map = settings.store.node_map();
        let (new_node, invalid_agent, invalid_external_services) =
            map.get_by_id(id).unwrap().unwrap();

        assert!(invalid_agent.is_empty());
        assert!(invalid_external_services.is_empty());
        assert_eq!(new_node.id, id);
        assert_eq!(new_node.name, "name");
        assert_eq!(new_node.agents.len(), 2);
        assert_eq!(new_node.agents[0].key, "hog");
        assert!(new_node.agents[0].config.is_none());
        assert!(new_node.agents[0].draft.is_some());
        assert_eq!(new_node.agents[1].key, "piglet");
        assert!(new_node.agents[1].config.is_none());
        let draft = new_node.agents[1].draft.clone().unwrap();
        let piglet: PigletConfig = toml::from_str(draft.as_ref()).unwrap();
        assert!(piglet.dump_items.is_some());
        assert!(piglet.dump_http_content_types.is_some_and(|v| v.is_empty()));
        assert_eq!(new_node.external_services.len(), 1);
        assert_eq!(new_node.external_services[0].key, "giganto");
        assert!(new_node.external_services[0].draft.is_some());
        let draft = new_node.external_services[0].draft.clone().unwrap();
        let giganto: GigantoConfig = toml::from_str(draft.as_ref()).unwrap();
        assert_eq!(
            giganto.retention,
            std::time::Duration::from_secs(100 * 24 * 60 * 60)
        );
    }

    #[test]
    fn migrate_0_39_account() {
        use bincode::Options;
        use chrono::Utc;

        use crate::{
            account::{PasswordHashAlgorithm, Role, SaltedPassword},
            migration::migration_structures::AccountV36,
            types::Account,
        };

        let settings = TestSchema::new();
        let map = settings.store.account_map();
        let raw = map.raw();

        // Create a few AccountV36 entries
        let now = Utc::now();
        let v36_1 = AccountV36 {
            username: "user1".to_string(),
            password: SaltedPassword::new_with_hash_algorithm(
                "pw1",
                &PasswordHashAlgorithm::Argon2id,
            )
            .unwrap(),
            role: Role::SecurityAdministrator,
            name: "User One".to_string(),
            department: "Dept1".to_string(),
            language: Some("en".to_string()),
            theme: Some("dark".to_string()),
            creation_time: now,
            last_signin_time: Some(now),
            allow_access_from: Some(vec!["127.0.0.1".parse().unwrap()]),
            max_parallel_sessions: Some(2),
            password_hash_algorithm: PasswordHashAlgorithm::Argon2id,
            password_last_modified_at: now,
            customer_ids: Some(vec![1, 2]),
        };
        let v36_2 = AccountV36 {
            username: "user2".to_string(),
            password: SaltedPassword::new_with_hash_algorithm(
                "pw2",
                &PasswordHashAlgorithm::Pbkdf2HmacSha512,
            )
            .unwrap(),
            role: Role::SystemAdministrator,
            name: "User Two".to_string(),
            department: "Dept2".to_string(),
            language: None,
            theme: None,
            creation_time: now,
            last_signin_time: None,
            allow_access_from: None,
            max_parallel_sessions: None,
            password_hash_algorithm: PasswordHashAlgorithm::Pbkdf2HmacSha512,
            password_last_modified_at: now,
            customer_ids: None,
        };
        let v36s = [v36_1, v36_2];
        for v36 in &v36s {
            let value = bincode::DefaultOptions::new()
                .serialize(v36)
                .expect("serializable");
            assert!(raw.put(v36.username.as_bytes(), &value).is_ok());
        }

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);

        assert!(super::migrate_0_39_account(&settings.store).is_ok());

        let map = settings.store.account_map();
        for v36 in &v36s {
            let raw_value = map.raw().get(v36.username.as_bytes()).expect("get value");
            assert!(raw_value.is_some());
            let account: Account = bincode::DefaultOptions::new()
                .deserialize(raw_value.unwrap().as_ref())
                .expect("deserialize Account");
            let expected: Account = v36.clone().into();
            assert_eq!(account, expected);
        }
    }
}
