//! Routines to check the database format version and migrate it if necessary.
#![allow(clippy::too_many_lines)]

mod migrate_classifiers_to_filesystem;
mod migrate_column_stats;
mod migrate_time_series;
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

use crate::{ExternalService, IterableMap, collections::Indexed};

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
const COMPATIBLE_VERSION_REQ: &str = ">=0.41,<0.42.0-alpha";

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
        migrate_time_series::run(database, store).await?;
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
        (
            VersionReq::parse(">=0.39.0,<0.40.0")?,
            Version::parse("0.40.0")?,
            migrate_0_39_to_0_40_0,
        ),
        (
            VersionReq::parse(">=0.40.0,<0.41.0")?,
            Version::parse("0.41.0")?,
            migrate_0_40_to_0_41_0,
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

fn migrate_0_40_to_0_41_0(store: &super::Store) -> Result<()> {
    migrate_0_41_events(store)
}

fn migrate_0_39_to_0_40_0(store: &super::Store) -> Result<()> {
    migrate_0_40_tidb(store)?;
    migrate_0_40_filter(store)
}

fn migrate_0_40_tidb(store: &super::Store) -> Result<()> {
    use bincode::Options;

    use crate::Tidb;
    use crate::migration::migration_structures::TidbV0_39;

    let map = store.tidb_map();
    let raw = map.raw();
    for (key, value) in raw.iter_forward()? {
        let old_tidb: TidbV0_39 = bincode::DefaultOptions::new().deserialize(value.as_ref())?;
        let new_tidb = Tidb::try_from(old_tidb)?;
        let (_new_key, new_value) = new_tidb.into_key_value()?;
        raw.put(&key, &new_value)?;
    }
    Ok(())
}

fn migrate_0_40_filter(store: &super::Store) -> Result<()> {
    use bincode::Options;

    use crate::Filter;
    use crate::migration::migration_structures::FilterValueV0_39;

    let map = store.filter_map();
    let raw = map.raw();
    for (key, old_value) in raw.iter_forward()? {
        // Deserialize old value format
        let old_filter_value: FilterValueV0_39 =
            bincode::DefaultOptions::new().deserialize(&old_value)?;

        // Convert to new filter (this will set username and name to empty strings)
        let mut new_filter = Filter::from(old_filter_value);

        // Extract username and name from key
        let sep = key
            .iter()
            .position(|c| *c == 0)
            .ok_or_else(|| anyhow::anyhow!("corrupted filter key"))?;
        let username = std::str::from_utf8(&key[..sep])?.to_string();
        let name = std::str::from_utf8(&key[sep + 1..])?.to_string();

        new_filter.username = username;
        new_filter.name = name;

        let (_, new_value) = new_filter.into_key_value()?;
        raw.update((&key, &old_value), (&key, &new_value))?;
    }
    Ok(())
}

fn migrate_0_37_to_0_38_0(store: &super::Store) -> Result<()> {
    migrate_0_38_node(store)
}

fn migrate_0_38_to_0_39_0(store: &super::Store) -> Result<()> {
    migrate_0_39_account(store)?;
    migrate_0_39_events(store)
}

fn migrate_0_39_account(store: &super::Store) -> Result<()> {
    use bincode::Options;

    use crate::{migration::migration_structures::AccountV0_36, types::Account};

    let map = store.account_map();
    let raw = map.raw();
    for (key, old_value) in raw.iter_forward()? {
        let old = bincode::DefaultOptions::new().deserialize::<AccountV0_36>(&old_value)?;
        let new: Account = old.into();
        let new_value = bincode::DefaultOptions::new().serialize::<Account>(&new)?;
        raw.update((&key, &old_value), (&key, &new_value))?;
    }
    Ok(())
}

fn migrate_0_38_node(store: &super::Store) -> Result<()> {
    use bincode::Options;
    use migration_structures::InnerV0_29;

    use crate::{
        IterableMap,
        tables::{InnerNode, UniqueKey, Value},
    };

    let map = store.node_map();
    let node_raw = map.raw();
    let external_service_raw = map.external_service_raw();
    for (_key, old_value) in node_raw.iter_forward()? {
        let old_inner_node = bincode::DefaultOptions::new()
            .deserialize::<InnerV0_29>(&old_value)
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
    use migration_structures::BlocklistTlsFieldsV0_36;
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
                update_event_db_with_new_event::<BlocklistTlsFieldsV0_36, BlocklistTlsFields>(
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

    use crate::migration::migration_structures::{AccountV0_34, AccountV0_36};

    let map = store.account_map();
    let raw = map.raw();
    for (key, old_value) in raw.iter_forward()? {
        let old = bincode::DefaultOptions::new().deserialize::<AccountV0_34>(&old_value)?;
        let intermediate: AccountV0_36 = old.into();
        let new_value = bincode::DefaultOptions::new().serialize::<AccountV0_36>(&intermediate)?;
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
        ExtraThreatV0_33, HttpThreatV0_33, NetworkThreatV0_33, WindowsThreatV0_33,
    };
    use num_traits::FromPrimitive;

    use crate::event::{
        EventKind, ExtraThreat, HttpThreatFieldsV0_34, NetworkThreat, WindowsThreat,
    };

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
                update_event_db_with_new_event::<HttpThreatV0_33, HttpThreatFieldsV0_34>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::NetworkThreat => {
                update_event_db_with_new_event::<NetworkThreatV0_33, NetworkThreat>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::ExtraThreat => {
                update_event_db_with_new_event::<ExtraThreatV0_33, ExtraThreat>(&k, &v, &event_db)?;
            }
            EventKind::WindowsThreat => {
                update_event_db_with_new_event::<WindowsThreatV0_33, WindowsThreat>(
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
        migration::migration_structures::AccountV0_34,
    };

    #[derive(Deserialize, Serialize)]
    pub struct AccountV0_33 {
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

    impl From<AccountV0_33> for AccountV0_34 {
        fn from(input: AccountV0_33) -> Self {
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
        let old = bincode::DefaultOptions::new().deserialize::<AccountV0_33>(&old_value)?;
        let new: AccountV0_34 = old.into();
        let new_value = bincode::DefaultOptions::new().serialize::<AccountV0_34>(&new)?;
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

fn migrate_0_39_events(store: &super::Store) -> Result<()> {
    use num_traits::FromPrimitive;

    use crate::event::{
        EventKind, FtpEventFieldsV0_38, FtpEventFieldsV0_39, LdapEventFieldsV0_38,
        LdapEventFieldsV0_39,
    };

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
            EventKind::FtpPlainText => {
                update_event_db_with_new_event::<FtpEventFieldsV0_38, FtpEventFieldsV0_39>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::LdapPlainText => {
                update_event_db_with_new_event::<LdapEventFieldsV0_38, LdapEventFieldsV0_39>(
                    &k, &v, &event_db,
                )?;
            }
            _ => {
                // No migration needed for other event types
            }
        }
    }

    Ok(())
}

fn migrate_0_41_events(store: &super::Store) -> Result<()> {
    use num_traits::FromPrimitive;

    use crate::event::{
        BlocklistConnFields, BlocklistHttpFieldsV0_40, BlocklistHttpFieldsV0_41,
        CryptocurrencyMiningPoolFieldsV0_39, CryptocurrencyMiningPoolFieldsV0_41, DgaFieldsV0_40,
        DgaFieldsV0_41, EventKind, ExternalDdosFieldsV0_39, ExternalDdosFieldsV0_41,
        FtpBruteForceFieldsV0_39, FtpBruteForceFieldsV0_41, HttpEventFieldsV0_39,
        HttpEventFieldsV0_41, HttpThreatFieldsV0_34, HttpThreatFieldsV0_41,
        LdapBruteForceFieldsV0_39, LdapBruteForceFieldsV0_41, MultiHostPortScanFieldsV0_39,
        MultiHostPortScanFieldsV0_41, PortScanFieldsV0_39, PortScanFieldsV0_41,
        RdpBruteForceFieldsV0_39, RdpBruteForceFieldsV0_41, RepeatedHttpSessionsFieldsV0_39,
        RepeatedHttpSessionsFieldsV0_41,
    };

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
        let time_nanos: i64 = (key >> 64).try_into().expect("valid i64");
        let kind = (key & 0xffff_ffff_0000_0000) >> 32;
        let Some(event_kind) = EventKind::from_i128(kind) else {
            return Err(anyhow!("Failed to migrate events: invalid event kind"));
        };

        match event_kind {
            EventKind::BlocklistConn => {
                let Ok(mut fields) = bincode::deserialize::<BlocklistConnFields>(v.as_ref()) else {
                    return Err(anyhow!("Failed to migrate BlocklistConn: invalid value"));
                };
                fields.end_time += time_nanos; // old `end_time` was duration
                let new_value = bincode::serialize(&fields).unwrap_or_default();
                event_db.update((&k, &v), (&k, &new_value))?;
            }
            EventKind::BlocklistHttp => {
                update_event_db_with_new_event::<BlocklistHttpFieldsV0_40, BlocklistHttpFieldsV0_41>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::CryptocurrencyMiningPool => {
                update_event_db_with_new_event::<
                    CryptocurrencyMiningPoolFieldsV0_39,
                    CryptocurrencyMiningPoolFieldsV0_41,
                >(&k, &v, &event_db)?;
            }
            EventKind::DomainGenerationAlgorithm => {
                update_event_db_with_new_event::<DgaFieldsV0_40, DgaFieldsV0_41>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::ExternalDdos => {
                update_event_db_with_new_event::<ExternalDdosFieldsV0_39, ExternalDdosFieldsV0_41>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::FtpBruteForce => {
                update_event_db_with_new_event::<FtpBruteForceFieldsV0_39, FtpBruteForceFieldsV0_41>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::HttpThreat => {
                update_event_db_with_new_event::<HttpThreatFieldsV0_34, HttpThreatFieldsV0_41>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::LdapBruteForce => {
                update_event_db_with_new_event::<
                    LdapBruteForceFieldsV0_39,
                    LdapBruteForceFieldsV0_41,
                >(&k, &v, &event_db)?;
            }
            EventKind::MultiHostPortScan => {
                update_event_db_with_new_event::<
                    MultiHostPortScanFieldsV0_39,
                    MultiHostPortScanFieldsV0_41,
                >(&k, &v, &event_db)?;
            }
            EventKind::NonBrowser => {
                update_event_db_with_new_event::<HttpEventFieldsV0_39, HttpEventFieldsV0_41>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::PortScan => {
                update_event_db_with_new_event::<PortScanFieldsV0_39, PortScanFieldsV0_41>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::RdpBruteForce => {
                update_event_db_with_new_event::<RdpBruteForceFieldsV0_39, RdpBruteForceFieldsV0_41>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::RepeatedHttpSessions => {
                let Ok(from_event) = bincode::deserialize::<RepeatedHttpSessionsFieldsV0_39>(&v)
                else {
                    return Err(anyhow!("Failed to migrate events: invalid event value"));
                };
                let mut to_event: RepeatedHttpSessionsFieldsV0_41 = from_event.into();
                to_event.start_time = chrono::DateTime::from_timestamp_nanos(time_nanos);
                to_event.end_time = chrono::DateTime::from_timestamp_nanos(time_nanos);
                let new = bincode::serialize(&to_event).unwrap_or_default();
                event_db.update((&k, &v), (&k, &new))?;
            }
            EventKind::TorConnection => {
                update_event_db_with_new_event::<HttpEventFieldsV0_39, HttpEventFieldsV0_41>(
                    &k, &v, &event_db,
                )?;
            }
            EventKind::TorConnectionConn => {
                let Ok(mut fields) = bincode::deserialize::<BlocklistConnFields>(v.as_ref()) else {
                    return Err(anyhow!(
                        "Failed to migrate TorConnectionConn: invalid value"
                    ));
                };
                fields.end_time += time_nanos; // old `end_time` was duration
                let new_value = bincode::serialize(&fields).unwrap_or_default();
                event_db.update((&k, &v), (&k, &new_value))?;
            }
            _ => {
                // No migration needed for other event types
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use semver::{Version, VersionReq};

    use super::COMPATIBLE_VERSION_REQ;
    use crate::{Store, migration::migration_structures::AccountV0_34};

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

        impl From<OldAccount> for AccountV0_34 {
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

        impl From<AccountV0_34> for OldAccount {
            fn from(input: AccountV0_34) -> Self {
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
        let new_account = AccountV0_34 {
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
            .deserialize::<AccountV0_34>(&value)
            .unwrap();

        assert_eq!(new_account, result_account);
    }

    #[test]
    fn migrate_0_30_to_0_34_events() {
        use std::net::IpAddr;

        use crate::{EventKind, EventMessage};

        let settings = TestSchema::new();
        let event_db = settings.store.events();

        let value = super::migration_structures::HttpThreatV0_33 {
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

        let value = super::migration_structures::NetworkThreatV0_33 {
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

        let value = super::migration_structures::WindowsThreatV0_33 {
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

        let value = super::migration_structures::ExtraThreatV0_33 {
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
            migration::migration_structures::AccountV0_36,
        };

        let settings = TestSchema::new();
        let map = settings.store.account_map();
        let raw = map.raw();

        let old_account = AccountV0_34 {
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
        let new_account = AccountV0_36::from(old_account.clone());
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
            .deserialize::<AccountV0_36>(res.as_ref())
            .unwrap();

        assert_eq!(account, new_account);
    }

    #[test]
    fn migrate_0_36_0_to_0_37() {
        use std::net::IpAddr;

        use num_traits::FromPrimitive;

        use crate::{EventKind, EventMessage, event::BlocklistTlsFields};

        let value = super::migration_structures::BlocklistTlsFieldsV0_36 {
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

        use super::migration_structures::{DumpItem, InnerV0_29, NodeV0_29};
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

        let old_node = NodeV0_29 {
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
        let old_inner_node: InnerV0_29 = old_node.clone().into();
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
            migration::migration_structures::AccountV0_36,
            types::Account,
        };

        let settings = TestSchema::new();
        let map = settings.store.account_map();
        let raw = map.raw();

        // Create a few AccountV36 entries
        let now = Utc::now();
        let v36_1 = AccountV0_36 {
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
        let v36_2 = AccountV0_36 {
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

    #[test]
    fn migrate_0_39_events() {
        use std::net::IpAddr;

        use num_traits::FromPrimitive;

        use crate::event::FtpEventFieldsV0_38;
        use crate::{EventKind, EventMessage};

        let settings = TestSchema::new();
        let event_db = settings.store.events();

        // Test FtpPlainText migration (confidence should be 1.0)
        let ftp_plain_event = FtpEventFieldsV0_38 {
            sensor: "sensor_1".to_string(),
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            src_port: 12345,
            dst_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            dst_port: 21,
            proto: 6,
            end_time: 1000,
            user: "testuser".to_string(),
            password: "testpass".to_string(),
            command: "RETR".to_string(),
            reply_code: "226".to_string(),
            reply_msg: "Transfer complete".to_string(),
            data_passive: false,
            data_orig_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            data_resp_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            data_resp_port: 20,
            file: "test.txt".to_string(),
            file_size: 1024,
            file_id: "file123".to_string(),
            category: crate::EventCategory::Collection,
        };
        let message = EventMessage {
            time: chrono::Utc::now(),
            kind: EventKind::FtpPlainText,
            fields: bincode::serialize(&ftp_plain_event).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);

        assert!(super::migrate_0_39_events(&settings.store).is_ok());

        let event_db = settings.store.events();
        let mut count = 0;
        for item in event_db.raw_iter_forward() {
            let (k, v) = item.unwrap();
            let key: [u8; 16] = k.as_ref().try_into().unwrap();
            let key = i128::from_be_bytes(key);
            let kind = (key & 0xffff_ffff_0000_0000) >> 32;
            let event_kind = EventKind::from_i128(kind).unwrap();

            if event_kind == EventKind::FtpPlainText {
                let event: crate::event::FtpEventFieldsV0_39 = bincode::deserialize(&v).unwrap();
                assert!((event.confidence - 1.0).abs() < f32::EPSILON);
                count += 1;
            } else {
                // Other event types should be ignored
            }
        }

        // Verify that all 5 test events were processed
        assert_eq!(count, 1);
    }

    #[test]
    fn migrate_0_40_tidb() {
        use bincode::Options;

        use crate::EventCategory;
        use crate::TidbKind;
        use crate::migration::migration_structures::{RuleV0_39, TidbV0_39};

        let settings = TestSchema::new();
        let map = settings.store.tidb_map();
        let raw = map.raw();

        let tidb_name = "HttpUriThreat".to_string();
        let old = TidbV0_39 {
            id: 201,
            name: tidb_name.clone(),
            description: None,
            kind: TidbKind::Token,
            category: EventCategory::Reconnaissance,
            version: "1.0".to_string(),
            patterns: vec![
                RuleV0_39 {
                    rule_id: 2_010_100,
                    category: EventCategory::Reconnaissance,
                    name: "http_uri_threat".to_string(),
                    description: None,
                    references: None,
                    samples: None,
                    signatures: Some(vec!["sql,injection,attack".to_string()]),
                },
                RuleV0_39 {
                    rule_id: 2_010_101,
                    category: EventCategory::Reconnaissance,
                    name: "http_uri_threat2".to_string(),
                    description: None,
                    references: None,
                    samples: None,
                    signatures: Some(vec!["etc,passwd".to_string()]),
                },
            ],
        };
        let value = bincode::DefaultOptions::new()
            .serialize(&old)
            .expect("serializable");

        assert!(raw.put(tidb_name.as_bytes(), &value).is_ok());

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);

        assert!(super::migrate_0_40_tidb(&settings.store).is_ok());

        let map = settings.store.tidb_map();
        let res = map.get(&tidb_name);
        assert!(res.is_ok());
        let new = res.unwrap();
        assert!(new.is_some());
        let new = new.unwrap();
        assert_eq!(new.id, 201);
        assert_eq!(new.category, EventCategory::Reconnaissance);
        new.patterns.iter().for_each(|rule| {
            assert_eq!(rule.confidence, None);
            assert_eq!(rule.kind, None);
        });
    }

    #[test]
    fn migrate_0_40_filter() {
        use bincode::Options;

        use crate::{
            Filter, PeriodForSearch,
            event::{FilterEndpoint, FlowKind, LearningMethod},
            migration::migration_structures::FilterValueV0_39,
            types::FromKeyValue,
        };

        let settings = TestSchema::new();
        let map = settings.store.filter_map();
        let raw = map.raw();

        // Create test data in the old format
        let old_filter_values = vec![
            FilterValueV0_39 {
                directions: Some(vec![FlowKind::Outbound]),
                keywords: Some(vec!["malware".to_string(), "suspicious".to_string()]),
                network_tags: Some(vec!["dmz".to_string()]),
                customers: Some(vec!["customer1".to_string()]),
                endpoints: Some(vec![FilterEndpoint {
                    direction: None,
                    predefined: None,
                    custom: None,
                }]),
                sensors: Some(vec!["sensor1".to_string()]),
                os: Some(vec!["windows".to_string()]),
                devices: Some(vec!["laptop".to_string()]),
                hostnames: Some(vec!["host1".to_string()]),
                user_ids: Some(vec!["user1".to_string()]),
                user_names: Some(vec!["John Doe".to_string()]),
                user_departments: Some(vec!["IT".to_string()]),
                countries: Some(vec!["US".to_string()]),
                categories: Some(vec![1, 2]),
                levels: Some(vec![3, 4]),
                kinds: Some(vec!["threat".to_string()]),
                learning_methods: Some(vec![LearningMethod::SemiSupervised]),
                confidence: Some(0.85),
            },
            FilterValueV0_39 {
                directions: None,
                keywords: None,
                network_tags: None,
                customers: None,
                endpoints: None,
                sensors: None,
                os: None,
                devices: None,
                hostnames: None,
                user_ids: None,
                user_names: None,
                user_departments: None,
                countries: None,
                categories: None,
                levels: None,
                kinds: None,
                learning_methods: None,
                confidence: None,
            },
        ];

        // Insert test data with keys in the format: username\0name
        let test_filters = vec![
            (
                "admin\0security_filter".to_string(),
                old_filter_values[0].clone(),
            ),
            (
                "user\0basic_filter".to_string(),
                old_filter_values[1].clone(),
            ),
        ];

        for (key, value) in &test_filters {
            let serialized_value = bincode::DefaultOptions::new()
                .serialize(value)
                .expect("serializable");
            assert!(raw.put(key.as_bytes(), &serialized_value).is_ok());
        }

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);

        // Run the migration
        assert!(super::migrate_0_40_filter(&settings.store).is_ok());

        // Verify the migration results
        let map = settings.store.filter_map();
        for (key, expected_old_value) in &test_filters {
            let raw_value = map.raw().get(key.as_bytes()).expect("get value");
            assert!(raw_value.is_some());

            // Deserialize the new `Filter` format
            let new_filter =
                Filter::from_key_value(key.as_bytes(), raw_value.unwrap().as_ref()).unwrap();

            // Verify that all the old fields are preserved
            assert_eq!(new_filter.directions, expected_old_value.directions);
            assert_eq!(new_filter.keywords, expected_old_value.keywords);
            assert_eq!(new_filter.network_tags, expected_old_value.network_tags);
            assert_eq!(new_filter.customers, expected_old_value.customers);
            assert_eq!(new_filter.endpoints, expected_old_value.endpoints);
            assert_eq!(new_filter.sensors, expected_old_value.sensors);
            assert_eq!(new_filter.os, expected_old_value.os);
            assert_eq!(new_filter.devices, expected_old_value.devices);
            assert_eq!(new_filter.hostnames, expected_old_value.hostnames);
            assert_eq!(new_filter.user_ids, expected_old_value.user_ids);
            assert_eq!(new_filter.user_names, expected_old_value.user_names);
            assert_eq!(
                new_filter.user_departments,
                expected_old_value.user_departments
            );
            assert_eq!(new_filter.countries, expected_old_value.countries);
            assert_eq!(new_filter.categories, expected_old_value.categories);
            assert_eq!(new_filter.levels, expected_old_value.levels);
            assert_eq!(new_filter.kinds, expected_old_value.kinds);
            assert_eq!(
                new_filter.learning_methods,
                expected_old_value.learning_methods
            );
            assert_eq!(new_filter.confidence, expected_old_value.confidence);

            // Verify that the new period field is set to the default value
            assert_eq!(
                new_filter.period,
                PeriodForSearch::Recent("1 hour".to_string())
            );
        }
    }

    #[test]
    fn migrate_0_40_events() {
        use std::net::IpAddr;

        use num_traits::FromPrimitive;

        use crate::event::{
            CryptocurrencyMiningPoolFieldsV0_39, FtpBruteForceFieldsV0_39, HttpEventFieldsV0_39,
            RdpBruteForceFieldsV0_39, RepeatedHttpSessionsFieldsV0_39,
        };
        use crate::{EventKind, EventMessage};

        let settings = TestSchema::new();
        let event_db = settings.store.events();

        // Test TorConnection migration (confidence should be 1.0)
        let now = chrono::Utc::now();
        let tor_event_fields = HttpEventFieldsV0_39 {
            sensor: "sensor_1".to_string(),
            end_time: now,
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            src_port: 12345,
            dst_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            uri: "/".to_string(),
            referer: String::new(),
            version: "1.1".to_string(),
            user_agent: "Mozilla".to_string(),
            request_len: 100,
            response_len: 200,
            status_code: 200,
            status_msg: "OK".to_string(),
            username: String::new(),
            password: String::new(),
            cookie: String::new(),
            content_encoding: String::new(),
            content_type: "text/html".to_string(),
            cache_control: String::new(),
            orig_filenames: vec![],
            orig_mime_types: vec![],
            resp_filenames: vec![],
            resp_mime_types: vec![],
            post_body: vec![],
            state: String::new(),
            category: crate::EventCategory::InitialAccess,
        };
        let message = EventMessage {
            time: now,
            kind: EventKind::TorConnection,
            fields: bincode::serialize(&tor_event_fields).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        // Test CryptocurrencyMiningPool migration (confidence should be 1.0)
        let now = chrono::Utc::now();
        let crypto_event = CryptocurrencyMiningPoolFieldsV0_39 {
            sensor: "sensor_1".to_string(),
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            src_port: 12345,
            dst_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            dst_port: 53,
            proto: 17,
            end_time: now,
            query: "example.com".to_string(),
            answer: vec!["1.2.3.4".to_string()],
            trans_id: 12345,
            rtt: 100,
            qclass: 1,
            qtype: 1,
            rcode: 0,
            aa_flag: false,
            tc_flag: false,
            rd_flag: true,
            ra_flag: true,
            ttl: vec![3600],
            coins: vec!["BTC".to_string()],
            category: crate::EventCategory::CommandAndControl,
        };
        let message = EventMessage {
            time: now,
            kind: EventKind::CryptocurrencyMiningPool,
            fields: bincode::serialize(&crypto_event).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        // Test FtpBruteForce migration (confidence should be 0.3)
        let now = chrono::Utc::now();
        let ftp_brute_event = FtpBruteForceFieldsV0_39 {
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            dst_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            dst_port: 21,
            proto: 6,
            user_list: vec!["admin".to_string(), "root".to_string()],
            start_time: now,
            end_time: now,
            is_internal: false,
            category: crate::EventCategory::CredentialAccess,
        };
        let message = EventMessage {
            time: now,
            kind: EventKind::FtpBruteForce,
            fields: bincode::serialize(&ftp_brute_event).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        // Test RdpBruteForce migration (confidence should be 0.3)
        let now = chrono::Utc::now();
        let rdp_brute_event = RdpBruteForceFieldsV0_39 {
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            dst_addrs: vec!["192.168.1.2".parse::<IpAddr>().unwrap()],
            proto: 6,
            start_time: now,
            end_time: now,
            category: crate::EventCategory::CredentialAccess,
        };
        let message = EventMessage {
            time: now,
            kind: EventKind::RdpBruteForce,
            fields: bincode::serialize(&rdp_brute_event).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        // Test RepeatedHttpSessions migration (confidence should be 0.3, start_time and end_time should be set)
        let repeated_http_event = RepeatedHttpSessionsFieldsV0_39 {
            sensor: "sensor_1".to_string(),
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            src_port: 8080,
            dst_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 6,
            category: crate::EventCategory::CommandAndControl,
        };
        let message = EventMessage {
            time: chrono::Utc::now(),
            kind: EventKind::RepeatedHttpSessions,
            fields: bincode::serialize(&repeated_http_event).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);

        // Run the migration
        assert!(super::migrate_0_41_events(&settings.store).is_ok());

        // Verify the migrated events have the correct confidence values
        let event_db = settings.store.events();
        let mut count = 0;
        for item in event_db.raw_iter_forward() {
            let (k, v) = item.unwrap();
            let key: [u8; 16] = k.as_ref().try_into().unwrap();
            let key = i128::from_be_bytes(key);
            let event_time =
                chrono::DateTime::from_timestamp_nanos((key >> 64).try_into().expect("valid i64"));
            let kind: i128 = (key & 0xffff_ffff_0000_0000) >> 32;
            let event_kind = EventKind::from_i128(kind).unwrap();

            match event_kind {
                EventKind::TorConnection => {
                    let event_fields: crate::event::HttpEventFieldsV0_41 =
                        bincode::deserialize(&v).unwrap();
                    assert!((event_fields.confidence - 1.0).abs() < f32::EPSILON);
                    count += 1;
                }
                EventKind::CryptocurrencyMiningPool => {
                    let event: crate::event::CryptocurrencyMiningPoolFieldsV0_41 =
                        bincode::deserialize(&v).unwrap();
                    assert!((event.confidence - 1.0).abs() < f32::EPSILON);
                    count += 1;
                }
                EventKind::FtpBruteForce => {
                    let event: crate::event::FtpBruteForceFieldsV0_41 =
                        bincode::deserialize(&v).unwrap();
                    assert!((event.confidence - 0.3).abs() < f32::EPSILON);
                    count += 1;
                }
                EventKind::RdpBruteForce => {
                    let event: crate::event::RdpBruteForceFieldsV0_41 =
                        bincode::deserialize(&v).unwrap();
                    assert!((event.confidence - 0.3).abs() < f32::EPSILON);
                    count += 1;
                }
                EventKind::RepeatedHttpSessions => {
                    let event: crate::event::RepeatedHttpSessionsFieldsV0_41 =
                        bincode::deserialize(&v).unwrap();
                    assert!((event.confidence - 0.3).abs() < f32::EPSILON);
                    // Verify that start_time and end_time are set (should be equal to the event time)
                    assert_eq!(event.start_time, event_time);
                    assert_eq!(event.end_time, event_time);
                    count += 1;
                }
                _ => {
                    // Other event types should be ignored
                }
            }
        }

        // Verify that all 5 test events were processed
        assert_eq!(count, 5);
    }

    #[test]
    fn migrate_0_40_to_0_41_sensor_field() {
        use std::net::IpAddr;

        use chrono::Utc;
        use num_traits::FromPrimitive;

        use crate::event::{
            ExternalDdosFieldsV0_39, FtpBruteForceFieldsV0_39, LdapBruteForceFieldsV0_39,
            MultiHostPortScanFieldsV0_39, PortScanFieldsV0_39, RdpBruteForceFieldsV0_39,
        };
        use crate::{EventKind, EventMessage};

        let settings = TestSchema::new();
        let event_db = settings.store.events();

        // Create test data for PortScan (V0_40 - no sensor field)
        let port_scan_event = PortScanFieldsV0_39 {
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            dst_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            dst_ports: vec![80, 443],
            start_time: Utc::now(),
            end_time: Utc::now(),
            proto: 6,
            category: crate::EventCategory::Discovery,
        };
        let message = EventMessage {
            time: Utc::now(),
            kind: EventKind::PortScan,
            fields: bincode::serialize(&port_scan_event).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        // Create test data for MultiHostPortScan (V0_40 - no sensor field)
        let multi_port_scan_event = MultiHostPortScanFieldsV0_39 {
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            dst_port: 22,
            dst_addrs: vec![
                "192.168.1.2".parse::<IpAddr>().unwrap(),
                "192.168.1.3".parse::<IpAddr>().unwrap(),
            ],
            proto: 6,
            start_time: Utc::now(),
            end_time: Utc::now(),
            category: crate::EventCategory::Discovery,
        };
        let message = EventMessage {
            time: Utc::now(),
            kind: EventKind::MultiHostPortScan,
            fields: bincode::serialize(&multi_port_scan_event).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        // Create test data for ExternalDdos (V0_40 - no sensor field)
        let external_ddos_event = ExternalDdosFieldsV0_39 {
            src_addrs: vec![
                "192.168.1.1".parse::<IpAddr>().unwrap(),
                "192.168.1.2".parse::<IpAddr>().unwrap(),
            ],
            dst_addr: "192.168.1.100".parse::<IpAddr>().unwrap(),
            proto: 6,
            start_time: Utc::now(),
            end_time: Utc::now(),
            category: crate::EventCategory::Impact,
        };
        let message = EventMessage {
            time: Utc::now(),
            kind: EventKind::ExternalDdos,
            fields: bincode::serialize(&external_ddos_event).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        // Create test data for RdpBruteForce (V0_40 - no sensor field)
        let rdp_brute_event = RdpBruteForceFieldsV0_39 {
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            dst_addrs: vec!["192.168.1.2".parse::<IpAddr>().unwrap()],
            start_time: Utc::now(),
            end_time: Utc::now(),
            proto: 6,
            category: crate::EventCategory::CredentialAccess,
        };
        let message = EventMessage {
            time: Utc::now(),
            kind: EventKind::RdpBruteForce,
            fields: bincode::serialize(&rdp_brute_event).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        // Create test data for FtpBruteForce (V0_40 - no sensor field)
        let ftp_brute_event = FtpBruteForceFieldsV0_39 {
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            dst_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            dst_port: 21,
            proto: 6,
            user_list: vec!["admin".to_string(), "user".to_string()],
            start_time: Utc::now(),
            end_time: Utc::now(),
            is_internal: false,
            category: crate::EventCategory::CredentialAccess,
        };
        let message = EventMessage {
            time: Utc::now(),
            kind: EventKind::FtpBruteForce,
            fields: bincode::serialize(&ftp_brute_event).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        // Create test data for LdapBruteForce (V0_40 - no sensor field)
        let ldap_brute_event = LdapBruteForceFieldsV0_39 {
            src_addr: "192.168.1.1".parse::<IpAddr>().unwrap(),
            dst_addr: "192.168.1.2".parse::<IpAddr>().unwrap(),
            dst_port: 389,
            proto: 6,
            user_pw_list: vec![("admin".to_string(), "password".to_string())],
            start_time: Utc::now(),
            end_time: Utc::now(),
            category: crate::EventCategory::CredentialAccess,
        };
        let message = EventMessage {
            time: Utc::now(),
            kind: EventKind::LdapBruteForce,
            fields: bincode::serialize(&ldap_brute_event).unwrap_or_default(),
        };
        assert!(event_db.put(&message).is_ok());

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);

        // Run the migration
        assert!(super::migrate_0_41_events(&settings.store).is_ok());

        // Verify the migrated events have the sensor field with empty string
        let event_db = settings.store.events();
        let mut migrated_events = 0;
        for item in event_db.raw_iter_forward() {
            let (k, v) = item.unwrap();
            let key: [u8; 16] = k.as_ref().try_into().unwrap();
            let key = i128::from_be_bytes(key);
            let kind = (key & 0xffff_ffff_0000_0000) >> 32;
            let Some(event_kind) = EventKind::from_i128(kind) else {
                continue;
            };

            match event_kind {
                EventKind::PortScan => {
                    let port_scan: crate::event::PortScanFieldsV0_41 =
                        bincode::deserialize(&v).unwrap();
                    assert_eq!(port_scan.sensor, "");
                    assert!((port_scan.confidence - 0.3).abs() < f32::EPSILON);
                    migrated_events += 1;
                }
                EventKind::MultiHostPortScan => {
                    let multi_scan: crate::event::MultiHostPortScanFieldsV0_41 =
                        bincode::deserialize(&v).unwrap();
                    assert_eq!(multi_scan.sensor, "");
                    assert!((multi_scan.confidence - 0.3).abs() < f32::EPSILON);
                    migrated_events += 1;
                }
                EventKind::ExternalDdos => {
                    let ddos: crate::event::ExternalDdosFieldsV0_41 =
                        bincode::deserialize(&v).unwrap();
                    assert_eq!(ddos.sensor, "");
                    assert!((ddos.confidence - 0.3).abs() < f32::EPSILON);
                    migrated_events += 1;
                }
                EventKind::RdpBruteForce => {
                    let rdp: crate::event::RdpBruteForceFieldsV0_41 =
                        bincode::deserialize(&v).unwrap();
                    assert_eq!(rdp.sensor, "");
                    assert!((rdp.confidence - 0.3).abs() < f32::EPSILON);
                    migrated_events += 1;
                }
                EventKind::FtpBruteForce => {
                    let ftp: crate::event::FtpBruteForceFieldsV0_41 =
                        bincode::deserialize(&v).unwrap();
                    assert_eq!(ftp.sensor, "");
                    assert!((ftp.confidence - 0.3).abs() < f32::EPSILON);
                    migrated_events += 1;
                }
                EventKind::LdapBruteForce => {
                    let ldap: crate::event::LdapBruteForceFieldsV0_41 =
                        bincode::deserialize(&v).unwrap();
                    assert_eq!(ldap.sensor, "");
                    assert!((ldap.confidence - 0.3).abs() < f32::EPSILON);
                    migrated_events += 1;
                }
                _ => {
                    // Other event types are not migrated in this test
                }
            }
        }

        // Verify that all 6 test events were processed
        assert_eq!(migrated_events, 6);
    }
}
