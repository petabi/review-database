//! Routines to check the database format version and migrate it if necessary.

use anyhow::{anyhow, Context, Result};
use bincode::Options;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

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
const COMPATIBLE_VERSION_REQ: &str = ">=0.6.0,<=0.7.0-alpha.1";

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
    let migration: Vec<(_, _, fn(_, _) -> Result<_, _>)> = vec![
        (
            VersionReq::parse(">=0.2,<0.4.0").expect("valid version requirement"),
            Version::parse("0.3.0").expect("valid version"),
            migrate_0_2_to_0_3,
        ),
        (
            VersionReq::parse(">=0.3,<0.5.0").expect("valid version requirement"),
            Version::parse("0.5.0").expect("valid version"),
            migrate_0_3_to_0_5,
        ),
        (
            VersionReq::parse(">=0.5.0,<0.6.0").expect("valid version requirement"),
            Version::parse("0.6.0").expect("valid version"),
            migrate_0_5_to_0_6,
        ),
        (
            VersionReq::parse(">=0.6.0,<=0.7.0-alpha.1").expect("valid version requirement"),
            Version::parse("0.7.0-alpha.1").expect("valid version"),
            migrate_0_6_to_0_7,
        ),
    ];

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

/// Migrates the database from 0.2 to 0.3.
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

/// Migrates the database from 0.3 to 0.5.
///
/// # Errors
///
/// Returns an error if database migration fails.
pub(crate) fn migrate_0_3_to_0_5<P: AsRef<Path>>(path: P, backup: P) -> Result<()> {
    use super::{
        event::{Filter, FilterEndpoint, FlowKind},
        IterableMap,
    };

    #[derive(Deserialize, Serialize)]
    struct OldFilter {
        name: String,
        directions: Option<Vec<FlowKind>>,
        keywords: Option<Vec<String>>,
        network_tags: Option<Vec<String>>,
        customers: Option<Vec<String>>,
        endpoints: Option<Vec<FilterEndpoint>>,
        sensors: Option<Vec<String>>,
        os: Option<Vec<String>>,
        devices: Option<Vec<String>>,
        host_names: Option<Vec<String>>,
        user_ids: Option<Vec<String>>,
        user_names: Option<Vec<String>>,
        user_departments: Option<Vec<String>>,
        countries: Option<Vec<String>>,
        categories: Option<Vec<u8>>,
        levels: Option<Vec<u8>>,
        kinds: Option<Vec<String>>,
    }

    impl From<&OldFilter> for Filter {
        fn from(input: &OldFilter) -> Self {
            Self {
                name: input.name.clone(),
                directions: input.directions.clone(),
                keywords: input.keywords.clone(),
                network_tags: input.network_tags.clone(),
                customers: input.customers.clone(),
                endpoints: input.endpoints.clone(),
                sensors: input.sensors.clone(),
                os: input.os.clone(),
                devices: input.devices.clone(),
                host_names: input.host_names.clone(),
                user_ids: input.user_ids.clone(),
                user_names: input.user_names.clone(),
                user_departments: input.user_departments.clone(),
                countries: input.countries.clone(),
                categories: input.categories.clone(),
                levels: input.levels.clone(),
                kinds: input.kinds.clone(),
                learning_methods: None,
                confidence: None,
            }
        }
    }

    let store = super::Store::new(path.as_ref(), backup.as_ref())?;
    store.backup(1)?;
    let filter_map = store.filter_map();

    for (k, v) in filter_map.iter_forward()? {
        let old: OldFilter = bincode::DefaultOptions::new().deserialize::<OldFilter>(&v)?;
        let filter: Filter = (&old).into();
        let new = bincode::DefaultOptions::new().serialize(&filter)?;
        filter_map.update((&k, &v), (&k, &new))?;
    }

    store.purge_old_backups(0)?;
    Ok(())
}

/// Migrates the database from 0.5 to 0.6.
///
/// # Errors
///
/// Returns an error if database migration fails.
pub(crate) fn migrate_0_5_to_0_6<P: AsRef<Path>>(path: P, backup: P) -> Result<()> {
    use super::{
        traffic_filter::{ProtocolPorts, TrafficFilter},
        IterableMap,
    };
    use chrono::{DateTime, Utc};
    use ipnet::IpNet;
    use std::collections::HashMap;

    #[derive(Deserialize)]
    struct OldTrafficFilter {
        agent: String,
        rules: Vec<IpNet>,
        _last_modification_time: DateTime<Utc>,
        _update_time: Option<DateTime<Utc>>,
    }

    impl From<&OldTrafficFilter> for TrafficFilter {
        fn from(input: &OldTrafficFilter) -> Self {
            let rules: HashMap<IpNet, ProtocolPorts> = input
                .rules
                .iter()
                .map(|net| (*net, ProtocolPorts::default()))
                .collect();
            Self {
                agent: input.agent.clone(),
                rules,
                last_modification_time: Utc::now(),
                update_time: None,
                description: None,
            }
        }
    }

    let store = super::Store::new(path.as_ref(), backup.as_ref())?;
    store.backup(1)?;
    let traffic_filter_map = store.traffic_filter_map();

    for (k, v) in traffic_filter_map.iter_forward()? {
        let old = bincode::DefaultOptions::new().deserialize::<OldTrafficFilter>(&v)?;
        let rule: TrafficFilter = (&old).into();
        let new = bincode::DefaultOptions::new().serialize(&rule)?;
        traffic_filter_map.update((&k, &v), (&k, &new))?;
    }

    store.purge_old_backups(0)?;
    Ok(())
}

/// Migrates the database from 0.6 to 0.7.
///
/// # Errors
///
/// Returns an error if database migration fails.
pub(crate) fn migrate_0_6_to_0_7<P: AsRef<Path>>(path: P, backup: P) -> Result<()> {
    use crate::IterableMap;
    use std::collections::HashMap;

    let store = super::Store::new(path.as_ref(), backup.as_ref())?;
    store.backup(1)?;

    #[derive(Deserialize, Serialize)]
    struct OutlierKey {
        model_id: i32,
        timestamp: i64,
        rank: i64,
        id: i64,
        source: String,
    }

    let map = store.outlier_map();

    let mut outliers = vec![];

    let mut max_ranks = HashMap::new();
    for (k, v) in map.iter_forward()? {
        let outlier_key: OutlierKey = bincode::DefaultOptions::new().deserialize(&k)?;
        let max_rank = max_ranks
            .entry((outlier_key.model_id, outlier_key.timestamp))
            .or_default();
        *max_rank = std::cmp::max(*max_rank, outlier_key.rank);
        outliers.push((outlier_key, (k, v)));
    }

    for (mut outlier_key, (k, v)) in outliers {
        let &max_rank = max_ranks
            .get(&(outlier_key.model_id, outlier_key.timestamp))
            .expect("the key should exists");
        outlier_key.rank = max_rank - outlier_key.rank + 1;
        let new_k = bincode::DefaultOptions::new().serialize(&outlier_key)?;
        map.update((&k, &v), (&new_k, &v))?;
    }

    store.purge_old_backups(0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use semver::{Version, VersionReq};

    use super::COMPATIBLE_VERSION_REQ;
    use crate::{IterableMap, Store};

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
        assert!(compatible.matches(&current));

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
    fn migrate_0_6_to_0_7() {
        use bincode::Options;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
        struct OutlierKey {
            model_id: i32,
            timestamp: i64,
            rank: i64,
            id: i64,
            source: String,
        }

        #[derive(Default, Deserialize, Serialize)]
        struct OutlierValue {
            distance: f64,
            is_saved: bool,
        }

        let value = OutlierValue::default();
        let value = bincode::DefaultOptions::new()
            .serialize(&value)
            .expect("serialize error");
        let keys = vec![
            (1, 11, 1, 1, "a"),
            (1, 11, 2, 2, "a"),
            (1, 11, 2, 2, "b"),
            (1, 11, 3, 3, "a"),
            (1, 22, 1, 1, "a"),
            (1, 22, 2, 2, "a"),
            (1, 22, 3, 3, "c"),
            (2, 11, 1, 1, "a"),
            (2, 22, 2, 1, "a"),
            (2, 22, 1, 2, "a"),
        ];
        let reversed = vec![
            (1, 11, 1, 3, "a"),
            (1, 11, 2, 2, "a"),
            (1, 11, 2, 2, "b"),
            (1, 11, 3, 1, "a"),
            (1, 22, 1, 3, "c"),
            (1, 22, 2, 2, "a"),
            (1, 22, 3, 1, "a"),
            (2, 11, 1, 1, "a"),
            (2, 22, 1, 1, "a"),
            (2, 22, 2, 2, "a"),
        ];

        let settings = TestSchema::new();
        let map = settings.store.outlier_map();
        for (model_id, timestamp, rank, id, source) in keys {
            let key = OutlierKey {
                model_id,
                timestamp,
                rank,
                id,
                source: source.to_owned(),
            };
            let key = bincode::DefaultOptions::new()
                .serialize(&key)
                .expect("serialize error");
            map.insert(&key, &value).expect("storing error");
        }

        let (db_dir, backup_dir) = settings.close();
        assert!(super::migrate_0_6_to_0_7(db_dir.path(), backup_dir.path()).is_ok());

        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        let map = settings.store.outlier_map();
        let updated: Vec<OutlierKey> = map
            .iter_forward()
            .expect("iter error")
            .map(|(k, _v)| {
                bincode::DefaultOptions::new()
                    .deserialize(&k)
                    .expect("deserialize error")
            })
            .collect();
        let reversed: Vec<_> = reversed
            .into_iter()
            .map(|(model_id, timestamp, rank, id, source)| OutlierKey {
                model_id,
                timestamp,
                rank,
                id,
                source: source.to_owned(),
            })
            .collect();
        assert_eq!(reversed, updated);
    }
}
