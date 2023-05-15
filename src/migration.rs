//! Routines to check the database format version and migrate it if necessary.

use anyhow::{anyhow, Context, Result};
use bincode::Options;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{
    fs::{create_dir_all, File},
    io::{Read, Write},
    net::IpAddr,
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
const COMPATIBLE_VERSION_REQ: &str = "=0.9.0-alpha.1";

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
            VersionReq::parse(">=0.6.0,<0.7.0").expect("valid version requirement"),
            Version::parse("0.7.0").expect("valid version"),
            migrate_0_6_to_0_7,
        ),
        (
            VersionReq::parse(">=0.7.0,<0.9.0").expect("valid version requirement"),
            Version::parse("0.9.0").expect("valid version"),
            migrate_0_7_to_0_9,
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
fn migrate_0_2_to_0_3<P: AsRef<Path>>(path: P, backup: P) -> Result<()> {
    use super::{
        account::{Account, PasswordHashAlgorithm, Role, SaltedPassword},
        IterableMap,
    };
    use chrono::{DateTime, Utc};

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
        account_map.update_raw((&k, &v), (&k, &new))?;
    }

    store.purge_old_backups(0)?;
    Ok(())
}

/// Migrates the database from 0.3 to 0.5.
///
/// # Errors
///
/// Returns an error if database migration fails.
fn migrate_0_3_to_0_5<P: AsRef<Path>>(path: P, backup: P) -> Result<()> {
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
fn migrate_0_5_to_0_6<P: AsRef<Path>>(path: P, backup: P) -> Result<()> {
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
fn migrate_0_6_to_0_7<P: AsRef<Path>>(path: P, backup: P) -> Result<()> {
    use crate::IterableMap;
    #[derive(Deserialize, Serialize)]
    struct OutlierKey {
        model_id: i32,
        timestamp: i64,
        rank: i64,
        id: i64,
        source: String,
    }

    let store = super::Store::new(path.as_ref(), backup.as_ref())?;
    store.backup(1)?;

    let map = store.outlier_map();

    let mut outliers = vec![];

    for (k, v) in map.iter_forward()? {
        let outlier_key: OutlierKey = bincode::DefaultOptions::new().deserialize(&k)?;

        outliers.push((outlier_key, (k, v)));
    }

    let mut prev = (-1, -1, -1);
    let mut rank = -1;
    let mut len = 0;
    for (mut outlier_key, (k, v)) in outliers.into_iter().rev() {
        if outlier_key.model_id != prev.0 || outlier_key.timestamp != prev.1 {
            len = 1;
            rank = 1;
        } else {
            len += 1;
            if prev.2 != outlier_key.rank {
                rank = len;
            }
        }

        prev = (
            outlier_key.model_id,
            outlier_key.timestamp,
            outlier_key.rank,
        );
        outlier_key.rank = rank;
        let new_k = bincode::DefaultOptions::new().serialize(&outlier_key)?;
        map.update((&k, &v), (&new_k, &v))?;
    }

    store.purge_old_backups(0)?;
    Ok(())
}

/// Migrates the database from 0.7 to 0.9.
///
/// # Errors
///
/// Returns an error if database migration fails.
#[allow(clippy::too_many_lines)]
fn migrate_0_7_to_0_9<P: AsRef<Path>>(path: P, backup: P) -> Result<()> {
    use crate::{
        event::{DnsEventFields, TorConnectionFields},
        EventKind,
    };
    use chrono::{TimeZone, Utc};
    use num_traits::FromPrimitive;

    #[derive(Deserialize, Serialize)]
    pub struct OldDnsEventFields {
        pub source: String,
        pub src_addr: IpAddr,
        pub src_port: u16,
        pub dst_addr: IpAddr,
        pub dst_port: u16,
        pub proto: u8,
        pub query: String,
        pub confidence: f32,
    }

    #[derive(Deserialize, Serialize)]
    pub struct OldTorConnectionFields {
        pub source: String,
        pub src_addr: IpAddr,
        pub src_port: u16,
        pub dst_addr: IpAddr,
        pub dst_port: u16,
        pub proto: u8,
    }

    impl From<OldDnsEventFields> for DnsEventFields {
        fn from(input: OldDnsEventFields) -> Self {
            Self {
                source: input.source.clone(),
                session_end_time: Utc.timestamp_nanos(0),
                src_addr: input.src_addr,
                src_port: input.src_port,
                dst_addr: input.dst_addr,
                dst_port: input.dst_port,
                proto: input.proto,
                query: input.query.clone(),
                answer: Vec::new(),
                trans_id: 0,
                rtt: 0,
                qclass: 1,
                qtype: 1,
                rcode: 0,
                aa_flag: false,
                tc_flag: false,
                rd_flag: false,
                ra_flag: false,
                ttl: Vec::new(),
                confidence: input.confidence,
            }
        }
    }

    impl From<OldTorConnectionFields> for TorConnectionFields {
        fn from(input: OldTorConnectionFields) -> Self {
            Self {
                source: input.source.clone(),
                session_end_time: Utc.timestamp_nanos(0),
                src_addr: input.src_addr,
                src_port: input.src_port,
                dst_addr: input.dst_addr,
                dst_port: input.dst_port,
                proto: input.proto,
                method: String::new(),
                host: String::new(),
                uri: String::new(),
                referrer: String::new(),
                version: String::new(),
                user_agent: String::new(),
                request_len: 0,
                response_len: 0,
                status_code: 0,
                status_msg: String::new(),
                username: String::new(),
                password: String::new(),
                cookie: String::new(),
                content_encoding: String::new(),
                content_type: String::new(),
                cache_control: String::new(),
            }
        }
    }

    let store = super::Store::new(path.as_ref(), backup.as_ref())?;
    store.backup(1)?;

    let event_db = store.events();
    for item in event_db.raw_iter_forward() {
        let (k, v) = item.context("Failed to read events Database")?;
        let key: [u8; 16] = if let Ok(key) = k.as_ref().try_into() {
            key
        } else {
            return Err(anyhow!("Failed to migrate events: Invalid Event key"));
        };
        let key = i128::from_be_bytes(key);
        let kind_num = (key & 0xffff_ffff_0000_0000) >> 32;
        let Some(kind) = EventKind::from_i128(kind_num) else {
            return Err(anyhow!("Failed to migrate events: Invalid Event key"));
        };
        match kind {
            EventKind::DnsCovertChannel => {
                let Ok(fields) = bincode::deserialize::<OldDnsEventFields>(v.as_ref()) else {
                    return Err(anyhow!("Failed to migrate events: Invalid Event value"));
                };
                let dns_event: DnsEventFields = fields.into();
                let new = bincode::serialize(&dns_event).unwrap_or_default();
                event_db.update((&k, &v), (&k, &new))?;
            }
            EventKind::TorConnection => {
                let Ok(fields) = bincode::deserialize::<OldTorConnectionFields>(v.as_ref()) else {
                    return Err(anyhow!("Failed to migrate events: Invalid Event value"));
                };
                let tor_event: TorConnectionFields = fields.into();
                let new = bincode::serialize(&tor_event).unwrap_or_default();
                event_db.update((&k, &v), (&k, &new))?;
            }
            _ => continue,
        }
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
            (1, 11, 3, 4, "a"),
            (1, 22, 1, 1, "a"),
            (1, 22, 2, 2, "a"),
            (1, 22, 2, 3, "c"),
            (2, 11, 1, 1, "a"),
            (2, 22, 1, 2, "a"),
            (2, 22, 2, 1, "a"),
        ];
        let reversed = vec![
            (1, 11, 1, 4, "a"),
            (1, 11, 2, 2, "a"),
            (1, 11, 2, 2, "b"),
            (1, 11, 4, 1, "a"),
            (1, 22, 1, 2, "a"),
            (1, 22, 1, 3, "c"),
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

    #[test]
    fn migrate_0_7_to_0_9() {
        use crate::{EventKind, EventMessage};
        use chrono::{TimeZone, Utc};
        use serde::{Deserialize, Serialize};
        use std::net::IpAddr;

        #[derive(Deserialize, Serialize)]
        pub struct OldDnsEventFields {
            pub source: String,
            pub src_addr: IpAddr,
            pub src_port: u16,
            pub dst_addr: IpAddr,
            pub dst_port: u16,
            pub proto: u8,
            pub query: String,
            pub confidence: f32,
        }

        #[derive(Deserialize, Serialize)]
        pub struct OldTorConnectionFields {
            pub source: String,
            pub src_addr: IpAddr,
            pub src_port: u16,
            pub dst_addr: IpAddr,
            pub dst_port: u16,
            pub proto: u8,
        }

        let dsn_kind = EventKind::DnsCovertChannel;
        let dns_time = Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 0).unwrap();
        let dns_value = OldDnsEventFields {
            source: "reveiw1".to_string(),
            src_addr: "192.168.4.100".parse::<IpAddr>().unwrap(),
            src_port: 40000,
            dst_addr: "31.3.245.100".parse::<IpAddr>().unwrap(),
            dst_port: 80,
            proto: 10,
            query: "Hello Server Hello Server Hello Server".to_string(),
            confidence: 1.1,
        };
        let dns_message = EventMessage {
            time: dns_time,
            kind: dsn_kind,
            fields: bincode::serialize(&dns_value).unwrap_or_default(),
        };

        let tor_kind = EventKind::TorConnection;
        let tor_time = Utc.with_ymd_and_hms(2023, 1, 20, 0, 0, 1).unwrap();
        let tor_value = OldTorConnectionFields {
            source: "reveiw1".to_string(),
            src_addr: "192.168.4.200".parse::<IpAddr>().unwrap(),
            src_port: 50000,
            dst_addr: "31.3.245.200".parse::<IpAddr>().unwrap(),
            dst_port: 160,
            proto: 20,
        };
        let tor_message = EventMessage {
            time: tor_time,
            kind: tor_kind,
            fields: bincode::serialize(&tor_value).unwrap_or_default(),
        };

        let settings = TestSchema::new();
        let event_db = settings.store.events();
        event_db.put(&dns_message).unwrap();
        event_db.put(&tor_message).unwrap();
        let (db_dir, backup_dir) = settings.close();

        assert!(super::migrate_0_7_to_0_9(db_dir.path(), backup_dir.path()).is_ok());
    }
}
