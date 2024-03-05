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
const COMPATIBLE_VERSION_REQ: &str = ">=0.25.0,<0.26.0-alpha";

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
    db: &super::Database,
    store: &super::Store,
    data_dir: P,
) -> Result<()> {
    // Below is an example for cases when data migration between `PostgreSQL`
    // and RocksDB is needed.
    let path = data_dir.as_ref();
    let file = path.join("VERSION");

    let version = read_version_file(&file)?;

    let Ok(compatible) = VersionReq::parse(COMPATIBLE_VERSION_REQ) else {
        unreachable!("COMPATIBLE_VERSION_REQ must be valid")
    };
    if compatible.matches(&version) {
        backend_0_23(db, store).await?;
    }
    Ok(())
}

async fn backend_0_23(db: &super::Database, store: &super::Store) -> Result<()> {
    tracing::info!("starting to transfer csv column extra data...");
    tracing::info!(
        "# of entries transferred: {}",
        transfer_csv_column_extras(db, store).await?
    );
    Ok(())
}

async fn transfer_csv_column_extras(db: &super::Database, store: &super::Store) -> Result<usize> {
    let data = db.load_csv_column_extras().await?;
    let table = store.csv_column_extra_map();

    if table.count()? > 0 {
        return Ok(0);
    }

    let mut next_mid = data
        .iter()
        .max_by_key(|e| e.model_id)
        .expect("invalid model id")
        .model_id
        + 1;

    let mut cur = 0;
    let mut to_remove = vec![];
    let data_len = data.len();
    for entry in data {
        while cur < entry.id {
            let added = table.insert(next_mid, None, None, None, None, None)?;

            if added != cur {
                return Err(anyhow!(
                    "corrupted category table: inserting {cur} and assigned with {added}"
                ));
            }

            to_remove.push(cur);
            next_mid += 1;
            cur += 1;
        }
        let added = table.insert(
            entry.model_id,
            entry.column_alias.as_deref(),
            entry.column_display.as_deref(),
            entry.column_top_n.as_deref(),
            entry.column_1.as_deref(),
            entry.column_n.as_deref(),
        )?;
        if added != cur || added != entry.id {
            return Err(anyhow!(
                "corrupted category table: inserting {cur} and assigned with {added}"
            ));
        }
        cur += 1;
    }

    for id in to_remove {
        table.remove(id)?;
    }

    Ok(data_len)
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
            VersionReq::parse(">=0.22.0,<0.24.0")?,
            Version::parse("0.24.0")?,
            migrate_0_22_to_0_24,
        ),
        (
            VersionReq::parse(">=0.24.0,<0.25.0")?,
            Version::parse("0.25.0")?,
            migrate_0_24_to_0_25,
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

fn migrate_0_24_to_0_25(store: &super::Store) -> Result<()> {
    migrate_batch_info_map(store)?;

    migrate_access_token_map(store)?;

    migrate_filter_map(store)?;

    migrate_node(store)
}

fn migrate_batch_info_map(store: &super::Store) -> Result<()> {
    use crate::IterableMap;
    use bincode::Options;

    let map = store.batch_info_map();
    for (old_k, v) in map.raw().iter_forward()? {
        let Ok((mid, id)) = bincode::DefaultOptions::new().deserialize::<(i32, i64)>(&old_k) else {
            continue;
        };

        let mut key = mid.to_be_bytes().to_vec();
        key.extend(id.to_be_bytes());
        map.raw().delete(&old_k)?;
        map.raw().insert(&key, &v)?;
    }
    Ok(())
}

fn migrate_access_token_map(store: &super::Store) -> Result<()> {
    use crate::IterableMap;
    use bincode::Options;
    use std::collections::HashSet;

    let map = store.access_token_map();

    for (k, v) in map.raw().iter_forward()? {
        let username = String::from_utf8_lossy(&k);
        let tokens = bincode::DefaultOptions::new().deserialize::<HashSet<String>>(&v)?;
        map.raw().delete(&k)?;
        for token in tokens {
            map.insert(&username, &token)?;
        }
    }
    Ok(())
}

fn migrate_filter_map(store: &super::Store) -> Result<()> {
    use crate::{Filter, FilterEndpoint, FlowKind, IterableMap, LearningMethod};
    use bincode::Options;
    use std::collections::HashMap;

    #[derive(Deserialize)]
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
        learning_methods: Option<Vec<LearningMethod>>,
        confidence: Option<f32>,
    }

    let map = store.filter_map();

    for (k, v) in map.raw().iter_forward()? {
        let username = String::from_utf8_lossy(&k);
        let filters =
            bincode::DefaultOptions::new().deserialize::<HashMap<String, OldFilter>>(&v)?;
        map.raw().delete(&k)?;
        for (_, filter) in filters {
            let new = Filter {
                username: username.to_string(),
                name: filter.name,
                directions: filter.directions,
                keywords: filter.keywords,
                network_tags: filter.network_tags,
                customers: filter.customers,
                endpoints: filter.endpoints,
                sensors: filter.sensors,
                os: filter.os,
                devices: filter.devices,
                host_names: filter.host_names,
                user_ids: filter.user_ids,
                user_names: filter.user_names,
                user_departments: filter.user_departments,
                countries: filter.countries,
                categories: filter.categories,
                levels: filter.levels,
                kinds: filter.kinds,
                learning_methods: filter.learning_methods,
                confidence: filter.confidence,
            };
            map.insert(new)?;
        }
    }
    Ok(())
}

fn migrate_node(store: &super::Store) -> Result<()> {
    use crate::collections::Indexed;
    use crate::node::{Node, NodeSetting};
    use crate::IterableMap;
    use bincode::Options;
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;

    type PortNumber = u16;

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Deserialize, Serialize)]
    pub struct OldNode {
        pub id: u32,
        pub name: String,
        pub customer_id: u32,
        pub description: String,
        pub hostname: String,

        pub review: bool,
        pub review_port: Option<PortNumber>,
        pub review_web_port: Option<PortNumber>,

        pub piglet: bool,
        pub piglet_giganto_ip: Option<IpAddr>,
        pub piglet_giganto_port: Option<PortNumber>,
        pub piglet_review_ip: Option<IpAddr>,
        pub piglet_review_port: Option<PortNumber>,
        pub save_packets: bool,
        pub http: bool,
        pub office: bool,
        pub exe: bool,
        pub pdf: bool,
        pub html: bool,
        pub txt: bool,
        pub smtp_eml: bool,
        pub ftp: bool,

        pub giganto: bool,
        pub giganto_ingestion_ip: Option<IpAddr>,
        pub giganto_ingestion_port: Option<PortNumber>,
        pub giganto_publish_ip: Option<IpAddr>,
        pub giganto_publish_port: Option<PortNumber>,
        pub giganto_graphql_ip: Option<IpAddr>,
        pub giganto_graphql_port: Option<PortNumber>,
        pub retention_period: Option<u16>,

        pub reconverge: bool,
        pub reconverge_review_ip: Option<IpAddr>,
        pub reconverge_review_port: Option<PortNumber>,
        pub reconverge_giganto_ip: Option<IpAddr>,
        pub reconverge_giganto_port: Option<PortNumber>,

        pub hog: bool,
        pub hog_review_ip: Option<IpAddr>,
        pub hog_review_port: Option<PortNumber>,
        pub hog_giganto_ip: Option<IpAddr>,
        pub hog_giganto_port: Option<PortNumber>,
        pub protocols: bool,
        pub protocol_list: HashMap<String, bool>,

        pub sensors: bool,
        pub sensor_list: HashMap<String, bool>,

        pub creation_time: DateTime<Utc>,

        pub apply_target_id: Option<u32>,
        pub apply_in_progress: bool,
    }

    impl From<OldNode> for Node {
        fn from(input: OldNode) -> Self {
            Self {
                id: input.id,
                creation_time: input.creation_time,
                as_is: None,
                to_be: Some(NodeSetting {
                    name: input.name,
                    customer_id: input.customer_id,
                    description: input.description,
                    hostname: input.hostname,
                    review: input.review,
                    review_port: input.review_port,
                    review_web_port: input.review_web_port,
                    piglet: input.piglet,
                    piglet_giganto_ip: input.piglet_giganto_ip,
                    piglet_giganto_port: input.piglet_giganto_port,
                    piglet_review_ip: input.piglet_review_ip,
                    piglet_review_port: input.piglet_review_port,
                    save_packets: input.save_packets,
                    http: input.http,
                    office: input.office,
                    exe: input.exe,
                    pdf: input.pdf,
                    html: input.html,
                    txt: input.txt,
                    smtp_eml: input.smtp_eml,
                    ftp: input.ftp,
                    giganto: input.giganto,
                    giganto_ingestion_ip: input.giganto_ingestion_ip,
                    giganto_ingestion_port: input.giganto_ingestion_port,
                    giganto_publish_ip: input.giganto_publish_ip,
                    giganto_publish_port: input.giganto_publish_port,
                    giganto_graphql_ip: input.giganto_graphql_ip,
                    giganto_graphql_port: input.giganto_graphql_port,
                    retention_period: input.retention_period,
                    reconverge: input.reconverge,
                    reconverge_review_ip: input.reconverge_review_ip,
                    reconverge_review_port: input.reconverge_review_port,
                    reconverge_giganto_ip: input.reconverge_giganto_ip,
                    reconverge_giganto_port: input.reconverge_giganto_port,
                    hog: input.hog,
                    hog_review_ip: input.hog_review_ip,
                    hog_review_port: input.hog_review_port,
                    hog_giganto_ip: input.hog_giganto_ip,
                    hog_giganto_port: input.hog_giganto_port,
                    protocols: input.protocols,
                    protocol_list: input.protocol_list,
                    sensors: input.sensors,
                    sensor_list: input.sensor_list,
                }),
            }
        }
    }

    let node_db = store.node_map();
    for (_key, old_value) in node_db.iter_forward()? {
        let old_node = bincode::DefaultOptions::new()
            .deserialize::<OldNode>(&old_value)
            .context("Failed to migrate node database: invalid node value")?;
        let new_node: Node = old_node.into();
        node_db.overwrite(&new_node)?;
    }
    Ok(())
}

fn migrate_0_22_to_0_24(store: &super::Store) -> Result<()> {
    use crate::collections::Indexed;
    use crate::{Indexable, IterableMap};
    use bincode::Options;
    use chrono::{DateTime, Utc};
    use std::{borrow::Cow, collections::HashMap};

    type PortNumber = u16;

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Deserialize, Serialize)]
    pub struct NewNode {
        pub id: u32,
        pub name: String,
        pub customer_id: u32,
        pub description: String,
        pub hostname: String,

        pub review: bool,
        pub review_port: Option<PortNumber>,
        pub review_web_port: Option<PortNumber>,

        pub piglet: bool,
        pub piglet_giganto_ip: Option<IpAddr>,
        pub piglet_giganto_port: Option<PortNumber>,
        pub piglet_review_ip: Option<IpAddr>,
        pub piglet_review_port: Option<PortNumber>,
        pub save_packets: bool,
        pub http: bool,
        pub office: bool,
        pub exe: bool,
        pub pdf: bool,
        pub html: bool,
        pub txt: bool,
        pub smtp_eml: bool,
        pub ftp: bool,

        pub giganto: bool,
        pub giganto_ingestion_ip: Option<IpAddr>,
        pub giganto_ingestion_port: Option<PortNumber>,
        pub giganto_publish_ip: Option<IpAddr>,
        pub giganto_publish_port: Option<PortNumber>,
        pub giganto_graphql_ip: Option<IpAddr>,
        pub giganto_graphql_port: Option<PortNumber>,
        pub retention_period: Option<u16>,

        pub reconverge: bool,
        pub reconverge_review_ip: Option<IpAddr>,
        pub reconverge_review_port: Option<PortNumber>,
        pub reconverge_giganto_ip: Option<IpAddr>,
        pub reconverge_giganto_port: Option<PortNumber>,

        pub hog: bool,
        pub hog_review_ip: Option<IpAddr>,
        pub hog_review_port: Option<PortNumber>,
        pub hog_giganto_ip: Option<IpAddr>,
        pub hog_giganto_port: Option<PortNumber>,
        pub protocols: bool,
        pub protocol_list: HashMap<String, bool>,

        pub sensors: bool,
        pub sensor_list: HashMap<String, bool>,

        pub creation_time: DateTime<Utc>,

        pub apply_target_id: Option<u32>,
        pub apply_in_progress: bool,
    }

    impl Indexable for NewNode {
        fn key(&self) -> Cow<[u8]> {
            Cow::from(self.name.as_bytes())
        }
        fn index(&self) -> u32 {
            self.id
        }
        fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
            key
        }
        fn value(&self) -> Vec<u8> {
            bincode::DefaultOptions::new()
                .serialize(self)
                .expect("serializable")
        }

        fn set_index(&mut self, index: u32) {
            self.id = index;
        }
    }

    #[allow(clippy::struct_excessive_bools)]
    #[derive(Deserialize, Serialize)]
    struct OldNode {
        pub id: u32,
        pub name: String,
        pub customer_id: u32,
        pub description: String,
        pub hostname: String,
        pub review: bool,
        pub review_port: Option<PortNumber>,
        pub review_web_port: Option<PortNumber>,
        pub piglet: bool,
        pub piglet_giganto_ip: Option<IpAddr>,
        pub piglet_giganto_port: Option<PortNumber>,
        pub piglet_review_ip: Option<IpAddr>,
        pub piglet_review_port: Option<PortNumber>,
        pub save_packets: bool,
        pub http: bool,
        pub office: bool,
        pub exe: bool,
        pub pdf: bool,
        pub html: bool,
        pub txt: bool,
        pub smtp_eml: bool,
        pub ftp: bool,
        pub giganto: bool,
        pub giganto_ingestion_ip: Option<IpAddr>,
        pub giganto_ingestion_port: Option<PortNumber>,
        pub giganto_publish_ip: Option<IpAddr>,
        pub giganto_publish_port: Option<PortNumber>,
        pub giganto_graphql_ip: Option<IpAddr>,
        pub giganto_graphql_port: Option<PortNumber>,
        pub retention_period: Option<u16>,
        pub reconverge: bool,
        pub reconverge_review_ip: Option<IpAddr>,
        pub reconverge_review_port: Option<PortNumber>,
        pub reconverge_giganto_ip: Option<IpAddr>,
        pub reconverge_giganto_port: Option<PortNumber>,
        pub hog: bool,
        pub hog_review_ip: Option<IpAddr>,
        pub hog_review_port: Option<PortNumber>,
        pub hog_giganto_ip: Option<IpAddr>,
        pub hog_giganto_port: Option<PortNumber>,
        pub protocols: bool,
        pub protocol_list: HashMap<String, bool>,
        pub sensors: bool,
        pub sensor_list: HashMap<String, bool>,
        pub creation_time: DateTime<Utc>,
    }

    impl From<OldNode> for NewNode {
        fn from(input: OldNode) -> Self {
            Self {
                id: input.id,
                name: input.name,
                customer_id: input.customer_id,
                description: input.description,
                hostname: input.hostname,
                review: input.review,
                review_port: input.review_port,
                review_web_port: input.review_web_port,
                piglet: input.piglet,
                piglet_giganto_ip: None,
                piglet_giganto_port: None,
                piglet_review_ip: None,
                piglet_review_port: None,
                save_packets: false,
                http: false,
                office: false,
                exe: false,
                pdf: false,
                html: false,
                txt: false,
                smtp_eml: false,
                ftp: false,
                giganto: input.giganto,
                giganto_ingestion_ip: input.giganto_ingestion_ip,
                giganto_ingestion_port: input.giganto_ingestion_port,
                giganto_publish_ip: input.giganto_publish_ip,
                giganto_publish_port: input.giganto_publish_port,
                giganto_graphql_ip: input.giganto_graphql_ip,
                giganto_graphql_port: input.giganto_graphql_port,
                retention_period: None,
                reconverge: input.reconverge,
                reconverge_review_ip: None,
                reconverge_review_port: None,
                reconverge_giganto_ip: None,
                reconverge_giganto_port: None,
                hog: input.hog,
                hog_review_ip: None,
                hog_review_port: None,
                hog_giganto_ip: None,
                hog_giganto_port: None,
                protocols: false,
                protocol_list: HashMap::new(),
                sensors: false,
                sensor_list: HashMap::new(),
                creation_time: input.creation_time,
                apply_target_id: None,
                apply_in_progress: false,
            }
        }
    }

    let node_db = store.node_map();
    for (_key, old_value) in node_db.iter_forward()? {
        let old_node = bincode::DefaultOptions::new()
            .deserialize::<OldNode>(&old_value)
            .context("Failed to migrate node database: invalid node value")?;
        let new_node: NewNode = old_node.into();
        node_db.overwrite(&new_node)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::COMPATIBLE_VERSION_REQ;
    use crate::{tables::Value, IterableMap, Store};
    use semver::{Version, VersionReq};

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
    fn migrate_0_24_to_0_25_batch_info() {
        use crate::{types::ModelBatchInfo, BatchInfo};
        use bincode::Options;

        let settings = TestSchema::new();
        let map = settings.store.batch_info_map();
        let testers = vec![
            BatchInfo {
                model: 1,
                inner: ModelBatchInfo {
                    id: 123,
                    earliest: 0,
                    latest: 3,
                    size: 4321,
                    sources: vec!["tester".to_string()],
                },
            },
            BatchInfo {
                model: 100,
                inner: ModelBatchInfo {
                    id: 12300,
                    earliest: 0,
                    latest: 3,
                    size: 4321,
                    sources: vec!["tester".to_string()],
                },
            },
        ];

        for tester in &testers {
            let value = tester.value();

            let old_key = bincode::DefaultOptions::new()
                .serialize(&(tester.model, tester.inner.id))
                .unwrap();
            map.raw().insert(&old_key, &value).unwrap();
        }

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_batch_info_map(&settings.store).is_ok());

        let map = settings.store.batch_info_map();
        for tester in testers {
            assert_eq!(map.count(tester.model).unwrap(), 1);
            let res = map.get(tester.model, tester.inner.id).unwrap();
            assert_eq!(res, Some(tester));
        }
    }

    #[test]
    fn migrate_0_24_to_0_25_access_token() {
        use crate::tables::Iterable;
        use crate::AccessToken;
        use bincode::Options;
        use rocksdb::Direction;
        use std::collections::HashSet;

        let settings = TestSchema::new();
        let map = settings.store.access_token_map();

        let users = ["user1", "user2"];
        let tokens = ["token1", "token2"];

        for user in &users {
            let key = user.as_bytes();
            let tokens: HashSet<_> = tokens.iter().map(|v| v.to_string()).collect();
            let value = bincode::DefaultOptions::new().serialize(&tokens).unwrap();
            map.raw().insert(key, &value).unwrap();
        }

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_access_token_map(&settings.store).is_ok());

        let map = settings.store.access_token_map();
        let entries = users.iter().flat_map(|u| {
            tokens.iter().map(|t| AccessToken {
                username: (*u).into(),
                token: (*t).into(),
            })
        });

        for (record, entry) in map.iter(Direction::Forward, None).zip(entries) {
            assert_eq!(record.unwrap(), entry);
        }

        assert_eq!(2 * 2, map.raw().iter_forward().unwrap().count());
    }

    #[test]
    fn migrate_0_24_to_0_25_filter() {
        use crate::tables::Iterable;
        use crate::{FilterEndpoint, FlowKind, LearningMethod};
        use bincode::Options;
        use rocksdb::Direction;
        use serde::Serialize;
        use std::collections::HashMap;

        #[derive(Default, Serialize)]
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
            learning_methods: Option<Vec<LearningMethod>>,
            confidence: Option<f32>,
        }

        let settings = TestSchema::new();
        let map = settings.store.filter_map();

        let mut users = vec!["user2", "user1"];
        let mut filters = vec!["filter_b", "filter_a"];
        for user in &users {
            let value: HashMap<_, _> = filters
                .iter()
                .map(|f| {
                    let mut old = OldFilter::default();
                    old.name = f.to_string();
                    (f.to_string(), old)
                })
                .collect();
            let value = bincode::DefaultOptions::new().serialize(&value).unwrap();
            map.raw().put(user.as_bytes(), &value).unwrap();
        }

        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_filter_map(&settings.store).is_ok());

        let map = settings.store.filter_map();

        assert_eq!(4, map.iter(Direction::Forward, None).count());

        let res = map
            .iter(Direction::Forward, None)
            .filter_map(|f| f.ok().map(|v| (v.username, v.name)))
            .collect::<Vec<_>>();

        users.sort_unstable();
        filters.sort_unstable();
        let testers: Vec<_> = users
            .into_iter()
            .flat_map(|u| filters.iter().map(|f| (u.to_string(), f.to_string())))
            .collect();
        assert_eq!(res, testers);
    }

    #[test]
    fn migrate_0_24_to_0_25_node() {
        type PortNumber = u16;
        use crate::{collections::Indexed, Indexable};
        use bincode::Options;
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Serialize};
        use std::{
            collections::HashMap,
            net::{IpAddr, Ipv4Addr},
        };

        #[derive(Deserialize, Serialize, Clone)]
        struct OldNode {
            id: u32,
            name: String,
            customer_id: u32,
            description: String,
            hostname: String,
            review: bool,
            review_port: Option<PortNumber>,
            review_web_port: Option<PortNumber>,
            piglet: bool,
            piglet_giganto_ip: Option<IpAddr>,
            piglet_giganto_port: Option<PortNumber>,
            piglet_review_ip: Option<IpAddr>,
            piglet_review_port: Option<PortNumber>,
            save_packets: bool,
            http: bool,
            office: bool,
            exe: bool,
            pdf: bool,
            html: bool,
            txt: bool,
            smtp_eml: bool,
            ftp: bool,
            giganto: bool,
            giganto_ingestion_ip: Option<IpAddr>,
            giganto_ingestion_port: Option<PortNumber>,
            giganto_publish_ip: Option<IpAddr>,
            giganto_publish_port: Option<PortNumber>,
            giganto_graphql_ip: Option<IpAddr>,
            giganto_graphql_port: Option<PortNumber>,
            retention_period: Option<u16>,
            reconverge: bool,
            reconverge_review_ip: Option<IpAddr>,
            reconverge_review_port: Option<PortNumber>,
            reconverge_giganto_ip: Option<IpAddr>,
            reconverge_giganto_port: Option<PortNumber>,
            hog: bool,
            hog_review_ip: Option<IpAddr>,
            hog_review_port: Option<PortNumber>,
            hog_giganto_ip: Option<IpAddr>,
            hog_giganto_port: Option<PortNumber>,
            protocols: bool,
            protocol_list: HashMap<String, bool>,
            sensors: bool,
            sensor_list: HashMap<String, bool>,
            creation_time: DateTime<Utc>,
            apply_target_id: Option<u32>,
            apply_in_progress: bool,
        }

        impl Indexable for OldNode {
            fn key(&self) -> Cow<[u8]> {
                Cow::from(self.name.as_bytes())
            }
            fn index(&self) -> u32 {
                self.id
            }
            fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
                key
            }
            fn value(&self) -> Vec<u8> {
                bincode::DefaultOptions::new()
                    .serialize(self)
                    .expect("serializable")
            }

            fn set_index(&mut self, index: u32) {
                self.id = index;
            }
        }

        let settings = TestSchema::new();
        let node_db = settings.store.node_map();

        let old_node = OldNode {
            id: 0,
            name: "name".to_string(),
            customer_id: 20,
            description: "description".to_string(),
            hostname: "host".to_string(),
            review: true,
            review_port: Some(4040),
            review_web_port: Some(8442),
            piglet: true,
            piglet_giganto_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2))),
            piglet_giganto_port: Some(3030),
            piglet_review_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            piglet_review_port: Some(4040),
            save_packets: true,
            http: false,
            office: false,
            exe: false,
            pdf: false,
            html: false,
            txt: false,
            smtp_eml: false,
            ftp: false,
            giganto: true,
            giganto_ingestion_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            giganto_ingestion_port: Some(3030),
            giganto_publish_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            giganto_publish_port: Some(3050),
            giganto_graphql_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            giganto_graphql_port: Some(5050),
            retention_period: Some(100),
            reconverge: false,
            reconverge_review_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            reconverge_review_port: Some(4040),
            reconverge_giganto_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            reconverge_giganto_port: Some(3050),
            hog: true,
            hog_review_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            hog_review_port: Some(4040),
            hog_giganto_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            hog_giganto_port: Some(3050),
            protocols: false,
            protocol_list: HashMap::new(),
            sensors: false,
            sensor_list: HashMap::new(),
            creation_time: Utc::now(),
            apply_target_id: Some(0),
            apply_in_progress: false,
        };

        assert!(node_db.insert(old_node.clone()).is_ok());
        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_node(&settings.store).is_ok());
    }

    #[test]
    fn migrate_0_22_to_0_24() {
        type PortNumber = u16;
        use crate::{collections::Indexed, Indexable};
        use bincode::Options;
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Serialize};
        use std::{
            collections::HashMap,
            net::{IpAddr, Ipv4Addr},
        };

        #[derive(Deserialize, Serialize, Clone)]
        struct OldNode {
            id: u32,
            name: String,
            customer_id: u32,
            description: String,
            hostname: String,
            review: bool,
            review_port: Option<PortNumber>,
            review_web_port: Option<PortNumber>,
            piglet: bool,
            piglet_giganto_ip: Option<IpAddr>,
            piglet_giganto_port: Option<PortNumber>,
            piglet_review_ip: Option<IpAddr>,
            piglet_review_port: Option<PortNumber>,
            save_packets: bool,
            http: bool,
            office: bool,
            exe: bool,
            pdf: bool,
            html: bool,
            txt: bool,
            smtp_eml: bool,
            ftp: bool,
            giganto: bool,
            giganto_ingestion_ip: Option<IpAddr>,
            giganto_ingestion_port: Option<PortNumber>,
            giganto_publish_ip: Option<IpAddr>,
            giganto_publish_port: Option<PortNumber>,
            giganto_graphql_ip: Option<IpAddr>,
            giganto_graphql_port: Option<PortNumber>,
            retention_period: Option<u16>,
            reconverge: bool,
            reconverge_review_ip: Option<IpAddr>,
            reconverge_review_port: Option<PortNumber>,
            reconverge_giganto_ip: Option<IpAddr>,
            reconverge_giganto_port: Option<PortNumber>,
            hog: bool,
            hog_review_ip: Option<IpAddr>,
            hog_review_port: Option<PortNumber>,
            hog_giganto_ip: Option<IpAddr>,
            hog_giganto_port: Option<PortNumber>,
            protocols: bool,
            protocol_list: HashMap<String, bool>,
            sensors: bool,
            sensor_list: HashMap<String, bool>,
            creation_time: DateTime<Utc>,
        }

        impl Indexable for OldNode {
            fn key(&self) -> Cow<[u8]> {
                Cow::from(self.name.as_bytes())
            }
            fn index(&self) -> u32 {
                self.id
            }
            fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
                key
            }
            fn value(&self) -> Vec<u8> {
                bincode::DefaultOptions::new()
                    .serialize(self)
                    .expect("serializable")
            }

            fn set_index(&mut self, index: u32) {
                self.id = index;
            }
        }

        let settings = TestSchema::new();
        let node_db = settings.store.node_map();

        let old_node = OldNode {
            id: 0,
            name: "name".to_string(),
            customer_id: 20,
            description: "description".to_string(),
            hostname: "host".to_string(),
            review: true,
            review_port: Some(4040),
            review_web_port: Some(8442),
            piglet: true,
            piglet_giganto_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2))),
            piglet_giganto_port: Some(3030),
            piglet_review_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            piglet_review_port: Some(4040),
            save_packets: true,
            http: false,
            office: false,
            exe: false,
            pdf: false,
            html: false,
            txt: false,
            smtp_eml: false,
            ftp: false,
            giganto: true,
            giganto_ingestion_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            giganto_ingestion_port: Some(3030),
            giganto_publish_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            giganto_publish_port: Some(3050),
            giganto_graphql_ip: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            giganto_graphql_port: Some(5050),
            retention_period: Some(100),
            reconverge: false,
            reconverge_review_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            reconverge_review_port: Some(4040),
            reconverge_giganto_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            reconverge_giganto_port: Some(3050),
            hog: true,
            hog_review_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            hog_review_port: Some(4040),
            hog_giganto_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            hog_giganto_port: Some(3050),
            protocols: false,
            protocol_list: HashMap::new(),
            sensors: false,
            sensor_list: HashMap::new(),
            creation_time: Utc::now(),
        };

        assert!(node_db.insert(old_node.clone()).is_ok());
        let (db_dir, backup_dir) = settings.close();
        let settings = TestSchema::new_with_dir(db_dir, backup_dir);
        assert!(super::migrate_0_22_to_0_24(&settings.store).is_ok());
    }
}
