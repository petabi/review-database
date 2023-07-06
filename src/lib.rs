#[macro_use]
extern crate diesel;

mod account;
mod backends;
pub mod backup;
mod category;
mod cluster;
mod collections;
mod column_statistics;
mod csv_column_extra;
mod csv_indicator;
pub mod event;
mod migration;
mod model;
mod outlier;
mod qualifier;
mod schema;
mod status;
mod tables;
mod ti;
mod time_series;
mod top_n;
mod traffic_filter;
pub mod types;

pub use self::account::Role;
use self::backends::ConnectionPool;
pub use self::category::Category;
pub use self::cluster::*;
pub use self::collections::{
    Indexable, Indexed, IndexedMap, IndexedMapIterator, IndexedMapUpdate, IndexedMultimap,
    IndexedSet, IterableMap, Map, MapIterator,
};
pub use self::column_statistics::*;
pub use self::csv_column_extra::CsvColumnExtraConfig;
pub use self::event::EventKind;
pub use self::event::{
    find_ip_country, CryptocurrencyMiningPool, Direction, DnsCovertChannel,
    DomainGenerationAlgorithm, Event, EventDb, EventFilter, EventIterator, EventMessage,
    ExternalDdos, Filter, FilterEndpoint, FlowKind, FtpBruteForce, FtpPlainText, HttpThreat,
    LdapBruteForce, LdapPlainText, LearningMethod, MultiHostPortScan, Network, NetworkEntry,
    NetworkEntryValue, NetworkType, NonBrowser, PortScan, RdpBruteForce, RepeatedHttpSessions,
    TorConnection, TrafficDirection, TriageScore,
};
pub use self::migration::migrate_data_dir;
pub use self::model::Model;
pub use self::outlier::*;
pub use self::qualifier::Qualifier;
pub use self::status::Status;
use self::tables::StateDb;
pub use self::tables::Table;
pub use self::ti::{Tidb, TidbKind, TidbRule};
pub use self::time_series::*;
pub use self::time_series::{ColumnTimeSeries, TimeCount, TimeSeriesResult};
pub use self::top_n::*;
pub use self::top_n::{
    ClusterScore, ClusterScoreSet, ClusterTrend, ElementCount, LineSegment, Regression,
    StructuredColumnType, TopColumnsOfCluster, TopMultimaps, TopTrendsByColumn,
};
pub use self::traffic_filter::{ProtocolPorts, TrafficFilter};
pub use self::types::{
    AttrCmpKind, Confidence, Customer, CustomerNetwork, DataSource, DataType, EventCategory,
    HostNetworkGroup, ModelIndicator, PacketAttr, Response, ResponseKind, Ti, TiCmpKind,
    TriagePolicy, ValueKind,
};
use anyhow::{anyhow, Result};
use backends::Value;
use bb8_postgres::{
    bb8,
    tokio_postgres::{self, types::Type},
};
pub use rocksdb::backup::BackupEngineInfo;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Clone)]
pub struct Database {
    pool: ConnectionPool,
}

impl Database {
    /// Creates a new database connection pool.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection pool cannot be created.
    pub async fn new<P: AsRef<Path>>(url: &str, db_root_ca: &[P]) -> Result<Self, Error> {
        ConnectionPool::new(url, db_root_ca)
            .await
            .map(|pool| Self { pool })
    }
}

const DEFAULT_STATES: &str = "states.db";
const EXCLUSIVE: bool = true;

/// A key-value store.
pub struct Store {
    states: StateDb,
    pretrained: PathBuf,
}

impl Store {
    const DEFAULT_PRETRAINED: &str = "pretrained";
    /// Opens a new key-value store and its backup.
    ///
    /// # Errors
    ///
    /// Returns an error if the key-value store or its backup cannot be opened.
    pub fn new(path: &Path, backup: &Path) -> Result<Self, anyhow::Error> {
        let db_path = path.join(DEFAULT_STATES);
        let backup_path = backup.join(DEFAULT_STATES);
        let states = StateDb::open(&db_path, backup_path)?;
        let pretrained = path.join(Self::DEFAULT_PRETRAINED);
        if let Err(e) = std::fs::create_dir_all(&pretrained) {
            if e.kind() != io::ErrorKind::AlreadyExists {
                return Err(anyhow::anyhow!("{e}"));
            }
        }
        let store = Self { states, pretrained };
        Ok(store)
    }

    #[must_use]
    pub fn events(&self) -> EventDb {
        self.states.events()
    }

    #[must_use]
    pub fn access_token_map(&self) -> Map {
        self.states
            .map(tables::ACCESS_TOKENS)
            .expect("always available")
    }

    #[must_use]
    pub fn account_map(&self) -> Table<types::Account> {
        self.states.accounts()
    }

    #[must_use]
    pub fn account_policy_map(&self) -> Map {
        self.states
            .map(tables::ACCOUNT_POLICY)
            .expect("always available")
    }

    #[must_use]
    pub fn allow_network_map(&self) -> IndexedMap {
        self.states
            .indexed_map(tables::ALLOW_NETWORKS)
            .expect("always available")
    }

    #[must_use]
    pub fn block_network_map(&self) -> IndexedMap {
        self.states
            .indexed_map(tables::BLOCK_NETWORKS)
            .expect("always available")
    }

    #[must_use]
    pub fn customer_map(&self) -> IndexedMap {
        self.states
            .indexed_map(tables::CUSTOMERS)
            .expect("always available")
    }

    #[must_use]
    pub fn data_source_map(&self) -> IndexedMap {
        self.states
            .indexed_map(tables::DATA_SOURCES)
            .expect("always available")
    }

    #[must_use]
    pub fn event_tag_set(&self) -> IndexedSet {
        self.states
            .indexed_set(tables::EVENT_TAGS)
            .expect("always available")
    }

    #[must_use]
    pub fn filter_map(&self) -> Map {
        self.states.map(tables::FILTERS).expect("always available")
    }

    #[must_use]
    pub fn model_indicator_map(&self) -> Map {
        self.states
            .map(tables::MODEL_INDICATORS)
            .expect("always available")
    }

    #[must_use]
    pub fn network_map(&self) -> IndexedMultimap {
        self.states
            .indexed_multimap(tables::NETWORKS)
            .expect("always available")
    }

    #[must_use]
    pub fn network_tag_set(&self) -> IndexedSet {
        self.states
            .indexed_set(tables::NETWORK_TAGS)
            .expect("always available")
    }

    #[must_use]
    pub fn node_map(&self) -> IndexedMap {
        self.states
            .indexed_map(tables::NODES)
            .expect("always available")
    }

    #[must_use]
    pub fn outlier_map(&self) -> Map {
        self.states.map(tables::OUTLIERS).expect("always available")
    }

    #[must_use]
    pub fn sampling_policy_map(&self) -> IndexedMap {
        self.states
            .indexed_map(tables::SAMPLING_POLICY)
            .expect("always available")
    }

    #[must_use]
    pub fn template_map(&self) -> Map {
        self.states
            .map(tables::TEMPLATES)
            .expect("always available")
    }

    #[must_use]
    pub fn tidb_map(&self) -> Map {
        self.states.map(tables::TIDB).expect("always available")
    }

    #[must_use]
    pub fn tor_exit_node_map(&self) -> Map {
        self.states
            .map(tables::TOR_EXIT_NODES)
            .expect("always available")
    }

    #[must_use]
    pub fn triage_policy_map(&self) -> IndexedMap {
        self.states
            .indexed_map(tables::TRIAGE_POLICY)
            .expect("always available")
    }

    #[must_use]
    pub fn triage_response_map(&self) -> IndexedMap {
        self.states
            .indexed_map(tables::TRIAGE_RESPONSE)
            .expect("always available")
    }

    #[must_use]
    pub fn trusted_dns_server_map(&self) -> Map {
        self.states
            .map(tables::TRUSTED_DNS_SERVERS)
            .expect("always available")
    }

    #[must_use]
    pub fn trusted_user_agent_map(&self) -> Map {
        self.states
            .map(tables::TRUSTED_USER_AGENTS)
            .expect("always available")
    }

    #[must_use]
    pub fn traffic_filter_map(&self) -> Map {
        self.states
            .map(tables::TRAFFIC_FILTER_RULES)
            .expect("always available")
    }

    #[must_use]
    pub fn workflow_tag_set(&self) -> IndexedSet {
        self.states
            .indexed_set(tables::WORKFLOW_TAGS)
            .expect("always available")
    }

    /// Fetch the most recent pretrained model with `name`
    ///
    /// # Errors
    ///
    /// Returns an error when model cannot be located.
    pub fn pretrained_model(&self, name: &str) -> Result<types::PretrainedModel> {
        use std::io::Read;

        let (_ts, most_recent) = get_most_recent(name, &self.pretrained)?;
        let mut file = std::fs::File::open(most_recent)?;
        let mut buf = vec![];
        file.read_to_end(&mut buf)?;

        Ok(types::PretrainedModel(buf))
    }

    /// Backup current database and keep most recent `num_backups_to_keep` backups
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails.
    pub(crate) fn backup(&mut self, flush: bool, num_of_backups_to_keep: u32) -> Result<()> {
        self.states
            .create_new_backup_flush(flush, num_of_backups_to_keep)
    }

    /// Get the backup information for backups on file.
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails.
    pub fn get_backup_info(&self) -> Result<Vec<BackupEngineInfo>> {
        self.states.get_backup_info()
    }

    /// Restore from the backup with `backup_id` on file
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails or restoration fails.
    pub fn restore_from_backup(&mut self, backup_id: u32) -> Result<()> {
        self.states.restore_from_backup(backup_id)
    }

    /// Restore from the latest backup on file
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails or restoration fails.
    pub fn restore_from_latest_backup(&mut self) -> Result<()> {
        self.states.restore_from_latest_backup()
    }

    /// Recover from the latest valid backup on file
    ///
    /// # Errors
    ///
    /// Returns an error when all the available backups are not valid
    /// for restoration.
    pub fn recover(&mut self) -> Result<()> {
        self.states.recover()
    }

    /// Purge old backups and only keep `num_backups_to_keep` backups on file
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails.
    pub fn purge_old_backups(&mut self, num_backups_to_keep: u32) -> Result<()> {
        self.states.purge_old_backups(num_backups_to_keep)?;
        Ok(())
    }
}

fn parse_pretrained_file_name(name: &str) -> Result<(&str, crate::types::Timestamp)> {
    use crate::types::Timestamp;

    let (name, ts) = name
        .rsplit_once('-')
        .ok_or(anyhow!("Malformated file name"))?;
    let ts = ts.parse::<Timestamp>()?;

    Ok((name, ts))
}

const DEFAULT_PRETRAINED_EXTENSION: &str = "tmm";

fn get_most_recent<P: AsRef<Path>>(name: &str, dir: P) -> Result<(i64, PathBuf)> {
    use std::fs::read_dir;

    let mut most_recent = None;
    for entry in read_dir(&dir)? {
        let entry = entry?.path();
        if entry.is_dir() {
            continue;
        }
        match entry.extension().and_then(std::ffi::OsStr::to_str) {
            Some(ext) => {
                if ext != DEFAULT_PRETRAINED_EXTENSION {
                    continue;
                }
            }
            None => continue,
        }

        if let Some(file) = entry.file_stem().and_then(std::ffi::OsStr::to_str) {
            let (file, ts) = parse_pretrained_file_name(file)?;
            if file != name {
                continue;
            }

            if let Some((cur_ts, _)) = &most_recent {
                if ts > *cur_ts {
                    most_recent = Some((ts, entry));
                }
            } else {
                most_recent = Some((ts, entry));
            }
        }
    }
    most_recent.ok_or(anyhow!(
        "Fail to locate {name:?} under {}",
        dir.as_ref().display()
    ))
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("diesel connection error: {0}")]
    Connection(#[from] diesel::ConnectionError),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("migration error: {0}")]
    Migration(Box<dyn std::error::Error + Send + Sync>),
    #[error("query error: {0}")]
    Query(#[from] diesel::result::Error),
    #[error("connection error: {0}")]
    PgConnection(#[from] bb8::RunError<tokio_postgres::Error>),
    #[error("PostgreSQL error: {0}")]
    Postgres(#[from] tokio_postgres::Error),
    #[error("JSON deserialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Certificate error: {0}")]
    Tls(String),
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    fn pseudo_pretrained() -> anyhow::Result<(TempDir, Vec<(&'static str, bool)>, Vec<i64>)> {
        let dir = tempfile::tempdir().unwrap();
        let names = vec![("test-model", true), ("test_model01", false)];
        let timestamps = vec![1, 2, 34567, 034568];

        for (name, with_ext) in &names {
            for ts in &timestamps {
                let file_name = if *with_ext {
                    format!("{name}-{ts}.{}", super::DEFAULT_PRETRAINED_EXTENSION)
                } else {
                    format!("{name}-{ts}")
                };
                let file_path = dir.path().join(&file_name);
                std::fs::File::create(file_path)?;
            }
        }
        Ok((dir, names, timestamps))
    }

    #[test]
    fn get_most_recent() {
        let (dir, names, timestamps) = pseudo_pretrained().expect("fail to set up temp dir");
        let most_recent = timestamps.iter().fold(0, |t, cur| std::cmp::max(t, *cur));
        for (name, with_ext) in names {
            if with_ext {
                let (ts, p) = super::get_most_recent(name, dir.path()).unwrap();
                assert_eq!(ts, most_recent);
                let cur = p.file_name().and_then(std::ffi::OsStr::to_str).unwrap();
                assert_eq!(
                    cur,
                    format!("{name}-{ts}.{}", super::DEFAULT_PRETRAINED_EXTENSION)
                );
            } else {
                assert!(super::get_most_recent(name, dir.path()).is_err());
            }
        }
    }
}
