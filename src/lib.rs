#[macro_use]
extern crate diesel;

mod account;
mod backends;
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
    find_ip_country, Direction, DnsCovertChannel, DomainGenerationAlgorithm, Event, EventDb,
    EventFilter, EventIterator, EventMessage, Filter, FilterEndpoint, FlowKind, HttpThreat,
    LearningMethod, Network, NetworkEntry, NetworkEntryValue, NetworkType, RdpBruteForce,
    RepeatedHttpSessions, TorConnection, TrafficDirection, TriageScore,
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
pub use self::traffic_filter::TrafficFilter;
pub use self::types::{
    AttrCmpKind, Confidence, Customer, CustomerNetwork, DataSource, DataType, EventCategory,
    HostNetworkGroup, ModelIndicator, PacketAttr, Response, ResponseKind, Ti, TiCmpKind,
    TriagePolicy, ValueKind,
};
use anyhow::Result;
use backends::Value;
use bb8_postgres::{
    bb8,
    tokio_postgres::{self, types::Type},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::sync::Notify;

#[derive(Clone)]
pub struct Database {
    pool: ConnectionPool,
}

impl Database {
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
    backup: PathBuf,
}

impl Store {
    pub fn new(path: &Path, backup: &Path) -> Result<Self, anyhow::Error> {
        let db_path = path.join(DEFAULT_STATES);
        let states = StateDb::open(&db_path)?;

        let store = Self {
            states,
            backup: backup.to_path_buf(),
        };
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

    /// Backup current database and keep most recent `num_backups_to_keep` backups
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails.
    pub fn backup(&self, num_of_backups_to_keep: u32) -> Result<()> {
        self.states.create_new_backup_flush(
            &self.backup.join(DEFAULT_STATES),
            false,
            num_of_backups_to_keep,
        )?;
        Ok(())
    }

    /// Restore from the latest backup on file
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails or restoration fails.
    pub fn restore_from_latest_backup(&self) -> Result<()> {
        self.states
            .restore_from_latest_backup(&self.backup.join(DEFAULT_STATES))?;
        Ok(())
    }

    /// Purge old backups and only keep `num_backups_to_keep` backups on file
    ///
    /// # Errors
    ///
    /// Returns an error when backup engine fails.
    pub fn purge_old_backups(&self, num_backups_to_keep: u32) -> Result<()> {
        StateDb::purge_old_backups(&self.backup.join(DEFAULT_STATES), num_backups_to_keep)?;
        Ok(())
    }
}

/// Schedule and execute database backup.
///
/// # Errors
///
/// Returns an error if backup fails.
pub async fn backup(
    store: Arc<Store>,
    schedule: (Duration, Duration),
    backups_to_keep: u32,
    stop: Arc<Notify>,
) -> Result<()> {
    use tokio::time::{sleep, Instant};
    use tracing::{info, warn};

    let (init, duration) = schedule;
    let sleep = sleep(init);
    tokio::pin!(sleep);

    loop {
        tokio::select! {
            () = &mut sleep => {
                sleep.as_mut().reset(Instant::now() + duration);
                let res = store.backup(backups_to_keep);
                if res.is_err() {
                    warn!("scheduled backup failed. {:?}", res);
                } else {
                    info!("database backup is created.");
                }

            }
            _ = stop.notified() => {
                let res = store.backup(backups_to_keep);
                if res.is_err() {
                    warn!("backup before exit failed. {:?}", res);
                } else {
                    info!("database backup is created before exit");
                }
                stop.notify_one();
                return Ok(());
            }

        }
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderDirection {
    /// Specifies an ascending order for a given orderBy argument.
    Asc,
    /// Specifies a descending order for a given orderBy argument.
    Desc,
}
