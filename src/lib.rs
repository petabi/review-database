#[macro_use]
extern crate diesel;

pub(crate) mod backends;
mod category;
mod cluster;
mod collections;
mod column_statistics;
mod csv_column_extra;
mod csv_indicator;
pub mod event;
mod model;
mod outlier;
mod qualifier;
mod schema;
mod state;
mod status;
mod ti;
mod time_series;
mod top_n;
mod traffic_filter;
pub mod types;

use self::backends::ConnectionPool;
pub use self::category::Category;
pub use self::cluster::*;
pub use self::collections::{
    Indexable, Indexed, IndexedMap, IndexedMapIterator, IndexedMapUpdate, IndexedMultimap,
    IndexedSet, IterableMap, Map, MapIterator,
};
pub use self::column_statistics::round::{RoundByCluster, RoundByModel};
pub use self::column_statistics::*;
pub use self::csv_column_extra::CsvColumnExtraConfig;
pub use self::event::EventKind;
pub use self::event::{
    find_ip_country, Direction, DnsCovertChannel, DomainGenerationAlgorithm, Event, EventDb,
    EventFilter, EventIterator, EventMessage, Filter, FilterEndpoint, FlowKind, HttpThreat,
    Network, NetworkEntry, NetworkEntryValue, NetworkType, RdpBruteForce, RepeatedHttpSessions,
    TorConnection, TrafficDirection, TriageScore,
};
pub use self::model::Model;
pub use self::outlier::*;
pub use self::qualifier::Qualifier;
pub use self::state::StateDb;
pub use self::status::Status;
pub use self::ti::{Tidb, TidbKind, TidbRule};
pub use self::time_series::*;
pub use self::time_series::{ColumnTimeSeries, TimeCount, TimeSeriesResult};
pub use self::top_n::*;
pub use self::top_n::{
    ClusterScore, ClusterScoreSet, ClusterTrend, ElementCount, LineSegment, Regression,
    StructuredColumnType, TopColumnsOfCluster, TopMultimaps, TopTrendsByColumn,
};
pub use self::traffic_filter::TrafficFilter;
use self::types::SaltedPassword;
pub use self::types::{
    AttrCmpKind, Confidence, Customer, CustomerNetwork, DataSource, DataType, EventCategory,
    HostNetworkGroup, ModelIndicator, PacketAttr, Response, ResponseKind, Role, Ti, TiCmpKind,
    TriagePolicy, ValueKind,
};
use anyhow::{anyhow, Context, Result};
use backends::Value;
use bb8_postgres::{
    bb8,
    tokio_postgres::{self, types::Type},
};
use bincode::Options;
use chrono::{DateTime, NaiveDateTime, Utc};
use diesel::{
    r2d2::{ConnectionManager, Pool, PooledConnection},
    PgConnection,
};
use std::fs::create_dir_all;
use std::net::IpAddr;
use std::{
    any::Any,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::sync::Notify;

type BlockingPgConn = PooledConnection<ConnectionManager<PgConnection>>;
pub(crate) type BlockingPgPool = r2d2::Pool<ConnectionManager<PgConnection>>;

/// Migrates the data directory to the up-to-date format if necessary.
///
/// # Errors
///
/// Returns an error if the data directory doesn't exist and cannot be created,
/// or if the data directory exists but is in the format too old to be upgraded.
pub fn migrate_data_dir(data_dir: &Path) -> Result<()> {
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

    let mut ver = String::new();
    File::open(&version_path)
        .context("cannot open VERSION")?
        .read_to_string(&mut ver)
        .context("cannot read VERSION")?;
    match ver.trim() {
        env!("CARGO_PKG_VERSION") => Ok(()),

        // backward-compatible versions
        // "0.17.0.alpha.2" => {
        //     create_version_file(&version_path).context("failed to update VERSION")?;
        //     Ok(())
        // }
        _ => Err(anyhow!("incompatible version")),
    }
}

fn create_version_file(path: &Path) -> Result<()> {
    let mut f = File::create(path).context("cannot create VERSION")?;
    f.write_all(env!("CARGO_PKG_VERSION").as_bytes())
        .context("cannot write VERSION")?;
    Ok(())
}

pub fn create_blocking_pool(database_url: &str) -> Result<BlockingPgPool, Error> {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    Ok(Pool::new(manager)?)
}

pub trait BlockingConnection {
    fn get_column_statistics(
        &mut self,
        _cluster: i32,
        _time: Option<NaiveDateTime>,
        _first_event_id: Option<i64>,
        _last_event_id: Option<i64>,
    ) -> Result<Vec<Statistics>, Error> {
        unimplemented!()
    }

    fn get_time_range_of_model(
        &mut self,
        _model_id: i32,
    ) -> Result<(Option<NaiveDateTime>, Option<NaiveDateTime>), Error> {
        unimplemented!()
    }

    fn get_top_time_series_of_cluster(
        &mut self,
        _model_id: i32,
        _cluster_id: &str,
        _start: Option<i64>,
        _end: Option<i64>,
    ) -> Result<TimeSeriesResult, Error> {
        unimplemented!()
    }

    #[allow(clippy::too_many_arguments)]
    fn get_top_time_series_of_model(
        &mut self,
        _model_id: i32,
        _time: Option<NaiveDateTime>,
        _start: Option<i64>,
        _end: Option<i64>,
    ) -> Result<Vec<TopTrendsByColumn>, Error> {
        unimplemented!()
    }

    fn get_top_clusters_by_score(
        &mut self,
        _model_id: i32,
        _size: usize,
        _time: Option<NaiveDateTime>,
        _types: Vec<StructuredColumnType>,
    ) -> Result<ClusterScoreSet, Error> {
        unimplemented!()
    }

    fn get_top_columns_of_model(
        &mut self,
        _model_id: i32,
        _size: usize,
        _time: Option<NaiveDateTime>,
        _portion_of_clusters: Option<f64>,
        _portion_of_top_n: Option<f64>,
        _types: Vec<StructuredColumnType>,
    ) -> Result<Vec<TopElementCountsByColumn>, Error> {
        unimplemented!()
    }

    fn get_top_ip_addresses_of_cluster(
        &mut self,
        _model_id: i32,
        _cluster_id: &str,
        _size: usize,
    ) -> Result<Vec<TopElementCountsByColumn>, Error> {
        unimplemented!()
    }

    fn get_top_ip_addresses_of_model(
        &mut self,
        _model_id: i32,
        _size: usize,
        _time: Option<NaiveDateTime>,
        _portion_of_clusters: Option<f64>,
        _portion_of_top_n: Option<f64>,
    ) -> Result<Vec<TopElementCountsByColumn>, Error> {
        unimplemented!()
    }

    fn get_top_multimaps_of_model(
        &mut self,
        _model_id: i32,
        _size: usize,
        _min_map_size: usize,
        _time: Option<NaiveDateTime>,
        _types: Vec<StructuredColumnType>,
    ) -> Result<Vec<TopMultimaps>, Error> {
        unimplemented!()
    }
}

pub trait BlockingConnectionPool: Send + Sync + 'static {
    fn as_any(&self) -> &dyn Any;
    fn get(&self) -> Result<Box<dyn BlockingConnection>, Error>;
}

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
const INITIAL_ADMINISTRATOR_ID: &str = "admin";
const INITIAL_ADMINISTRATOR_PASSWORD: &str = "admin";

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

        let account_map = store.account_map();
        if account_map
            .iter_forward()
            .context("cannot read from database")?
            .next()
            .is_none()
        {
            let (key, value) = initial_account()?;
            account_map.put(&key, &value)?;
        }
        Ok(store)
    }

    #[must_use]
    pub fn events(&self) -> EventDb {
        self.states.events()
    }

    #[must_use]
    pub fn access_token_map(&self) -> Map {
        self.states
            .map(state::ACCESS_TOKENS)
            .expect("always available")
    }

    #[must_use]
    pub fn account_map(&self) -> Map {
        self.states.map(state::ACCOUNTS).expect("always available")
    }

    #[must_use]
    pub fn account_policy_map(&self) -> Map {
        self.states
            .map(state::ACCOUNT_POLICY)
            .expect("always available")
    }

    #[must_use]
    pub fn allow_network_map(&self) -> IndexedMap {
        self.states
            .indexed_map(state::ALLOW_NETWORKS)
            .expect("always available")
    }

    #[must_use]
    pub fn block_network_map(&self) -> IndexedMap {
        self.states
            .indexed_map(state::BLOCK_NETWORKS)
            .expect("always available")
    }

    #[must_use]
    pub fn customer_map(&self) -> IndexedMap {
        self.states
            .indexed_map(state::CUSTOMERS)
            .expect("always available")
    }

    #[must_use]
    pub fn data_source_map(&self) -> IndexedMap {
        self.states
            .indexed_map(state::DATA_SOURCES)
            .expect("always available")
    }

    #[must_use]
    pub fn event_tag_set(&self) -> IndexedSet {
        self.states
            .indexed_set(state::EVENT_TAGS)
            .expect("always available")
    }

    #[must_use]
    pub fn filter_map(&self) -> Map {
        self.states.map(state::FILTERS).expect("always available")
    }

    #[must_use]
    pub fn model_indicator_map(&self) -> Map {
        self.states
            .map(state::MODEL_INDICATORS)
            .expect("always available")
    }

    #[must_use]
    pub fn network_map(&self) -> IndexedMultimap {
        self.states
            .indexed_multimap(state::NETWORKS)
            .expect("always available")
    }

    #[must_use]
    pub fn network_tag_set(&self) -> IndexedSet {
        self.states
            .indexed_set(state::NETWORK_TAGS)
            .expect("always available")
    }

    #[must_use]
    pub fn node_map(&self) -> IndexedMap {
        self.states
            .indexed_map(state::NODES)
            .expect("always available")
    }

    #[must_use]
    pub fn sampling_policy_map(&self) -> IndexedMap {
        self.states
            .indexed_map(state::SAMPLING_POLICY)
            .expect("always available")
    }

    #[must_use]
    pub fn template_map(&self) -> Map {
        self.states.map(state::TEMPLATES).expect("always available")
    }

    #[must_use]
    pub fn tidb_map(&self) -> Map {
        self.states.map(state::TIDB).expect("always available")
    }

    #[must_use]
    pub fn tor_exit_node_map(&self) -> Map {
        self.states
            .map(state::TOR_EXIT_NODES)
            .expect("always available")
    }

    #[must_use]
    pub fn triage_policy_map(&self) -> IndexedMap {
        self.states
            .indexed_map(state::TRIAGE_POLICY)
            .expect("always available")
    }

    #[must_use]
    pub fn triage_response_map(&self) -> IndexedMap {
        self.states
            .indexed_map(state::TRIAGE_RESPONSE)
            .expect("always available")
    }

    #[must_use]
    pub fn trusted_dns_server_map(&self) -> Map {
        self.states
            .map(state::TRUSTED_DNS_SERVERS)
            .expect("always available")
    }

    #[must_use]
    pub fn traffic_filter_map(&self) -> Map {
        self.states
            .map(state::TRAFFIC_FILTER_RULES)
            .expect("always available")
    }

    #[must_use]
    pub fn workflow_tag_set(&self) -> IndexedSet {
        self.states
            .indexed_set(state::WORKFLOW_TAGS)
            .expect("always available")
    }

    pub fn backup(&self, num_of_backups_to_keep: u32) -> Result<()> {
        self.states.create_new_backup_flush(
            &self.backup.join(DEFAULT_STATES),
            false,
            num_of_backups_to_keep,
        )?;
        Ok(())
    }

    pub fn restore_from_latest_backup(&self) -> Result<()> {
        self.states
            .restore_from_latest_backup(&self.backup.join(DEFAULT_STATES))?;
        Ok(())
    }
}

pub fn initial_account() -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let salted_password = SaltedPassword::new(INITIAL_ADMINISTRATOR_PASSWORD)?;
    let value = bincode::DefaultOptions::new().serialize(&(
        INITIAL_ADMINISTRATOR_ID,
        salted_password,
        Role::SystemAdministrator,
        "System Administrator",
        "",
        Utc::now(),
        None as Option<DateTime<Utc>>,
        None as Option<Vec<IpAddr>>,
        None as Option<u32>,
    ))?;
    Ok((INITIAL_ADMINISTRATOR_ID.as_bytes().to_vec(), value))
}

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
    Migration(#[from] Box<refinery::Error>),
    #[error("query error: {0}")]
    Query(#[from] diesel::result::Error),
    #[error("connection error: {0}")]
    R2D2(#[from] r2d2::Error),
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
