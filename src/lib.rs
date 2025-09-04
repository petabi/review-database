#[macro_use]
extern crate diesel;

mod account;
mod backends;
pub mod backup;
mod batch_info;
mod category;
mod classifier_fs;
mod cluster;
mod collections;
mod column_statistics;
pub mod event;
mod migration;
mod model;
mod schema;
mod scores;
mod tables;
mod tags;
#[cfg(test)]
mod test;
mod top_n;
pub mod types;
mod util;

use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
pub use attrievent::attribute::RawEventKind;
use bb8_postgres::{bb8, tokio_postgres};
pub use rocksdb::backup::BackupEngineInfo;
pub use tags::TagSet;
use tags::{EventTagId, NetworkTagId, WorkflowTagId};
use thiserror::Error;

pub use self::account::Role;
use self::backends::ConnectionPool;
pub use self::batch_info::BatchInfo;
pub use self::category::Category;
pub use self::cluster::*;
pub use self::collections::Indexable;
pub(crate) use self::collections::{IndexedMap, IndexedMapUpdate, IterableMap, Map};
pub use self::column_statistics::*;
pub use self::event::{Event, EventDb, EventKind, EventMessage};
pub use self::migration::{migrate_backend, migrate_data_dir};
pub use self::model::{Digest as ModelDigest, Model};
pub use self::scores::Scores;
use self::tables::StateDb;
pub use self::tables::{
    AccessToken, AccountPolicy, Agent, AgentConfig, AgentKind, AgentStatus, AllowNetwork,
    AllowNetworkUpdate, AttrCmpKind, BlockNetwork, BlockNetworkUpdate, ClusterTimeSeries,
    ColumnStats, ColumnTimeSeries, Confidence, CsvColumnExtra as CsvColumnExtraConfig, Customer,
    CustomerNetwork, CustomerUpdate, DataSource, DataSourceUpdate, DataType, ExternalService,
    ExternalServiceConfig, ExternalServiceKind, ExternalServiceStatus, Filter, IndexedTable,
    Iterable, ModelIndicator, Network, NetworkUpdate, Node, NodeProfile, NodeTable, NodeUpdate,
    OutlierInfo, OutlierInfoKey, OutlierInfoValue, PacketAttr, PeriodForSearch, ProtocolPorts,
    Response, ResponseKind, SamplingInterval, SamplingKind, SamplingPeriod, SamplingPolicy,
    SamplingPolicyUpdate, Structured, StructuredClusteringAlgorithm, Table, Template, Ti,
    TiCmpKind, Tidb, TidbKind, TidbRule, TidbRuleKind, TimeSeries, TorExitNode, TrafficFilter,
    TriagePolicy, TriagePolicyUpdate, TriageResponse, TriageResponseUpdate, TrustedDomain,
    TrustedUserAgent, UniqueKey, Unstructured, UnstructuredClusteringAlgorithm, ValueKind,
};
pub use self::top_n::*;
#[allow(deprecated)]
pub use self::top_n::{
    ClusterTrend, ElementCount, LineSegment, Regression, StructuredColumnType, TopColumnsOfCluster,
    TopMultimaps, TopTrendsByColumn,
};
pub use self::types::{EventCategory, HostNetworkGroup, Qualifier, Status};
pub use self::util::find_ip_country;

#[derive(Clone)]
pub struct Database {
    pool: ConnectionPool,
    classifier_fm: classifier_fs::ClassifierFileManager,
}

impl Database {
    /// Creates a new database connection pool.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection pool cannot be created.
    pub async fn new<P: AsRef<Path>>(
        url: &str,
        db_root_ca: &[P],
        data_dir: P,
    ) -> Result<Self, Error> {
        let pool = ConnectionPool::new(url, db_root_ca).await?;
        let classifier_fm = classifier_fs::ClassifierFileManager::new(data_dir)?;
        Ok(Self {
            pool,
            classifier_fm,
        })
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
    const DEFAULT_PRETRAINED: &'static str = "pretrained";
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
        if let Err(e) = std::fs::create_dir_all(&pretrained)
            && e.kind() != io::ErrorKind::AlreadyExists
        {
            return Err(anyhow::anyhow!("{e}"));
        }
        let store = Self { states, pretrained };
        Ok(store)
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn events(&self) -> EventDb<'_> {
        self.states.events()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn access_token_map(&self) -> Table<'_, AccessToken> {
        self.states.access_tokens()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn account_map(&self) -> Table<'_, types::Account> {
        self.states.accounts()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn account_policy_map(&self) -> Table<'_, AccountPolicy> {
        self.states.account_policy()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn agents_map(&self) -> Table<'_, Agent> {
        self.states.agents()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn allow_network_map(&self) -> IndexedTable<'_, AllowNetwork> {
        self.states.allow_networks()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn batch_info_map(&self) -> Table<'_, batch_info::BatchInfo> {
        self.states.batch_info()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn block_network_map(&self) -> IndexedTable<'_, BlockNetwork> {
        self.states.block_networks()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn category_map(&self) -> IndexedTable<'_, category::Category> {
        self.states.categories()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn column_stats_map(&self) -> Table<'_, ColumnStats> {
        self.states.column_stats()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn csv_column_extra_map(&self) -> IndexedTable<'_, CsvColumnExtraConfig> {
        self.states.csv_column_extras()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn customer_map(&self) -> IndexedTable<'_, Customer> {
        self.states.customers()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn data_source_map(&self) -> IndexedTable<'_, DataSource> {
        self.states.data_sources()
    }

    /// Returns the tag set for event.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails or the data is invalid.
    #[allow(clippy::missing_panics_doc)]
    pub fn event_tag_set(&self) -> Result<TagSet<'_, EventTagId>> {
        let set = self
            .states
            .indexed_set(tables::EVENT_TAGS)
            .expect("always available");
        TagSet::new(set)
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn filter_map(&self) -> Table<'_, Filter> {
        self.states.filters()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn model_indicator_map(&self) -> Table<'_, ModelIndicator> {
        self.states.model_indicators()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn network_map(&self) -> IndexedTable<'_, Network> {
        self.states.networks()
    }

    /// Returns the tag set for network.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails or the data is invalid.
    #[allow(clippy::missing_panics_doc)]
    pub fn network_tag_set(&self) -> Result<TagSet<'_, NetworkTagId>> {
        let set = self
            .states
            .indexed_set(tables::NETWORK_TAGS)
            .expect("always available");
        TagSet::new(set)
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn node_map(&self) -> NodeTable<'_> {
        self.states.nodes()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn outlier_map(&self) -> Table<'_, OutlierInfo> {
        self.states.outlier_infos()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn external_service_map(&self) -> Table<'_, ExternalService> {
        self.states.external_service()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn sampling_policy_map(&self) -> IndexedTable<'_, SamplingPolicy> {
        self.states.sampling_policies()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn qualifier_map(&self) -> IndexedTable<'_, types::Qualifier> {
        self.states.qualifiers()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn scores_map(&self) -> Table<'_, scores::Scores> {
        self.states.scores()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn status_map(&self) -> IndexedTable<'_, types::Status> {
        self.states.statuses()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn template_map(&self) -> Table<'_, Template> {
        self.states.templates()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn tidb_map(&self) -> Table<'_, Tidb> {
        self.states.tidbs()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn time_series_map(&self) -> Table<'_, TimeSeries> {
        self.states.time_series()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn tor_exit_node_map(&self) -> Table<'_, TorExitNode> {
        self.states.tor_exit_nodes()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn triage_policy_map(&self) -> IndexedTable<'_, TriagePolicy> {
        self.states.triage_policies()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn triage_response_map(&self) -> IndexedTable<'_, TriageResponse> {
        self.states.triage_responses()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn trusted_domain_map(&self) -> Table<'_, TrustedDomain> {
        self.states.trusted_domains()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn trusted_user_agent_map(&self) -> Table<'_, TrustedUserAgent> {
        self.states.trusted_user_agents()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn traffic_filter_map(&self) -> Table<'_, TrafficFilter> {
        self.states.traffic_filters()
    }

    /// Returns the tag set for workflow.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails or the data is invalid.
    #[allow(clippy::missing_panics_doc)]
    pub fn workflow_tag_set(&self) -> Result<TagSet<'_, WorkflowTagId>> {
        let set = self
            .states
            .indexed_set(tables::WORKFLOW_TAGS)
            .expect("always available");
        TagSet::new(set)
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
    #[error("ClassifierFileManager error: {0}")]
    Classifier(#[from] classifier_fs::ClassifierFsError),
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    fn pseudo_pretrained() -> (TempDir, Vec<(&'static str, bool)>, Vec<i64>) {
        let dir = tempfile::tempdir().unwrap();
        let names = vec![("test-model", true), ("test_model01", false)];
        let timestamps = vec![1, 2, 34567, 34568];

        for (name, with_ext) in &names {
            for ts in &timestamps {
                let file_name = if *with_ext {
                    format!("{name}-{ts}.{}", super::DEFAULT_PRETRAINED_EXTENSION)
                } else {
                    format!("{name}-{ts}")
                };
                let file_path = dir.path().join(&file_name);
                std::fs::File::create(file_path).unwrap();
            }
        }
        (dir, names, timestamps)
    }

    #[test]
    fn get_most_recent() {
        let (dir, names, timestamps) = pseudo_pretrained();
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
