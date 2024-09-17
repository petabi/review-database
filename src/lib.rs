#[macro_use]
extern crate diesel;

mod account;
mod backends;
pub mod backup;
mod batch_info;
mod category;
mod cluster;
mod collections;
mod column_statistics;
mod csv_indicator;
mod data;
pub mod event;
mod migration;
mod model;
mod schema;
mod scores;
mod tables;
mod tags;
#[cfg(test)]
mod test;
mod time_series;
mod top_n;
pub mod types;

use std::io;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use backends::Value;
use bb8_postgres::{
    bb8,
    tokio_postgres::{self, types::Type},
};
pub use rocksdb::backup::BackupEngineInfo;
pub use tags::TagSet;
use tags::{EventTagId, NetworkTagId, WorkflowTagId};
use thiserror::Error;

pub use self::account::Role;
use self::backends::ConnectionPool;
pub use self::batch_info::BatchInfo;
pub use self::category::Category;
pub use self::cluster::*;
pub use self::collections::{Indexable, Indexed};
pub(crate) use self::collections::{IndexedMap, IndexedMapUpdate, IterableMap, Map};
pub use self::column_statistics::*;
pub use self::event::EventKind;
pub use self::event::{
    find_ip_country, BlockListBootp, BlockListBootpFields, BlockListConn, BlockListConnFields,
    BlockListDceRpc, BlockListDceRpcFields, BlockListDhcp, BlockListDhcpFields, BlockListDns,
    BlockListDnsFields, BlockListFtp, BlockListHttp, BlockListHttpFields, BlockListKerberos,
    BlockListKerberosFields, BlockListLdap, BlockListMqtt, BlockListMqttFields, BlockListNfs,
    BlockListNfsFields, BlockListNtlm, BlockListNtlmFields, BlockListRdp, BlockListRdpFields,
    BlockListSmb, BlockListSmbFields, BlockListSmtp, BlockListSmtpFields, BlockListSsh,
    BlockListSshFields, BlockListTls, BlockListTlsFields, CryptocurrencyMiningPool,
    CryptocurrencyMiningPoolFields, DgaFields, Direction, DnsCovertChannel, DnsEventFields,
    DomainGenerationAlgorithm, Event, EventDb, EventFilter, EventIterator, EventMessage,
    ExternalDdos, ExternalDdosFields, ExtraThreat, FilterEndpoint, FlowKind, FtpBruteForce,
    FtpBruteForceFields, FtpEventFields, FtpPlainText, HttpEventFields, HttpThreat,
    HttpThreatFields, LdapBruteForce, LdapBruteForceFields, LdapEventFields, LdapPlainText,
    LearningMethod, LockyRansomware, MultiHostPortScan, MultiHostPortScanFields, NetworkThreat,
    NetworkType, NonBrowser, PortScan, PortScanFields, RdpBruteForce, RdpBruteForceFields,
    RecordType, RepeatedHttpSessions, RepeatedHttpSessionsFields, SuspiciousTlsTraffic,
    TorConnection, TrafficDirection, TriageScore, WindowsThreat,
};
pub use self::migration::{migrate_backend, migrate_data_dir};
pub use self::model::{Digest as ModelDigest, Model};
use self::tables::StateDb;
pub use self::tables::{
    AccessToken, AccountPolicy, Agent, AgentConfig, AgentKind, AgentStatus, AllowNetwork,
    AllowNetworkUpdate, AttrCmpKind, BlockNetwork, BlockNetworkUpdate, Confidence,
    CsvColumnExtra as CsvColumnExtraConfig, Customer, CustomerNetwork, CustomerUpdate, DataSource,
    DataSourceUpdate, DataType, Filter, Giganto, IndexedTable, Iterable, ModelIndicator, Network,
    NetworkUpdate, Node, NodeProfile, NodeTable, NodeUpdate, OutlierInfo, OutlierInfoKey,
    OutlierInfoValue, PacketAttr, ProtocolPorts, Response, ResponseKind, SamplingInterval,
    SamplingKind, SamplingPeriod, SamplingPolicy, SamplingPolicyUpdate, Structured,
    StructuredClusteringAlgorithm, Table, Template, Ti, TiCmpKind, Tidb, TidbKind, TidbRule,
    TorExitNode, TrafficFilter, TriagePolicy, TriagePolicyUpdate, TriageResponse,
    TriageResponseUpdate, TrustedDomain, TrustedUserAgent, UniqueKey, Unstructured,
    UnstructuredClusteringAlgorithm, ValueKind,
};
pub use self::time_series::*;
pub use self::time_series::{ColumnTimeSeries, TimeCount, TimeSeriesResult};
pub use self::top_n::*;
pub use self::top_n::{
    ClusterScore, ClusterScoreSet, ClusterTrend, ElementCount, LineSegment, Regression,
    StructuredColumnType, TopColumnsOfCluster, TopMultimaps, TopTrendsByColumn,
};
pub use self::types::{EventCategory, HostNetworkGroup, Qualifier, Status};

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

const DEFAULT_STATES: &str = "states.ndb";
const LEGACY_STATES: &str = "states.db"; // in RocksDB format
const EXCLUSIVE: bool = true;

/// A local storage.
pub struct Store {
    states: native_db::Database<'static>,
    backup_path: PathBuf,
    legacy_states: StateDb,
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
        let legacy_db_path = path.join(LEGACY_STATES);
        let legacy_backup_path = backup.join(LEGACY_STATES);
        let states = native_db::Builder::new().create(&data::MODELS, db_path)?;
        let legacy_states = StateDb::open(&legacy_db_path, legacy_backup_path)?;
        let pretrained = path.join(Self::DEFAULT_PRETRAINED);
        if let Err(e) = std::fs::create_dir_all(&pretrained) {
            if e.kind() != io::ErrorKind::AlreadyExists {
                return Err(anyhow::anyhow!("{e}"));
            }
        }
        let store = Self {
            states,
            backup_path,
            legacy_states,
            pretrained,
        };
        Ok(store)
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn events(&self) -> EventDb {
        self.legacy_states.events()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn access_token_map(&self) -> Table<AccessToken> {
        self.legacy_states.access_tokens()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn account_map(&self) -> Table<types::Account> {
        self.legacy_states.accounts()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn account_policy_map(&self) -> Table<AccountPolicy> {
        self.legacy_states.account_policy()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn agents_map(&self) -> Table<Agent> {
        self.legacy_states.agents()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn allow_network_map(&self) -> IndexedTable<AllowNetwork> {
        self.legacy_states.allow_networks()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn batch_info_map(&self) -> Table<batch_info::BatchInfo> {
        self.legacy_states.batch_info()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn block_network_map(&self) -> IndexedTable<BlockNetwork> {
        self.legacy_states.block_networks()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn category_map(&self) -> IndexedTable<category::Category> {
        self.legacy_states.categories()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn csv_column_extra_map(&self) -> IndexedTable<CsvColumnExtraConfig> {
        self.legacy_states.csv_column_extras()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn customer_map(&self) -> IndexedTable<Customer> {
        self.legacy_states.customers()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn data_source_map(&self) -> IndexedTable<DataSource> {
        self.legacy_states.data_sources()
    }

    /// Returns the tag set for event.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails or the data is invalid.
    #[allow(clippy::missing_panics_doc)]
    pub fn event_tag_set(&self) -> Result<TagSet<EventTagId>> {
        let set = self
            .legacy_states
            .indexed_set(tables::EVENT_TAGS)
            .expect("always available");
        TagSet::new(set)
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn filter_map(&self) -> Table<Filter> {
        self.legacy_states.filters()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn model_indicator_map(&self) -> Table<ModelIndicator> {
        self.legacy_states.model_indicators()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn network_map(&self) -> IndexedTable<Network> {
        self.legacy_states.networks()
    }

    /// Returns the tag set for network.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails or the data is invalid.
    #[allow(clippy::missing_panics_doc)]
    pub fn network_tag_set(&self) -> Result<TagSet<NetworkTagId>> {
        let set = self
            .legacy_states
            .indexed_set(tables::NETWORK_TAGS)
            .expect("always available");
        TagSet::new(set)
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn node_map(&self) -> NodeTable {
        self.legacy_states.nodes()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn outlier_map(&self) -> Table<OutlierInfo> {
        self.legacy_states.outlier_infos()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn sampling_policy_map(&self) -> IndexedTable<SamplingPolicy> {
        self.legacy_states.sampling_policies()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn qualifier_map(&self) -> IndexedTable<types::Qualifier> {
        self.legacy_states.qualifiers()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn scores_map(&self) -> Table<scores::Scores> {
        self.legacy_states.scores()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn status_map(&self) -> IndexedTable<types::Status> {
        self.legacy_states.statuses()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn template_map(&self) -> Table<Template> {
        self.legacy_states.templates()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn tidb_map(&self) -> Table<Tidb> {
        self.legacy_states.tidbs()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn tor_exit_node_map(&self) -> Table<TorExitNode> {
        self.legacy_states.tor_exit_nodes()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn triage_policy_map(&self) -> IndexedTable<TriagePolicy> {
        self.legacy_states.triage_policies()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn triage_response_map(&self) -> IndexedTable<TriageResponse> {
        self.legacy_states.triage_responses()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn trusted_domain_map(&self) -> Table<TrustedDomain> {
        self.legacy_states.trusted_domains()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn trusted_user_agent_map(&self) -> Table<TrustedUserAgent> {
        self.legacy_states.trusted_user_agents()
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn traffic_filter_map(&self) -> Table<TrafficFilter> {
        self.legacy_states.traffic_filters()
    }

    /// Returns the tag set for workflow.
    ///
    /// # Errors
    ///
    /// Returns an error if database operation fails or the data is invalid.
    #[allow(clippy::missing_panics_doc)]
    pub fn workflow_tag_set(&self) -> Result<TagSet<WorkflowTagId>> {
        let set = self
            .legacy_states
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
