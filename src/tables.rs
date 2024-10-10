mod access_token;
mod account_policy;
mod accounts;
mod agent;
mod allow_network;
mod batch_info;
mod block_network;
mod category;
mod csv_column_extra;
mod customer;
mod data_source;
mod filter;
mod model_indicator;
mod network;
mod node;
mod outlier_info;
mod qualifier;
mod sampling_policy;
mod scores;
mod status;
mod template;
mod tidb;
mod tor_exit_node;
mod traffic_filter;
mod triage_policy;
mod triage_response;
mod trusted_domain;
mod trusted_user_agent;

use std::{
    borrow::Borrow,
    ops::RangeBounds,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use anyhow::{anyhow, Result};
use names::TRUSTED_DOMAIN_NAMES;
use serde::{Deserialize, Serialize};

pub use self::access_token::AccessToken;
pub use self::account_policy::AccountPolicy;
pub use self::agent::{Agent, Config as AgentConfig, Kind as AgentKind, Status as AgentStatus};
pub use self::allow_network::{AllowNetwork, Update as AllowNetworkUpdate};
pub use self::block_network::{BlockNetwork, Update as BlockNetworkUpdate};
pub use self::csv_column_extra::CsvColumnExtra;
pub use self::customer::{Customer, Network as CustomerNetwork, Update as CustomerUpdate};
pub use self::data_source::{DataSource, DataType, Update as DataSourceUpdate};
pub use self::filter::Filter;
pub use self::model_indicator::ModelIndicator;
pub use self::network::{Network, Update as NetworkUpdate};
pub(crate) use self::node::Inner as InnerNode;
pub use self::node::{
    Giganto, Node, Profile as NodeProfile, Table as NodeTable, Update as NodeUpdate,
};
pub use self::outlier_info::{Key as OutlierInfoKey, OutlierInfo, Value as OutlierInfoValue};
pub use self::sampling_policy::{
    Interval as SamplingInterval, Kind as SamplingKind, Period as SamplingPeriod, SamplingPolicy,
    Update as SamplingPolicyUpdate,
};
pub use self::template::{
    Structured, StructuredClusteringAlgorithm, Template, Unstructured,
    UnstructuredClusteringAlgorithm,
};
pub use self::tidb::{Kind as TidbKind, Rule as TidbRule, Tidb};
pub use self::tor_exit_node::TorExitNode;
pub use self::traffic_filter::{ProtocolPorts, TrafficFilter};
pub use self::triage_policy::{
    AttrCmpKind, Confidence, PacketAttr, Response, ResponseKind, Ti, TiCmpKind, TriagePolicy,
    Update as TriagePolicyUpdate, ValueKind,
};
pub use self::triage_response::{TriageResponse, Update as TriageResponseUpdate};
pub use self::trusted_domain::TrustedDomain;
pub use self::trusted_user_agent::TrustedUserAgent;
use super::{event, Indexed, IndexedMap, Map};
use crate::{
    batch_info::BatchInfo,
    category::Category,
    collections::IndexedSet,
    scores::Scores,
    types::{Account, FromKeyValue, Qualifier, Status},
    Direction, Indexable,
};

pub(crate) mod names {
    pub(crate) const TRUSTED_DOMAIN_NAMES: &str = "trusted_domain_names 0.31.0";
}

pub(crate) const NAMES: [&str; 1] = [TRUSTED_DOMAIN_NAMES];

// Key-value map names in `Database`.
pub(super) const ACCESS_TOKENS: &str = "access_tokens";
pub(super) const ACCOUNTS: &str = "accounts";
pub(super) const ACCOUNT_POLICY: &str = "account policy";
pub(super) const AGENTS: &str = "agents";
pub(super) const ALLOW_NETWORKS: &str = "allow networks";
pub(super) const BATCH_INFO: &str = "batch_info";
pub(super) const BLOCK_NETWORKS: &str = "block networks";
pub(super) const CATEGORY: &str = "category";
pub(super) const CSV_COLUMN_EXTRAS: &str = "csv column extras";
pub(super) const CUSTOMERS: &str = "customers";
pub(super) const DATA_SOURCES: &str = "data sources";
pub(super) const FILTERS: &str = "filters";
pub(super) const MODEL_INDICATORS: &str = "model indicators";
const META: &str = "meta";
pub(super) const NETWORKS: &str = "networks";
pub(super) const NODES: &str = "nodes";
pub(super) const OUTLIERS: &str = "outliers";
pub(super) const QUALIFIERS: &str = "qualifiers";
pub(super) const SAMPLING_POLICY: &str = "sampling policy";
pub(super) const SCORES: &str = "scores";
pub(super) const STATUSES: &str = "statuses";
pub(super) const TEMPLATES: &str = "templates";
pub(super) const TIDB: &str = "TI database";
pub(super) const TOR_EXIT_NODES: &str = "Tor exit nodes";
pub(super) const TRAFFIC_FILTER_RULES: &str = "traffic filter rules";
pub(super) const TRIAGE_POLICY: &str = "triage policy";
pub(super) const TRIAGE_RESPONSE: &str = "triage response";
pub(super) const TRUSTED_DNS_SERVERS: &str = "trusted DNS servers";
pub(super) const TRUSTED_USER_AGENTS: &str = "trusted user agents";

const MAP_NAMES: [&str; 29] = [
    ACCESS_TOKENS,
    ACCOUNTS,
    ACCOUNT_POLICY,
    AGENTS,
    ALLOW_NETWORKS,
    BATCH_INFO,
    BLOCK_NETWORKS,
    CATEGORY,
    CSV_COLUMN_EXTRAS,
    CUSTOMERS,
    DATA_SOURCES,
    FILTERS,
    MODEL_INDICATORS,
    META,
    NETWORKS,
    NODES,
    OUTLIERS,
    QUALIFIERS,
    SAMPLING_POLICY,
    SCORES,
    STATUSES,
    TEMPLATES,
    TIDB,
    TOR_EXIT_NODES,
    TRAFFIC_FILTER_RULES,
    TRIAGE_POLICY,
    TRIAGE_RESPONSE,
    TRUSTED_DNS_SERVERS,
    TRUSTED_USER_AGENTS,
];

// Keys for the meta map.
pub(super) const EVENT_TAGS: &[u8] = b"event tags";
pub(super) const NETWORK_TAGS: &[u8] = b"network tags";
pub(super) const WORKFLOW_TAGS: &[u8] = b"workflow tags";

static DUMMY_DB: LazyLock<redb::Database> = LazyLock::new(|| {
    redb::Builder::new()
        .create_with_backend(redb::backends::InMemoryBackend::new())
        .expect("infallible in memory")
});

#[allow(clippy::module_name_repetitions)]
pub(crate) struct StateDb {
    inner: Option<rocksdb::OptimisticTransactionDB>,
    backup: PathBuf,
    db: PathBuf,
}

impl StateDb {
    pub fn open(path: &Path, backup: PathBuf) -> Result<Self> {
        Self::open_db(path).map(|db| Self {
            inner: Some(db),
            backup,
            db: path.to_owned(),
        })
    }

    #[must_use]
    pub(crate) fn access_tokens(&self) -> Table<AccessToken> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<AccessToken>::open(inner).expect("{ACCESS_TOKENS} table must be present")
    }

    #[must_use]
    pub(crate) fn accounts(&self) -> Table<Account> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Account>::open(inner).expect("{ACCOUNTS} table must be present")
    }

    #[must_use]
    pub(crate) fn account_policy(&self) -> Table<AccountPolicy> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<AccountPolicy>::open(inner).expect("{ACCOUNT_POLICY} table must be present")
    }

    #[must_use]
    pub(crate) fn agents(&self) -> Table<Agent> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Agent>::open(inner).expect("{AGENTS} table must be present")
    }

    #[must_use]
    pub(crate) fn batch_info(&self) -> Table<BatchInfo> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<BatchInfo>::open(inner).expect("{BATCH_INFO} table must be present")
    }

    #[must_use]
    pub(crate) fn filters(&self) -> Table<Filter> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Filter>::open(inner).expect("{FILTERS} table must be present")
    }

    #[must_use]
    pub(crate) fn model_indicators(&self) -> Table<ModelIndicator> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<ModelIndicator>::open(inner).expect("{MODEL_INDICATORS} table must be present")
    }

    #[must_use]
    pub(crate) fn scores(&self) -> Table<Scores> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Scores>::open(inner).expect("{SCORES} table must be present")
    }

    #[must_use]
    pub(crate) fn templates(&self) -> Table<Template> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Template>::open(inner).expect("{TEMPLATES} table must be present")
    }

    #[must_use]
    pub(crate) fn tor_exit_nodes(&self) -> Table<TorExitNode> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<TorExitNode>::open(inner).expect("{TOR_EXIT_NODES} table must be present")
    }

    #[must_use]
    pub(crate) fn categories(&self) -> IndexedTable<Category> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Category>::open(inner).expect("{CATEGORY} table must be present")
    }

    #[must_use]
    pub(crate) fn qualifiers(&self) -> IndexedTable<Qualifier> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Qualifier>::open(inner).expect("{QUALIFIERS} table must be present")
    }

    #[must_use]
    pub(crate) fn statuses(&self) -> IndexedTable<Status> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Status>::open(inner).expect("{STATUSES} table must be present")
    }

    #[must_use]
    pub(crate) fn csv_column_extras(&self) -> IndexedTable<CsvColumnExtra> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<CsvColumnExtra>::open(inner)
            .expect("{CSV_COLUMN_EXTRAS} table must be present")
    }

    #[must_use]
    pub(crate) fn triage_responses(&self) -> IndexedTable<TriageResponse> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<TriageResponse>::open(inner)
            .expect("{TRIAGE_RESPONSE} table must be present")
    }

    #[must_use]
    pub(crate) fn networks(&self) -> IndexedTable<Network> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Network>::open(inner).expect("{NETWORKS} table must be present")
    }

    #[must_use]
    pub(crate) fn allow_networks(&self) -> IndexedTable<AllowNetwork> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<AllowNetwork>::open(inner).expect("{ALLOW_NETWORKS} table must be present")
    }

    #[must_use]
    pub(crate) fn block_networks(&self) -> IndexedTable<BlockNetwork> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<BlockNetwork>::open(inner).expect("{BLOCK_NETWORKS} table must be present")
    }

    #[must_use]
    pub(crate) fn sampling_policies(&self) -> IndexedTable<SamplingPolicy> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<SamplingPolicy>::open(inner)
            .expect("{SAMPLING_POLICY} table must be present")
    }

    #[must_use]
    pub(crate) fn customers(&self) -> IndexedTable<Customer> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<Customer>::open(inner).expect("{CUSTOMERS} table must be present")
    }

    #[must_use]
    pub(crate) fn data_sources(&self) -> IndexedTable<DataSource> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<DataSource>::open(inner).expect("{DATA_SOURCES} table must be present")
    }

    pub(crate) fn nodes(&self) -> NodeTable {
        let inner = self.inner.as_ref().expect("database must be open");
        NodeTable::open(inner).expect("{NETWORKS} table must be present")
    }

    #[must_use]
    pub(crate) fn triage_policies(&self) -> IndexedTable<TriagePolicy> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedTable::<TriagePolicy>::open(inner).expect("{TRIAGE_POLICY} table must be present")
    }

    #[must_use]
    pub(crate) fn tidbs(&self) -> Table<Tidb> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<Tidb>::open(inner).expect("{TIDB} table must be present")
    }

    #[must_use]
    pub(crate) fn trusted_domains(&self) -> Table<TrustedDomain, &'static str, &'static str> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<TrustedDomain, &'static str, &'static str>::open(inner)
            .expect("{TRUSTED_DNS_SERVERS} table must be present")
    }

    pub(crate) fn trusted_user_agents(&self) -> Table<TrustedUserAgent> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<TrustedUserAgent>::open(inner).expect("{TRUSTED_USER_AGENTS} table must be present")
    }

    pub(crate) fn traffic_filters(&self) -> Table<TrafficFilter> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<TrafficFilter>::open(inner).expect("{TRAFFIC_FILTER_RULES} table must be present")
    }

    pub(crate) fn outlier_infos(&self) -> Table<OutlierInfo> {
        let inner = self.inner.as_ref().expect("database must be open");
        Table::<OutlierInfo>::open(inner).expect("{OUTLIERS} table must be present")
    }

    #[must_use]
    pub fn events(&self) -> event::EventDb {
        let inner = self.inner.as_ref().expect("database must be open");
        event::EventDb::new(inner)
    }

    #[must_use]
    pub(super) fn indexed_set(&self, name: &'static [u8]) -> Option<IndexedSet> {
        let inner = self.inner.as_ref().expect("database must be open");
        IndexedSet::new(inner, META, name).ok()
    }

    pub(super) fn create_new_backup_flush(
        &mut self,
        flush: bool,
        num_of_backups_to_keep: u32,
    ) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        let inner = self
            .inner
            .as_ref()
            .ok_or(anyhow!("unable to backup, database has closed"))?;
        engine.create_new_backup_flush(inner, flush)?;

        engine
            .purge_old_backups(num_of_backups_to_keep as usize)
            .or_else(|_| self.reboot())
    }

    pub fn restore_from_latest_backup(&mut self) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        let mut opts = rocksdb::backup::RestoreOptions::default();
        opts.set_keep_log_files(true);

        self.close();

        engine.restore_from_latest_backup(&self.db, &self.db, &opts)?;

        self.reboot()
    }

    pub fn restore_from_backup(&mut self, id: u32) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        let opts = rocksdb::backup::RestoreOptions::default();

        self.close();

        engine.restore_from_backup(&self.db, &self.db, &opts, id)?;

        self.reboot()
    }

    pub fn get_backup_info(&self) -> Result<Vec<rocksdb::backup::BackupEngineInfo>> {
        let engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        Ok(engine.get_backup_info())
    }

    pub fn purge_old_backups(&mut self, num_of_backups_to_keep: u32) -> Result<()> {
        let mut engine = open_rocksdb_backup_engine(self.backup.as_path())?;

        if engine
            .purge_old_backups(num_of_backups_to_keep as usize)
            .is_err()
        {
            self.reboot()?;
        }
        Ok(())
    }

    fn close(&mut self) {
        if let Some(db) = self.inner.as_ref() {
            db.cancel_all_background_work(true);
        }
        self.inner = None;
    }

    fn reboot(&mut self) -> Result<()> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = rocksdb::OptimisticTransactionDB::open_cf(&opts, &self.db, MAP_NAMES)?;

        self.inner = Some(db);
        Ok(())
    }

    fn open_db(path: &Path) -> Result<rocksdb::OptimisticTransactionDB> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        Ok(rocksdb::OptimisticTransactionDB::open_cf(
            &opts, path, MAP_NAMES,
        )?)
    }

    pub(crate) fn clear_table(&mut self, name: &str) -> Result<()> {
        let inner = self.inner.as_mut().expect("database must be open");
        inner.drop_cf(name)?;
        Ok(())
    }
}

/// Represents a table that can be iterated over.
pub trait Iterable<'i, I>
where
    I: Iterator,
{
    /// Returns an iterator over the records in the table.
    fn iter(&'i self, direction: Direction, from: Option<&[u8]>) -> I;
    /// Returns an iterator over the records with prefix in the table.
    fn prefix_iter(&'i self, direction: Direction, from: Option<&[u8]>, prefix: &[u8]) -> I;
}

/// An iterator over the records in a table.
pub struct TableIter<'i, R> {
    inner: rocksdb::DBIteratorWithThreadMode<
        'i,
        rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
    >,
    _phantom: std::marker::PhantomData<R>,
}

impl<'i, R> TableIter<'i, R> {
    fn new(
        inner: rocksdb::DBIteratorWithThreadMode<
            'i,
            rocksdb::OptimisticTransactionDB<rocksdb::SingleThreaded>,
        >,
    ) -> Self {
        Self {
            inner,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'i, R> Iterator for TableIter<'i, R>
where
    R: FromKeyValue,
{
    type Item = Result<R, anyhow::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let serialized_item = self.inner.next()?;
        match serialized_item {
            Ok((mut key, mut value)) => {
                if key.is_empty() {
                    match self.inner.next()? {
                        Ok((k, v)) => {
                            key = k;
                            value = v;
                        }
                        Err(e) => return Some(Err(e.into())),
                    }
                }
                let item = R::from_key_value(&key, &value);
                Some(item.map_err(Into::into))
            }
            Err(e) => Some(Err(e.into())),
        }
    }
}

/// A database table storing records of type `R`.
#[derive(Clone)]
pub struct Table<'db, 'n, 'd, R, K = (), V = ()>
where
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    // This has both redb and RocksDB table information. `map` will be removed
    // once all the tables are migrated to redb.
    db: &'db redb::Database,
    def: redb::TableDefinition<'n, K, V>,
    map: Map<'d>,
    _phantom: std::marker::PhantomData<R>,
}

impl<'db, 'n, 'd, R, K, V> Table<'db, 'n, 'd, R, K, V>
where
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    fn new(map: Map<'d>) -> Self {
        Self {
            db: &DUMMY_DB,
            def: redb::TableDefinition::new("dummy"), // a placeholder
            map,
            _phantom: std::marker::PhantomData,
        }
    }

    pub(crate) fn database(&mut self, db: &'db redb::Database) -> &mut Self {
        self.db = db;
        self
    }

    pub(crate) fn name(&mut self, name: &'n str) -> &mut Self {
        self.def = redb::TableDefinition::new(name);
        self
    }
}

impl<'db, 'n, 'd, R, K, V> Table<'db, 'n, 'd, R, K, V>
where
    R: UniqueKey + Value,
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    /// Stores a record into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, record: &R) -> Result<()> {
        self.map
            .put(record.unique_key().as_ref(), record.value().as_ref())
    }

    /// Adds a record into the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the record with the same key exists, or the database
    /// operation fails.
    pub fn insert(&self, record: &R) -> Result<()> {
        self.map
            .insert(record.unique_key().as_ref(), record.value().as_ref())
    }
}

impl<'db, 'n, 'd, R, K, V> Table<'db, 'n, 'd, R, K, V>
where
    R: KeyValue<K, V>,
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    /// Stores a record into the database.
    ///
    /// If the table has a record with the same key, it will be replaced.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn upsert(&self, record: &R) -> Result<()> {
        let txn = self.db.begin_write()?;
        let mut tbl = txn.open_table::<K, V>(self.def)?;
        tbl.insert(record.db_key(), record.db_value())?;
        drop(tbl);
        txn.commit()?;
        Ok(())
    }

    /// Constructs a double-ended iterator over a sub-range of elements in the table.
    ///
    /// # Errors
    ///
    /// Returns an error if database operations fail.
    pub fn range<'a, KR>(&self, range: impl RangeBounds<KR> + 'a) -> Result<Range<'_, R, K, V>>
    where
        KR: Borrow<K::SelfType<'a>> + 'a,
    {
        let txn = self.db.begin_read()?;
        let tbl = txn.open_table::<K, V>(self.def)?;
        Ok(tbl.range(range)?.into())
    }
}

pub struct Range<'a, R, K, V>
where
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    inner: redb::Range<'a, K, V>,
    _phantom: std::marker::PhantomData<R>,
}

impl<'a, R, K, V> From<redb::Range<'a, K, V>> for Range<'a, R, K, V>
where
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    fn from(inner: redb::Range<'a, K, V>) -> Self {
        Self {
            inner,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<R, K, V> Iterator for Range<'_, R, K, V>
where
    R: KeyValue<K, V>,
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    type Item = Result<R>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|r| {
            r.map(|(k, v)| R::from_key_value(k.value(), v.value()))
                .map_err(Into::into)
        })
    }
}

impl<R, K, V> DoubleEndedIterator for Range<'_, R, K, V>
where
    R: KeyValue<K, V>,
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(|r| {
            r.map(|(k, v)| R::from_key_value(k.value(), v.value()))
                .map_err(Into::into)
        })
    }
}

impl<'db, 'n, 'i, 'j, 'k, R, K, V> Iterable<'i, TableIter<'k, R>> for Table<'db, 'n, 'j, R, K, V>
where
    'j: 'k,
    'i: 'k,
    R: FromKeyValue,
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    fn iter(&self, direction: Direction, from: Option<&[u8]>) -> TableIter<'k, R> {
        use rocksdb::IteratorMode;

        match direction {
            Direction::Forward => match from {
                Some(from) => TableIter::new(
                    self.map
                        .db
                        .iterator_cf(self.map.cf, IteratorMode::From(from, Direction::Forward)),
                ),
                None => TableIter::new(self.map.db.iterator_cf(self.map.cf, IteratorMode::Start)),
            },
            Direction::Reverse => match from {
                Some(from) => TableIter::new(
                    self.map
                        .db
                        .iterator_cf(self.map.cf, IteratorMode::From(from, Direction::Reverse)),
                ),
                None => TableIter::new(self.map.db.iterator_cf(self.map.cf, IteratorMode::End)),
            },
        }
    }

    fn prefix_iter(
        &'i self,
        direction: Direction,
        from: Option<&[u8]>,
        prefix: &[u8],
    ) -> TableIter<'k, R> {
        let mut readopts = rocksdb::ReadOptions::default();
        readopts.set_iterate_range(rocksdb::PrefixRange(prefix));
        let mode = {
            match from {
                Some(from) => rocksdb::IteratorMode::From(from, direction),
                None => match direction {
                    Direction::Forward => rocksdb::IteratorMode::Start,
                    Direction::Reverse => rocksdb::IteratorMode::End,
                },
            }
        };
        let iter = self.map.db.iterator_cf_opt(self.map.cf, readopts, mode);

        TableIter::new(iter)
    }
}

pub struct IndexedTable<'d, R> {
    indexed_map: IndexedMap<'d>,
    _phantom: std::marker::PhantomData<R>,
}

impl<'d, R> IndexedTable<'d, R> {
    fn new(indexed_map: IndexedMap<'d>) -> Self {
        Self {
            indexed_map,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Returns the number of entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the map index is not found or the database operation fails.
    pub fn count(&self) -> Result<usize> {
        self.indexed_map.count()
    }

    /// Stores a record with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn put(&self, entry: R) -> Result<u32>
    where
        R: Indexable,
    {
        self.indexed_map.insert(entry)
    }

    /// Removes a record with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn remove(&self, id: u32) -> Result<Vec<u8>>
    where
        R: Indexable,
    {
        self.indexed_map.remove::<R>(id)
    }

    /// Get a record with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn get_by_id(&self, id: u32) -> Result<Option<R>>
    where
        R: Indexable + FromKeyValue,
    {
        self.indexed_map.get_by_id(id)
    }

    /// Deactivates a key-value pair with the given ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    pub fn deactivate(&self, id: u32) -> Result<Vec<u8>> {
        self.indexed_map.deactivate(id)
    }
}

impl<'i, 'j, 'k, R> Iterable<'i, TableIter<'k, R>> for IndexedTable<'j, R>
where
    'j: 'k,
    'i: 'k,
    R: FromKeyValue,
{
    fn iter(&'i self, direction: Direction, from: Option<&[u8]>) -> TableIter<'k, R> {
        use rocksdb::IteratorMode;

        match direction {
            Direction::Forward => match from {
                Some(from) => TableIter::new(self.indexed_map.db().iterator_cf(
                    self.indexed_map.cf(),
                    IteratorMode::From(from, Direction::Forward),
                )),
                None => TableIter::new(
                    self.indexed_map
                        .db()
                        .iterator_cf(self.indexed_map.cf(), IteratorMode::Start),
                ),
            },
            Direction::Reverse => match from {
                Some(from) => TableIter::new(self.indexed_map.db().iterator_cf(
                    self.indexed_map.cf(),
                    IteratorMode::From(from, Direction::Reverse),
                )),
                None => TableIter::new(
                    self.indexed_map
                        .db()
                        .iterator_cf(self.indexed_map.cf(), IteratorMode::End),
                ),
            },
        }
    }

    fn prefix_iter(
        &'i self,
        direction: Direction,
        from: Option<&[u8]>,
        prefix: &[u8],
    ) -> TableIter<'k, R> {
        let mut readopts = rocksdb::ReadOptions::default();
        readopts.set_iterate_range(rocksdb::PrefixRange(prefix));
        let mode = {
            match from {
                Some(from) => rocksdb::IteratorMode::From(from, direction),
                None => match direction {
                    Direction::Forward => rocksdb::IteratorMode::Start,
                    Direction::Reverse => rocksdb::IteratorMode::End,
                },
            }
        };
        let iter = self
            .indexed_map
            .db()
            .iterator_cf_opt(self.indexed_map.cf(), readopts, mode);

        TableIter::new(iter)
    }
}

/// Represents entities that can be uniquely identified by a key.
///
/// The `UniqueKey` trait is designed to provide a standardized way to retrieve
/// a unique, opaque key for instances of structs that implement this trait. The
/// key is returned as a `AsRef<[u8]>`, allowing for flexible ownership
/// models.
///
/// Implementing this trait allows for unique identification of instances, which
/// can be used for indexing, identification in collections, or any scenario
/// where a distinct, non-colliding identifier is necessary.
///
/// # Examples
///
/// ```
/// # use review_database::UniqueKey;
/// struct User {
///     id: u32,
///     username: String,
/// }
///
/// impl UniqueKey for User {
///     type AsBytes<'a> = [u8; 4];
///
///     fn unique_key(&self) -> [u8; 4] {
///         self.id.to_be_bytes()
///     }
/// }
/// ```
pub trait UniqueKey {
    type AsBytes<'a>: AsRef<[u8]> + 'a
    where
        Self: 'a;

    /// Returns a unique, opaque key for the instance.
    ///
    /// This method should return an object that implements `AsRef<[u8]>` and
    /// uniquely identifies the instance of the struct.
    ///
    /// # Examples
    ///
    /// Using the `UniqueKey` implementation for a `User` struct defined in the
    /// trait-level documentation:
    ///
    /// ```
    /// # use review_database::UniqueKey;
    /// # struct User {
    /// #     id: u32,
    /// #     username: String,
    /// # }
    /// # impl UniqueKey for User {
    /// #     type AsBytes<'a> = [u8; 4];
    /// #     fn unique_key(&self) -> [u8; 4] {
    /// #         self.id.to_be_bytes()
    /// #     }
    /// # }
    /// let user = User { id: 1, username: String::from("alice") };
    /// assert_eq!(user.unique_key().as_ref(), b"\x00\x00\x00\x01");
    /// ```
    ///
    /// In this example, the `unique_key` method returns the user's `id` as a
    /// byte array, providing a unique key for the user instance.
    fn unique_key(&self) -> Self::AsBytes<'_>;
}

pub trait Value {
    type AsBytes<'a>: AsRef<[u8]> + 'a
    where
        Self: 'a;

    fn value(&self) -> Self::AsBytes<'_>;
}

fn serialize<I: Serialize>(input: &I) -> anyhow::Result<Vec<u8>> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new().serialize(input)?)
}

fn deserialize<'de, O: Deserialize<'de>>(input: &'de [u8]) -> anyhow::Result<O> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new().deserialize(input)?)
}

/// Opens a RocksDB backup engine using the default options and environment.
fn open_rocksdb_backup_engine(
    path: &Path,
) -> Result<rocksdb::backup::BackupEngine, rocksdb::Error> {
    let opts = rocksdb::backup::BackupEngineOptions::new(path)?;
    let db_env = rocksdb::Env::new()?;
    rocksdb::backup::BackupEngine::open(&opts, &db_env)
}

pub trait KeyValue<K, V>
where
    K: redb::Key,
    V: redb::Value,
{
    fn db_key(&self) -> K::SelfType<'_>;
    fn db_value(&self) -> V::SelfType<'_>;
    fn from_key_value(key: K::SelfType<'_>, value: V::SelfType<'_>) -> Self;
}
